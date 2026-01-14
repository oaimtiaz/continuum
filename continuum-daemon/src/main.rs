//! Continuum Daemon - Service that runs on device
//!
//! Exposes gRPC API for CLI and other interfaces, spawns shim processes
//! to execute tasks, and maintains in-memory task state.

use std::pin::Pin;
use std::sync::Arc;

use async_stream::stream;
use continuum_core::task::TaskId;
use continuum_core::task::TaskStatus as CoreTaskStatus;
use continuum_proto::{
    continuum_server::{Continuum, ContinuumServer},
    CancelTaskRequest, CancelTaskResponse, GetTaskRequest, GetTaskResponse, ListTasksRequest,
    ListTasksResponse, OutputChunk, RunTaskRequest, RunTaskResponse, SendInputRequest,
    SendInputResponse, StreamOutputRequest, TaskStatus as ProtoTaskStatus, FILE_DESCRIPTOR_SET,
};

use convert::{output_chunk_to_proto, task_to_view};
use tokio_stream::Stream;
use tonic::{transport::Server, Request, Response, Status};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod convert;
mod ipc;
mod store;
mod supervisor;

use store::TaskStore;
use supervisor::TaskSupervisor;

pub struct ContinuumService {
    store: Arc<TaskStore>,
    supervisor: TaskSupervisor,
}

impl std::fmt::Debug for ContinuumService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContinuumService")
            .field("supervisor", &self.supervisor)
            .finish()
    }
}

type StreamOutputResult = Pin<Box<dyn Stream<Item = Result<OutputChunk, Status>> + Send>>;

#[tonic::async_trait]
impl Continuum for ContinuumService {
    type StreamOutputStream = StreamOutputResult;

    async fn run_task(
        &self,
        request: Request<RunTaskRequest>,
    ) -> Result<Response<RunTaskResponse>, Status> {
        let req = request.into_inner();

        let name = if req.name.is_empty() {
            req.cmd
                .first()
                .cloned()
                .unwrap_or_else(|| "task".to_string())
        } else {
            req.name
        };

        let cwd = req.cwd.unwrap_or_else(|| {
            std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "/".to_string())
        });

        if req.cmd.is_empty() {
            return Err(Status::invalid_argument("cmd is required"));
        }

        tracing::info!(name = %name, cmd = ?req.cmd, cwd = %cwd, "RunTask request");

        let task_id = self
            .supervisor
            .spawn_task(name, req.cmd, cwd, req.env)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Wait a moment for the task to start and get initial state
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let task = self
            .store
            .get(&task_id)
            .await
            .ok_or_else(|| Status::internal("Task not found after creation"))?;

        let task_view = task_to_view(&task);
        Ok(Response::new(RunTaskResponse {
            task: Some(task_view),
        }))
    }

    async fn list_tasks(
        &self,
        request: Request<ListTasksRequest>,
    ) -> Result<Response<ListTasksResponse>, Status> {
        let req = request.into_inner();
        tracing::debug!(status_filter = ?req.status_filter, limit = ?req.limit, "ListTasks request");

        let mut tasks = self.store.list().await;

        // Apply status filter if provided
        if let Some(status_filter) = req.status_filter {
            let filter_status = match ProtoTaskStatus::try_from(status_filter) {
                Ok(ProtoTaskStatus::Queued) => Some(CoreTaskStatus::Queued),
                Ok(ProtoTaskStatus::Running) => Some(CoreTaskStatus::Running),
                Ok(ProtoTaskStatus::Completed) => Some(CoreTaskStatus::Completed),
                Ok(ProtoTaskStatus::Failed) => Some(CoreTaskStatus::Failed),
                Ok(ProtoTaskStatus::Canceled) => Some(CoreTaskStatus::Canceled),
                _ => None,
            };
            if let Some(status) = filter_status {
                tasks.retain(|t| t.status == status);
            }
        }

        // Sort by created_at descending (most recent first)
        tasks.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply limit if provided
        if let Some(limit) = req.limit {
            tasks.truncate(limit as usize);
        }

        let task_views = tasks.iter().map(task_to_view).collect();
        Ok(Response::new(ListTasksResponse { tasks: task_views }))
    }

    async fn get_task(
        &self,
        request: Request<GetTaskRequest>,
    ) -> Result<Response<GetTaskResponse>, Status> {
        let req = request.into_inner();
        tracing::debug!(task_id = %req.task_id, "GetTask request");

        let uuid = Uuid::parse_str(&req.task_id)
            .map_err(|_| Status::invalid_argument("Invalid task ID format"))?;
        let task_id = TaskId::new(uuid);

        let task = self
            .store
            .get(&task_id)
            .await
            .ok_or_else(|| Status::not_found("Task not found"))?;

        let task_view = task_to_view(&task);
        Ok(Response::new(GetTaskResponse {
            task: Some(task_view),
        }))
    }

    async fn send_input(
        &self,
        request: Request<SendInputRequest>,
    ) -> Result<Response<SendInputResponse>, Status> {
        let req = request.into_inner();
        tracing::debug!(task_id = %req.task_id, bytes = req.data.len(), "SendInput request");

        let uuid = Uuid::parse_str(&req.task_id)
            .map_err(|_| Status::invalid_argument("Invalid task ID format"))?;
        let task_id = TaskId::new(uuid);

        self.supervisor
            .send_input(&task_id, req.data)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SendInputResponse {}))
    }

    async fn stream_output(
        &self,
        request: Request<StreamOutputRequest>,
    ) -> Result<Response<Self::StreamOutputStream>, Status> {
        let req = request.into_inner();
        tracing::debug!(task_id = %req.task_id, from_offset = ?req.from_offset, "StreamOutput request");

        let uuid = Uuid::parse_str(&req.task_id)
            .map_err(|_| Status::invalid_argument("Invalid task ID format"))?;
        let task_id = TaskId::new(uuid);

        // Verify task exists
        if self.store.get(&task_id).await.is_none() {
            return Err(Status::not_found("Task not found"));
        }

        let from_offset = req.from_offset.unwrap_or(0) as usize;

        // Get historical output
        let historical = self.store.get_output(&task_id, from_offset).await;

        // Subscribe to live output
        let mut receiver = self
            .store
            .subscribe_output(&task_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let store = self.store.clone();
        let task_id_clone = task_id.clone();

        let output_stream = stream! {
            // First, yield historical chunks
            for chunk in historical {
                yield Ok(output_chunk_to_proto(&chunk));
            }

            // Then stream live output until task completes or error
            loop {
                // Check if task has completed
                if let Some(task) = store.get(&task_id_clone).await {
                    if task.status.is_terminal() {
                        tracing::debug!(task = %task_id_clone.0, status = ?task.status, "Task completed, ending stream");
                        break;
                    }
                }

                match tokio::time::timeout(tokio::time::Duration::from_millis(500), receiver.recv()).await {
                    Ok(Ok(chunk)) => {
                        yield Ok(output_chunk_to_proto(&chunk));
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                        tracing::warn!(task = %task_id_clone.0, skipped = n, "Stream lagged");
                        // Continue streaming
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                        tracing::debug!(task = %task_id_clone.0, "Broadcast channel closed");
                        break;
                    }
                    Err(_) => {
                        // Timeout - loop back to check task status
                        continue;
                    }
                };

            }
        };

        Ok(Response::new(Box::pin(output_stream)))
    }

    async fn cancel_task(
        &self,
        request: Request<CancelTaskRequest>,
    ) -> Result<Response<CancelTaskResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(task_id = %req.task_id, force = req.force, "CancelTask request");

        let uuid = Uuid::parse_str(&req.task_id)
            .map_err(|_| Status::invalid_argument("Invalid task ID format"))?;
        let task_id = TaskId::new(uuid);

        // Verify task exists and is running
        let task = self
            .store
            .get(&task_id)
            .await
            .ok_or_else(|| Status::not_found("Task not found"))?;

        if task.status.is_terminal() {
            return Err(Status::failed_precondition("Task already terminated"));
        }

        // SIGTERM = 15, SIGKILL = 9
        let signum = if req.force { 9 } else { 15 };

        self.supervisor
            .send_signal(&task_id, signum)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CancelTaskResponse {}))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let addr = "127.0.0.1:50051".parse()?;

    let store = Arc::new(TaskStore::new());
    let supervisor = TaskSupervisor::new(store.clone());

    let service = ContinuumService { store, supervisor };

    tracing::info!("Continuum daemon listening on {}", addr);

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()?;

    Server::builder()
        .add_service(reflection)
        .add_service(ContinuumServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
