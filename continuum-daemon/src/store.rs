//! In-memory task storage with output buffering.

use std::collections::HashMap;

use continuum_core::task::{Stream, Task, TaskEvent, TaskId, TaskStatus};
use continuum_shim_proto::DaemonToShim;
use tokio::sync::{broadcast, mpsc, RwLock};

/// A chunk of output from a task.
#[derive(Debug, Clone)]
pub struct OutputChunk {
    pub stream: Stream,
    pub data: Vec<u8>,
    pub timestamp_ms: i64,
}

/// Error type for store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("task not found: {0}")]
    TaskNotFound(String),
    #[error("shim not connected for task: {0}")]
    ShimNotConnected(String),
    #[error("failed to send to shim: {0}")]
    SendFailed(String),
    #[error("invalid state transition: {0}")]
    InvalidTransition(String),
}

/// Internal entry for a task with associated channels and buffers.
struct TaskEntry {
    /// The task state.
    task: Task,
    /// Buffered output chunks.
    output_buffer: Vec<OutputChunk>,
    /// Broadcast sender for live output streaming.
    output_tx: broadcast::Sender<OutputChunk>,
    /// Channel to send messages to the shim.
    shim_tx: Option<mpsc::Sender<DaemonToShim>>,
}

/// In-memory task store.
pub struct TaskStore {
    inner: RwLock<HashMap<TaskId, TaskEntry>>,
}

impl TaskStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Insert a new task into the store.
    pub async fn insert(&self, task: Task) -> TaskId {
        let id = task.id.clone();
        let (output_tx, _) = broadcast::channel(256);

        let entry = TaskEntry {
            task,
            output_buffer: Vec::new(),
            output_tx,
            shim_tx: None,
        };

        let mut inner = self.inner.write().await;
        inner.insert(id.clone(), entry);
        id
    }

    /// Get a task by ID.
    pub async fn get(&self, id: &TaskId) -> Option<Task> {
        let inner = self.inner.read().await;
        inner.get(id).map(|e| e.task.clone())
    }

    /// List all tasks.
    pub async fn list(&self) -> Vec<Task> {
        let inner = self.inner.read().await;
        inner.values().map(|e| e.task.clone()).collect()
    }

    /// Apply an event to a task.
    pub async fn apply_event(&self, id: &TaskId, event: TaskEvent) -> Result<(), StoreError> {
        let mut inner = self.inner.write().await;
        let entry = inner
            .get_mut(id)
            .ok_or_else(|| StoreError::TaskNotFound(id.0.to_string()))?;

        entry
            .task
            .apply(&event)
            .map_err(|e| StoreError::InvalidTransition(e.to_string()))?;

        Ok(())
    }

    /// Append output to a task's buffer and broadcast to subscribers.
    pub async fn append_output(&self, id: &TaskId, chunk: OutputChunk) {
        let mut inner = self.inner.write().await;
        if let Some(entry) = inner.get_mut(id) {
            // Buffer the output
            entry.output_buffer.push(chunk.clone());

            // Broadcast to subscribers (ignore errors - no subscribers is fine)
            let _ = entry.output_tx.send(chunk);
        }
    }

    /// Get buffered output starting from an offset.
    pub async fn get_output(&self, id: &TaskId, from_offset: usize) -> Vec<OutputChunk> {
        let inner = self.inner.read().await;
        inner
            .get(id)
            .map(|e| e.output_buffer.iter().skip(from_offset).cloned().collect())
            .unwrap_or_default()
    }

    /// Subscribe to live output for a task.
    pub async fn subscribe_output(
        &self,
        id: &TaskId,
    ) -> Result<broadcast::Receiver<OutputChunk>, StoreError> {
        let inner = self.inner.read().await;
        let entry = inner
            .get(id)
            .ok_or_else(|| StoreError::TaskNotFound(id.0.to_string()))?;

        Ok(entry.output_tx.subscribe())
    }

    /// Set the shim sender channel for a task.
    pub async fn set_shim_sender(&self, id: &TaskId, tx: mpsc::Sender<DaemonToShim>) {
        let mut inner = self.inner.write().await;
        if let Some(entry) = inner.get_mut(id) {
            entry.shim_tx = Some(tx);
        }
    }

    /// Clear the shim sender channel for a task.
    #[allow(dead_code)]
    pub async fn clear_shim_sender(&self, id: &TaskId) {
        let mut inner = self.inner.write().await;
        if let Some(entry) = inner.get_mut(id) {
            entry.shim_tx = None;
        }
    }

    /// Send a message to a task's shim.
    pub async fn send_to_shim(&self, id: &TaskId, msg: DaemonToShim) -> Result<(), StoreError> {
        let inner = self.inner.read().await;
        let entry = inner
            .get(id)
            .ok_or_else(|| StoreError::TaskNotFound(id.0.to_string()))?;

        let tx = entry
            .shim_tx
            .as_ref()
            .ok_or_else(|| StoreError::ShimNotConnected(id.0.to_string()))?;

        tx.try_send(msg)
            .map_err(|e| StoreError::SendFailed(e.to_string()))?;

        Ok(())
    }

    /// Check if a task exists.
    #[allow(dead_code)]
    pub async fn exists(&self, id: &TaskId) -> bool {
        let inner = self.inner.read().await;
        inner.contains_key(id)
    }

    /// Get the status of a task.
    #[allow(dead_code)]
    pub async fn get_status(&self, id: &TaskId) -> Option<TaskStatus> {
        let inner = self.inner.read().await;
        inner.get(id).map(|e| e.task.status)
    }

    /// Update task with a closure.
    #[allow(dead_code)]
    pub async fn update<F>(&self, id: &TaskId, f: F) -> Result<(), StoreError>
    where
        F: FnOnce(&mut Task),
    {
        let mut inner = self.inner.write().await;
        let entry = inner
            .get_mut(id)
            .ok_or_else(|| StoreError::TaskNotFound(id.0.to_string()))?;

        f(&mut entry.task);
        Ok(())
    }
}

impl Default for TaskStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use continuum_core::identity::DeviceId;
    use continuum_core::task::{CreatedVia, TaskEventKind, TaskId};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_task(name: &str) -> Task {
        Task::new(
            TaskId::new(Uuid::new_v4()),
            name.to_string(),
            vec!["echo".to_string(), "hello".to_string()],
            PathBuf::from("/tmp"),
            BTreeMap::new(),
            DeviceId::new("test-device"),
            CreatedVia::Cli,
        )
    }

    #[tokio::test]
    async fn test_insert_and_get() {
        let store = TaskStore::new();
        let task = make_task("test");
        let id = task.id.clone();

        store.insert(task.clone()).await;

        let retrieved = store.get(&id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "test");
    }

    #[tokio::test]
    async fn test_list_tasks() {
        let store = TaskStore::new();

        store.insert(make_task("task1")).await;
        store.insert(make_task("task2")).await;

        let tasks = store.list().await;
        assert_eq!(tasks.len(), 2);
    }

    #[tokio::test]
    async fn test_apply_event() {
        let store = TaskStore::new();
        let task = make_task("test");
        let id = task.id.clone();
        store.insert(task).await;

        // Apply Started event
        let event = TaskEvent::new(TaskEventKind::Started { pid: Some(1234) });
        store.apply_event(&id, event).await.unwrap();

        let task = store.get(&id).await.unwrap();
        assert_eq!(task.status, TaskStatus::Running);
        assert_eq!(task.pid, Some(1234));
    }

    #[tokio::test]
    async fn test_output_buffering() {
        let store = TaskStore::new();
        let task = make_task("test");
        let id = task.id.clone();
        store.insert(task).await;

        // Append some output
        store
            .append_output(
                &id,
                OutputChunk {
                    stream: Stream::Pty,
                    data: b"hello".to_vec(),
                    timestamp_ms: 1000,
                },
            )
            .await;

        store
            .append_output(
                &id,
                OutputChunk {
                    stream: Stream::Pty,
                    data: b"world".to_vec(),
                    timestamp_ms: 2000,
                },
            )
            .await;

        // Get all output
        let output = store.get_output(&id, 0).await;
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].data, b"hello");
        assert_eq!(output[1].data, b"world");

        // Get from offset
        let output = store.get_output(&id, 1).await;
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].data, b"world");
    }

    #[tokio::test]
    async fn test_output_subscription() {
        let store = TaskStore::new();
        let task = make_task("test");
        let id = task.id.clone();
        store.insert(task).await;

        // Subscribe before appending
        let mut rx = store.subscribe_output(&id).await.unwrap();

        // Append output
        store
            .append_output(
                &id,
                OutputChunk {
                    stream: Stream::Pty,
                    data: b"test".to_vec(),
                    timestamp_ms: 1000,
                },
            )
            .await;

        // Receive should work
        let chunk = rx.recv().await.unwrap();
        assert_eq!(chunk.data, b"test");
    }
}
