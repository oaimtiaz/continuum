//! In-memory task storage with output buffering and database persistence.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use continuum_core::task::{Stream, Task, TaskEvent, TaskId, TaskStatus};
use continuum_shim_proto::DaemonToShim;
use tokio::sync::{broadcast, mpsc, RwLock};

use crate::db::DbService;

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
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::Database(e.to_string())
    }
}

/// Internal entry for a task with associated channels and buffers.
struct TaskEntry {
    /// The task state.
    task: Task,
    /// Buffered output chunks (for in-memory access).
    output_buffer: Vec<OutputChunk>,
    /// Broadcast sender for live output streaming.
    output_tx: broadcast::Sender<OutputChunk>,
    /// Channel to send messages to the shim.
    shim_tx: Option<mpsc::Sender<DaemonToShim>>,
    /// Sequence counter for events (used for DB ordering).
    event_sequence: AtomicI64,
    /// Current output chunk offset (for DB persistence).
    output_offset: AtomicI64,
    /// Whether this task was loaded from the database (vs created fresh).
    from_db: bool,
}

/// Task store with database persistence.
///
/// Maintains in-memory state for fast access while persisting critical
/// data to SQLite for durability across daemon restarts.
pub struct TaskStore {
    inner: RwLock<HashMap<TaskId, TaskEntry>>,
    db: DbService,
    /// Flag indicating the daemon is shutting down.
    shutting_down: AtomicBool,
}

impl TaskStore {
    /// Create a new store with database persistence.
    pub fn new(db: DbService) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            db,
            shutting_down: AtomicBool::new(false),
        }
    }

    /// Check if the daemon is shutting down.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Relaxed)
    }

    /// Load existing tasks from the database.
    ///
    /// Should be called once at startup after marking orphaned tasks as failed.
    pub async fn load_from_db(&self) -> Result<(), StoreError> {
        let tasks = self.db.load_all_tasks().await?;
        let mut inner = self.inner.write().await;

        for task in tasks {
            let (output_tx, _) = broadcast::channel(256);
            let entry = TaskEntry {
                task,
                output_buffer: Vec::new(), // Output loaded on-demand for historical tasks
                output_tx,
                shim_tx: None,
                event_sequence: AtomicI64::new(0),
                output_offset: AtomicI64::new(0),
                from_db: true,
            };
            inner.insert(entry.task.id.clone(), entry);
        }

        Ok(())
    }

    /// Insert a new task into the store.
    ///
    /// Persists the task to the database immediately (write-through).
    pub async fn insert(&self, task: Task) -> Result<TaskId, StoreError> {
        let id = task.id.clone();

        // Persist to database first
        self.db.insert_task(&task).await?;

        let (output_tx, _) = broadcast::channel(256);
        let entry = TaskEntry {
            task,
            output_buffer: Vec::new(),
            output_tx,
            shim_tx: None,
            event_sequence: AtomicI64::new(0),
            output_offset: AtomicI64::new(0),
            from_db: false,
        };

        let mut inner = self.inner.write().await;
        inner.insert(id.clone(), entry);
        Ok(id)
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
    ///
    /// For lifecycle events (Started, Exited, Canceled, FailedToStart),
    /// the updated task state is persisted to the database.
    pub async fn apply_event(&self, id: &TaskId, event: TaskEvent) -> Result<(), StoreError> {
        let is_lifecycle = event.is_lifecycle();

        let mut inner = self.inner.write().await;
        let entry = inner
            .get_mut(id)
            .ok_or_else(|| StoreError::TaskNotFound(id.0.to_string()))?;

        // Apply event to in-memory state
        entry
            .task
            .apply(&event)
            .map_err(|e| StoreError::InvalidTransition(e.to_string()))?;

        // Persist lifecycle events to database
        if is_lifecycle {
            let seq = entry.event_sequence.fetch_add(1, Ordering::SeqCst);

            // Update task state in DB
            if let Err(e) = self.db.update_task(&entry.task).await {
                tracing::error!(error = %e, task = %id.0, "Failed to persist task state");
            }

            // Insert event for audit trail
            if let Err(e) = self.db.insert_event(id, &event, seq).await {
                tracing::error!(error = %e, task = %id.0, "Failed to persist event");
            }
        }

        Ok(())
    }

    /// Append output to a task's buffer, broadcast to subscribers, and persist to DB.
    ///
    /// Output is persisted immediately (optimistic drain) so that if the daemon
    /// crashes, we don't lose output data.
    pub async fn append_output(&self, id: &TaskId, chunk: OutputChunk) {
        let offset = {
            let mut inner = self.inner.write().await;
            if let Some(entry) = inner.get_mut(id) {
                // Get and increment offset atomically
                let offset = entry.output_offset.fetch_add(1, Ordering::SeqCst);

                // Buffer the output for in-memory access
                entry.output_buffer.push(chunk.clone());

                // Broadcast to subscribers (ignore errors - no subscribers is fine)
                let _ = entry.output_tx.send(chunk.clone());

                Some((offset, chunk))
            } else {
                None
            }
        };

        // Persist to database outside the lock
        if let Some((offset, chunk)) = offset {
            if let Err(e) = self
                .db
                .insert_output_chunks(id, &[(chunk, offset as usize)])
                .await
            {
                tracing::error!(error = %e, task = %id.0, offset = offset, "Failed to persist output chunk");
            }
        }
    }

    /// Get buffered output starting from an offset.
    ///
    /// For tasks loaded from the database (historical), this loads output from
    /// the database. For active tasks, returns from the in-memory buffer.
    pub async fn get_output(&self, id: &TaskId, from_offset: usize) -> Vec<OutputChunk> {
        let inner = self.inner.read().await;

        if let Some(entry) = inner.get(id) {
            // For tasks loaded from DB with terminal status, load from database
            if entry.from_db && entry.task.status.is_terminal() && entry.output_buffer.is_empty() {
                drop(inner); // Release lock before DB call
                match self.db.load_output(id, from_offset).await {
                    Ok(chunks) => return chunks,
                    Err(e) => {
                        tracing::error!(error = %e, task = %id.0, "Failed to load output from DB");
                        return Vec::new();
                    }
                }
            }

            // For active tasks or tasks with in-memory buffer, use buffer
            entry
                .output_buffer
                .iter()
                .skip(from_offset)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
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

        tracing::debug!(task = %id.0, "Queuing message to shim channel");
        tx.try_send(msg)
            .map_err(|e| StoreError::SendFailed(e.to_string()))?;
        tracing::debug!(task = %id.0, "Message queued successfully");

        Ok(())
    }

    /// Signal shutdown and notify all connected shims.
    ///
    /// Sets the shutting_down flag (checked by output streams), marks running
    /// tasks as canceled, then sends Shutdown message to all shims and closes channels.
    ///
    /// Returns the number of shims that were notified.
    pub async fn broadcast_shutdown(&self) -> usize {
        use continuum_core::task::{Actor, TaskEvent, TaskEventKind};
        use continuum_shim_proto::{daemon_to_shim, Shutdown};

        // Set shutdown flag first - this will cause output streams to exit
        self.shutting_down.store(true, Ordering::SeqCst);

        let mut inner = self.inner.write().await;
        let mut count = 0;

        for (task_id, entry) in inner.iter_mut() {
            // Mark running tasks as canceled so CLI shows correct status
            if entry.task.status == TaskStatus::Running {
                let event = TaskEvent::new(TaskEventKind::Canceled {
                    actor: Actor::system(),
                });
                // Apply event to in-memory state (ignore errors during shutdown)
                let _ = entry.task.apply(&event);

                // Persist to database
                if let Err(e) = self.db.update_task(&entry.task).await {
                    tracing::error!(task = %task_id.0, error = %e, "Failed to persist shutdown status");
                }

                tracing::info!(task = %task_id.0, "Marked task as canceled due to shutdown");
            }

            if let Some(tx) = entry.shim_tx.take() {
                let msg = DaemonToShim {
                    msg: Some(daemon_to_shim::Msg::Shutdown(Shutdown {})),
                };

                // Use try_send to avoid blocking on stuck shims
                if tx.try_send(msg).is_ok() {
                    tracing::debug!(task = %task_id.0, "Sent shutdown to shim");
                    count += 1;
                } else {
                    tracing::warn!(task = %task_id.0, "Failed to send shutdown to shim");
                }
                // tx is dropped here, closing the channel
            }
        }

        count
    }

    /// Get count of tasks with active shim connections.
    #[allow(dead_code)]
    pub async fn active_shim_count(&self) -> usize {
        let inner = self.inner.read().await;
        inner.values().filter(|e| e.shim_tx.is_some()).count()
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

#[cfg(test)]
mod tests {
    use super::*;
    use continuum_core::identity::DeviceId;
    use continuum_core::task::{CreatedVia, TaskEventKind, TaskId};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tempfile::tempdir;
    use uuid::Uuid;

    async fn make_store() -> TaskStore {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = DbService::open(&db_path).await.unwrap();
        // Leak the tempdir to keep the DB file alive for the test
        std::mem::forget(dir);
        TaskStore::new(db)
    }

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
        let store = make_store().await;
        let task = make_task("test");
        let id = task.id.clone();

        store.insert(task.clone()).await.unwrap();

        let retrieved = store.get(&id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "test");
    }

    #[tokio::test]
    async fn test_list_tasks() {
        let store = make_store().await;

        store.insert(make_task("task1")).await.unwrap();
        store.insert(make_task("task2")).await.unwrap();

        let tasks = store.list().await;
        assert_eq!(tasks.len(), 2);
    }

    #[tokio::test]
    async fn test_apply_event() {
        let store = make_store().await;
        let task = make_task("test");
        let id = task.id.clone();
        store.insert(task).await.unwrap();

        // Apply Started event
        let event = TaskEvent::new(TaskEventKind::Started { pid: Some(1234) });
        store.apply_event(&id, event).await.unwrap();

        let task = store.get(&id).await.unwrap();
        assert_eq!(task.status, TaskStatus::Running);
        assert_eq!(task.pid, Some(1234));
    }

    #[tokio::test]
    async fn test_output_buffering() {
        let store = make_store().await;
        let task = make_task("test");
        let id = task.id.clone();
        store.insert(task).await.unwrap();

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
        let store = make_store().await;
        let task = make_task("test");
        let id = task.id.clone();
        store.insert(task).await.unwrap();

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

    #[tokio::test]
    async fn test_persistence_roundtrip() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // Create store, insert task, apply events
        {
            let db = DbService::open(&db_path).await.unwrap();
            let store = TaskStore::new(db);

            let task = make_task("persistent-task");
            let id = task.id.clone();
            store.insert(task).await.unwrap();

            // Start the task
            let event = TaskEvent::new(TaskEventKind::Started { pid: Some(9999) });
            store.apply_event(&id, event).await.unwrap();

            // Verify in-memory state
            let task = store.get(&id).await.unwrap();
            assert_eq!(task.status, TaskStatus::Running);
        }

        // Create new store from same DB, verify task was loaded
        {
            let db = DbService::open(&db_path).await.unwrap();
            let store = TaskStore::new(db);
            store.load_from_db().await.unwrap();

            let tasks = store.list().await;
            assert_eq!(tasks.len(), 1);

            let task = &tasks[0];
            assert_eq!(task.name, "persistent-task");
            assert_eq!(task.status, TaskStatus::Running);
            assert_eq!(task.pid, Some(9999));
        }
    }
}
