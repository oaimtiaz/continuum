//! Task supervisor - spawns and manages shim processes.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use continuum_core::identity::DeviceId;
use continuum_core::task::{CreatedVia, Task, TaskId};
use tokio::net::UnixListener;
use uuid::Uuid;

use crate::ipc::handle_shim_connection;
use crate::store::TaskStore;

/// Directory for task sockets.
const SOCKET_DIR: &str = "/tmp/continuum";

/// Task supervisor that spawns shim processes and manages their lifecycle.
pub struct TaskSupervisor {
    store: Arc<TaskStore>,
    socket_dir: PathBuf,
    shim_binary: PathBuf,
    device_id: DeviceId,
}

impl TaskSupervisor {
    /// Create a new supervisor.
    pub fn new(store: Arc<TaskStore>) -> Self {
        // Find the shim binary - first check for debug build, then release
        let shim_binary = Self::find_shim_binary();

        // Ensure socket directory exists
        let socket_dir = PathBuf::from(SOCKET_DIR);
        std::fs::create_dir_all(&socket_dir).ok();

        Self {
            store,
            socket_dir,
            shim_binary,
            device_id: DeviceId::new(
                hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".to_string()),
            ),
        }
    }

    /// Find the shim binary path.
    fn find_shim_binary() -> PathBuf {
        // Check common locations
        let candidates = [
            // Relative to cargo workspace
            PathBuf::from("target/debug/continuum-shim"),
            PathBuf::from("target/release/continuum-shim"),
            // Absolute paths for when running from different directories
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug/continuum-shim"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/release/continuum-shim"),
        ];

        for candidate in &candidates {
            if candidate.exists() {
                return candidate
                    .canonicalize()
                    .unwrap_or_else(|_| candidate.clone());
            }
        }

        // Default to hoping it's in PATH
        PathBuf::from("continuum-shim")
    }

    /// Spawn a new task.
    pub async fn spawn_task(
        &self,
        name: String,
        cmd: Vec<String>,
        cwd: String,
        env: std::collections::HashMap<String, String>,
    ) -> Result<TaskId, anyhow::Error> {
        // Create task ID
        let task_id = TaskId::new(Uuid::new_v4());

        // Create task in Queued state
        let task = Task::new(
            task_id.clone(),
            name.clone(),
            cmd.clone(),
            PathBuf::from(&cwd),
            env.clone().into_iter().collect::<BTreeMap<_, _>>(),
            self.device_id.clone(),
            CreatedVia::Cli,
        );

        // Insert into store (persists to database)
        self.store.insert(task).await?;

        // Create socket path
        let socket_path = self.socket_dir.join(format!("{}.sock", task_id.0));

        // Remove existing socket if present
        let _ = std::fs::remove_file(&socket_path);

        // Bind listener before spawning shim
        let listener = UnixListener::bind(&socket_path)?;
        tracing::debug!(task = %task_id.0, socket = %socket_path.display(), "Created socket");

        // Build shim command
        let mut shim_cmd = Command::new(&self.shim_binary);
        shim_cmd
            .arg("--task-id")
            .arg(task_id.0.to_string())
            .arg("--connect")
            .arg(&socket_path)
            .arg("--rows")
            .arg("24")
            .arg("--cols")
            .arg("80")
            .arg("--cwd")
            .arg(&cwd)
            // Ensure shim inherits stderr and stdout for logging
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());

        // Add environment variables
        for (key, value) in &env {
            shim_cmd.arg("--env").arg(format!("{}={}", key, value));
        }

        // Add command separator and command
        shim_cmd.arg("--");
        for arg in &cmd {
            shim_cmd.arg(arg);
        }

        tracing::info!(
            task = %task_id.0,
            name = %name,
            cmd = ?cmd,
            "Spawning task"
        );

        tracing::debug!(task = %task_id.0, "Command: {:?}", shim_cmd);

        // Spawn the shim process
        let mut child = shim_cmd.spawn().map_err(|e| {
            tracing::error!(error = %e, shim = %self.shim_binary.display(), "Failed to spawn shim");
            anyhow::anyhow!("Failed to spawn shim: {}", e)
        })?;

        let pid = child.id();
        tracing::info!(task=%task_id.0, pid=?pid, "Spawned shim");

        tokio::spawn(async move {
            match child.wait() {
                Ok(status) => tracing::info!(task=%task_id.0, pid=?pid, %status, "Shim exited"),
                Err(e) => {
                    tracing::error!(task=%task_id.0, pid=?pid, error=%e, "Failed waiting for shim")
                }
            }
        });

        // Spawn task to accept connection and handle IPC
        let store = self.store.clone();
        let task_id_clone = task_id.clone();
        tokio::spawn(async move {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    tracing::debug!(task = %task_id_clone.0, "Shim connected");
                    handle_shim_connection(task_id_clone, stream, store).await;
                }
                Err(e) => {
                    tracing::error!(task = %task_id_clone.0, error = %e, "Failed to accept shim connection");
                }
            }
        });

        Ok(task_id)
    }

    /// Send input to a task.
    pub async fn send_input(&self, task_id: &TaskId, data: Vec<u8>) -> Result<(), anyhow::Error> {
        use continuum_shim_proto::{daemon_to_shim, DaemonToShim, Stdin};

        let msg = DaemonToShim {
            msg: Some(daemon_to_shim::Msg::Stdin(Stdin { data })),
        };

        self.store
            .send_to_shim(task_id, msg)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Resize the terminal for a task.
    #[allow(dead_code)]
    pub async fn resize(
        &self,
        task_id: &TaskId,
        rows: u32,
        cols: u32,
    ) -> Result<(), anyhow::Error> {
        use continuum_shim_proto::{daemon_to_shim, DaemonToShim, Resize};

        let msg = DaemonToShim {
            msg: Some(daemon_to_shim::Msg::Resize(Resize { rows, cols })),
        };

        self.store
            .send_to_shim(task_id, msg)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Send a signal to a task.
    pub async fn send_signal(&self, task_id: &TaskId, signum: i32) -> Result<(), anyhow::Error> {
        use continuum_shim_proto::{daemon_to_shim, DaemonToShim, Signal};

        let msg = DaemonToShim {
            msg: Some(daemon_to_shim::Msg::Signal(Signal { signum })),
        };

        self.store
            .send_to_shim(task_id, msg)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    }
}

impl std::fmt::Debug for TaskSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskSupervisor")
            .field("socket_dir", &self.socket_dir)
            .field("shim_binary", &self.shim_binary)
            .finish()
    }
}
