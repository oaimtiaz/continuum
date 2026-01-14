//! Database service for persistent task storage.
//!
//! Wraps SQLite access via sqlx, providing async database operations
//! for the daemon's task store.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use continuum_core::identity::DeviceId;
use continuum_core::task::{
    AttentionState, CreatedVia, ProcessMetrics, Task, TaskEvent, TaskId, TaskStatus,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

/// Database service wrapping SQLite access.
///
/// Provides async operations for persisting and retrieving tasks,
/// events, and output chunks.
#[derive(Clone)]
pub struct DbService {
    pool: SqlitePool,
}

impl DbService {
    /// Open or create a database at the given path.
    ///
    /// Runs migrations automatically to ensure schema is up to date.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, sqlx::Error> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                sqlx::Error::Configuration(format!("Failed to create db directory: {}", e).into())
            })?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            // WAL mode for better concurrent read performance
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            // NORMAL sync balances durability vs speed
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(1) // SQLite performs best with single writer
            .connect_with(options)
            .await?;

        // Run migrations
        sqlx::migrate!().run(&pool).await?;

        Ok(Self { pool })
    }

    #[cfg(test)]
    /// Get a reference to the underlying connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    // =========================================================================
    // Task CRUD Operations
    // =========================================================================

    /// Insert a new task into the database.
    pub async fn insert_task(&self, task: &Task) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO tasks (
                id, name, cmd, cwd, env, status, created_at, started_at, ended_at,
                pid, exit_code, failure_reason, created_by, created_via,
                last_output_at, last_input_at, output_bytes, input_bytes,
                attention_state, metrics
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20
            )
            "#,
        )
        .bind(task.id.0.to_string())
        .bind(&task.name)
        .bind(serde_json::to_string(&task.cmd).unwrap())
        .bind(task.cwd.to_string_lossy().to_string())
        .bind(serde_json::to_string(&task.env).unwrap())
        .bind(serde_json::to_string(&task.status).unwrap())
        .bind(task.created_at.to_rfc3339())
        .bind(task.started_at.map(|t| t.to_rfc3339()))
        .bind(task.ended_at.map(|t| t.to_rfc3339()))
        .bind(task.pid.map(|p| p as i64))
        .bind(task.exit_code)
        .bind(&task.failure_reason)
        .bind(&task.created_by.0)
        .bind(serde_json::to_string(&task.created_via).unwrap())
        .bind(task.last_output_at.map(|t| t.to_rfc3339()))
        .bind(task.last_input_at.map(|t| t.to_rfc3339()))
        .bind(task.output_bytes as i64)
        .bind(task.input_bytes as i64)
        .bind(serde_json::to_string(&task.attention).unwrap())
        .bind(serde_json::to_string(&task.metrics).unwrap())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update an existing task's state in the database.
    pub async fn update_task(&self, task: &Task) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE tasks SET
                status = ?2,
                started_at = ?3,
                ended_at = ?4,
                pid = ?5,
                exit_code = ?6,
                failure_reason = ?7,
                last_output_at = ?8,
                last_input_at = ?9,
                output_bytes = ?10,
                input_bytes = ?11,
                attention_state = ?12,
                metrics = ?13
            WHERE id = ?1
            "#,
        )
        .bind(task.id.0.to_string())
        .bind(serde_json::to_string(&task.status).unwrap())
        .bind(task.started_at.map(|t| t.to_rfc3339()))
        .bind(task.ended_at.map(|t| t.to_rfc3339()))
        .bind(task.pid.map(|p| p as i64))
        .bind(task.exit_code)
        .bind(&task.failure_reason)
        .bind(task.last_output_at.map(|t| t.to_rfc3339()))
        .bind(task.last_input_at.map(|t| t.to_rfc3339()))
        .bind(task.output_bytes as i64)
        .bind(task.input_bytes as i64)
        .bind(serde_json::to_string(&task.attention).unwrap())
        .bind(serde_json::to_string(&task.metrics).unwrap())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Insert a task event for audit trail.
    pub async fn insert_event(
        &self,
        task_id: &TaskId,
        event: &TaskEvent,
        sequence: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO task_events (id, task_id, ts, kind, payload, sequence)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(event.id.0.to_string())
        .bind(task_id.0.to_string())
        .bind(event.ts.to_rfc3339())
        .bind(event_kind_name(&event.kind))
        .bind(serde_json::to_string(&event.kind).unwrap())
        .bind(sequence)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Load all tasks from the database.
    pub async fn load_all_tasks(&self) -> Result<Vec<Task>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, cmd, cwd, env, status, created_at, started_at, ended_at,
                pid, exit_code, failure_reason, created_by, created_via,
                last_output_at, last_input_at, output_bytes, input_bytes,
                attention_state, metrics
            FROM tasks
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut tasks = Vec::with_capacity(rows.len());
        for row in rows {
            let task = parse_task_row(&row)?;
            tasks.push(task);
        }

        Ok(tasks)
    }

    /// Mark all tasks with status "running" as failed.
    ///
    /// Called on daemon startup to handle tasks that were running when the daemon
    /// was previously terminated.
    pub async fn mark_orphaned_tasks_failed(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE tasks
            SET status = '"failed"',
                failure_reason = 'Daemon restarted while task was running',
                ended_at = ?1
            WHERE status = '"running"'
            "#,
        )
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // =========================================================================
    // Output Chunk Operations
    // =========================================================================

    /// Batch insert output chunks for a task.
    ///
    /// Each chunk is paired with its offset (position in the output stream).
    pub async fn insert_output_chunks(
        &self,
        task_id: &TaskId,
        chunks: &[(crate::store::OutputChunk, usize)],
    ) -> Result<(), sqlx::Error> {
        if chunks.is_empty() {
            return Ok(());
        }

        // Use a transaction for batch insert
        let mut tx = self.pool.begin().await?;

        for (chunk, offset) in chunks {
            sqlx::query(
                r#"
                INSERT OR REPLACE INTO output_chunks (task_id, stream, data, timestamp_ms, offset)
                VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
            )
            .bind(task_id.0.to_string())
            .bind(serde_json::to_string(&chunk.stream).unwrap())
            .bind(&chunk.data)
            .bind(chunk.timestamp_ms)
            .bind(*offset as i64)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Load output chunks for a task starting from a given offset.
    pub async fn load_output(
        &self,
        task_id: &TaskId,
        from_offset: usize,
    ) -> Result<Vec<crate::store::OutputChunk>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT stream, data, timestamp_ms
            FROM output_chunks
            WHERE task_id = ?1 AND offset >= ?2
            ORDER BY offset
            "#,
        )
        .bind(task_id.0.to_string())
        .bind(from_offset as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut chunks = Vec::with_capacity(rows.len());
        for row in rows {
            let stream_json: String = row.try_get("stream")?;
            let stream: continuum_core::task::Stream = serde_json::from_str(&stream_json)
                .map_err(|e| sqlx::Error::Decode(format!("Invalid stream JSON: {}", e).into()))?;

            let data: Vec<u8> = row.try_get("data")?;
            let timestamp_ms: i64 = row.try_get("timestamp_ms")?;

            chunks.push(crate::store::OutputChunk {
                stream,
                data,
                timestamp_ms,
            });
        }

        Ok(chunks)
    }
}

/// Get the event kind name for the database.
fn event_kind_name(kind: &continuum_core::task::TaskEventKind) -> &'static str {
    use continuum_core::task::TaskEventKind;
    match kind {
        TaskEventKind::Started { .. } => "started",
        TaskEventKind::Exited { .. } => "exited",
        TaskEventKind::Canceled { .. } => "canceled",
        TaskEventKind::FailedToStart { .. } => "failed_to_start",
        TaskEventKind::OutputAppended { .. } => "output_appended",
        TaskEventKind::InputSent { .. } => "input_sent",
        TaskEventKind::MetricsSampled { .. } => "metrics_sampled",
        TaskEventKind::AttentionChanged { .. } => "attention_changed",
    }
}

/// Parse a database row into a Task.
fn parse_task_row(row: &sqlx::sqlite::SqliteRow) -> Result<Task, sqlx::Error> {
    let id_str: String = row.try_get("id")?;
    let id = TaskId(
        Uuid::parse_str(&id_str)
            .map_err(|e| sqlx::Error::Decode(format!("Invalid UUID: {}", e).into()))?,
    );

    let name: String = row.try_get("name")?;

    let cmd_json: String = row.try_get("cmd")?;
    let cmd: Vec<String> = serde_json::from_str(&cmd_json)
        .map_err(|e| sqlx::Error::Decode(format!("Invalid cmd JSON: {}", e).into()))?;

    let cwd_str: String = row.try_get("cwd")?;
    let cwd = PathBuf::from(cwd_str);

    let env_json: String = row.try_get("env")?;
    let env: BTreeMap<String, String> = serde_json::from_str(&env_json)
        .map_err(|e| sqlx::Error::Decode(format!("Invalid env JSON: {}", e).into()))?;

    let status_json: String = row.try_get("status")?;
    let status: TaskStatus = serde_json::from_str(&status_json)
        .map_err(|e| sqlx::Error::Decode(format!("Invalid status JSON: {}", e).into()))?;

    let created_at_str: String = row.try_get("created_at")?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map_err(|e| sqlx::Error::Decode(format!("Invalid created_at: {}", e).into()))?
        .with_timezone(&Utc);

    let started_at: Option<DateTime<Utc>> = row
        .try_get::<Option<String>, _>("started_at")?
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let ended_at: Option<DateTime<Utc>> = row
        .try_get::<Option<String>, _>("ended_at")?
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let pid: Option<u32> = row.try_get::<Option<i64>, _>("pid")?.map(|p| p as u32);
    let exit_code: Option<i32> = row.try_get("exit_code")?;
    let failure_reason: Option<String> = row.try_get("failure_reason")?;

    let created_by_str: String = row.try_get("created_by")?;
    let created_by = DeviceId::new(created_by_str);

    let created_via_json: String = row.try_get("created_via")?;
    let created_via: CreatedVia = serde_json::from_str(&created_via_json)
        .map_err(|e| sqlx::Error::Decode(format!("Invalid created_via JSON: {}", e).into()))?;

    let last_output_at: Option<DateTime<Utc>> = row
        .try_get::<Option<String>, _>("last_output_at")?
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let last_input_at: Option<DateTime<Utc>> = row
        .try_get::<Option<String>, _>("last_input_at")?
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let output_bytes: u64 = row.try_get::<i64, _>("output_bytes")? as u64;
    let input_bytes: u64 = row.try_get::<i64, _>("input_bytes")? as u64;

    let attention_json: String = row.try_get("attention_state")?;
    let attention: AttentionState = serde_json::from_str(&attention_json)
        .map_err(|e| sqlx::Error::Decode(format!("Invalid attention_state JSON: {}", e).into()))?;

    let metrics_json: String = row.try_get("metrics")?;
    let metrics: ProcessMetrics = serde_json::from_str(&metrics_json)
        .map_err(|e| sqlx::Error::Decode(format!("Invalid metrics JSON: {}", e).into()))?;

    Ok(Task {
        id,
        name,
        cmd,
        cwd,
        env,
        status,
        created_at,
        started_at,
        ended_at,
        pid,
        exit_code,
        failure_reason,
        created_by,
        created_via,
        last_output_at,
        last_input_at,
        output_bytes,
        input_bytes,
        attention,
        metrics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_migrations_create_tables() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let db = DbService::open(&db_path).await.unwrap();

        // Verify tables exist by querying them
        let _: Vec<(String,)> = sqlx::query_as("SELECT id FROM tasks")
            .fetch_all(db.pool())
            .await
            .unwrap();

        let _: Vec<(String,)> = sqlx::query_as("SELECT id FROM task_events")
            .fetch_all(db.pool())
            .await
            .unwrap();

        let _: Vec<(i64,)> = sqlx::query_as("SELECT id FROM output_chunks")
            .fetch_all(db.pool())
            .await
            .unwrap();
    }
}
