-- Initial schema for continuum-daemon persistence
-- Stores tasks, lifecycle events, and output chunks

-- Core task table (denormalized current state for fast queries)
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY NOT NULL,           -- UUID as text
    name TEXT NOT NULL,
    cmd TEXT NOT NULL,                      -- JSON array of command + args
    cwd TEXT NOT NULL,                      -- Working directory path
    env TEXT NOT NULL,                      -- JSON object of env vars
    status TEXT NOT NULL,                   -- queued, running, completed, failed, canceled
    created_at TEXT NOT NULL,               -- ISO8601 timestamp
    started_at TEXT,                        -- ISO8601 timestamp (nullable)
    ended_at TEXT,                          -- ISO8601 timestamp (nullable)
    pid INTEGER,                            -- Process ID (nullable)
    exit_code INTEGER,                      -- Exit code (nullable)
    failure_reason TEXT,                    -- Why task failed (nullable)
    created_by TEXT NOT NULL,               -- DeviceId
    created_via TEXT NOT NULL,              -- cli, mobile, web
    last_output_at TEXT,                    -- ISO8601 timestamp (nullable)
    last_input_at TEXT,                     -- ISO8601 timestamp (nullable)
    output_bytes INTEGER NOT NULL DEFAULT 0,
    input_bytes INTEGER NOT NULL DEFAULT 0,
    attention_state TEXT NOT NULL DEFAULT '{"state":"none"}',  -- JSON
    metrics TEXT NOT NULL DEFAULT '{}'      -- JSON ProcessMetrics
);

-- Event log for audit trail and state reconstruction
CREATE TABLE IF NOT EXISTS task_events (
    id TEXT PRIMARY KEY NOT NULL,           -- EventId UUID
    task_id TEXT NOT NULL,                  -- References tasks(id)
    ts TEXT NOT NULL,                       -- ISO8601 timestamp
    kind TEXT NOT NULL,                     -- Event type discriminator
    payload TEXT NOT NULL,                  -- JSON of TaskEventKind
    sequence INTEGER NOT NULL,              -- Monotonic per task for ordering

    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    UNIQUE(task_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_task_events_task_id ON task_events(task_id);
CREATE INDEX IF NOT EXISTS idx_task_events_ts ON task_events(ts);

-- Output chunks (potentially large, separate table)
CREATE TABLE IF NOT EXISTS output_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,                  -- References tasks(id)
    stream TEXT NOT NULL,                   -- pty, stdout, stderr
    data BLOB NOT NULL,                     -- Raw bytes
    timestamp_ms INTEGER NOT NULL,          -- Unix timestamp in milliseconds
    offset INTEGER NOT NULL,                -- Chunk index within task

    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    UNIQUE(task_id, offset)
);

CREATE INDEX IF NOT EXISTS idx_output_chunks_task_id ON output_chunks(task_id);
CREATE INDEX IF NOT EXISTS idx_output_chunks_task_offset ON output_chunks(task_id, offset);
