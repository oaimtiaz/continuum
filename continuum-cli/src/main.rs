//! Continuum CLI - Command-line interface for task management

use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use continuum_proto::{
    continuum_client::ContinuumClient, CancelTaskRequest, GetTaskRequest, ListTasksRequest,
    RunTaskRequest, SendInputRequest, StreamOutputRequest, TaskStatus, TaskView,
};
use tokio_stream::StreamExt;
use tonic::transport::Channel;

/// Continuum - Distributed task execution
#[derive(Parser)]
#[command(name = "continuum", version, about)]
struct Cli {
    /// Daemon address
    #[arg(long, default_value = "http://127.0.0.1:50051", global = true)]
    daemon: String,

    /// Output JSON instead of human-readable text
    #[arg(long, global = true)]
    json: bool,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a new task
    Run {
        /// Interactive mode (PTY-backed)
        #[arg(short, long)]
        interactive: bool,

        /// Task name
        #[arg(long)]
        name: Option<String>,

        /// Working directory
        #[arg(long)]
        cwd: Option<PathBuf>,

        /// Environment variables (KEY=VALUE)
        #[arg(long = "env", value_name = "KEY=VALUE")]
        envs: Vec<String>,

        /// Command and arguments (after --)
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// List tasks
    Ls {
        /// Filter by status
        #[arg(long, value_enum)]
        status: Option<StatusFilter>,

        /// Show last N tasks
        #[arg(long, default_value = "20")]
        recent: i32,

        /// Show all tasks (ignore --recent)
        #[arg(long)]
        all: bool,
    },

    /// Show task details
    Show {
        /// Task ID
        task_id: String,

        /// Show last N output lines
        #[arg(long)]
        tail: Option<usize>,
    },

    /// Attach to task output
    Attach {
        /// Task ID
        task_id: String,

        /// Interactive mode (forward stdin)
        #[arg(short, long)]
        interactive: bool,

        /// Don't strip/process output
        #[arg(long)]
        raw: bool,

        /// Print history and exit (don't follow)
        #[arg(long)]
        no_follow: bool,
    },

    /// Send input to a task
    Send {
        /// Task ID
        task_id: String,

        /// Data to send (if not using --file or --ctrl-c)
        data: Option<String>,

        /// Send contents of file
        #[arg(long)]
        file: Option<PathBuf>,

        /// Send Ctrl+C (interrupt)
        #[arg(long)]
        ctrl_c: bool,

        /// Don't append newline to data
        #[arg(long)]
        raw: bool,
    },

    /// Cancel a running task
    Cancel {
        /// Task ID
        task_id: String,

        /// Force kill (SIGKILL instead of SIGTERM)
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, ValueEnum)]
enum StatusFilter {
    Queued,
    Running,
    Completed,
    Failed,
    Canceled,
}

impl StatusFilter {
    fn to_proto(&self) -> i32 {
        match self {
            StatusFilter::Queued => TaskStatus::Queued as i32,
            StatusFilter::Running => TaskStatus::Running as i32,
            StatusFilter::Completed => TaskStatus::Completed as i32,
            StatusFilter::Failed => TaskStatus::Failed as i32,
            StatusFilter::Canceled => TaskStatus::Canceled as i32,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let result = run(cli).await;

    if let Err(e) = &result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    let mut client = connect(&cli.daemon).await?;

    match &cli.command {
        Commands::Run {
            interactive,
            name,
            cwd,
            envs,
            cmd,
        } => {
            cmd_run(
                &mut client,
                &cli,
                *interactive,
                name.clone(),
                cwd.clone(),
                envs.clone(),
                cmd.clone(),
            )
            .await
        }

        Commands::Ls {
            status,
            recent,
            all,
        } => cmd_ls(&mut client, &cli, status.clone(), *recent, *all).await,

        Commands::Show { task_id, tail } => {
            cmd_show(&mut client, &cli, task_id.clone(), *tail).await
        }

        Commands::Attach {
            task_id,
            interactive,
            raw: _,
            no_follow,
        } => cmd_attach(&mut client, &cli, task_id.clone(), *interactive, *no_follow).await,

        Commands::Send {
            task_id,
            data,
            file,
            ctrl_c,
            raw,
        } => {
            cmd_send(
                &mut client,
                task_id.clone(),
                data.clone(),
                file.clone(),
                *ctrl_c,
                *raw,
            )
            .await
        }

        Commands::Cancel { task_id, force } => {
            cmd_cancel(&mut client, task_id.clone(), *force).await
        }
    }
}

async fn connect(addr: &str) -> Result<ContinuumClient<Channel>> {
    ContinuumClient::connect(addr.to_string())
        .await
        .context("Failed to connect to daemon")
}

// ============================================================================
// Commands
// ============================================================================

async fn cmd_run(
    client: &mut ContinuumClient<Channel>,
    cli: &Cli,
    interactive: bool,
    name: Option<String>,
    cwd: Option<PathBuf>,
    envs: Vec<String>,
    cmd: Vec<String>,
) -> Result<()> {
    // Parse environment variables
    let env: std::collections::HashMap<String, String> = envs
        .into_iter()
        .filter_map(|e| {
            let mut parts = e.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next()?;
            Some((key.to_string(), value.to_string()))
        })
        .collect();

    let request = RunTaskRequest {
        name: name.unwrap_or_default(),
        cmd,
        cwd: cwd.map(|p| p.to_string_lossy().to_string()),
        env,
    };

    let response = client
        .run_task(request)
        .await
        .context("RunTask failed")?
        .into_inner();

    let task = response.task.context("No task in response")?;

    if cli.json {
        println!("{}", serde_json::to_string(&task_to_json(&task))?);
    } else {
        // Print task_id to stdout (script-friendly)
        println!("{}", task.id);
        // Human info to stderr
        eprintln!("Started task: {} ({})", task.name, status_str(task.status));
    }

    // If interactive, attach immediately
    if interactive {
        cmd_attach(client, cli, task.id, true, false).await?;
    }

    Ok(())
}

async fn cmd_ls(
    client: &mut ContinuumClient<Channel>,
    cli: &Cli,
    status: Option<StatusFilter>,
    recent: i32,
    all: bool,
) -> Result<()> {
    let request = ListTasksRequest {
        status_filter: status.as_ref().map(|s| s.to_proto()),
        limit: if all { None } else { Some(recent) },
    };

    let response = client
        .list_tasks(request)
        .await
        .context("ListTasks failed")?
        .into_inner();

    if cli.json {
        let tasks: Vec<_> = response.tasks.iter().map(task_to_json).collect();
        println!("{}", serde_json::to_string(&tasks)?);
    } else {
        if response.tasks.is_empty() {
            eprintln!("No tasks found");
        } else {
            // Header
            println!("{:<36}  {:<12}  {:<10}  {}", "ID", "STATUS", "NAME", "CMD");
            println!("{}", "-".repeat(80));

            for task in &response.tasks {
                let display_status = if task.needs_input {
                    "waiting"
                } else {
                    status_str(task.status)
                };
                let cmd_preview: String = task.cmd.join(" ").chars().take(30).collect();
                println!(
                    "{:<36}  {:<12}  {:<10}  {}",
                    task.id,
                    display_status,
                    truncate(&task.name, 10),
                    cmd_preview
                );
            }
        }
    }

    Ok(())
}

async fn cmd_show(
    client: &mut ContinuumClient<Channel>,
    cli: &Cli,
    task_id: String,
    tail: Option<usize>,
) -> Result<()> {
    let request = GetTaskRequest {
        task_id: task_id.clone(),
    };

    let response = client
        .get_task(request)
        .await
        .context("GetTask failed")?
        .into_inner();

    let task = response.task.context("No task in response")?;

    if cli.json {
        println!("{}", serde_json::to_string(&task_to_json(&task))?);
    } else {
        println!("Task: {}", task.id);
        println!("Name: {}", task.name);
        println!("Command: {}", task.cmd.join(" "));
        println!("CWD: {}", task.cwd);
        println!("Status: {}", status_str(task.status));

        if let Some(code) = task.exit_code {
            println!("Exit Code: {}", code);
        }
        if let Some(ref reason) = task.failure_reason {
            println!("Failure: {}", reason);
        }
        if task.needs_input {
            println!("Attention: Needs input");
        }

        // Timestamps
        println!("Created: {}", format_timestamp(task.created_at_ms));
        if let Some(ts) = task.started_at_ms {
            println!("Started: {}", format_timestamp(ts));
        }
        if let Some(ts) = task.ended_at_ms {
            println!("Ended: {}", format_timestamp(ts));
        }
    }

    // Show tail if requested
    if let Some(n) = tail {
        println!("\n--- Last {} lines ---", n);
        let request = StreamOutputRequest {
            task_id,
            from_offset: None,
        };

        let mut stream = client
            .stream_output(request)
            .await
            .context("StreamOutput failed")?
            .into_inner();

        let mut lines: Vec<String> = Vec::new();
        while let Some(chunk) = stream.next().await {
            if let Ok(chunk) = chunk {
                let text = String::from_utf8_lossy(&chunk.data);
                for line in text.lines() {
                    lines.push(line.to_string());
                }
            }
        }

        // Print last N lines
        let start = lines.len().saturating_sub(n);
        for line in &lines[start..] {
            println!("{}", line);
        }
    }

    Ok(())
}

async fn cmd_attach(
    client: &mut ContinuumClient<Channel>,
    _cli: &Cli,
    task_id: String,
    interactive: bool,
    no_follow: bool,
) -> Result<()> {
    // First verify task exists
    let get_request = GetTaskRequest {
        task_id: task_id.clone(),
    };
    let task = client
        .get_task(get_request)
        .await
        .context("Task not found")?
        .into_inner()
        .task
        .context("No task")?;

    let is_terminal = matches!(
        TaskStatus::try_from(task.status),
        Ok(TaskStatus::Completed) | Ok(TaskStatus::Failed) | Ok(TaskStatus::Canceled)
    );

    // Start streaming output
    let request = StreamOutputRequest {
        task_id: task_id.clone(),
        from_offset: None,
    };

    let mut stream = client
        .stream_output(request)
        .await
        .context("StreamOutput failed")?
        .into_inner();

    // If interactive and task is running, spawn stdin reader
    let stdin_handle = if interactive && !is_terminal {
        let task_id_clone = task_id.clone();
        let daemon_addr = _cli.daemon.clone();

        Some(tokio::spawn(async move {
            if let Err(e) = forward_stdin(daemon_addr, task_id_clone).await {
                eprintln!("stdin forwarding error: {}", e);
            }
        }))
    } else {
        None
    };

    // Stream output
    let mut stdout = io::stdout();
    while let Some(result) = stream.next().await {
        match result {
            Ok(chunk) => {
                stdout.write_all(&chunk.data)?;
                stdout.flush()?;
            }
            Err(e) => {
                if !no_follow {
                    eprintln!("\nStream error: {}", e);
                }
                break;
            }
        }

        if no_follow && is_terminal {
            break;
        }
    }

    // Cancel stdin forwarder if running
    if let Some(handle) = stdin_handle {
        handle.abort();
    }

    Ok(())
}

async fn forward_stdin(daemon_addr: String, task_id: String) -> Result<()> {
    let mut client = connect(&daemon_addr).await?;
    let mut stdin = tokio::io::stdin();

    loop {
        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut stdin, &mut buf).await?;
        if n == 0 {
            break;
        }
        buf.truncate(n);

        let request = SendInputRequest {
            task_id: task_id.clone(),
            data: buf,
        };

        client.send_input(request).await?;
    }

    Ok(())
}

async fn cmd_send(
    client: &mut ContinuumClient<Channel>,
    task_id: String,
    data: Option<String>,
    file: Option<PathBuf>,
    ctrl_c: bool,
    raw: bool,
) -> Result<()> {
    let mut bytes = if ctrl_c {
        // Ctrl+C = ASCII 0x03
        vec![0x03]
    } else if let Some(path) = file {
        std::fs::read(&path).context("Failed to read file")?
    } else if let Some(text) = data {
        text.into_bytes()
    } else {
        // Read from stdin
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };

    // Append newline unless --raw or --ctrl-c
    if !raw && !ctrl_c && !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }

    let request = SendInputRequest {
        task_id,
        data: bytes,
    };

    client
        .send_input(request)
        .await
        .context("SendInput failed")?;

    Ok(())
}

async fn cmd_cancel(
    client: &mut ContinuumClient<Channel>,
    task_id: String,
    force: bool,
) -> Result<()> {
    let request = CancelTaskRequest { task_id, force };

    client
        .cancel_task(request)
        .await
        .context("CancelTask failed")?;

    eprintln!(
        "Task canceled ({})",
        if force { "SIGKILL" } else { "SIGTERM" }
    );

    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

fn status_str(status: i32) -> &'static str {
    match TaskStatus::try_from(status) {
        Ok(TaskStatus::Unspecified) => "unknown",
        Ok(TaskStatus::Queued) => "queued",
        Ok(TaskStatus::Running) => "running",
        Ok(TaskStatus::Completed) => "completed",
        Ok(TaskStatus::Failed) => "failed",
        Ok(TaskStatus::Canceled) => "canceled",
        Err(_) => "unknown",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

fn format_timestamp(ms: i64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_millis_opt(ms)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "invalid".to_string())
}

fn task_to_json(task: &TaskView) -> serde_json::Value {
    serde_json::json!({
        "id": task.id,
        "name": task.name,
        "cmd": task.cmd,
        "cwd": task.cwd,
        "status": status_str(task.status),
        "created_at_ms": task.created_at_ms,
        "started_at_ms": task.started_at_ms,
        "ended_at_ms": task.ended_at_ms,
        "exit_code": task.exit_code,
        "failure_reason": task.failure_reason,
        "needs_input": task.needs_input,
    })
}
