//! Continuum CLI - Command-line interface for task management

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use commands::{check_status, clients, run_enrollment, run_local_enrollment, EnrollmentResult, IdentityStore};
use continuum_auth::identity::Fingerprint;
use continuum_proto::{
    continuum_client::ContinuumClient, CancelTaskRequest, GetTaskRequest, ListTasksRequest,
    RunTaskRequest, SendInputRequest, StreamOutputRequest, TaskStatus, TaskView,
};
use tls::{build_mtls_config, build_tls_channel, EnrollmentVerifier};
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use trust::TrustStore;

mod commands;
mod tls;
mod trust;
mod utils;

// ============================================================================
// Raw Terminal Mode
// ============================================================================

/// Guard that sets the terminal to raw mode and restores it on drop.
struct RawModeGuard {
    fd: i32,
    original: libc::termios,
}

impl RawModeGuard {
    /// Enter raw mode on stdin. Returns None if stdin is not a TTY.
    fn enter() -> Option<Self> {
        let fd = std::io::stdin().as_raw_fd();

        // Check if stdin is a TTY
        if unsafe { libc::isatty(fd) } != 1 {
            return None;
        }

        // Get current settings
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return None;
        }

        // Create raw mode settings
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };

        // Apply raw mode
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return None;
        }

        Some(Self { fd, original })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // Restore original settings
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

/// Continuum - Distributed task execution
#[derive(Parser)]
#[command(name = "continuum", version, about)]
struct Cli {
    /// Daemon address (port 50052 for main API, 50051 for enrollment)
    #[arg(long, default_value = "http://127.0.0.1:50052", global = true)]
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
    /// Enroll this client with the daemon
    Enroll {
        /// Enrollment token (required for remote enrollment)
        #[arg(long, short = 't', required_unless_present = "local")]
        token: Option<String>,

        /// Optional label for this client
        #[arg(long)]
        label: Option<String>,

        /// Use local enrollment (same-machine, no token required)
        #[arg(long)]
        local: bool,
    },

    /// Check enrollment status
    Status,

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

    /// Manage authorized clients
    Clients {
        #[command(subcommand)]
        action: ClientsAction,
    },
}

#[derive(Subcommand)]
enum ClientsAction {
    /// List all authorized clients
    List,

    /// Revoke a client's authorization
    Revoke {
        /// Client fingerprint to revoke (e.g., SHA256:abc...)
        fingerprint: String,
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
    // Handle commands that don't need a task client connection
    match &cli.command {
        Commands::Enroll { token, label, local } => {
            // Enrollment uses port 50051 (server-auth only, no mTLS)
            let enrollment_addr = to_enrollment_addr(&cli.daemon);
            if *local {
                return cmd_enroll_local(&enrollment_addr, label.as_deref()).await;
            } else {
                let token = token
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Token required (or use --local)"))?;
                return cmd_enroll(&enrollment_addr, token, label.as_deref()).await;
            }
        }
        Commands::Status => {
            return cmd_status(&cli.daemon).await;
        }
        Commands::Clients { action } => {
            return cmd_clients(&cli, action).await;
        }
        _ => {}
    }

    // For local connections, use ad-hoc mode (sends local proof header)
    // For remote connections, use enrolled mode (mTLS)
    if is_local_address(&cli.daemon) {
        match connect_local_adhoc(&cli.daemon).await {
            Ok(mut client) => run_task_commands(&mut client, &cli).await,
            Err(local_err) => {
                Err(local_err.context("Local connection failed. Is the daemon running?"))
            }
        }
    } else {
        // Remote connection requires enrollment
        match connect_authenticated(&cli.daemon).await {
            Ok(mut client) => run_task_commands(&mut client, &cli).await,
            Err(err) => Err(err.context("Not enrolled with remote daemon")),
        }
    }
}

/// Execute task commands with a connected client.
/// Generic over the transport type to support both enrolled and ad-hoc connections.
async fn run_task_commands<T>(client: &mut ContinuumClient<T>, cli: &Cli) -> Result<()>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
    match &cli.command {
        Commands::Enroll { .. } | Commands::Status | Commands::Clients { .. } => unreachable!(),
        Commands::Run {
            interactive,
            name,
            cwd,
            envs,
            cmd,
        } => {
            cmd_run(
                client,
                cli,
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
        } => cmd_ls(client, cli, status.clone(), *recent, *all).await,

        Commands::Show { task_id, tail } => cmd_show(client, cli, task_id.clone(), *tail).await,

        Commands::Attach {
            task_id,
            interactive,
            raw: _,
            no_follow,
        } => cmd_attach(client, cli, task_id.clone(), *interactive, *no_follow).await,

        Commands::Send {
            task_id,
            data,
            file,
            ctrl_c,
            raw,
        } => {
            cmd_send(
                client,
                task_id.clone(),
                data.clone(),
                file.clone(),
                *ctrl_c,
                *raw,
            )
            .await
        }

        Commands::Cancel { task_id, force } => cmd_cancel(client, task_id.clone(), *force).await,
    }
}

/// Connect to daemon with mTLS and return the channel (requires prior enrollment).
async fn connect_authenticated_channel(addr: &str) -> Result<Channel> {
    // Load trust store to get server fingerprint
    let trust_store = TrustStore::load()?;
    let trusted = trust_store
        .get(addr)
        .with_context(|| format!("Not enrolled with {}. Run 'continuum enroll <token>' first.", addr))?;

    // Load client identity
    let identity_store = IdentityStore::open()?;
    let (_private_key, identity) = identity_store.load_or_generate()?;

    // Parse stored server fingerprint
    let server_fp = Fingerprint::parse(&trusted.fingerprint)
        .context("Invalid server fingerprint in trust store")?;

    // Create verifier that pins to the trusted fingerprint
    let verifier = EnrollmentVerifier::from_fingerprint(&server_fp);

    // Build mTLS config with client identity and pinned server verification
    let tls_config = build_mtls_config(&identity, verifier)?;

    build_tls_channel(addr, tls_config)
        .await
        .context("Failed to connect with mTLS")
}

/// Connect to daemon with mTLS (requires prior enrollment).
async fn connect_authenticated(addr: &str) -> Result<ContinuumClient<Channel>> {
    let channel = connect_authenticated_channel(addr).await?;
    Ok(ContinuumClient::new(channel))
}

/// Check if an address is a local address.
fn is_local_address(addr: &str) -> bool {
    addr.contains("127.0.0.1") || addr.contains("localhost") || addr.contains("[::1]")
}

/// Convert a daemon address to the enrollment port (50051).
///
/// The main API runs on port 50052 (mTLS required), while enrollment
/// runs on port 50051 (server-auth only, no client cert required).
fn to_enrollment_addr(addr: &str) -> String {
    // Replace port 50052 with 50051 for enrollment
    addr.replace(":50052", ":50051")
}

/// Convert an enrollment address back to the main API port (50052).
///
/// Used when storing trust entries - we want to key by main API address.
fn to_main_api_addr(addr: &str) -> String {
    // Replace port 50051 with 50052 for main API
    addr.replace(":50051", ":50052")
}

/// Connect to local daemon without enrollment (ad-hoc mode).
/// Returns a channel that can be used with the same-machine proof.
async fn connect_local_adhoc_channel(addr: &str) -> Result<Channel> {
    use commands::{compute_local_trust_proof, read_local_server_fingerprint};

    // Read server fingerprint from local file
    let server_fingerprint = read_local_server_fingerprint()
        .context("Server fingerprint not found. Is daemon running locally?")?;

    // Verify same-machine proof is available
    let _local_trust_proof = compute_local_trust_proof()
        .context("Not on same machine as daemon")?;

    // Create TLS config pinned to server fingerprint (no client cert)
    let verifier = EnrollmentVerifier::from_fingerprint(&server_fingerprint);
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    build_tls_channel(addr, tls_config)
        .await
        .context("Failed to connect to local daemon")
}

/// Interceptor that injects same-machine proof into requests.
#[derive(Clone)]
struct LocalProofInterceptor {
    proof: [u8; 32],
}

impl tonic::service::Interceptor for LocalProofInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        req.metadata_mut().insert_bin(
            "x-local-trust-proof-bin",
            tonic::metadata::MetadataValue::from_bytes(&self.proof),
        );
        Ok(req)
    }
}

/// Connect to local daemon without enrollment (ad-hoc mode).
/// Returns a client with interceptor that injects same-machine proof.
async fn connect_local_adhoc(
    addr: &str,
) -> Result<ContinuumClient<tonic::service::interceptor::InterceptedService<Channel, LocalProofInterceptor>>>
{
    use commands::compute_local_trust_proof;

    let channel = connect_local_adhoc_channel(addr).await?;

    // Get the proof for the interceptor
    let proof = compute_local_trust_proof().context("Not on same machine as daemon")?;

    let interceptor = LocalProofInterceptor { proof };
    Ok(ContinuumClient::with_interceptor(channel, interceptor))
}

// ============================================================================
// Enrollment Commands
// ============================================================================

fn print_enrollment_result(result: EnrollmentResult, prefix: &str) -> Result<()> {
    match result {
        EnrollmentResult::Approved { client_fingerprint } => {
            eprintln!("{} enrollment approved!", prefix);
            eprintln!("  Client fingerprint: {}", client_fingerprint);
            Ok(())
        }
        EnrollmentResult::Pending { client_fingerprint } => {
            eprintln!("Enrollment pending approval");
            eprintln!("  Client fingerprint: {}", client_fingerprint);
            eprintln!("  Run 'continuum status' to check approval status.");
            Ok(())
        }
        EnrollmentResult::Rejected { reason } => {
            anyhow::bail!("Enrollment rejected: {}", reason);
        }
    }
}

async fn cmd_enroll(enrollment_addr: &str, token: &str, label: Option<&str>) -> Result<()> {
    // Convert enrollment address (50051) to main API address (50052) for trust store
    let main_api_addr = to_main_api_addr(enrollment_addr);
    eprintln!("Enrolling with daemon at {}", enrollment_addr);
    let result = run_enrollment(enrollment_addr, &main_api_addr, token, label).await?;
    print_enrollment_result(result, "Remote")
}

async fn cmd_enroll_local(enrollment_addr: &str, label: Option<&str>) -> Result<()> {
    // Convert enrollment address (50051) to main API address (50052) for trust store
    let main_api_addr = to_main_api_addr(enrollment_addr);
    eprintln!("Local enrollment with daemon at {}", enrollment_addr);
    let result = run_local_enrollment(enrollment_addr, &main_api_addr, label).await?;
    print_enrollment_result(result, "Local")
}

async fn cmd_status(daemon_addr: &str) -> Result<()> {
    let is_authorized = check_status(daemon_addr).await?;

    if is_authorized {
        eprintln!("✓ Client is authorized");
    } else {
        eprintln!("✗ Client is not authorized");
        eprintln!("  Run 'continuum enroll <token>' to enroll.");
    }

    Ok(())
}

async fn cmd_clients(cli: &Cli, action: &ClientsAction) -> Result<()> {
    // Connect with mTLS for admin commands
    let channel = connect_authenticated_channel(&cli.daemon).await?;

    match action {
        ClientsAction::List => clients::list_clients(channel, cli.json).await,
        ClientsAction::Revoke { fingerprint } => clients::revoke_client(channel, fingerprint).await,
    }
}

// ============================================================================
// Task Commands
// ============================================================================

async fn cmd_run<T>(
    client: &mut ContinuumClient<T>,
    cli: &Cli,
    interactive: bool,
    name: Option<String>,
    cwd: Option<PathBuf>,
    envs: Vec<String>,
    cmd: Vec<String>,
) -> Result<()>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
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

async fn cmd_ls<T>(
    client: &mut ContinuumClient<T>,
    cli: &Cli,
    status: Option<StatusFilter>,
    recent: i32,
    all: bool,
) -> Result<()>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
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

async fn cmd_show<T>(
    client: &mut ContinuumClient<T>,
    cli: &Cli,
    task_id: String,
    tail: Option<usize>,
) -> Result<()>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
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

async fn cmd_attach<T>(
    client: &mut ContinuumClient<T>,
    _cli: &Cli,
    task_id: String,
    interactive: bool,
    no_follow: bool,
) -> Result<()>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
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

    // Enter raw mode if interactive (disables local echo, lets remote PTY handle it)
    let _raw_mode = if interactive && !is_terminal {
        eprintln!("(Use ~. to detach)");
        RawModeGuard::enter()
    } else {
        None
    };

    // Create detach channel
    let (detach_tx, mut detach_rx) = tokio::sync::oneshot::channel::<()>();

    // If interactive and task is running, spawn stdin reader
    let stdin_handle = if interactive && !is_terminal {
        let task_id_clone = task_id.clone();
        let daemon_addr = _cli.daemon.clone();

        Some(tokio::spawn(async move {
            forward_stdin(daemon_addr, task_id_clone, detach_tx).await
        }))
    } else {
        None
    };

    // Track if we detached vs task exited
    let mut detached = false;

    // Stream output, also watching for detach signal
    let mut stdout = io::stdout();
    loop {
        tokio::select! {
            // Check for detach signal
            _ = &mut detach_rx => {
                detached = true;
                break;
            }

            // Stream output
            result = stream.next() => {
                match result {
                    Some(Ok(chunk)) => {
                        stdout.write_all(&chunk.data)?;
                        stdout.flush()?;
                    }
                    Some(Err(e)) => {
                        if !no_follow {
                            eprintln!("\nStream error: {}", e);
                        }
                        break;
                    }
                    None => {
                        // Stream ended (task exited)
                        break;
                    }
                }

                if no_follow && is_terminal {
                    break;
                }
            }
        }
    }

    // Cancel stdin forwarder if running
    if let Some(handle) = stdin_handle {
        handle.abort();
    }

    // Drop raw mode before printing exit message
    drop(_raw_mode);

    // Show appropriate message
    if interactive && !no_follow {
        if detached {
            eprintln!(
                "\n[Detached - task still running. Reattach with: continuum attach -i {}]",
                task_id
            );
        } else {
            // Fetch final task status and show exit info (with timeout in case daemon is gone)
            let get_request = GetTaskRequest {
                task_id: task_id.clone(),
            };
            let get_result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client.get_task(get_request),
            )
            .await;
            if let Ok(Ok(resp)) = get_result {
                if let Some(task) = resp.into_inner().task {
                    let exit_msg = match TaskStatus::try_from(task.status) {
                        Ok(TaskStatus::Completed) => {
                            let code = task.exit_code.unwrap_or(0);
                            if code == 0 {
                                Some("Process exited normally".to_string())
                            } else {
                                Some(format!("Process exited with code {}", code))
                            }
                        }
                        Ok(TaskStatus::Failed) => {
                            if let Some(code) = task.exit_code {
                                if code > 128 {
                                    // Signal exit (128 + signal number)
                                    let sig = code - 128;
                                    let sig_name = match sig {
                                        2 => "SIGINT",
                                        9 => "SIGKILL",
                                        15 => "SIGTERM",
                                        _ => "",
                                    };
                                    if sig_name.is_empty() {
                                        Some(format!("Process killed by signal {}", sig))
                                    } else {
                                        Some(format!("Process killed by {}", sig_name))
                                    }
                                } else {
                                    Some(format!("Process exited with code {}", code))
                                }
                            } else if let Some(ref reason) = task.failure_reason {
                                Some(format!("Process failed: {}", reason))
                            } else {
                                Some("Process failed".to_string())
                            }
                        }
                        Ok(TaskStatus::Canceled) => Some("Process canceled".to_string()),
                        _ => None,
                    };

                    if let Some(msg) = exit_msg {
                        eprintln!("\n[{}]", msg);
                        wait_for_keypress();
                    }
                }
            } else {
                // Daemon unreachable (likely shutdown)
                eprintln!("\n[Connection lost - daemon may have shutdown]");
                wait_for_keypress();
            }
        }
    }

    Ok(())
}

/// Wait for a single keypress (used after task exits).
fn wait_for_keypress() {
    let fd = std::io::stdin().as_raw_fd();

    // Check if stdin is a TTY
    if unsafe { libc::isatty(fd) } != 1 {
        return;
    }

    // Get current settings
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        return;
    }

    // Create raw mode settings
    let mut raw = original;
    unsafe { libc::cfmakeraw(&mut raw) };

    // Apply raw mode
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
        return;
    }

    // Read a single byte
    let mut buf = [0u8; 1];
    let _ = std::io::stdin().read_exact(&mut buf);

    // Restore original settings
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
}

/// Result of stdin forwarding
#[allow(dead_code)]
enum StdinResult {
    Eof,
    Detach,
    Error(anyhow::Error),
}

/// Escape sequence state machine (~. to detach)
struct EscapeDetector {
    saw_tilde: bool,
}

impl EscapeDetector {
    fn new() -> Self {
        Self { saw_tilde: false }
    }

    /// Process input bytes, returns (bytes_to_send, should_detach)
    fn process(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        let mut output = Vec::with_capacity(input.len());

        for &byte in input {
            if self.saw_tilde {
                self.saw_tilde = false;
                match byte {
                    b'.' => {
                        // ~. = detach
                        return (output, true);
                    }
                    b'~' => {
                        // ~~ = send single ~
                        output.push(b'~');
                    }
                    _ => {
                        // ~<other> = send both
                        output.push(b'~');
                        output.push(byte);
                    }
                }
            } else if byte == b'~' {
                // Potential start of escape sequence - hold it
                self.saw_tilde = true;
            } else {
                output.push(byte);
            }
        }

        (output, false)
    }
}

async fn forward_stdin(
    daemon_addr: String,
    task_id: String,
    detach_tx: tokio::sync::oneshot::Sender<()>,
) -> StdinResult {
    // Use local ad-hoc for local connections, enrolled for remote
    if is_local_address(&daemon_addr) {
        match connect_local_adhoc(&daemon_addr).await {
            Ok(mut client) => {
                forward_stdin_with_client(&mut client, task_id, detach_tx).await
            }
            Err(e) => StdinResult::Error(e),
        }
    } else {
        match connect_authenticated(&daemon_addr).await {
            Ok(mut client) => {
                forward_stdin_with_client(&mut client, task_id, detach_tx).await
            }
            Err(e) => StdinResult::Error(e),
        }
    }
}

async fn forward_stdin_with_client<T>(
    client: &mut ContinuumClient<T>,
    task_id: String,
    detach_tx: tokio::sync::oneshot::Sender<()>,
) -> StdinResult
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
    let mut stdin = tokio::io::stdin();
    let mut escape = EscapeDetector::new();

    loop {
        let mut buf = vec![0u8; 1024];
        let n = match tokio::io::AsyncReadExt::read(&mut stdin, &mut buf).await {
            Ok(0) => return StdinResult::Eof,
            Ok(n) => n,
            Err(e) => return StdinResult::Error(e.into()),
        };
        buf.truncate(n);

        // Process through escape detector
        let (data, should_detach) = escape.process(&buf);

        if should_detach {
            let _ = detach_tx.send(());
            return StdinResult::Detach;
        }

        // Only send if there's data (escape sequence might consume all input)
        if !data.is_empty() {
            let request = SendInputRequest {
                task_id: task_id.clone(),
                data,
            };

            if let Err(e) = client.send_input(request).await {
                // Ignore transport errors (task probably exited)
                if !e.to_string().contains("transport error") {
                    return StdinResult::Error(e.into());
                }
                return StdinResult::Eof;
            }
        }
    }
}

async fn cmd_send<T>(
    client: &mut ContinuumClient<T>,
    task_id: String,
    data: Option<String>,
    file: Option<PathBuf>,
    ctrl_c: bool,
    raw: bool,
) -> Result<()>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
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

async fn cmd_cancel<T>(
    client: &mut ContinuumClient<T>,
    task_id: String,
    force: bool,
) -> Result<()>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
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
    utils::format_timestamp_millis(ms)
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
