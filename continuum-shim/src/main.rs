//! Continuum shim - bridges a single PTY child to the daemon.
//!
//! Each shim instance:
//! - Owns one PTY child process
//! - Streams output to the daemon via Unix socket IPC
//! - Receives stdin, signals, and resize from the daemon
//! - Detects "attention" (prompts needing input, stalls)
//! - Exits when the child exits

mod args;
mod attention;
mod child;
mod io;
mod ipc;
mod run;
mod util;

use args::Args;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    tracing::info!(task_id = %args.task_id, "shim started");

    let exit_code = match run::run(args).await {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("shim error: {:#}", e);
            1
        }
    };

    std::process::exit(exit_code);
}
