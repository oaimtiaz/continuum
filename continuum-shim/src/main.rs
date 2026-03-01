//! Continuum shim binary - thin wrapper around the library.

use clap::Parser;
use continuum_shim::{Args, run};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    tracing::info!(task_id = %args.task_id, "shim started");

    let exit_code = match run(args).await {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("shim error: {:#}", e);
            1
        }
    };

    std::process::exit(exit_code);
}
