//! CLI argument parsing.

use clap::Parser;
use std::path::PathBuf;

/// Continuum shim process - bridges a single PTY child to the daemon.
#[derive(Parser, Debug)]
#[command(name = "continuum-shim")]
pub struct Args {
    /// Task ID for this shim instance
    #[arg(long)]
    pub task_id: String,

    /// Unix socket path to connect to daemon
    #[arg(long, value_name = "PATH")]
    pub connect: PathBuf,

    /// Terminal rows
    #[arg(long, default_value = "24")]
    pub rows: u16,

    /// Terminal columns
    #[arg(long, default_value = "80")]
    pub cols: u16,

    /// Working directory for child
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Environment variables (KEY=VALUE), can be repeated
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env_vars: Vec<String>,

    /// Command and arguments to run (after --)
    #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
    pub cmd: Vec<String>,
}

impl Args {
    /// Parse environment variables into key-value pairs.
    pub fn parse_env(&self) -> Vec<(String, String)> {
        self.env_vars
            .iter()
            .filter_map(|s| {
                let mut parts = s.splitn(2, '=');
                let key = parts.next()?;
                let value = parts.next().unwrap_or("");
                Some((key.to_string(), value.to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(args)
    }

    #[test]
    fn test_basic_args() {
        let args = parse_args(&[
            "continuum-shim",
            "--task-id",
            "task-123",
            "--connect",
            "/tmp/daemon.sock",
            "--",
            "bash",
        ])
        .unwrap();

        assert_eq!(args.task_id, "task-123");
        assert_eq!(args.connect.to_str().unwrap(), "/tmp/daemon.sock");
        assert_eq!(args.cmd, vec!["bash"]);
    }

    #[test]
    fn test_command_with_args() {
        let args = parse_args(&[
            "continuum-shim",
            "--task-id",
            "t1",
            "--connect",
            "/sock",
            "--",
            "ls",
            "-la",
            "--color=always",
        ])
        .unwrap();

        assert_eq!(args.cmd, vec!["ls", "-la", "--color=always"]);
    }

    #[test]
    fn test_hyphen_values_pass_through() {
        // Ensure --help after -- doesn't trigger our help
        let args = parse_args(&[
            "continuum-shim",
            "--task-id",
            "t1",
            "--connect",
            "/sock",
            "--",
            "grep",
            "--help",
        ])
        .unwrap();

        assert_eq!(args.cmd, vec!["grep", "--help"]);
    }

    #[test]
    fn test_env_vars() {
        let args = parse_args(&[
            "continuum-shim",
            "--task-id",
            "t1",
            "--connect",
            "/sock",
            "--env",
            "FOO=bar",
            "--env",
            "BAZ=qux=123",
            "--",
            "env",
        ])
        .unwrap();

        let env = args.parse_env();
        assert_eq!(env.len(), 2);
        assert_eq!(env[0], ("FOO".to_string(), "bar".to_string()));
        // Value can contain =
        assert_eq!(env[1], ("BAZ".to_string(), "qux=123".to_string()));
    }

    #[test]
    fn test_env_var_empty_value() {
        let args = parse_args(&[
            "continuum-shim",
            "--task-id",
            "t1",
            "--connect",
            "/sock",
            "--env",
            "EMPTY=",
            "--",
            "env",
        ])
        .unwrap();

        let env = args.parse_env();
        assert_eq!(env[0], ("EMPTY".to_string(), String::new()));
    }

    #[test]
    fn test_custom_dimensions() {
        let args = parse_args(&[
            "continuum-shim",
            "--task-id",
            "t1",
            "--connect",
            "/sock",
            "--rows",
            "40",
            "--cols",
            "120",
            "--",
            "vim",
        ])
        .unwrap();

        assert_eq!(args.rows, 40);
        assert_eq!(args.cols, 120);
    }

    #[test]
    fn test_default_dimensions() {
        let args = parse_args(&[
            "continuum-shim",
            "--task-id",
            "t1",
            "--connect",
            "/sock",
            "--",
            "bash",
        ])
        .unwrap();

        assert_eq!(args.rows, 24);
        assert_eq!(args.cols, 80);
    }

    #[test]
    fn test_missing_command_fails() {
        let result = parse_args(&[
            "continuum-shim",
            "--task-id",
            "t1",
            "--connect",
            "/sock",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_args_fails() {
        // Missing --connect
        let result = parse_args(&[
            "continuum-shim",
            "--task-id",
            "t1",
            "--",
            "bash",
        ]);
        assert!(result.is_err());

        // Missing --task-id
        let result = parse_args(&[
            "continuum-shim",
            "--connect",
            "/sock",
            "--",
            "bash",
        ]);
        assert!(result.is_err());
    }
}
