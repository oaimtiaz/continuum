//! Unix domain socket connection.

use std::path::Path;
use tokio::net::UnixStream;

/// Connect to a Unix domain socket.
pub async fn connect(path: &Path) -> std::io::Result<UnixStream> {
    tracing::debug!("connecting to Unix socket: {:?}", path);
    let stream = UnixStream::connect(path).await?;
    tracing::info!("connected to daemon");
    Ok(stream)
}
