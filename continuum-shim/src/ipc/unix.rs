//! Unix domain socket connection.

use std::path::Path;
use tokio::net::UnixStream;

/// Connect to a Unix domain socket.
pub async fn connect(path: &Path) -> std::io::Result<UnixStream> {
    UnixStream::connect(path).await
}
