//! High-level IPC client for shim↔daemon communication.

use continuum_shim_proto::{
    Attention, AttentionKind, DaemonToShim, Exited, Output, ShimToDaemon, Started,
    shim_to_daemon,
};
use prost::Message;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use crate::io::framing::{read_frame, write_frame};

/// IPC client for communicating with the daemon.
pub struct IpcClient {
    reader: Mutex<ReadHalf<UnixStream>>,
    writer: Mutex<WriteHalf<UnixStream>>,
}

impl IpcClient {
    /// Create a new IPC client from a Unix stream.
    pub fn new(stream: UnixStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }

    /// Send a message to the daemon.
    async fn send(&self, msg: ShimToDaemon) -> std::io::Result<()> {
        let data = msg.encode_to_vec();
        let mut writer = self.writer.lock().await;
        write_frame(&mut *writer, &data).await
    }

    /// Receive a message from the daemon.
    pub async fn recv(&self) -> std::io::Result<Option<DaemonToShim>> {
        let mut reader = self.reader.lock().await;
        match read_frame(&mut *reader).await {
            Ok(data) => {
                let msg = DaemonToShim::decode(data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(Some(msg))
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Send Started message.
    pub async fn send_started(&self, pid: i32, pgid: i32) -> std::io::Result<()> {
        let msg = ShimToDaemon {
            msg: Some(shim_to_daemon::Msg::Started(Started { pid, pgid })),
        };
        self.send(msg).await
    }

    /// Send Output message.
    pub async fn send_output(&self, timestamp_ms: i64, data: Vec<u8>) -> std::io::Result<()> {
        let msg = ShimToDaemon {
            msg: Some(shim_to_daemon::Msg::Output(Output { timestamp_ms, data })),
        };
        self.send(msg).await
    }

    /// Send Attention message.
    pub async fn send_attention(
        &self,
        kind: AttentionKind,
        timestamp_ms: i64,
        context: Option<String>,
    ) -> std::io::Result<()> {
        let msg = ShimToDaemon {
            msg: Some(shim_to_daemon::Msg::Attention(Attention {
                kind: kind as i32,
                timestamp_ms,
                context,
            })),
        };
        self.send(msg).await
    }

    /// Send Exited message with exit code.
    pub async fn send_exited_code(&self, code: i32) -> std::io::Result<()> {
        let msg = ShimToDaemon {
            msg: Some(shim_to_daemon::Msg::Exited(Exited {
                status: Some(continuum_shim_proto::exited::Status::Code(code)),
            })),
        };
        self.send(msg).await
    }

    /// Send Exited message with signal.
    pub async fn send_exited_signal(&self, signal: i32) -> std::io::Result<()> {
        let msg = ShimToDaemon {
            msg: Some(shim_to_daemon::Msg::Exited(Exited {
                status: Some(continuum_shim_proto::exited::Status::Signal(signal)),
            })),
        };
        self.send(msg).await
    }
}
