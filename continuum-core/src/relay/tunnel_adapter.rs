//! Tunnel adapter for bridging gRPC streams to AsyncRead/AsyncWrite.
//!
//! The relay uses gRPC bidirectional streaming for the tunnel data plane.
//! This adapter converts those streams into standard Tokio async I/O traits,
//! allowing TLS to be layered on top for end-to-end encryption.

use bytes::{Bytes, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Bridges gRPC bidirectional streams to AsyncRead/AsyncWrite.
///
/// This adapter allows TLS to be layered on top of the tunnel, providing
/// end-to-end encryption between client and daemon even though the relay
/// forwards the bytes.
///
/// # Example
///
/// ```ignore
/// let (tx, rx) = mpsc::channel(1024);
/// let adapter = TunnelAdapter::new(rx, tx);
///
/// // Layer TLS on top
/// let tls_stream = connector.connect(adapter).await?;
/// ```
pub struct TunnelAdapter {
    rx: mpsc::Receiver<Bytes>,
    tx: mpsc::Sender<Bytes>,
    read_buffer: BytesMut,
    /// Pending write that couldn't be sent immediately
    pending_write: Option<Bytes>,
}

impl TunnelAdapter {
    /// Create a new tunnel adapter.
    ///
    /// # Arguments
    ///
    /// * `rx` - Receiver for incoming data from the tunnel
    /// * `tx` - Sender for outgoing data to the tunnel
    pub fn new(rx: mpsc::Receiver<Bytes>, tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            rx,
            tx,
            read_buffer: BytesMut::new(),
            pending_write: None,
        }
    }

    /// Split into separate read and write halves.
    ///
    /// This is useful when you need to pass the read and write sides to
    /// different tasks or functions.
    pub fn into_split(self) -> (TunnelAdapterRead, TunnelAdapterWrite) {
        (
            TunnelAdapterRead {
                rx: self.rx,
                read_buffer: self.read_buffer,
            },
            TunnelAdapterWrite {
                tx: self.tx,
                pending_write: self.pending_write,
            },
        )
    }
}

impl AsyncRead for TunnelAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, drain any buffered data from previous reads
        if !self.read_buffer.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer.split_to(n));
            return Poll::Ready(Ok(()));
        }

        // Poll the receiver for new data
        match Pin::new(&mut self.rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                // Buffer any remaining data
                if n < data.len() {
                    self.read_buffer.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed - EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TunnelAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If we have a pending write, try to send it first
        if let Some(pending) = self.pending_write.take() {
            match self.tx.try_send(pending.clone()) {
                Ok(()) => {
                    // Successfully sent pending data, now try to send new data
                }
                Err(mpsc::error::TrySendError::Full(data)) => {
                    // Still no capacity, put it back and wait
                    self.pending_write = Some(data);
                    // Register waker (we can't easily do this with mpsc::Sender)
                    // Fall back to a spin-yield approach
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "tunnel channel closed",
                    )));
                }
            }
        }

        // Try to send the new data
        let data = Bytes::copy_from_slice(buf);
        match self.tx.try_send(data.clone()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(data)) => {
                // Channel is full, store pending and return pending
                self.pending_write = Some(data);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tunnel channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // No buffering on our end, always flushed
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Dropping the sender will close the channel
        Poll::Ready(Ok(()))
    }
}

/// Read half of a split tunnel adapter.
pub struct TunnelAdapterRead {
    rx: mpsc::Receiver<Bytes>,
    read_buffer: BytesMut,
}

impl AsyncRead for TunnelAdapterRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, drain any buffered data
        if !self.read_buffer.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer.split_to(n));
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buffer.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Write half of a split tunnel adapter.
pub struct TunnelAdapterWrite {
    tx: mpsc::Sender<Bytes>,
    pending_write: Option<Bytes>,
}

impl AsyncWrite for TunnelAdapterWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Handle pending write first
        if let Some(pending) = self.pending_write.take() {
            match self.tx.try_send(pending.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(data)) => {
                    self.pending_write = Some(data);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "tunnel channel closed",
                    )));
                }
            }
        }

        let data = Bytes::copy_from_slice(buf);
        match self.tx.try_send(data.clone()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(data)) => {
                self.pending_write = Some(data);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tunnel channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_basic_read_write() {
        let (tx1, rx1) = mpsc::channel(16);
        let (tx2, mut rx2) = mpsc::channel(16);

        let mut adapter = TunnelAdapter::new(rx1, tx2);

        // Send some data through tx1 (simulating remote sending)
        tx1.send(Bytes::from("hello")).await.unwrap();

        // Read it from the adapter
        let mut buf = [0u8; 5];
        let n = adapter.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        // Write data through the adapter
        adapter.write_all(b"world").await.unwrap();

        // Receive it from rx2
        let received = rx2.recv().await.unwrap();
        assert_eq!(&received[..], b"world");
    }

    #[tokio::test]
    async fn test_buffering_large_message() {
        let (tx, rx) = mpsc::channel(16);
        let (out_tx, _out_rx) = mpsc::channel(16);

        let mut adapter = TunnelAdapter::new(rx, out_tx);

        // Send a large message
        tx.send(Bytes::from(vec![0u8; 100])).await.unwrap();

        // Read in small chunks
        let mut buf = [0u8; 20];
        let n1 = adapter.read(&mut buf).await.unwrap();
        assert_eq!(n1, 20);

        let n2 = adapter.read(&mut buf).await.unwrap();
        assert_eq!(n2, 20);

        // Buffer should still have 60 bytes
        assert_eq!(adapter.read_buffer.len(), 60);
    }
}
