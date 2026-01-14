//! Length-delimited message framing.
//!
//! Wire format: 4-byte big-endian length prefix followed by payload.

use bytes::{Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum frame size (16 MB).
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Read a length-delimited frame from an async reader.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Bytes> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes", len),
        ));
    }

    // Read payload
    let mut buf = BytesMut::with_capacity(len);
    buf.resize(len, 0);
    reader.read_exact(&mut buf).await?;

    Ok(buf.freeze())
}

/// Write a length-delimited frame to an async writer.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame too large: {} bytes", data.len()),
        ));
    }

    // Write 4-byte length prefix
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;

    // Write payload
    writer.write_all(data).await?;
    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_roundtrip() {
        let data = b"hello world";

        // Write to buffer
        let mut buf = Vec::new();
        write_frame(&mut buf, data).await.unwrap();

        // Read from buffer
        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor).await.unwrap();

        assert_eq!(&result[..], data);
    }

    #[tokio::test]
    async fn test_empty_frame() {
        let data = b"";

        let mut buf = Vec::new();
        write_frame(&mut buf, data).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor).await.unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_large_frame() {
        // Test a reasonably large frame (64KB)
        let data = vec![0xAB_u8; 64 * 1024];

        let mut buf = Vec::new();
        write_frame(&mut buf, &data).await.unwrap();

        // Verify header + payload size
        assert_eq!(buf.len(), 4 + data.len());

        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor).await.unwrap();

        assert_eq!(result.len(), data.len());
        assert!(result.iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn test_multiple_frames() {
        let frames = vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()];

        // Write all frames
        let mut buf = Vec::new();
        for frame in &frames {
            write_frame(&mut buf, frame).await.unwrap();
        }

        // Read all frames back
        let mut cursor = Cursor::new(buf);
        for expected in &frames {
            let result = read_frame(&mut cursor).await.unwrap();
            assert_eq!(&result[..], &expected[..]);
        }
    }

    #[tokio::test]
    async fn test_frame_too_large_write() {
        // Try to write a frame larger than MAX_FRAME_SIZE
        let data = vec![0_u8; MAX_FRAME_SIZE + 1];
        let mut buf = Vec::new();

        let result = write_frame(&mut buf, &data).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_frame_too_large_read() {
        // Craft a header claiming a frame larger than MAX_FRAME_SIZE
        let huge_len = (MAX_FRAME_SIZE + 1) as u32;
        let buf = huge_len.to_be_bytes().to_vec();

        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_truncated_frame() {
        // Write a header claiming 100 bytes but only provide 50
        let mut buf = Vec::new();
        buf.extend_from_slice(&100_u32.to_be_bytes());
        buf.extend_from_slice(&[0_u8; 50]); // Only 50 bytes instead of 100

        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_binary_data() {
        // Test with binary data including null bytes
        let data: Vec<u8> = (0..=255).collect();

        let mut buf = Vec::new();
        write_frame(&mut buf, &data).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor).await.unwrap();

        assert_eq!(result.len(), 256);
        for (i, &byte) in result.iter().enumerate() {
            assert_eq!(byte, i as u8);
        }
    }
}
