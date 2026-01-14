//! Mock daemon for manual testing.
//!
//! Run with: cargo run -p continuum-shim --example mock_daemon
//!
//! Then in another terminal:
//! ./target/debug/continuum-shim --task-id test --connect /tmp/mock-daemon.sock -- bash

use std::io::Read;
use std::os::unix::net::UnixListener;
use std::path::Path;

use bytes::Bytes;
use continuum_shim_proto::{shim_to_daemon, AttentionKind, ShimToDaemon};
use prost::Message;

fn read_frame(stream: &mut std::os::unix::net::UnixStream) -> std::io::Result<Bytes> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;

    Ok(Bytes::from(buf))
}

fn attention_kind_name(kind: i32) -> &'static str {
    match AttentionKind::try_from(kind) {
        Ok(AttentionKind::Unspecified) => "Unspecified",
        Ok(AttentionKind::MaybeNeedsInput) => "MaybeNeedsInput",
        Ok(AttentionKind::NeedsInput) => "NeedsInput",
        Ok(AttentionKind::Stalled) => "Stalled",
        Ok(AttentionKind::Error) => "Error",
        Err(_) => "Unknown",
    }
}

fn main() -> std::io::Result<()> {
    let socket_path = Path::new("/tmp/mock-daemon.sock");

    // Clean up existing socket
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    println!("Mock daemon listening on {}", socket_path.display());
    println!(
        "Run shim with: ./target/debug/continuum-shim --task-id test --connect {} -- <command>",
        socket_path.display()
    );
    println!();

    loop {
        println!("Waiting for connection...");
        let (mut stream, _) = listener.accept()?;
        println!("=== Connection accepted ===\n");

        loop {
            match read_frame(&mut stream) {
                Ok(frame) => match ShimToDaemon::decode(frame) {
                    Ok(msg) => match msg.msg {
                        Some(shim_to_daemon::Msg::Started(s)) => {
                            println!("📦 Started {{ pid: {}, pgid: {} }}", s.pid, s.pgid);
                        }
                        Some(shim_to_daemon::Msg::Output(o)) => {
                            let text = String::from_utf8_lossy(&o.data);
                            let preview: String = text.chars().take(100).collect();
                            println!(
                                "📤 Output {{ ts: {}, len: {}, data: {:?} }}",
                                o.timestamp_ms,
                                o.data.len(),
                                preview
                            );
                        }
                        Some(shim_to_daemon::Msg::Attention(a)) => {
                            println!(
                                "⚠️  Attention {{ kind: {}, ts: {}, context: {:?} }}",
                                attention_kind_name(a.kind),
                                a.timestamp_ms,
                                a.context
                            );
                        }
                        Some(shim_to_daemon::Msg::Exited(e)) => match e.status {
                            Some(continuum_shim_proto::exited::Status::Code(c)) => {
                                println!("🏁 Exited {{ code: {} }}", c);
                            }
                            Some(continuum_shim_proto::exited::Status::Signal(s)) => {
                                println!("🏁 Exited {{ signal: {} }}", s);
                            }
                            None => {
                                println!("🏁 Exited {{ status: None }}");
                            }
                        },
                        None => {
                            println!("❓ Empty message");
                        }
                    },
                    Err(e) => {
                        println!("❌ Decode error: {}", e);
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    println!("\n=== Connection closed ===\n");
                    break;
                }
                Err(e) => {
                    println!("❌ Read error: {}", e);
                    break;
                }
            }
        }
    }
}
