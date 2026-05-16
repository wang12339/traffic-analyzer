//! Send loop: drains captured frames from the mpsc channel and sends
//! them to the ingest server over TCP in bincode-encoded batches.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{info, warn};
use traffic_core::PacketFrame;

const SEND_BUF_SIZE: usize = 512;
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Runs the send loop on a Tokio runtime. Reads frames from `rx`, batches them,
/// and sends to `ingest_addr` via TCP. Blocks until `running` is false.
pub fn run_send_loop(
    ingest_addr: String,
    rx: Receiver<PacketFrame>,
    running: Arc<AtomicBool>,
) {
    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    rt.block_on(async {
        let mut batch: Vec<PacketFrame> = Vec::with_capacity(SEND_BUF_SIZE);
        let mut stream: Option<TcpStream> = None;

        while running.load(Ordering::SeqCst) {
            if stream.is_none() {
                match TcpStream::connect(&ingest_addr).await {
                    Ok(s) => {
                        info!("Connected to ingest");
                        stream = Some(s);
                    }
                    Err(e) => {
                        warn!("Connect failed: {} (retry {:?})", e, RECONNECT_DELAY);
                        tokio::time::sleep(RECONNECT_DELAY).await;
                        continue;
                    }
                }
            }

            // Drain available frames (non-blocking)
            while let Ok(frame) = rx.try_recv() {
                batch.push(frame);
                if batch.len() >= SEND_BUF_SIZE {
                    break;
                }
            }

            if batch.is_empty() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }

            if let Some(ref mut s) = stream {
                let buf = match bincode::serialize(&batch) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Serialize error: {}", e);
                        batch.clear();
                        continue;
                    }
                };
                let len = (buf.len() as u32).to_le_bytes();
                if s.write_all(&len).await.is_err() || s.write_all(&buf).await.is_err() {
                    warn!("Send failed, reconnecting...");
                    let _ = s.shutdown().await;
                    stream = None;
                }
                batch.clear();
            }
        }

        info!("Agent shutdown");
    });
}
