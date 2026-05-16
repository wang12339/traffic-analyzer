mod dns_parser;
mod flow_agg;
mod http_parser;
mod mysql_parser;
mod quic_parser;
mod redis_parser;
mod storage;
mod tcp_reasm;
mod tls_parser;
mod anomaly;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use traffic_core::{now_ns, PacketFrame};

use flow_agg::ShardedFlowAggregator;
use storage::ClickStore;

const FRAME_CHAN_SIZE: usize = 65536;
const FLOW_EXPIRE_SECS: u64 = 15;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(name = "ingest", about = "Traffic analysis engine")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:9100")]
    listen: String,

    #[arg(short, long, default_value = "localhost:8123")]
    clickhouse: String,

    #[arg(long, default_value = "traffic")]
    db_name: String,

    #[arg(short = 'u', long, default_value = "2055")]
    udp_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_target(false)
        .init();

    let args = Args::parse();
    info!(
        "Ingest server starting — listen={}, clickhouse={}",
        args.listen, args.clickhouse
    );

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("ctrlc handler");

    // ClickHouse storage
    let store = ClickStore::new(&args.clickhouse, &args.db_name)
        .await
        .context("ClickHouse init")?;
    let store = Arc::new(store);

    // UDP compatibility socket (receives JSON flow records from Python agent)
    let udp_addr = format!("0.0.0.0:{}", args.udp_port);
    let udp_sock = tokio::net::UdpSocket::bind(&udp_addr).await?;
    let store_udp = store.clone();
    let run_udp = running.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let udp_store = store_udp;
        while run_udp.load(Ordering::SeqCst) {
            match udp_sock.recv_from(&mut buf).await {
                Ok((n, _addr)) => {
                    let data = &buf[..n];
                    if let Ok(text) = std::str::from_utf8(data) {
                        if let Ok(rec) = serde_json::from_str::<serde_json::Value>(text) {
                            let rtype = rec["type"].as_str().unwrap_or("").to_string();
                            if rtype == "device_info" {
                                if let Err(e) = udp_store.write_device_info(&rec).await {
                                    warn!("UDP device_info error: {}", e);
                                }
                            } else if rtype == "http_request" || rtype == "http_response" {
                                if let Err(e) = udp_store.write_http_session(&rec).await {
                                    warn!("UDP http error: {}", e);
                                }
                            } else {
                                if let Err(e) = udp_store.write_json_flow(&rec).await {
                                    warn!("UDP store error: {}", e);
                                }
                            }
                        }
                    }
                }
                Err(e) => warn!("UDP recv error: {}", e),
            }
        }
    });

    let (pkt_tx, mut pkt_rx) = mpsc::channel::<(String, PacketFrame)>(FRAME_CHAN_SIZE);

    // Accept agent connections
    let listener = TcpListener::bind(&args.listen)
        .await
        .context("bind listener")?;
    info!("Listening on {}", args.listen);

    let run_accept = running.clone();
    let accept_tx = pkt_tx.clone();
    tokio::spawn(async move {
        while run_accept.load(Ordering::SeqCst) {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    info!("Agent connected from {}", addr);
                    let tx = accept_tx.clone();
                    let agent_id = addr.to_string();
                    tokio::spawn(async move {
                        const MAX_MSG_LEN: usize = 10 * 1024 * 1024; // 10MB 安全上限
                        let mut buf = Vec::with_capacity(8192);
                        let mut len_buf = [0u8; 4];
                        loop {
                            if let Err(e) = stream.read_exact(&mut len_buf).await {
                                warn!("Agent {} disconnected: {}", agent_id, e);
                                return;
                            }
                            let msg_len = u32::from_le_bytes(len_buf) as usize;
                            if msg_len > MAX_MSG_LEN {
                                warn!("Agent {} oversize msg ({} > {}), drop", agent_id, msg_len, MAX_MSG_LEN);
                                return;
                            }
                            buf.resize(msg_len, 0);
                            if stream.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                            match bincode::deserialize::<Vec<PacketFrame>>(&buf) {
                                Ok(frames) => {
                                    for f in frames {
                                        // try_send: channel 满时丢帧而非阻塞 agent TCP 连接
                                        // 背压由内核 TCP buffer 自然处理
                                        use tokio::sync::mpsc::error::TrySendError;
                                        match tx.try_send((agent_id.clone(), f)) {
                                            Err(TrySendError::Full(_)) => {
                                                static DROP_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                                                let c = DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                                if c % 1000 == 0 {
                                                    warn!("Ingest channel full, dropped {} frames", c + 1000);
                                                }
                                            }
                                            Err(TrySendError::Closed(_)) => {
                                                warn!("Agent send channel closed");
                                                return;
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                Err(e) => warn!("Deserialize error from {}: {}", agent_id, e),
                            }
                        }
                    });
                }
                Err(e) => error!("Accept error: {}", e),
            }
        }
    });

    // Flow aggregation pipeline (4 shards for reduced lock contention)
    let agg = Arc::new(ShardedFlowAggregator::new(
        4,
        FLOW_EXPIRE_SECS,
        store.clone(),
    ));

    let run_agg = running.clone();
    let agg_instance = agg.clone();
    let agg_handle = tokio::spawn(async move {
        let mut last_flush = SystemTime::now();
        while run_agg.load(Ordering::SeqCst) {
            let elapsed = last_flush.elapsed().unwrap_or_default();
            if elapsed >= FLUSH_INTERVAL {
                agg_instance.flush_expired(now_ns()).await;
                last_flush = SystemTime::now();
            }
            sleep(Duration::from_millis(200)).await;
        }
    });

    // Main packet processing loop
    info!("Packet processing started");
    while running.load(Ordering::SeqCst) {
        tokio::select! {
            Some((_, frame)) = pkt_rx.recv() => {
                agg.process_packet(now_ns(), &frame).await;
            }
            _ = sleep(Duration::from_millis(500)) => {}
        }
    }

    // Shutdown: flush remaining flows
    info!("Shutting down, flushing remaining flows...");
    agg.flush_all().await;

    agg_handle.abort();
    info!("Ingest server stopped");
    Ok(())
}
