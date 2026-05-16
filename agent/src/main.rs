//! Agent: runs on the router. Captures raw ethernet frames via AF_PACKET,
//! parses headers, and sends raw payloads to the Rust ingest server over TCP.
//! Linux-only — uses AF_PACKET raw sockets (not available on macOS/Windows).

#[cfg(target_os = "linux")]
mod capture;
#[cfg(target_os = "linux")]
mod parse;
#[cfg(target_os = "linux")]
mod send;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Error: agent binary is Linux-only (requires AF_PACKET raw sockets)");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = linux_main() {
        eprintln!("Agent fatal error: {:#}", e);
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn linux_main() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use clap::Parser;
    use tracing::info;
    use tracing_subscriber::EnvFilter;

    #[derive(Parser)]
    #[command(name = "agent", about = "Raw packet capture agent for OpenWrt")]
    struct Args {
        #[arg(short = 'n', long, default_value = "br-lan")]
        interface: String,
        #[arg(short = 's', long, default_value = "192.168.66.186:9100")]
        ingest_addr: String,
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_target(false)
        .init();

    let args = Args::parse();
    info!(
        "Agent starting — iface={}, ingest={}",
        args.interface, args.ingest_addr
    );

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("ctrlc handler");

    // Bounded channel between capture thread and send loop (防止 OOM)
    let (tx, rx) = std::sync::mpsc::sync_channel::<traffic_core::PacketFrame>(100_000);

    // Start capture thread (AF_PACKET is blocking, dedicated thread required)
    capture::spawn_capture_loop(&args.interface, tx, running.clone())?;

    // Send loop (runs on Tokio runtime)
    send::run_send_loop(args.ingest_addr, rx, running);

    Ok(())
}
