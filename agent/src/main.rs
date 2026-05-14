//! Agent: runs on the router. Captures raw ethernet frames via AF_PACKET,
//! parses headers, and sends raw payloads to the Rust ingest server over TCP.
//! Linux-only — uses AF_PACKET raw sockets (not available on macOS/Windows).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Error: agent binary is Linux-only (requires AF_PACKET raw sockets)");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    linux_main();
}

#[cfg(target_os = "linux")]
fn linux_main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anyhow::Result;
    use clap::Parser;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::time::sleep;
    use tracing::{error as log_error, info, warn};
    use traffic_core::PacketFrame;
    macro_rules! error { ($($arg:tt)*) => { log_error!($($arg)*) } }
    use tracing_subscriber::EnvFilter;

    const SNAPLEN: usize = 2048;
    const SEND_BUF_SIZE: usize = 512;
    const RECONNECT_DELAY: Duration = Duration::from_secs(5);

    #[derive(Parser)]
    #[command(name = "agent", about = "Raw packet capture agent for OpenWrt")]
    struct Args {
        #[arg(short = 'n', long, default_value = "br-lan")]
        interface: String,
        #[arg(short = 's', long, default_value = "192.168.66.186:9100")]
        ingest_addr: String,
    }

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    fn ip4_bytes(b: &[u8]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    }
    fn ip6_bytes(b: &[u8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap_or([0; 16])))
    }
    fn ip_to_vec(ip: IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        }
    }

    #[repr(C)]
    struct sockaddr_ll {
        sll_family: u16,
        sll_protocol: u16,
        sll_ifindex: i32,
        sll_hatype: u16,
        sll_pkttype: u8,
        sll_halen: u8,
        sll_addr: [u8; 8],
    }

    /// Parse AF_PACKET capture into a PacketFrame.
    fn parse_frame(buf: &[u8]) -> Option<PacketFrame> {
        if buf.len() < 14 {
            return None;
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&buf[6..12]);
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);

        match ethertype {
            0x0800 => {
                if buf.len() < 34 {
                    return None;
                }
                let ihl = ((buf[14] & 0x0F) * 4) as usize;
                if buf.len() < 14 + ihl + 4 {
                    return None;
                }
                let proto = buf[23];
                let src_ip = ip4_bytes(&buf[26..30]);
                let dst_ip = ip4_bytes(&buf[30..34]);
                let (sport, dport, pay_start) = if proto == 6 || proto == 17 {
                    (
                        u16::from_be_bytes([buf[14 + ihl], buf[14 + ihl + 1]]),
                        u16::from_be_bytes([buf[14 + ihl + 2], buf[14 + ihl + 3]]),
                        14 + ihl,
                    )
                } else {
                    return None;
                };
                let pay_len = (u16::from_be_bytes([buf[16], buf[17]]) as usize)
                    .saturating_sub(ihl)
                    .min(256);
                let payload = if pay_start + pay_len > buf.len() {
                    &[]
                } else {
                    &buf[pay_start..pay_start + pay_len]
                };
                Some(PacketFrame {
                    timestamp_ns: now_ns(),
                    src_ip: ip_to_vec(src_ip),
                    dst_ip: ip_to_vec(dst_ip),
                    src_port: sport,
                    dst_port: dport,
                    protocol: proto,
                    payload: payload.to_vec(),
                    src_mac: mac,
                    snaplen: SNAPLEN as u16,
                })
            }
            0x86DD => {
                if buf.len() < 54 {
                    return None;
                }
                let proto = buf[20];
                if proto != 6 && proto != 17 {
                    return None;
                }
                let src_ip = ip6_bytes(&buf[22..38]);
                let dst_ip = ip6_bytes(&buf[38..54]);
                let sport = u16::from_be_bytes([buf[54], buf[55]]);
                let dport = u16::from_be_bytes([buf[56], buf[57]]);
                let pay_len = (u16::from_be_bytes([buf[4], buf[5]]) as usize)
                    .saturating_sub(40)
                    .min(256);
                let payload = if 54 + pay_len > buf.len() {
                    &[]
                } else {
                    &buf[54..54 + pay_len]
                };
                Some(PacketFrame {
                    timestamp_ns: now_ns(),
                    src_ip: ip_to_vec(src_ip),
                    dst_ip: ip_to_vec(dst_ip),
                    src_port: sport,
                    dst_port: dport,
                    protocol: proto,
                    payload: payload.to_vec(),
                    src_mac: mac,
                    snaplen: SNAPLEN as u16,
                })
            }
            _ => None,
        }
    }

    /// Get interface index from name (SIOCGIFINDEX).
    fn if_nametoindex(name: &str) -> Result<i32> {
        use std::ffi::CString;
        let cname = CString::new(name)?;
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            anyhow::bail!("interface {} not found", name);
        }
        Ok(idx as i32)
    }

    // ─── Main logic ───
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_target(false)
        .init();

    let args = Args::parse();
    info!(
        "Agent starting — iface={}, ingest={}",
        args.interface, args.ingest_addr
    );

    // ─── Raw socket (AF_PACKET) ───
    let sock = unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (0x0003u16).to_be() as i32);
        if fd < 0 {
            anyhow::bail!(
                "socket(AF_PACKET) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        fd
    };
    let ifindex = if_nametoindex(&args.interface)?;
    let sll = sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (0x0003u16).to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0u8; 8],
    };
    let bind_ret = unsafe {
        libc::bind(
            sock,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_ll>() as u32,
        )
    };
    if bind_ret < 0 {
        anyhow::bail!("bind failed: {}", std::io::Error::last_os_error());
    }
    info!("Bound to {}", args.interface);

    // ─── Async runtime ───
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("ctrlc handler");

    let (tx, mut rx) = std::sync::mpsc::channel::<PacketFrame>();

    // Capture thread (AF_PACKET is blocking, must be in dedicated thread)
    let run_cap = running.clone();
    let iface_name = args.interface.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; SNAPLEN + 128];
        let mut pkt_count = 0u64;
        let mut last_report_ns = now_ns();
        // Set socket timeout so we can check running flag
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }
        info!("Capture loop started on {}", iface_name);
        while run_cap.load(Ordering::SeqCst) {
            let n = unsafe {
                libc::recvfrom(
                    sock,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.raw_os_error() == Some(libc::EINTR)
                {
                    continue;
                }
                warn!("recvfrom error: {}", err);
                continue;
            }
            let n = n as usize;
            if n < 14 {
                continue;
            }
            pkt_count += 1;
            if let Some(frame) = parse_frame(&buf[..n]) {
                tx.send(frame).ok();
            }
            let now = now_ns();
            if now - last_report_ns >= 10_000_000_000 {
                info!("Captured {} pkts", pkt_count);
                pkt_count = 0;
                last_report_ns = now;
            }
        }
        unsafe {
            libc::close(sock);
        }
        info!("Capture loop ended");
    });

    // ─── Send loop ───
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut batch: Vec<PacketFrame> = Vec::with_capacity(SEND_BUF_SIZE);
        let mut stream: Option<TcpStream> = None;

        while running.load(Ordering::SeqCst) {
            if stream.is_none() {
                match TcpStream::connect(&args.ingest_addr).await {
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

    Ok(())
}
