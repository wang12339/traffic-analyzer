//! AF_PACKET capture loop: reads raw ethernet frames from a network interface.

use crate::parse::{if_nametoindex, parse_ethernet_frame, sockaddr_ll, SNAPLEN};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use tracing::{info, warn};
use traffic_core::PacketFrame;

/// Spawns a capture thread that reads raw frames from `iface` via AF_PACKET
/// and sends them through `tx`. Returns when the thread is spawned or on error.
pub fn spawn_capture_loop(
    iface: &str,
    tx: SyncSender<PacketFrame>,
    running: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    // Raw socket (AF_PACKET)
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

    let ifindex = if_nametoindex(iface)?;
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
    info!("Bound to {}", iface);

    // Set socket timeout so we can check the running flag
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

    let iface_name = iface.to_string();
    let run = running.clone();

    std::thread::spawn(move || {
        info!("Capture loop started on {}", iface_name);
        let mut buf = vec![0u8; SNAPLEN + 128];
        let mut pkt_count = 0u64;
        let mut last_report_ns = traffic_core::now_ns();

        while run.load(Ordering::SeqCst) {
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
            if let Some(frame) = parse_ethernet_frame(&buf[..n]) {
                if tx.try_send(frame).is_err() {
                    // Channel full — 背压传导到内核 socket buffer，内核自动丢包
                }
            }
            let now = traffic_core::now_ns();
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

    Ok(())
}
