//! Ethernet frame parsing and packet capture helpers.

/// AF_PACKET address structure (Linux ABI).
#[repr(C)]
pub struct sockaddr_ll {
    pub sll_family: u16,
    pub sll_protocol: u16,
    pub sll_ifindex: i32,
    pub sll_hatype: u16,
    pub sll_pkttype: u8,
    pub sll_halen: u8,
    pub sll_addr: [u8; 8],
}

pub const SNAPLEN: usize = 2048;

use anyhow::Result;
use traffic_core::{ip_from_bytes, ip_to_vec, now_ns, PacketFrame};

/// Parse an AF_PACKET-captured ethernet frame into a PacketFrame.
pub fn parse_ethernet_frame(buf: &[u8]) -> Option<PacketFrame> {
    if buf.len() < 14 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&buf[6..12]);
    let ethertype = u16::from_be_bytes([buf[12], buf[13]]);

    match ethertype {
        0x0800 => parse_ipv4(buf, mac),
        0x86DD => parse_ipv6(buf, mac),
        _ => None,
    }
}

/// Build a PacketFrame from IP-parsed fields and raw L4 data.
#[inline]
fn build_frame(
    buf: &[u8],
    hdr_start: usize,
    proto: u8,
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
    mac: [u8; 6],
    pay_len: usize,
) -> Option<PacketFrame> {
    let l4_hdr_len = if proto == 6 {
        ((buf[hdr_start + 12] >> 4) * 4) as usize
    } else {
        8
    };
    let payload_offset = hdr_start + l4_hdr_len;
    let tcp_flags = if proto == 6 { buf[hdr_start + 13] } else { 0 };
    let tcp_seq = if proto == 6 {
        u32::from_be_bytes([
            buf[hdr_start + 4],
            buf[hdr_start + 5],
            buf[hdr_start + 6],
            buf[hdr_start + 7],
        ])
    } else {
        0
    };
    let payload = if payload_offset + pay_len > buf.len() {
        &[]
    } else {
        &buf[payload_offset..payload_offset + pay_len]
    };
    Some(PacketFrame {
        timestamp_ns: now_ns(),
        src_ip: ip_to_vec(src_ip),
        dst_ip: ip_to_vec(dst_ip),
        src_port: u16::from_be_bytes([buf[hdr_start], buf[hdr_start + 1]]),
        dst_port: u16::from_be_bytes([buf[hdr_start + 2], buf[hdr_start + 3]]),
        protocol: proto,
        payload: payload.to_vec(),
        src_mac: mac,
        snaplen: SNAPLEN as u16,
        tcp_flags,
        tcp_seq,
    })
}

fn parse_ipv4(buf: &[u8], mac: [u8; 6]) -> Option<PacketFrame> {
    if buf.len() < 34 {
        return None;
    }
    let ihl = ((buf[14] & 0x0F) * 4) as usize;
    if buf.len() < 14 + ihl + 4 {
        return None;
    }
    let proto = buf[23];
    if proto != 6 && proto != 17 {
        return None;
    }
    let hdr_start = 14 + ihl;
    // IPv4 total length includes IP header — subtract both IP and L4 header
    let l4_hdr_len = if proto == 6 {
        ((buf[hdr_start + 12] >> 4) * 4) as usize
    } else {
        8
    };
    let pay_len = (u16::from_be_bytes([buf[16], buf[17]]) as usize)
        .saturating_sub(ihl + l4_hdr_len)
        .min(SNAPLEN);
    build_frame(
        buf,
        hdr_start,
        proto,
        ip_from_bytes(&buf[26..30]),
        ip_from_bytes(&buf[30..34]),
        mac,
        pay_len,
    )
}

fn parse_ipv6(buf: &[u8], mac: [u8; 6]) -> Option<PacketFrame> {
    if buf.len() < 54 {
        return None;
    }
    let proto = buf[20];
    if proto != 6 && proto != 17 {
        return None;
    }
    // IPv6 payload length field excludes the 40-byte IP header
    let l4_hdr_len = if proto == 6 {
        ((buf[54 + 12] >> 4) * 4) as usize
    } else {
        8
    };
    let pay_len = (u16::from_be_bytes([buf[4], buf[5]]) as usize)
        .saturating_sub(l4_hdr_len)
        .min(SNAPLEN);
    build_frame(
        buf,
        54,
        proto,
        ip_from_bytes(&buf[22..38]),
        ip_from_bytes(&buf[38..54]),
        mac,
        pay_len,
    )
}

/// Get network interface index from name (SIOCGIFINDEX).
pub fn if_nametoindex(name: &str) -> Result<i32> {
    use std::ffi::CString;
    let cname = CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        anyhow::bail!("interface {} not found", name);
    }
    Ok(idx as i32)
}
