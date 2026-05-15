use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod classifier;
pub use classifier::{Classification, EngineVerdict, FlowFeatures, MultiClassification};

pub type Port = u16;
pub type Protocol = u8;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

// TCP flags (byte 13 of TCP header)
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;

/// Wire format: agent → ingest. Length-delimited binary frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketFrame {
    pub timestamp_ns: u64,
    pub src_ip: Vec<u8>, // 4 (IPv4) or 16 (IPv6) bytes
    pub dst_ip: Vec<u8>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub payload: Vec<u8>,
    pub src_mac: [u8; 6],
    pub snaplen: u16,
    /// TCP flags byte (FIN=0x01, SYN=0x02, RST=0x04). 0 for non-TCP.
    pub tcp_flags: u8,
}

// ─── Shared utility functions ───

/// Convert 4-byte (IPv4) or 16-byte (IPv6) slice to `IpAddr`.
/// Returns `0.0.0.0` for invalid lengths and logs a warning.
pub fn ip_from_bytes(bytes: &[u8]) -> IpAddr {
    if bytes.len() == 4 {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else if bytes.len() == 16 {
        let mut b = [0u8; 16];
        b.copy_from_slice(bytes);
        IpAddr::V6(Ipv6Addr::from(b))
    } else {
        tracing::warn!("ip_from_bytes: unexpected byte length {}", bytes.len());
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    }
}

/// Convert `IpAddr` to a Vec of bytes (4 for IPv4, 16 for IPv6).
pub fn ip_to_vec(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

/// Format a 6-byte MAC address as `xx:xx:xx:xx:xx:xx` (lowercase hex).
pub fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// ─── Flow Key ───

/// Direction-aware 5-tuple flow key for TCP reassembly.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Port,
    pub dst_port: Port,
    pub protocol: u8,
}

impl FlowKey {
    pub fn canonical(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Port,
        dst_port: Port,
        protocol: u8,
    ) -> Self {
        let (a, pa, b, pb) = match (src_ip, src_port) < (dst_ip, dst_port) {
            true => (src_ip, src_port, dst_ip, dst_port),
            false => (dst_ip, dst_port, src_ip, src_port),
        };
        Self {
            src_ip: a,
            dst_ip: b,
            src_port: pa,
            dst_port: pb,
            protocol,
        }
    }
}

/// Completed TLS handshake metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsMeta {
    pub sni: String,
    pub ja3: String,
    pub ja3s: String,
    pub tls_version: String,
    pub cipher_suite: u16,
}

/// HTTP request metadata (extracted from cleartext traffic).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpMeta {
    pub host: String,
    pub method: String,
    pub uri_truncated: String, // first 128 chars only, not stored long-term
    pub user_agent: String,
}

/// Enriched flow record sent to ClickHouse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub timestamp: DateTime<Utc>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,

    // L7 metadata
    pub sni: String,
    pub ja3: String,
    pub ja3s: String,
    pub tls_version: String,
    pub server_cipher_suite: u16,
    pub tls_signature_hash: String,
    pub dns_domain: String,
    pub http_host: String,
    pub http_method: String,
    pub http_ua: String,

    // Flow statistics
    pub packets_up: u32,
    pub packets_down: u32,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub duration_ms: i64,

    // Packet size histogram (buckets: 0-64, 64-128, 128-256, 256-512, 512-1024, 1024-1500, 1500+)
    pub pkt_size_hist: [u32; 7],
    pub pkt_iat_mean_us: f64,

    // Application classification
    pub app_id: u32,
    pub app_name: String,
    pub app_category: String,
    pub confidence: f32,

    // Device enrichment
    pub src_mac: String,
    pub device_manufacturer: String,
    pub device_hostname: String,

    // Multi-engine classification verdicts (JSON array)
    pub engines: String,
}

/// Device information sent by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub ip: String,
    pub mac: String,
    pub hostname: String,
    pub vendor_class: String,
    pub first_seen_ns: u64,
}
