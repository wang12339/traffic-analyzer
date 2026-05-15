//! Flow aggregation: per-5-tuple state tracking, packet statistics,
//! TLS/HTTP/DNS metadata correlation, and application classification.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::dns_parser;
use crate::http_parser;
use crate::mysql_parser;
use crate::redis_parser;
use crate::storage::ClickStore;
use crate::tcp_reasm::TcpReassembler;
use chrono::DateTime;
use tracing::{debug, info};
use traffic_core::{
    Classification, FlowKey, FlowRecord, PacketFrame, classifier,
};

/// Per-flow state maintained during aggregation.
#[derive(Debug)]
struct FlowState {
    first_seen_ns: u64,
    last_seen_ns: u64,
    packets_up: u32,
    packets_down: u32,
    bytes_up: i64,
    bytes_down: i64,
    // Packet size distribution (7 buckets)
    pkt_size_hist_up: [u32; 7],
    pkt_size_hist_down: [u32; 7],
    // Inter-arrival time accumulator for mean calculation
    iat_sum_us: f64,
    iat_count: u32,
    last_pkt_time_ns: u64,

    // L7 metadata
    sni: Option<String>,
    ja3: Option<String>,
    ja3s: Option<String>,
    tls_version: Option<String>,
    tls_signature_hash: Option<String>, // compact TLS fingerprint
    server_cipher_suite: Option<u16>,   // cipher suite selected by server
    dns_domain: Option<String>,
    http_host: Option<String>,
    http_method: Option<String>,
    http_ua: Option<String>,

    // Classification result
    classification: Option<Classification>,

    // Multi-engine verdicts (JSON array, from classify_multi)
    engines: Option<String>,

    // Device info (populated from agent)
    src_mac: Option<String>,
    device_hostname: Option<String>,

    // Marker
    finalized: bool,

    /// canonical key 是否交换了原始 src/dst 顺序
    swapped: bool,
}

impl FlowState {
    fn new(ts_ns: u64) -> Self {
        Self {
            first_seen_ns: ts_ns,
            last_seen_ns: ts_ns,
            packets_up: 0,
            packets_down: 0,
            bytes_up: 0,
            bytes_down: 0,
            pkt_size_hist_up: [0; 7],
            pkt_size_hist_down: [0; 7],
            iat_sum_us: 0.0,
            iat_count: 0,
            last_pkt_time_ns: ts_ns,
            sni: None,
            ja3: None,
            ja3s: None,
            tls_version: None,
            tls_signature_hash: None,
            server_cipher_suite: None,
            dns_domain: None,
            http_host: None,
            http_method: None,
            http_ua: None,
            classification: None,
            engines: None,
            src_mac: None,
            device_hostname: None,
            finalized: false,
            swapped: false,
        }
    }

    fn record_packet(&mut self, ts_ns: u64, size: usize, direction_up: bool) {
        if direction_up {
            self.packets_up += 1;
            self.bytes_up += size as i64;
            let bucket = Self::size_bucket(size);
            self.pkt_size_hist_up[bucket] += 1;
        } else {
            self.packets_down += 1;
            self.bytes_down += size as i64;
            let bucket = Self::size_bucket(size);
            self.pkt_size_hist_down[bucket] += 1;
        }

        if self.last_pkt_time_ns != 0 && ts_ns > self.last_pkt_time_ns {
            let iat_ns = ts_ns - self.last_pkt_time_ns;
            if iat_ns < 10_000_000_000 {
                // ignore >10s gaps
                self.iat_sum_us += iat_ns as f64 / 1000.0;
                self.iat_count += 1;
            }
        }
        self.last_pkt_time_ns = ts_ns;
        self.last_seen_ns = ts_ns;
    }

    fn size_bucket(size: usize) -> usize {
        match size {
            0..=64 => 0,
            65..=128 => 1,
            129..=256 => 2,
            257..=512 => 3,
            513..=1024 => 4,
            1025..=1500 => 5,
            _ => 6,
        }
    }

    fn to_flow_record(&self, key: &FlowKey, app: &Classification) -> FlowRecord {
        let first = DateTime::from_timestamp_nanos(self.first_seen_ns as i64);
        let duration_ns = self.last_seen_ns.saturating_sub(self.first_seen_ns);

        // Merge up/down histograms
        let mut hist = [0u32; 7];
        for i in 0..7 {
            hist[i] = self.pkt_size_hist_up[i] + self.pkt_size_hist_down[i];
        }

        let iat_mean = if self.iat_count > 0 {
            self.iat_sum_us / self.iat_count as f64
        } else {
            0.0
        };

        let (record_src_ip, record_dst_ip, record_src_port, record_dst_port) = if self.swapped {
            (key.dst_ip, key.src_ip, key.dst_port, key.src_port)
        } else {
            (key.src_ip, key.dst_ip, key.src_port, key.dst_port)
        };

        FlowRecord {
            timestamp: first,
            first_seen: self.first_seen_ns as i64,
            last_seen: self.last_seen_ns as i64,
            src_ip: record_src_ip.to_string(),
            dst_ip: record_dst_ip.to_string(),
            src_port: record_src_port,
            dst_port: record_dst_port,
            protocol: if key.protocol == 6 {
                "TCP".into()
            } else {
                "UDP".into()
            },
            sni: self.sni.clone().unwrap_or_default(),
            ja3: self.ja3.clone().unwrap_or_default(),
            ja3s: self.ja3s.clone().unwrap_or_default(),
            tls_version: self.tls_version.clone().unwrap_or_default(),
            server_cipher_suite: self.server_cipher_suite.unwrap_or(0),
            tls_signature_hash: self.tls_signature_hash.clone().unwrap_or_default(),
            dns_domain: self.dns_domain.clone().unwrap_or_default(),
            http_host: self.http_host.clone().unwrap_or_default(),
            http_method: self.http_method.clone().unwrap_or_default(),
            http_ua: self.http_ua.clone().unwrap_or_default(),
            packets_up: self.packets_up,
            packets_down: self.packets_down,
            bytes_up: self.bytes_up,
            bytes_down: self.bytes_down,
            duration_ms: (duration_ns / 1_000_000) as i64,
            pkt_size_hist: hist,
            pkt_iat_mean_us: iat_mean,
            app_id: app.app_id,
            app_name: app.app_name.clone(),
            app_category: app.app_category.clone(),
            confidence: app.confidence,
            src_mac: self.src_mac.clone().unwrap_or_default(),
            device_manufacturer: String::new(),
            device_hostname: self.device_hostname.clone().unwrap_or_default(),
            engines: self.engines.clone().unwrap_or_default(),
        }
    }
}

/// Flow aggregator: manages all active flows, their state, and expiry.
pub struct FlowAggregator {
    flows: HashMap<FlowKey, FlowState>,
    ip_to_mac: HashMap<IpAddr, (String, String, u64)>, // IP → (MAC, hostname, last_seen_ns)
    tcp_reasm: TcpReassembler,
    store: Arc<ClickStore>,
    expire_secs: u64,
    flow_counter: u64,
}

impl FlowAggregator {
    pub fn new(expire_secs: u64, store: Arc<ClickStore>) -> Self {
        Self {
            flows: HashMap::new(),
            ip_to_mac: HashMap::new(),
            tcp_reasm: TcpReassembler::new(),
            store,
            expire_secs,
            flow_counter: 0,
        }
    }

    /// Process a single packet frame from the agent.
    pub async fn process_packet(&mut self, ts_ns: u64, frame: &PacketFrame) {
        let src_ip = ip_from_bytes(&frame.src_ip);
        let dst_ip = ip_from_bytes(&frame.dst_ip);
        let src_mac = mac_to_string(&frame.src_mac);

        // Track IP→MAC mapping (with timestamp for TTL eviction)
        if !src_mac.is_empty() {
            self.ip_to_mac
                .insert(src_ip, (src_mac.clone(), String::new(), ts_ns));
        }

        let key = FlowKey::canonical(
            src_ip,
            dst_ip,
            frame.src_port,
            frame.dst_port,
            frame.protocol,
        );
        let is_up = ip_from_bytes(&frame.src_ip) == key.src_ip;
        let is_swapped = !is_up;

        let state = self
            .flows
            .entry(key.clone())
            .or_insert_with(|| {
                let mut s = FlowState::new(ts_ns);
                s.swapped = is_swapped;
                s
            });
        state.record_packet(ts_ns, frame.payload.len() + 40 + 20 + 14, is_up);

        // Store MAC on first packet
        if state.src_mac.is_none() && !src_mac.is_empty() {
            state.src_mac = Some(src_mac.clone());
        }

        // ─── L7 Analysis ───
        if frame.protocol == 6 {
            // TCP
            // Determine if this packet is from client side（使用 is_up 避免 canonical key 交换影响）
            let is_client_side = is_up;

            // TCP reassembly for TLS
            if !frame.payload.is_empty() {
                let tls_result =
                    self.tcp_reasm
                        .process_segment(&key, &frame.payload, is_client_side);
                if let Some((ch, sh)) = tls_result {
                    if !ch.sni.is_empty() {
                        state.sni = Some(ch.sni.clone());
                    }
                    if !ch.ja3.is_empty() {
                        state.ja3 = Some(ch.ja3.clone());
                    }
                    if !ch.tls_signature.is_empty() {
                        state.tls_signature_hash = Some(ch.tls_signature.clone());
                    }
                    if sh.tls_version != 0 {
                        state.tls_version = Some(format!(
                            "TLSv1.{}",
                            if sh.tls_version == 0x0304 {
                                3
                            } else if sh.tls_version == 0x0303 {
                                2
                            } else {
                                1
                            }
                        ));
                        state.ja3s = Some(sh.ja3s.clone());
                        state.server_cipher_suite = Some(sh.cipher_suite);
                    }
                }

                // HTTP parsing (cleartext ports)
                if frame.dst_port == 80 || frame.dst_port == 8080 || frame.dst_port == 8000 {
                    // HTTP request from client
                    if is_client_side {
                        if let Some(http) = http_parser::parse_http_request(&frame.payload) {
                            state.http_host = Some(http.host);
                            state.http_method = Some(http.method);
                            state.http_ua = Some(http.user_agent);
                        }
                    }
                }

                // CONNECT parsing (HTTP proxy)
                if frame.dst_port == 80 || frame.dst_port == 8080 {
                    if is_client_side {
                        if let Some(host) = http_parser::parse_connect_request(&frame.payload) {
                            state.sni = Some(host);
                        }
                    }
                }

                // MySQL protocol parsing (port 3306)
                if frame.dst_port == 3306 && !frame.payload.is_empty() {
                    if let Some(hs) = mysql_parser::parse_handshake(&frame.payload) {
                        let meta = format!("mysql:{}/{}", hs.server_version, hs.auth_plugin);
                        state.http_host = Some(meta);
                    }
                    if is_client_side {
                        if let Some(cmd) = mysql_parser::parse_command(&frame.payload) {
                            if cmd.dangerous {
                                tracing::warn!(
                                    "Dangerous MySQL command detected: {} -> {}",
                                    key.src_ip,
                                    cmd.query_summary
                                );
                            }
                        }
                    }
                }

                // Redis protocol parsing (port 6379)
                if (frame.dst_port == 6379 || frame.src_port == 6379) && !frame.payload.is_empty() {
                    if let Some(r) = redis_parser::parse_command(&frame.payload) {
                        let mut meta = format!("redis:{}", r.command);
                        if let Some(db) = r.db_index {
                            meta.push_str(&format!(" db={}", db));
                        }
                        if r.dangerous {
                            meta.push_str(" ⚠️");
                            tracing::warn!(
                                "Dangerous Redis command: {} from {}",
                                r.command,
                                key.src_ip
                            );
                        }
                        state.http_ua = Some(meta);
                    }
                }
            }
        } else if frame.protocol == 17 {
            // UDP
            if (frame.dst_port == 53 || frame.src_port == 53) && !frame.payload.is_empty() {
                let dns = dns_parser::parse_dns_query(&frame.payload);
                if let Some(domain) = dns {
                    state.dns_domain = Some(domain);
                }
            }
            // QUIC SNI extraction (UDP/443)
            if (frame.src_port == 443 || frame.dst_port == 443) && !frame.payload.is_empty() {
                tracing::debug!("QUIC: UDP/443 packet, payload_len={}", frame.payload.len());
                let quic = crate::quic_parser::parse_quic_initial(&frame.payload);
                if let Some(q) = quic {
                    tracing::debug!("QUIC parsed: sni={}", q.sni);
                    if !q.sni.is_empty() {
                        state.sni = Some(q.sni.clone());
                    }
                }
            }
        }

        // Classify/re-classify: multi-engine with all available data
        let has_better_data = state.sni.is_some() || state.dns_domain.is_some();
        let is_port_only = state
            .classification
            .as_ref()
            .map(|c| c.confidence <= 0.6)
            .unwrap_or(true);
        if state.classification.is_none() || (has_better_data && is_port_only) {
            let sni = state.sni.as_deref().unwrap_or("");
            let dns = state.dns_domain.as_deref().unwrap_or("");
            let ja3 = state.ja3.as_deref().unwrap_or("");
            let features = classifier::FlowFeatures {
                bytes_up: state.bytes_up as f64,
                bytes_down: state.bytes_down as f64,
                packets_up: state.packets_up,
                packets_down: state.packets_down,
                duration_ms: ((state.last_seen_ns.saturating_sub(state.first_seen_ns)) / 1_000_000)
                    as i64,
                pkt_iat_mean_us: if state.iat_count > 0 {
                    state.iat_sum_us / state.iat_count as f64
                } else {
                    0.0
                },
            };

            let multi = classifier::classify_multi(sni, dns, ja3, key.dst_port, Some(&features));
            if multi.primary.confidence > 0.3 {
                state.classification = Some(multi.primary);
            }
            // 序列化引擎判定结果
            if !multi.engines.is_empty() {
                state.engines = Some(serde_json::to_string(&multi.engines).unwrap_or_default());
            }
        }
    }

    /// Flush all expired flows to ClickHouse.
    pub async fn flush_expired(&mut self, now_ns: u64) -> Result<(), anyhow::Error> {
        let idle_cutoff = now_ns - self.expire_secs * 1_000_000_000;
        let max_lifetime = 60_000_000_000u64; // 60 seconds max lifetime for any flow
        let expired_keys: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, s)| {
                // Expire if idle too long OR lived too long (force flush active flows)
                !s.finalized
                    && (s.last_seen_ns < idle_cutoff
                        || now_ns.saturating_sub(s.first_seen_ns) > max_lifetime)
            })
            .map(|(k, _)| k.clone())
            .collect();

        // Periodically evict stale IP→MAC mappings (TTL: 1 hour)
        let mac_ttl = now_ns - 3_600_000_000_000u64; // 1 hour
        self.ip_to_mac.retain(|_, v| v.2 > mac_ttl);

        if expired_keys.is_empty() {
            if self.flows.len() > 0 {
                tracing::info!("FlushCheck: {} active flows, 0 expired", self.flows.len());
            }
            return Ok(());
        }
        tracing::info!(
            "Flushing {} expired flows (active: {})",
            expired_keys.len(),
            self.flows.len()
        );

        let mut records = Vec::with_capacity(expired_keys.len());
        for key in &expired_keys {
            if let Some(mut state) = self.flows.remove(key) {
                state.finalized = true;
                let app = state
                    .classification
                    .clone()
                    .unwrap_or_else(|| Classification::unknown());
                records.push(state.to_flow_record(key, &app));
                self.tcp_reasm.remove(key);
            }
        }

        if !records.is_empty() {
            self.flow_counter += records.len() as u64;
            debug!(
                "Flushing {} flow records (total: {})",
                records.len(),
                self.flow_counter
            );

            // Batch write to ClickHouse
            let store = self.store.clone();
            tokio::spawn(async move {
                if let Err(e) = store.write_flows(&records).await {
                    tracing::warn!("ClickHouse write failed: {:#}", e);
                }
            });
        }

        Ok(())
    }

    /// Flush all remaining flows (on shutdown).
    pub async fn flush_all(&mut self) -> Result<(), anyhow::Error> {
        let keys: Vec<FlowKey> = self.flows.keys().cloned().collect();
        let mut records = Vec::with_capacity(keys.len());
        for key in &keys {
            if let Some(state) = self.flows.remove(key) {
                let app = state
                    .classification
                    .clone()
                    .unwrap_or_else(|| Classification::unknown());
                records.push(state.to_flow_record(key, &app));
            }
        }
        if !records.is_empty() {
            self.store.write_flows(&records).await?;
            info!("Flushed {} remaining flows", records.len());
        }
        Ok(())
    }

}

fn ip_from_bytes(bytes: &[u8]) -> IpAddr {
    if bytes.len() == 4 {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else if bytes.len() == 16 {
        let mut b = [0u8; 16];
        b.copy_from_slice(bytes);
        IpAddr::V6(Ipv6Addr::from(b))
    } else {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    }
}

fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_core::FlowKey;

    #[test]
    fn test_flow_state_new() {
        let state = FlowState::new(1_000_000);
        assert_eq!(state.first_seen_ns, 1_000_000);
        assert_eq!(state.packets_up, 0);
        assert_eq!(state.packets_down, 0);
        assert!(!state.finalized);
    }

    #[test]
    fn test_flow_state_record_packet_up() {
        let mut state = FlowState::new(1_000_000);
        state.record_packet(1_000_001, 100, true);
        assert_eq!(state.packets_up, 1);
        assert_eq!(state.bytes_up, 100);
        assert_eq!(state.packets_down, 0);
    }

    #[test]
    fn test_flow_state_record_packet_down() {
        let mut state = FlowState::new(1_000_000);
        state.record_packet(1_000_001, 200, false);
        assert_eq!(state.packets_down, 1);
        assert_eq!(state.bytes_down, 200);
    }

    #[test]
    fn test_size_bucket_boundaries() {
        // bucket 0: 0..=64
        assert_eq!(FlowState::size_bucket(0), 0);
        assert_eq!(FlowState::size_bucket(64), 0);
        // bucket 1: 65..=128
        assert_eq!(FlowState::size_bucket(65), 1);
        assert_eq!(FlowState::size_bucket(128), 1);
        // bucket 2: 129..=256
        assert_eq!(FlowState::size_bucket(129), 2);
        assert_eq!(FlowState::size_bucket(256), 2);
        // bucket 3: 257..=512
        assert_eq!(FlowState::size_bucket(257), 3);
        assert_eq!(FlowState::size_bucket(512), 3);
        // bucket 4: 513..=1024
        assert_eq!(FlowState::size_bucket(513), 4);
        assert_eq!(FlowState::size_bucket(1024), 4);
        // bucket 5: 1025..=1500
        assert_eq!(FlowState::size_bucket(1025), 5);
        assert_eq!(FlowState::size_bucket(1500), 5);
        // bucket 6: 1501+
        assert_eq!(FlowState::size_bucket(1501), 6);
        assert_eq!(FlowState::size_bucket(9000), 6);
    }

    #[test]
    fn test_iat_calculation() {
        let mut state = FlowState::new(1_000_000_000);
        // Record two packets 1ms apart
        state.record_packet(1_000_000_000, 100, true);
        state.record_packet(1_001_000_000, 100, true); // 1ms = 1000us
        assert_eq!(state.iat_count, 1);
        assert!((state.iat_sum_us - 1000.0).abs() < 0.001);
    }

    #[test]
    fn test_iat_ignores_large_gaps() {
        let mut state = FlowState::new(1_000_000_000);
        state.record_packet(1_000_000_000, 100, true);
        state.record_packet(50_000_000_000, 100, true); // 49s gap, > 10s
        assert_eq!(state.iat_count, 0, "gaps > 10s should be ignored");
    }

    #[test]
    fn test_histogram_merge_in_to_flow_record() {
        let mut state = FlowState::new(1_000_000);
        state.record_packet(1_000_001, 50, true); // bucket 0 up
        state.record_packet(1_000_002, 200, false); // bucket 2 down
        state.record_packet(1_000_003, 1000, false); // bucket 4 down

        let key = FlowKey::canonical(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            54321,
            443,
            6,
        );
        let app = Classification::unknown();
        let record = state.to_flow_record(&key, &app);

        assert_eq!(record.pkt_size_hist[0], 1); // one 50-byte packet
        assert_eq!(record.pkt_size_hist[2], 1); // one 200-byte packet
        assert_eq!(record.pkt_size_hist[4], 1); // one 1000-byte packet
        assert_eq!(record.packets_up, 1);
        assert_eq!(record.packets_down, 2);
    }

    #[test]
    fn test_to_flow_record_populates_fields() {
        let mut state = FlowState::new(1_000_000);
        state.record_packet(1_000_001, 100, true);
        state.sni = Some("example.com".into());
        state.dns_domain = Some("example.com".into());
        state.http_host = Some("example.com".into());
        state.src_mac = Some("aa:bb:cc:dd:ee:ff".into());

        state.swapped = true; // canonical 交换了 src(10.x) 和 dst(8.x)
        let key = FlowKey::canonical(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            12345,
            443,
            6,
        );
        let app = Classification::named(1, "YouTube", "Video", 0.85);
        let record = state.to_flow_record(&key, &app);

        // to_flow_record 使用 swapped 标记恢复原始方向
        assert_eq!(record.src_ip, "10.0.0.5");
        assert_eq!(record.dst_ip, "8.8.8.8");
        assert_eq!(record.sni, "example.com");
        assert_eq!(record.app_name, "YouTube");
        assert_eq!(record.app_category, "Video");
        assert_eq!(record.confidence, 0.85);
        assert_eq!(record.src_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(record.duration_ms, 0);
    }

    #[test]
    fn test_flow_key_canonical() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let k1 = FlowKey::canonical(a, b, 1000, 443, 6);
        let k2 = FlowKey::canonical(b, a, 443, 1000, 6);

        // After canonicalization, both should normalize to the same key
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_flow_key_different_protocols() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let tcp = FlowKey::canonical(a, b, 1000, 443, 6);
        let udp = FlowKey::canonical(a, b, 1000, 443, 17);

        assert_ne!(tcp, udp);
    }

    #[test]
    fn test_ip_from_bytes() {
        let v4 = ip_from_bytes(&[192, 168, 1, 1]);
        assert_eq!(v4.to_string(), "192.168.1.1");

        let v6 = ip_from_bytes(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        assert_eq!(v6.to_string(), "2001:db8::1");

        // Invalid length -> 0.0.0.0
        let fallback = ip_from_bytes(&[1, 2, 3]);
        assert_eq!(fallback.to_string(), "0.0.0.0");
    }

    #[test]
    fn test_mac_to_string() {
        assert_eq!(
            mac_to_string(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            mac_to_string(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            "00:11:22:33:44:55"
        );
    }
}
