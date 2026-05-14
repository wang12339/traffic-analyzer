//! Flow aggregation: per-5-tuple state tracking, packet statistics,
//! TLS/HTTP/DNS metadata correlation, and application classification.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use traffic_core::{Classification, FlowKey, FlowRecord, PacketFrame, classifier};
use tokio::sync::Mutex;
use tracing::{debug, info};
use crate::dns_parser;
use crate::http_parser;
use crate::storage::ClickStore;
use crate::tcp_reasm::TcpReassembler;

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
    dns_domain: Option<String>,
    http_host: Option<String>,
    http_method: Option<String>,
    http_ua: Option<String>,

    // Classification result
    classification: Option<Classification>,

    // Device info (populated from agent)
    src_mac: Option<String>,
    device_hostname: Option<String>,

    // Marker
    finalized: bool,
}

impl FlowState {
    fn new(ts_ns: u64) -> Self {
        Self {
            first_seen_ns: ts_ns,
            last_seen_ns: ts_ns,
            packets_up: 0, packets_down: 0,
            bytes_up: 0, bytes_down: 0,
            pkt_size_hist_up: [0; 7], pkt_size_hist_down: [0; 7],
            iat_sum_us: 0.0, iat_count: 0, last_pkt_time_ns: ts_ns,
            sni: None, ja3: None, ja3s: None, tls_version: None,
            dns_domain: None, http_host: None, http_method: None, http_ua: None,
            classification: None,
            src_mac: None, device_hostname: None,
            finalized: false,
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
            if iat_ns < 10_000_000_000 { // ignore >10s gaps
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
        // Keep timestamps in UTC — timezone conversion is a display-layer concern
        let first = DateTime::from_timestamp_nanos(self.first_seen_ns as i64);
        let last = DateTime::from_timestamp_nanos(self.last_seen_ns as i64);
        let duration_ns = self.last_seen_ns.saturating_sub(self.first_seen_ns);

        // Merge up/down histograms
        let mut hist = [0u32; 7];
        for i in 0..7 { hist[i] = self.pkt_size_hist_up[i] + self.pkt_size_hist_down[i]; }

        let iat_mean = if self.iat_count > 0 { self.iat_sum_us / self.iat_count as f64 } else { 0.0 };

        FlowRecord {
            timestamp: first,
            first_seen: self.first_seen_ns as i64,
            last_seen: self.last_seen_ns as i64,
            src_ip: key.src_ip.to_string(),
            dst_ip: key.dst_ip.to_string(),
            src_port: key.src_port,
            dst_port: key.dst_port,
            protocol: if key.protocol == 6 { "TCP".into() } else { "UDP".into() },
            sni: self.sni.clone().unwrap_or_default(),
            ja3: self.ja3.clone().unwrap_or_default(),
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
        }
    }
}

/// Flow aggregator: manages all active flows, their state, and expiry.
pub struct FlowAggregator {
    flows: HashMap<FlowKey, FlowState>,
    ip_to_mac: HashMap<IpAddr, (String, String)>, // IP → (MAC, hostname)
    known_ips: HashSet<IpAddr>,
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
            known_ips: HashSet::new(),
            tcp_reasm: TcpReassembler::new(),
            store,
            expire_secs,
            flow_counter: 0,
        }
    }

    /// Process a single packet frame from the agent.
    pub async fn process_packet(&mut self, ts_ns: u64, frame: &PacketFrame) -> Result<(), anyhow::Error> {
        let src_ip = ip_from_bytes(&frame.src_ip);
        let dst_ip = ip_from_bytes(&frame.dst_ip);
        let src_mac = mac_to_string(&frame.src_mac);

        // Track IP→MAC mapping
        if !src_mac.is_empty() {
            self.ip_to_mac.insert(src_ip, (src_mac.clone(), String::new()));
        }

        let is_up = true; // from agent's perspective, src is the client
        let key = FlowKey::canonical(src_ip, dst_ip, frame.src_port, frame.dst_port, frame.protocol);

        let state = self.flows.entry(key.clone()).or_insert_with(|| FlowState::new(ts_ns));
        state.record_packet(ts_ns, frame.payload.len() + 40 + 20 + 14, is_up);

        // Store MAC on first packet
        if state.src_mac.is_none() && !src_mac.is_empty() {
            state.src_mac = Some(src_mac.clone());
        }

        // ─── L7 Analysis ───
        if frame.protocol == 6 { // TCP
            // Determine if this packet is from client side
            let is_client_side = frame.src_port == key.src_port;

            // TCP reassembly for TLS
            if !frame.payload.is_empty() {
                let tls_result = self.tcp_reasm.process_segment(&key, &frame.payload, is_client_side);
                if let Some((ch, sh)) = tls_result {
                    if !ch.sni.is_empty() {
                        state.sni = Some(ch.sni.clone());
                    }
                    if !ch.ja3.is_empty() {
                        state.ja3 = Some(ch.ja3.clone());
                    }
                    if sh.tls_version != 0 {
                        state.tls_version = Some(format!("TLSv1.{}", if sh.tls_version == 0x0304 { 3 } else if sh.tls_version == 0x0303 { 2 } else { 1 }));
                        state.ja3s = Some(sh.ja3s.clone());
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
            }
        } else if frame.protocol == 17 { // UDP
            // DNS parsing
            if (frame.dst_port == 53 || frame.src_port == 53) && !frame.payload.is_empty() {
                let dns = dns_parser::parse_dns_query(&frame.payload);
                if let Some(domain) = dns {
                    state.dns_domain = Some(domain);
                }
            }
        }

        // Classify when we have enough info (after L7 extraction)
        if state.classification.is_none() {
            let sni = state.sni.as_deref().unwrap_or("");
            let dns = state.dns_domain.as_deref().unwrap_or("");
            let app = classifier::classify(sni, dns, key.dst_port);
            if app.confidence > 0.3 {
                state.classification = Some(app);
            }
        }

        Ok(())
    }

    /// Flush all expired flows to ClickHouse.
    pub async fn flush_expired(&mut self, now_ns: u64) -> Result<(), anyhow::Error> {
        let idle_cutoff = now_ns - self.expire_secs * 1_000_000_000;
        let max_lifetime = 60_000_000_000u64; // 60 seconds max lifetime for any flow
        let expired_keys: Vec<FlowKey> = self.flows.iter()
            .filter(|(_, s)| {
                // Expire if idle too long OR lived too long (force flush active flows)
                !s.finalized && (s.last_seen_ns < idle_cutoff ||
                    now_ns.saturating_sub(s.first_seen_ns) > max_lifetime)
            })
            .map(|(k, _)| k.clone())
            .collect();

        if expired_keys.is_empty() {
            if self.flows.len() > 0 {
                tracing::info!("FlushCheck: {} active flows, 0 expired", self.flows.len());
            }
            return Ok(());
        }
        tracing::info!("Flushing {} expired flows (active: {})", expired_keys.len(), self.flows.len());

        let mut records = Vec::with_capacity(expired_keys.len());
        for key in &expired_keys {
            if let Some(mut state) = self.flows.remove(key) {
                state.finalized = true;
                let app = state.classification.clone().unwrap_or_else(|| Classification::unknown());
                records.push(state.to_flow_record(key, &app));
                self.tcp_reasm.remove(key);
            }
        }

        if !records.is_empty() {
            self.flow_counter += records.len() as u64;
            debug!("Flushing {} flow records (total: {})", records.len(), self.flow_counter);

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
                let app = state.classification.clone().unwrap_or_else(|| Classification::unknown());
                records.push(state.to_flow_record(key, &app));
            }
        }
        if !records.is_empty() {
            self.store.write_flows(&records).await?;
            info!("Flushed {} remaining flows", records.len());
        }
        Ok(())
    }

    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
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
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
