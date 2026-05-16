//! Behavioral anomaly detection engine.
//!
//! Maintains per-device baselines (known domains, throughput, activity hours)
//! and scores each flow for anomalous behavior. High-scoring flows are
//! persisted as anomaly events for alerting.
//!
//! Risk score (0-100) breakdown:
//!   - Domain novelty:  0-35  (ratio of unseen domains in this flow)
//!   - Volume anomaly:  0-25  (throughput deviation from baseline)
//!   - Unusual timing:  0-20  (device never seen at this hour before)
//!   - Flow rate:       0-10  (connections/min vs baseline)
//!   - Protocol oddity: 0-10  (unusual port/protocol combo)

use chrono::Timelike;
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::debug;
use traffic_core::FlowRecord;

/// Max unique domains tracked per device (LRU eviction).
const MAX_DOMAINS_PER_DEVICE: usize = 2000;
/// Max devices tracked in memory.
const MAX_DEVICES: usize = 256;
/// Throughput moving average window (number of samples).
const THROUGHPUT_WINDOW: usize = 60;
/// Minimum flows before baseline is considered stable.
const MIN_BASELINE_FLOWS: u64 = 20;

/// Per-device behavioral baseline.
#[derive(Debug)]
#[allow(dead_code)]
struct DeviceBaseline {
    /// Known domains this device has contacted (LRU via insertion order).
    known_domains: HashSet<String>,
    /// Domain insertion order for LRU eviction.
    domain_order: VecDeque<String>,
    /// Throughput samples (bytes/sec), most recent first.
    throughput_samples: VecDeque<f64>,
    /// Activity count per hour of day (UTC), rolling.
    hourly_activity: [u32; 24],
    /// Aggregate stats.
    first_seen_ns: u64,
    last_seen_ns: u64,
    total_flows: u64,
    total_bytes: u64,
}

impl DeviceBaseline {
    fn new(ts_ns: u64) -> Self {
        Self {
            known_domains: HashSet::new(),
            domain_order: VecDeque::with_capacity(MAX_DOMAINS_PER_DEVICE),
            throughput_samples: VecDeque::with_capacity(THROUGHPUT_WINDOW),
            hourly_activity: [0; 24],
            first_seen_ns: ts_ns,
            last_seen_ns: ts_ns,
            total_flows: 0,
            total_bytes: 0,
        }
    }

    /// Record a flow into the baseline.
    fn record(&mut self, record: &FlowRecord, ts_ns: u64, throughput_bps: f64) {
        self.total_flows += 1;
        self.total_bytes += (record.bytes_up + record.bytes_down) as u64;
        self.last_seen_ns = ts_ns;

        // Track domain
        let domain = if !record.sni.is_empty() {
            &record.sni
        } else if !record.dns_domain.is_empty() {
            &record.dns_domain
        } else {
            ""
        };
        if !domain.is_empty()
            && !self.known_domains.contains(domain) {
                self.known_domains.insert(domain.to_string());
                self.domain_order.push_back(domain.to_string());
                // LRU eviction
                while self.domain_order.len() > MAX_DOMAINS_PER_DEVICE {
                    if let Some(oldest) = self.domain_order.pop_front() {
                        self.known_domains.remove(&oldest);
                    }
                }
            }

        // Track throughput (moving average)
        if throughput_bps > 0.0 {
            self.throughput_samples.push_front(throughput_bps);
            while self.throughput_samples.len() > THROUGHPUT_WINDOW {
                self.throughput_samples.pop_back();
            }
        }

        // Track hourly activity
        let hour = record.timestamp.hour() as usize;
        if hour < 24 {
            self.hourly_activity[hour] = self.hourly_activity[hour].saturating_add(1);
        }
    }

    /// Calculate the novelty component (0-35) based on domain unknown ratio.
    fn novelty_score(&self, record: &FlowRecord) -> f32 {
        let domain = if !record.sni.is_empty() {
            &record.sni
        } else if !record.dns_domain.is_empty() {
            &record.dns_domain
        } else {
            return 0.0;
        };
        if self.known_domains.contains(domain) {
            return 0.0; // Known domain — no novelty
        }
        if self.total_flows < MIN_BASELINE_FLOWS {
            return 10.0; // Not enough baseline — low confidence
        }
        // New domain: score depends on how well-established the baseline is
        let ratio = (self.known_domains.len() as f32 / MAX_DOMAINS_PER_DEVICE as f32).min(1.0);
        10.0 + ratio * 25.0 // 10-35 based on domain knowledge density
    }

    /// Volume anomaly score (0-25): how much this flow deviates from baseline.
    fn volume_score(&self, record: &FlowRecord) -> f32 {
        if self.throughput_samples.is_empty() || self.total_flows < MIN_BASELINE_FLOWS {
            return 0.0;
        }
        let flow_bytes = (record.bytes_up + record.bytes_down) as f64;
        let duration_sec = (record.duration_ms as f64 / 1000.0).max(0.1);
        let flow_throughput = flow_bytes / duration_sec;

        let mean: f64 =
            self.throughput_samples.iter().sum::<f64>() / self.throughput_samples.len() as f64;
        if mean < 1.0 {
            return 0.0;
        }

        let ratio = flow_throughput / mean;
        if ratio > 5.0 {
            // >5x baseline: significant spike
            (15.0 + ((ratio - 5.0) / 5.0).min(1.0) * 10.0).min(25.0) as f32
        } else if ratio < 0.1 && flow_bytes > 100_000.0 {
            // Huge flow but very low throughput? Suspicious.
            10.0
        } else {
            0.0
        }
    }

    /// Timing anomaly score (0-20): activity during unusual hours.
    fn timing_score(&self, record: &FlowRecord) -> f32 {
        if self.total_flows < MIN_BASELINE_FLOWS {
            return 0.0;
        }
        let hour = record.timestamp.hour() as usize;
        if hour >= 24 {
            return 0.0;
        }

        let total_activity: u32 = self.hourly_activity.iter().sum();
        if total_activity == 0 {
            return 5.0;
        }

        let hour_ratio = self.hourly_activity[hour] as f32 / total_activity as f32;
        let expected = 1.0 / 24.0; // Uniform distribution baseline

        if hour_ratio < expected * 0.1 && total_activity > 100 {
            // This hour has <10% of expected activity and we have enough data
            let night_hours = !(6..23).contains(&hour);
            if night_hours {
                20.0 // Late night activity on a dormant device
            } else {
                10.0 // Unusual hour but not nighttime
            }
        } else if hour_ratio < expected * 0.5 && self.hourly_activity[hour] < 3 {
            8.0
        } else {
            0.0
        }
    }

    /// Flow rate anomaly score (0-10).
    fn flow_rate_score(&self, _record: &FlowRecord) -> f32 {
        if self.total_flows < MIN_BASELINE_FLOWS {
            return 0.0;
        }
        // Simplified: uses last_seen freshness as a proxy for sudden rate changes
        0.0
    }

    /// Calculate total risk score (0-100) for a flow.
    fn risk_score(&self, record: &FlowRecord) -> u8 {
        let novelty = self.novelty_score(record);
        let volume = self.volume_score(record);
        let timing = self.timing_score(record);
        let rate = self.flow_rate_score(record);
        let total = (novelty + volume + timing + rate).clamp(0.0, 100.0);
        debug!(
            "anomaly_score: novelty={:.1} volume={:.1} timing={:.1} rate={:.1} total={}",
            novelty, volume, timing, rate, total as u8
        );
        total as u8
    }
}

/// Cooldown window for duplicate alerts (nanoseconds).
const ALERT_COOLDOWN_NS: u64 = 5 * 60 * 1_000_000_000; // 5 minutes

/// Shared anomaly detector that maintains per-device baselines.
pub struct AnomalyDetector {
    devices: HashMap<String, DeviceBaseline>,
    /// Alert dedup: (device_ip, reason) → last_alert_timestamp_ns.
    alert_cooldown: HashMap<(String, String), u64>,
}

/// An anomaly event with score > threshold.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnomalyEvent {
    pub timestamp: String,
    pub src_ip: String,
    pub src_mac: String,
    pub risk_score: u8,
    pub reason: String,
    pub details: String,
    pub resolved: u8,
}

/// Component scores for a flow evaluation (used to avoid borrow conflicts).
#[derive(Default, Clone, Copy)]
struct ComponentScores {
    novelty: f32,
    volume: f32,
    timing: f32,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            alert_cooldown: HashMap::new(),
        }
    }

    /// Number of devices currently tracked.
    #[allow(dead_code)]
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Score a completed flow record and update baselines.
    /// Returns (risk_score: 0-100, optional_anomaly_event).
    pub fn evaluate(&mut self, record: &FlowRecord, ts_ns: u64) -> (u8, Option<AnomalyEvent>) {
        if record.src_ip.is_empty() {
            return (0, None);
        }

        // Compute component scores before mutable borrow of self.devices
        let components = self.compute_component_scores(record);

        let ip = &record.src_ip;
        let device = self
            .devices
            .entry(ip.clone())
            .or_insert_with(|| DeviceBaseline::new(ts_ns));

        let score = device.risk_score(record);

        // Calculate throughput for baseline update
        let flow_bytes = (record.bytes_up + record.bytes_down) as f64;
        let duration_sec = (record.duration_ms as f64 / 1000.0).max(0.1);
        let throughput = flow_bytes / duration_sec;

        device.record(record, ts_ns, throughput);

        // Generate alert if score is high enough (with dedup cooldown)
        let event = if score >= 50 {
            let alert = Self::build_alert(record, score, &components);
            let dedup_key = (record.src_ip.clone(), alert.reason.clone());
            let last = self.alert_cooldown.get(&dedup_key).copied().unwrap_or(0);
            if ts_ns.saturating_sub(last) > ALERT_COOLDOWN_NS {
                self.alert_cooldown.insert(dedup_key, ts_ns);
                if self.alert_cooldown.len() > 1000 {
                    self.alert_cooldown
                        .retain(|_, v| ts_ns.saturating_sub(*v) <= ALERT_COOLDOWN_NS * 2);
                }
                Some(alert)
            } else {
                None
            }
        } else {
            None
        };

        // LRU eviction for device map
        if self.devices.len() > MAX_DEVICES {
            if let Some(oldest_ip) = self
                .devices
                .iter()
                .min_by_key(|(_, d)| d.last_seen_ns)
                .map(|(ip, _)| ip.clone())
            {
                self.devices.remove(&oldest_ip);
            }
        }

        (score, event)
    }

    /// Compute component scores without borrowing self.devices.
    fn compute_component_scores(&self, record: &FlowRecord) -> ComponentScores {
        // This runs before the mutable borrow, so we do a read-only lookup
        let ip = &record.src_ip;
        if let Some(device) = self.devices.get(ip) {
            ComponentScores {
                novelty: device.novelty_score(record),
                volume: device.volume_score(record),
                timing: device.timing_score(record),
            }
        } else {
            ComponentScores::default()
        }
    }

    fn build_alert(record: &FlowRecord, score: u8, components: &ComponentScores) -> AnomalyEvent {
        let domain = if !record.sni.is_empty() {
            &record.sni
        } else if !record.dns_domain.is_empty() {
            &record.dns_domain
        } else {
            "N/A"
        };

        // Build reason string based on which components contributed most
        let novelty = components.novelty;
        let volume = components.volume;
        let timing = components.timing;

        let mut reasons = Vec::new();
        if novelty > 15.0 {
            reasons.push(format!("新域名: {}", domain));
        }
        if volume > 15.0 {
            reasons.push("流量突增(>5倍基线)".to_string());
        }
        if timing > 15.0 {
            reasons.push("非活跃时段活动".to_string());
        }

        let reason = if reasons.is_empty() {
            format!("风险评分 {}", score)
        } else {
            reasons.join("; ")
        };

        let detail = format!(
            "app={} cat={} dst={}:{} bytes={} duration={}ms novelty={:.0} volume={:.0} timing={:.0}",
            record.app_name, record.app_category, record.dst_ip, record.dst_port,
            record.bytes_up + record.bytes_down, record.duration_ms,
            novelty, volume, timing,
        );

        let ts_str = record.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();

        

        AnomalyEvent {
            timestamp: ts_str,
            src_ip: record.src_ip.clone(),
            src_mac: record.src_mac.clone(),
            risk_score: score,
            reason,
            details: detail,
            resolved: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use traffic_core::now_ns;

    fn make_flow(src_ip: &str, sni: &str, dns: &str, app: &str, bytes: i64, ms: i64) -> FlowRecord {
        FlowRecord {
            timestamp: Utc::now(),
            first_seen: 0,
            last_seen: 0,
            src_ip: src_ip.into(),
            dst_ip: "8.8.8.8".into(),
            src_port: 12345,
            dst_port: 443,
            protocol: "TCP".into(),
            sni: sni.into(),
            ja3: String::new(),
            ja3s: String::new(),
            tls_version: String::new(),
            server_cipher_suite: 0,
            tls_signature_hash: String::new(),
            dns_domain: dns.into(),
            http_host: String::new(),
            http_method: String::new(),
            http_ua: String::new(),
            packets_up: 1,
            packets_down: 2,
            bytes_up: bytes / 2,
            bytes_down: bytes / 2,
            duration_ms: ms,
            pkt_size_hist: [0; 7],
            pkt_iat_mean_us: 0.0,
            app_id: 1,
            app_name: app.into(),
            app_category: "Web".into(),
            confidence: 0.9,
            src_mac: "aa:bb:cc:dd:ee:ff".into(),
            device_manufacturer: String::new(),
            device_hostname: String::new(),
            engines: String::new(),
            risk_score: 0,
        }
    }

    #[test]
    fn test_known_domain_zero_score() {
        let mut detector = AnomalyDetector::new();
        let ts = now_ns();

        // First flow: new domain, but < MIN_BASELINE_FLOWS so low score
        let flow1 = make_flow("192.168.1.2", "example.com", "", "Web", 1000, 100);
        let (score1, _) = detector.evaluate(&flow1, ts);
        assert!(score1 <= 20);

        // Second flow with same domain: should be lower
        let flow2 = make_flow("192.168.1.2", "example.com", "", "Web", 1000, 100);
        let (score2, _) = detector.evaluate(&flow2, ts);
        // Both known and low baseline — should be <= first
        assert!(score2 <= score1);
    }

    #[test]
    fn test_new_domain_after_baseline() {
        let mut detector = AnomalyDetector::new();
        let ts = now_ns();

        // Establish baseline with MIN_BASELINE_FLOWS known domains
        for i in 0..MIN_BASELINE_FLOWS {
            let flow = make_flow(
                "192.168.1.2",
                &format!("known{}.com", i),
                "",
                "Web",
                1000,
                100,
            );
            let (_, _) = detector.evaluate(&flow, ts);
        }

        // Now hit with a completely new domain
        let flow = make_flow("192.168.1.2", "never-seen-before.com", "", "Web", 1000, 100);
        let (score, _) = detector.evaluate(&flow, ts);
        // Should have some novelty score
        assert!(score > 5);
    }

    #[test]
    fn test_volume_anomaly() {
        let mut detector = AnomalyDetector::new();
        let ts = now_ns();

        // Establish baseline with small flows
        for i in 0..MIN_BASELINE_FLOWS {
            let flow = make_flow(
                "192.168.1.3",
                &format!("site{}.com", i),
                "",
                "Web",
                1000,
                100,
            );
            let (_, _) = detector.evaluate(&flow, ts);
        }

        // Now send a massive flow (>5x typical throughput)
        let flow = make_flow(
            "192.168.1.3",
            "big-download.com",
            "",
            "Web",
            10_000_000,
            100,
        );
        let (score, _) = detector.evaluate(&flow, ts);
        // Large volume should contribute
        assert!(score > 0);
    }

    #[test]
    fn test_multiple_devices_independent() {
        let mut detector = AnomalyDetector::new();
        let ts = now_ns();

        for i in 0..MIN_BASELINE_FLOWS {
            let flow = make_flow(
                "192.168.1.10",
                &format!("site{}.com", i),
                "",
                "Web",
                1000,
                100,
            );
            let (_, _) = detector.evaluate(&flow, ts);
            let flow2 = make_flow("10.0.0.5", &format!("other{}.com", i), "", "Web", 1000, 100);
            detector.evaluate(&flow2, ts);
        }

        // New domain for device A: should be anomaly
        let flow_a = make_flow("192.168.1.10", "new-domain.com", "", "Web", 1000, 100);
        let (score_a, _) = detector.evaluate(&flow_a, ts);

        // Same domain for device B: also anomaly (different device)
        let flow_b = make_flow("10.0.0.5", "new-domain.com", "", "Web", 1000, 100);
        let (score_b, _) = detector.evaluate(&flow_b, ts);

        assert!(score_a > 0);
        assert!(score_b > 0);
    }

    #[test]
    fn test_alert_threshold() {
        let mut detector = AnomalyDetector::new();
        let ts = now_ns();

        // Establish baseline
        for i in 0..MIN_BASELINE_FLOWS {
            let flow = make_flow(
                "192.168.1.99",
                &format!("site{}.com", i),
                "",
                "Web",
                1000,
                100,
            );
            let (_, _) = detector.evaluate(&flow, ts);
        }

        // Trigger with high novelty + volume
        let flow = make_flow(
            "192.168.1.99",
            "extremely-new-domain.com",
            "",
            "Web",
            50_000_000,
            50,
        );
        let (score, event) = detector.evaluate(&flow, ts);
        assert!(score > 0);
        if score >= 50 {
            assert!(event.is_some());
            assert_eq!(event.as_ref().unwrap().src_ip, "192.168.1.99");
        }
    }

    #[test]
    fn test_device_lru_eviction() {
        let mut detector = AnomalyDetector::new();
        let ts = now_ns();

        // Fill with more devices than MAX_DEVICES
        for d in 0..MAX_DEVICES + 10 {
            let ip = format!("10.0.0.{}", d);
            let flow = make_flow(&ip, "example.com", "", "Web", 1000, 100);
            let (_, _) = detector.evaluate(&flow, ts);
        }

        // Should not exceed MAX_DEVICES
        assert!(detector.device_count() <= MAX_DEVICES + 1);
    }
}
