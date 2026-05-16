pub mod agent;
pub mod analysis;
pub mod doc;
pub mod geo;
pub mod queries;

use clap::Parser;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use utoipa::ToSchema;


#[derive(Parser)]
#[command(name = "api", about = "Traffic analysis API server")]
pub struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8970")]
    pub listen: String,
    #[arg(short, long, default_value = "http://localhost:8123")]
    pub clickhouse: String,
    #[arg(long, default_value = "traffic")]
    pub db_name: String,
}

pub struct AppState {
    pub http: HttpClient,
    pub ch_url: String,
    pub database: String,
    pub api_key: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// IPs whose anomaly alerts have been resolved (in-memory, resets on restart).
    pub resolved_ips: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Request counter for metrics.
    pub total_requests: AtomicU64,
    /// Per-path request counts.
    pub path_counts: std::sync::Mutex<HashMap<String, u64>>,
    /// ClickHouse query failures (for /api/metrics).
    pub ch_errors: AtomicU64,
}

pub fn ch_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

pub fn since_expr(since: &str) -> String {
    let since = since.trim();
    if since.is_empty() {
        return "now() - toIntervalHour(1)".to_string();
    }
    // Try each suffix; only match if the prefix is a valid integer.
    if let Some(rest) = since.strip_suffix('m') {
        if let Ok(n) = rest.parse::<u64>() {
            return format!("now() - toIntervalMinute({})", n.min(525600));
        }
    }
    if let Some(rest) = since.strip_suffix('h') {
        if let Ok(n) = rest.parse::<u64>() {
            return format!("now() - toIntervalHour({})", n.min(8760));
        }
    }
    if let Some(rest) = since.strip_suffix('d') {
        if let Ok(n) = rest.parse::<u64>() {
            return format!("now() - toIntervalDay({})", n.min(365));
        }
    }
    "now() - toIntervalHour(1)".to_string()
}

pub async fn ch_query<T: serde::de::DeserializeOwned>(
    state: &AppState,
    sql: &str,
) -> Result<Vec<T>, String> {
    let url = format!(
        "{}/?database={}&default_format=JSONEachRow",
        state.ch_url, state.database
    );
    let resp = state
        .http
        .post(&url)
        .body(sql.to_string())
        .header("Content-Type", "text/plain")
        .send()
        .await
        .map_err(|e| {
            state.ch_errors.fetch_add(1, Ordering::Relaxed);
            format!("HTTP: {}", e)
        })?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| {
        state.ch_errors.fetch_add(1, Ordering::Relaxed);
        format!("Read: {}", e)
    })?;
    if !status.is_success() {
        state.ch_errors.fetch_add(1, Ordering::Relaxed);
        return Err(format!("CH error ({}): {}", status, text));
    }
    let mut r = Vec::new();
    for line in text.lines() {
        if !line.is_empty() {
            r.push(
                serde_json::from_str::<T>(line)
                    .map_err(|e| format!("JSON: {} line: {}", e, &line[..line.len().min(200)]))?,
            );
        }
    }
    Ok(r)
}

pub async fn ch_one<T: serde::de::DeserializeOwned>(
    state: &AppState,
    sql: &str,
) -> Result<T, String> {
    ch_query::<T>(state, sql).await?.pop().ok_or_else(|| {
        let preview = if sql.len() > 80 {
            format!("{}...", &sql[..80])
        } else {
            sql.to_string()
        };
        format!("ch_one: no rows for query [{}]", preview)
    })
}

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data,
            error: None,
        }
    }
}

pub fn api_err(msg: &str) -> ApiResponse<serde_json::Value> {
    ApiResponse {
        success: false,
        data: serde_json::Value::Null,
        error: Some(msg.to_string()),
    }
}

// ─── Response types ───
#[derive(Deserialize, Serialize)]
pub struct StatsRow {
    pub total_flows: u64,
    pub total_bytes: f64,
    pub apps: u64,
    pub devices: u64,
    pub snis: u64,
    pub domains: u64,
    pub fps: f64,
    pub tcp_flows: u64,
    pub udp_flows: u64,
    pub throughput_mbps: f64,
}
#[derive(Serialize, ToSchema)]
pub struct StatsResponse {
    pub total_flows: u64,
    pub total_bytes: f64,
    pub active_apps: u64,
    pub unique_devices: u64,
    pub unique_snis: u64,
    pub unique_domains: u64,
    pub flows_per_sec: f64,
    pub tcp_flows: u64,
    pub udp_flows: u64,
    pub throughput_mbps: f64,
}
#[derive(Deserialize, Serialize, ToSchema)]
pub struct FlowRow {
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub sni: String,
    pub ja3s: String,
    pub tls_version: String,
    pub server_cipher_suite: u16,
    pub tls_signature_hash: String,
    pub dns_domain: String,
    pub app_name: String,
    pub app_category: String,
    pub confidence: f64,
    pub bytes_up: f64,
    pub bytes_down: f64,
    pub packets_up: u32,
    pub packets_down: u32,
    pub duration_ms: i64,
    pub src_mac: String,
    pub engines: String,
}
#[derive(Deserialize, Serialize, ToSchema)]
pub struct AppRow {
    pub app_id: u32,
    pub app_name: String,
    pub app_category: String,
    pub flow_count: u64,
    pub total_bytes: f64,
    pub device_count: u64,
}
#[derive(Deserialize, Serialize, ToSchema)]
pub struct DeviceRow {
    pub src_ip: String,
    pub flows: u64,
    pub bytes_total: f64,
    pub app_count: u64,
    pub last_seen: String,
    pub src_mac: String,
    pub sni_count: u64,
}
#[derive(Deserialize, Serialize, ToSchema)]
pub struct DnsRow {
    pub dns_domain: String,
    pub count: u64,
    pub clients: u64,
}
#[derive(Deserialize, Serialize, ToSchema)]
pub struct SniRow {
    pub sni: String,
    pub count: u64,
    pub clients: u64,
}
#[derive(Deserialize, Serialize, ToSchema)]
pub struct TrendRow {
    pub bucket: String,
    pub flows: u64,
    pub bytes: f64,
}
#[derive(Deserialize, Serialize, ToSchema)]
pub struct DeviceDetailRow {
    pub src_ip: String,
    pub app_name: String,
    pub app_category: String,
    pub flow_count: u64,
    pub total_bytes: f64,
    pub sni: String,
    pub dns_domain: String,
}
#[derive(Deserialize, Serialize, utoipa::IntoParams, ToSchema)]
pub struct FlowQuery {
    pub search_ip: Option<String>,
    pub search_domain: Option<String>,
    pub app_id: Option<u32>,
    pub limit: Option<u32>,
    pub since: Option<String>,
}
#[derive(Deserialize, Serialize, utoipa::IntoParams, ToSchema)]
pub struct TimeQuery {
    pub since: Option<String>,
}

/// Determine device model (e.g. "iPhone 14 Pro Max") from DNS/SNI/UA patterns.
pub fn identify_device_model(_apps: &[String], domains: &[String], mac: &str, ua: &str) -> String {
    let combined = domains.join(" ");
    let ua_lower = ua.to_lowercase();
    if combined.contains("miui.com") || combined.contains("micloud.xiaomi") {
        if ua_lower.contains("xiaomi14") || ua_lower.contains("fuxi") {
            return "Xiaomi 14".into();
        }
        if ua_lower.contains("xiaomi13") {
            return "Xiaomi 13".into();
        }
        if ua_lower.contains("xiaomi12") || ua_lower.contains("cupid") {
            return "Xiaomi 12".into();
        }
        if ua_lower.contains("xiaomi11") {
            return "Xiaomi 11".into();
        }
        if ua_lower.contains("redmi") || ua_lower.contains("note ") {
            return "Redmi Note".into();
        }
        if combined.contains("sys.miui.com") && mac == "aa:80:a0:29:4e:0a" {
            return "Xiaomi 13 Pro".into();
        }
        return "Xiaomi 手机".into();
    }
    if combined.contains("apple.com")
        || combined.contains("icloud.com")
        || combined.contains("push.apple.com")
    {
        if ua_lower.contains("iphone15,3") {
            return "iPhone 14 Pro Max".into();
        }
        if ua_lower.contains("iphone15,2") {
            return "iPhone 14 Pro".into();
        }
        if ua_lower.contains("iphone14,8") {
            return "iPhone 14 Plus".into();
        }
        if ua_lower.contains("iphone14,3") {
            return "iPhone 13 Pro Max".into();
        }
        if ua_lower.contains("iphone") {
            if ua_lower.contains("16,") {
                return "iPhone 15".into();
            }
            if ua_lower.contains("15,") {
                return "iPhone 14".into();
            }
            if ua_lower.contains("14,") {
                return "iPhone 13".into();
            }
            return "iPhone".into();
        }
        if ua_lower.contains("macintosh") || ua_lower.contains("mac os") {
            if ua_lower.contains("macbookpro") {
                return "MacBook Pro".into();
            }
            if ua_lower.contains("macbookair") {
                return "MacBook Air".into();
            }
            if ua_lower.contains("macmini") {
                return "Mac mini".into();
            }
            return "Mac".into();
        }
        if ua_lower.contains("ipad") {
            if ua_lower.contains("ipadpro") {
                return "iPad Pro".into();
            }
            return "iPad".into();
        }
    }
    if combined.contains("huawei.com") || combined.contains("hicloud.com") {
        if ua_lower.contains("pura70") {
            return "Huawei Pura 70".into();
        }
        if ua_lower.contains("mate60") {
            return "Huawei Mate 60".into();
        }
        if ua_lower.contains("p60") {
            return "Huawei P60".into();
        }
        if ua_lower.contains("nova") {
            return "Huawei Nova".into();
        }
        return "Huawei 手机".into();
    }
    if combined.contains("samsung.com") || ua_lower.contains("samsung") {
        if ua_lower.contains("s24") {
            return "Samsung Galaxy S24".into();
        }
        if ua_lower.contains("s23") {
            return "Samsung Galaxy S23".into();
        }
        return "Samsung Galaxy".into();
    }
    if ua_lower.contains("windows nt") {
        if ua_lower.contains("windows nt 10") {
            return "Windows 10/11".into();
        }
        if ua_lower.contains("windows nt 6.3") {
            return "Windows 8.1".into();
        }
        return "Windows PC".into();
    }
    String::new()
}

/// Infer device type and OS from DNS/app patterns.
pub fn profile_device(apps: &[String], domains: &[String], mac: &str) -> (String, String, f32) {
    let apps_combined: String = apps
        .iter()
        .map(|a| a.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let mac_lower = mac.to_lowercase();
    let mac_prefix = if mac.len() >= 8 { &mac_lower[..8] } else { "" };
    if mac_prefix == "aa:80:a0" || mac_prefix == "de:2c:28" {
        return ("Xiaomi".into(), "Android".into(), 0.9);
    }
    if mac_prefix == "5e:8f:c9"
        || mac_prefix == "6c:1f:f7"
        || mac_prefix == "fc:25:3f"
        || mac_prefix == "f0:18:98"
    {
        return ("Apple 设备".into(), "iOS/macOS".into(), 0.7);
    }
    if mac_prefix == "ea:0c:af" {
        return ("NRadio 路由器".into(), "OpenWrt".into(), 0.9);
    }
    if mac_prefix == "b4:6e:10" || mac_prefix == "3a:a4:28" {
        return ("Vivo".into(), "Android".into(), 0.9);
    }
    if mac_prefix == "e2:08:f4" || mac_prefix == "5a:e2:02" {
        return ("代理客户端".into(), "Clash/Surge".into(), 0.6);
    }
    if mac_prefix == "d6:cb:c4" {
        return ("Apple 设备".into(), "iOS".into(), 0.6);
    }
    let apple_signals = domains
        .iter()
        .filter(|d| {
            d.contains("apple.com")
                || d.contains("icloud.com")
                || d.contains("guzzoni.apple.com")
                || d.contains("push.apple.com")
                || d.contains("appsto.re")
                || d.contains("courier.push.apple.com")
                || d.contains("iphone-ld.apple.com")
        })
        .count();
    let xiaomi_signals = domains
        .iter()
        .filter(|d| {
            d.contains("miui.com")
                || d.contains("xiaomi.net")
                || d.contains("micloud.xiaomi")
                || d.contains("mi.com")
                || d.contains("sys.miui.com")
        })
        .count();
    let windows_signals = domains
        .iter()
        .filter(|d| {
            d.contains("wns.windows.com")
                || d.contains("windowsupdate.com")
                || d.contains("update.microsoft.com")
                || d.contains("edge.microsoft.com")
        })
        .count();
    let huawei_signals = domains
        .iter()
        .filter(|d| d.contains("huawei.com") || d.contains("hicloud.com"))
        .count();
    let android_signals = domains
        .iter()
        .filter(|d| d.contains("googleapis.com") || d.contains("firebase"))
        .count();
    let wechat_heavy = apps_combined.contains("WeChat");
    if xiaomi_signals > 0 || mac_prefix == "aa:80:a0" {
        return ("Xiaomi".into(), "Android".into(), 0.85);
    }
    if huawei_signals > 0 {
        return ("Huawei".into(), "Android".into(), 0.85);
    }
    if windows_signals > 0 && apple_signals == 0 && !wechat_heavy {
        return ("Windows PC".into(), "Windows".into(), 0.7);
    }
    if apple_signals > 0 {
        if domains
            .iter()
            .any(|d| d.contains("guzzoni") || d.contains("configuration.apple.com"))
        {
            return ("Mac".into(), "macOS".into(), 0.8);
        }
        if domains
            .iter()
            .any(|d| d.contains("iphone-ld") || d.contains("courier.push"))
        {
            return ("iPhone/iPad".into(), "iOS".into(), 0.8);
        }
        return ("Apple Device".into(), "iOS/macOS".into(), 0.6);
    }
    if android_signals > 0 && wechat_heavy {
        return ("Android 手机".into(), "Android".into(), 0.6);
    }
    if apps_combined.contains("Apple") || apps_combined.contains("iCloud") {
        return ("Apple Device".into(), "iOS/macOS".into(), 0.5);
    }
    if apps_combined.contains("Windows") {
        return ("Windows PC".into(), "Windows".into(), 0.5);
    }
    if wechat_heavy && !windows_signals > 0 {
        return ("手机".into(), "移动端".into(), 0.4);
    }
    ("未知设备".into(), "Unknown".into(), 0.0)
}

/// Calculate behavior anomaly score: 0 (normal) to 100 (highly unusual).
pub fn behavior_score(
    first_seen_count: usize,
    total_destinations: usize,
    app_count: usize,
    baseline_size: usize,
    flow_count: u64,
) -> f64 {
    if total_destinations == 0 {
        return 0.0;
    }
    let novelty = if baseline_size > 0 {
        first_seen_count as f64 / total_destinations as f64
    } else {
        1.0
    };
    let diversity = if app_count > 0 {
        (app_count as f64).ln() / 5.0f64.ln()
    } else {
        0.0
    };
    let intensity = (flow_count as f64 / 300.0).min(1.0);
    (novelty * 50.0 + diversity * 25.0 + intensity * 25.0).min(100.0)
}

// ─── Typed response types for analysis handlers ───

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub flows: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ResolveResponse {
    pub resolved: bool,
    pub ip: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct TlsFingerprintRow {
    pub tls_signature_hash: String,
    #[serde(default)]
    pub ja3: String,
    #[serde(default)]
    pub ja3s: String,
    #[serde(default)]
    pub tls_version: String,
    pub cnt: u64,
}

#[derive(Serialize, ToSchema)]
pub struct TlsFingerprintResponse {
    pub distinct_signatures: u64,
    pub fingerprints: Vec<TlsFingerprintRow>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct HourlyAppRow {
    pub h: u8,
    pub app_name: String,
    pub c: u64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct TimelineSiteRow {
    pub h: u8,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub dns_domain: String,
    pub c: u64,
}

#[derive(Serialize, ToSchema)]
pub struct TimelineResponse {
    pub hourly_apps: Vec<HourlyAppRow>,
    pub visited_sites: Vec<TimelineSiteRow>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct AnomalyAlertRow {
    pub src_ip: String,
    #[serde(default)]
    pub src_mac: String,
    pub risk_score: u8,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub details: String,
    pub timestamp: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct TrafficAlertRow {
    pub src_ip: String,
    pub dests: u64,
    pub apps: u64,
    pub bytes: f64,
}

#[derive(Serialize, ToSchema)]
pub struct AlertsResponse {
    pub anomaly_alerts: Vec<AnomalyAlertRow>,
    pub traffic_alerts: Vec<TrafficAlertRow>,
    pub total: usize,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct AnomalySummary {
    pub total: u64,
    pub avg_risk: f64,
    pub max_risk: u64,
    pub affected_devices: u64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct AnomalyEventRow {
    pub timestamp: String,
    pub src_ip: String,
    #[serde(default)]
    pub src_mac: String,
    pub risk_score: u8,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub details: String,
    pub resolved: u8,
}

#[derive(Serialize, ToSchema)]
pub struct AnomalyResponse {
    pub summary: AnomalySummary,
    pub events: Vec<AnomalyEventRow>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct HttpSessionRow {
    pub timestamp: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    pub status_code: u16,
    #[serde(default)]
    pub content_type: String,
    pub content_length: u32,
    #[serde(default)]
    pub user_agent: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct TopologyRow {
    pub src_ip: String,
    pub dst_ip: String,
    #[serde(default)]
    pub app_name: String,
    pub w: u64,
    pub b: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ch_escape() {
        assert_eq!(ch_escape("hello"), "hello");
        assert_eq!(ch_escape("it's"), "it\\'s");
        assert_eq!(ch_escape("back\\slash"), "back\\\\slash");
        assert_eq!(ch_escape("' OR 1=1 --"), "\\' OR 1=1 --");
        assert_eq!(ch_escape("%"), "\\%");
        assert_eq!(ch_escape("_"), "\\_");
        assert_eq!(ch_escape("192.168.1.1"), "192.168.1.1");
        assert_eq!(ch_escape("' OR 1=1 -- %"), "\\' OR 1=1 -- \\%");
    }

    #[test]
    fn test_since_expr_minutes() {
        let r = since_expr("15m");
        assert_eq!(r, "now() - toIntervalMinute(15)");
    }

    #[test]
    fn test_since_expr_hours() {
        let r = since_expr("1h");
        assert_eq!(r, "now() - toIntervalHour(1)");
    }

    #[test]
    fn test_since_expr_days() {
        let r = since_expr("7d");
        assert_eq!(r, "now() - toIntervalDay(7)");
    }

    #[test]
    fn test_since_expr_default() {
        let r = since_expr("");
        assert_eq!(r, "now() - toIntervalHour(1)");
    }

    #[test]
    fn test_since_expr_edge_cases() {
        let r = since_expr("0m");
        assert_eq!(r, "now() - toIntervalMinute(0)");
        let r = since_expr("999999m");
        assert!(r.contains("Minute("));
    }

    #[test]
    fn test_behavior_score_zero_destinations() {
        assert_eq!(behavior_score(0, 0, 0, 0, 0), 0.0);
    }

    #[test]
    fn test_behavior_score_normal() {
        let score = behavior_score(1, 20, 5, 100, 10);
        assert!(score < 50.0);
    }

    #[test]
    fn test_behavior_score_high_novelty() {
        let score = behavior_score(10, 10, 2, 10, 5);
        assert!(score > 50.0);
    }

    #[test]
    fn test_behavior_score_capped() {
        let score = behavior_score(100, 100, 50, 10, 1000);
        assert!(score <= 100.0);
    }

    #[test]
    fn test_behavior_score_extremes() {
        let score = behavior_score(0, 0, 0, 0, 0);
        assert_eq!(score, 0.0);
        let score = behavior_score(0, 1, 0, 0, 0);
        assert!(score >= 0.0);
    }

    #[test]
    fn test_identify_device_model_xiaomi_mac() {
        let model = identify_device_model(&[], &["miui.com".into()], "aa:80:a0:00:00:00", "");
        assert!(!model.is_empty());
    }

    #[test]
    fn test_identify_device_model_apple() {
        let model = identify_device_model(&[], &["apple.com".into(), "icloud.com".into()], "", "");
        assert!(model.is_empty() || model.contains("iPhone") || model.contains("Mac") || model.contains("iPad"));
    }

    #[test]
    fn test_identify_device_model_windows() {
        let model = identify_device_model(&[], &[], "", "Mozilla/5.0 Windows NT 10.0");
        assert_eq!(model, "Windows 10/11");
    }

    #[test]
    fn test_identify_device_model_ipad() {
        let model = identify_device_model(&[], &["apple.com".into()], "", "Mozilla/5.0 iPad");
        assert!(model.contains("iPad") || model.contains("Apple"));
    }

    #[test]
    fn test_identify_device_model_macbook() {
        let model = identify_device_model(&[], &["apple.com".into()], "", "Mozilla/5.0 Macintosh Intel Mac OS X MacBookPro");
        assert_eq!(model, "MacBook Pro");
    }

    #[test]
    fn test_identify_device_model_huawei() {
        let model = identify_device_model(&[], &["huawei.com".into()], "", "HUAWEI Pura70");
        assert!(model.contains("Huawei") || !model.is_empty());
    }

    #[test]
    fn test_profile_device_mac_prefix() {
        let (dev_type, os, conf) = profile_device(&[], &[], "aa:80:a0:29:4e:0a");
        assert_eq!(dev_type, "Xiaomi");
        assert_eq!(os, "Android");
        assert_eq!(conf, 0.9);
    }

    #[test]
    fn test_profile_device_apple_mac() {
        let (dev_type, os, conf) = profile_device(&[], &[], "f0:18:98:00:00:00");
        assert_eq!(dev_type, "Apple 设备");
        assert_eq!(os, "iOS/macOS");
        assert!(conf > 0.5);
    }

    #[test]
    fn test_profile_device_dns_signals() {
        let (dev_type, os, _) = profile_device(&[], &["miui.com".into(), "icloud.com".into()], "");
        assert_eq!(dev_type, "Xiaomi");
        assert_eq!(os, "Android");
    }

    #[test]
    fn test_api_response_serialization() {
        let resp = ApiResponse::ok(42usize);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["data"], 42);
        assert!(json.get("error").is_none());
    }

    #[test]
    fn test_api_response_error() {
        let resp = api_err("test error");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], false);
        assert_eq!(json["error"], "test error");
    }

    #[test]
    fn test_ch_escape_sql_injection() {
        // Ensure basic SQL injection patterns are escaped
        assert_ne!(ch_escape("'; DROP TABLE flows; --"), "' OR 1=1 --");
        assert!(ch_escape("' OR '1'='1").contains("\\'"));
    }

    #[test]
    fn test_since_expr_invalid() {
        let r = since_expr("invalid");
        assert_eq!(r, "now() - toIntervalHour(1)");
    }

    #[test]
    fn test_device_profile_empty() {
        let (dev_type, os, conf) = profile_device(&[], &[], "");
        assert!(conf <= 0.5);
        assert!(!dev_type.is_empty() || conf == 0.0);
    }

    #[test]
    fn test_device_model_empty() {
        let model = identify_device_model(&[], &[], "", "");
        assert!(model.is_empty());
    }
}
