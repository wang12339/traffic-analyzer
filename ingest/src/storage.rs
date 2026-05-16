//! ClickHouse storage layer: schema management, batch inserts.

use anyhow::{Context, Result};
use clickhouse::Client;
use tracing::{info, warn};

pub struct ClickStore {
    http_client: reqwest::Client, // HTTP client for JSONEachRow inserts
    database: String,
    ch_http_url: String,
    _client: clickhouse::Client, // Used for DDL at init time only
}

impl ClickStore {
    pub async fn new(addr: &str, database: &str) -> Result<Self> {
        let client = Client::default()
            .with_url(format!("http://{}/", addr))
            .with_database(database);

        // Create database if not exists
        let sql = format!("CREATE DATABASE IF NOT EXISTS {}", database);
        client
            .query(&sql)
            .execute()
            .await
            .unwrap_or_else(|e| warn!("ClickHouse CREATE DATABASE (may be ok): {}", e));

        // Create flows table
        let ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.flows (
                timestamp       DateTime64(6),
                first_seen      Int64,
                last_seen       Int64,
                src_ip          String,
                dst_ip          String,
                src_port        UInt16,
                dst_port        UInt16,
                protocol        String,
                sni             String,
                ja3             String,
                ja3s            String,
                tls_version     String,
                server_cipher_suite UInt16,
                tls_signature_hash  String,
                dns_domain      String,
                http_host       String,
                http_method     String,
                http_ua         String,
                packets_up      UInt32,
                packets_down    UInt32,
                bytes_up        Int64,
                bytes_down      Int64,
                duration_ms     Int64,
                pkt_size_hist   String,
                pkt_iat_mean_us Float64,
                app_id          UInt32,
                app_name        String,
                app_category    String,
                confidence      Float32,
                src_mac         String,
                device_manufacturer String,
                device_hostname String,
                engines         String,
                risk_score      UInt8 DEFAULT 0
            ) ENGINE = ReplacingMergeTree(last_seen)
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (timestamp, src_ip, first_seen)
            TTL toDateTime(timestamp) + INTERVAL 90 DAY
        "#,
            database
        );
        client
            .query(&ddl)
            .execute()
            .await
            .context("create flows table")?;

        // Create daily aggregation table
        let agg_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.flow_stats_daily (
                date            Date,
                app_id          UInt32,
                app_name        String,
                app_category    String,
                flow_count      UInt64,
                total_bytes     Int64,
                unique_devices  UInt64
            ) ENGINE = SummingMergeTree
            PARTITION BY toYYYYMM(date)
            ORDER BY (date, app_id)
        "#,
            database
        );
        client.query(&agg_ddl).execute().await.unwrap_or_else(|e| {
            warn!("CREATE flow_stats_daily (may be ok if exists): {}", e);
        });

        // Create anomaly_alerts table
        let anomaly_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.anomaly_alerts (
                timestamp       DateTime,
                src_ip          String,
                src_mac         String,
                risk_score      UInt8,
                reason          String,
                details         String,
                resolved        UInt8 DEFAULT 0
            ) ENGINE = MergeTree
            ORDER BY (src_ip, timestamp)
            TTL toDateTime(timestamp) + INTERVAL 30 DAY
        "#,
            database
        );
        client
            .query(&anomaly_ddl)
            .execute()
            .await
            .unwrap_or_else(|e| {
                warn!("CREATE anomaly_alerts (may be ok if exists): {}", e);
            });

        // Create device_info table
        let dev_ddl = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.device_info (
                ip           String,
                mac          String,
                hostname     String,
                vendor_class String,
                manufacturer String,
                first_seen   Int64
            ) ENGINE = MergeTree
            ORDER BY ip
        "#,
            database
        );
        client.query(&dev_ddl).execute().await.unwrap_or_else(|e| {
            warn!("CREATE device_info (may be ok if exists): {}", e);
        });

        let ch_http_url = format!("http://{}/", addr);

        info!("ClickHouse storage initialized (database: {})", database);
        Ok(Self {
            _client: client,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()?,
            database: database.to_string(),
            ch_http_url,
        })
    }

    /// Batch insert flow records via JSON HTTP (avoids binary protocol column issues).
    pub async fn write_flows(&self, records: &[traffic_core::FlowRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let query = format!("INSERT INTO {}.flows FORMAT JSONEachRow", self.database);
        let url = format!(
            "{}?database={}&query={}",
            self.ch_http_url,
            self.database,
            Self::urlencoding(&query)
        );
        let mut json_rows = Vec::with_capacity(records.len());
        for r in records {
            json_rows.push(serde_json::json!({
                "timestamp": r.timestamp.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S.%6f").to_string(),
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "src_port": r.src_port,
                "dst_port": r.dst_port,
                "protocol": r.protocol,
                "sni": r.sni, "ja3": r.ja3, "ja3s": r.ja3s, "tls_version": r.tls_version,
                "server_cipher_suite": r.server_cipher_suite,
                "tls_signature_hash": r.tls_signature_hash,
                "dns_domain": r.dns_domain,
                "http_host": r.http_host, "http_method": r.http_method, "http_ua": r.http_ua,
                "packets_up": r.packets_up, "packets_down": r.packets_down,
                "bytes_up": r.bytes_up, "bytes_down": r.bytes_down,
                "duration_ms": r.duration_ms,
                "pkt_size_hist": serde_json::to_string(&r.pkt_size_hist).unwrap_or_default(),
                "pkt_iat_mean_us": r.pkt_iat_mean_us,
                "app_id": r.app_id, "app_name": r.app_name, "app_category": r.app_category,
                "confidence": r.confidence,
                "src_mac": r.src_mac, "device_manufacturer": r.device_manufacturer,
                "device_hostname": r.device_hostname,
                "engines": r.engines,
                "risk_score": r.risk_score,
            }));
        }
        let body = json_rows
            .iter()
            .map(|j| j.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        self.http_post_retry(&url, body).await?;
        Ok(())
    }

    /// POST JSON to ClickHouse with exponential backoff (3 attempts: 200ms, 500ms, 1s).
    async fn http_post_retry(&self, url: &str, body: String) -> Result<()> {
        let delays = [200, 500, 1000];
        let mut last_err = None;
        for (attempt, delay_ms) in delays.iter().enumerate() {
            match self
                .http_client
                .post(url)
                .body(body.clone())
                .header("Content-Type", "application/json")
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(());
                    }
                    let text = resp.text().await.unwrap_or_default();
                    last_err = Some(format!("HTTP {}: {}", status, text));
                    tracing::warn!(
                        "CH write attempt {} failed: {}",
                        attempt + 1,
                        last_err.as_ref().unwrap()
                    );
                }
                Err(e) => {
                    last_err = Some(format!("{}", e));
                    tracing::warn!("CH write attempt {} network error: {}", attempt + 1, e);
                }
            }
            if attempt < delays.len() - 1 {
                tokio::time::sleep(std::time::Duration::from_millis(*delay_ms)).await;
            }
        }
        Err(anyhow::anyhow!(
            "ClickHouse write failed after {} attempts: {}",
            delays.len(),
            last_err.unwrap_or_default()
        ))
    }

    /// Simple URL encoding for query parameters (replacing spaces and special chars).
    fn urlencoding(s: &str) -> String {
        s.replace(' ', "%20").replace('\'', "%27")
    }

    /// Write a JSON flow record received from the Python capture agent.
    /// Uses SQL INSERT FORMAT JSONEachRow for direct compatibility.
    pub async fn write_json_flow(&self, rec: &serde_json::Value) -> Result<(), anyhow::Error> {
        let r#type = rec["type"].as_str().unwrap_or("");
        if r#type != "flow_end" {
            return Ok(());
        }

        // Build a clean JSON object with only the columns we need
        let mut row = serde_json::Map::new();
        let ts = rec["timestamp"].as_f64().unwrap_or(0.0);
        if let Some(utc) =
            chrono::DateTime::from_timestamp(ts as i64, (ts.fract() * 1_000_000_000.0) as u32)
        {
            // Convert UTC to local time (Asia/Shanghai)
            let local = utc.with_timezone(&chrono::Local);
            row.insert(
                "timestamp".into(),
                local.format("%Y-%m-%d %H:%M:%S.%6f").to_string().into(),
            );
        }
        let fs = rec["first_seen"].as_f64().unwrap_or(ts) as i64;
        let ls = rec["last_seen"].as_f64().unwrap_or(ts) as i64;
        row.insert("first_seen".into(), fs.into());
        row.insert("last_seen".into(), ls.into());
        row.insert("src_ip".into(), rec["src_ip"].as_str().unwrap_or("").into());
        row.insert("dst_ip".into(), rec["dst_ip"].as_str().unwrap_or("").into());
        row.insert(
            "src_port".into(),
            rec["src_port"].as_i64().unwrap_or(0).into(),
        );
        row.insert(
            "dst_port".into(),
            rec["dst_port"].as_i64().unwrap_or(0).into(),
        );
        row.insert(
            "protocol".into(),
            rec["protocol"].as_str().unwrap_or("TCP").into(),
        );
        row.insert("sni".into(), rec["tls_sni"].as_str().unwrap_or("").into());
        row.insert(
            "http_host".into(),
            rec["http_host"].as_str().unwrap_or("").into(),
        );
        row.insert("ja3".into(), "".into());
        row.insert("ja3s".into(), "".into());
        row.insert("tls_version".into(), "".into());
        row.insert("server_cipher_suite".into(), 0.into());
        row.insert("tls_signature_hash".into(), "".into());
        row.insert(
            "dns_domain".into(),
            rec["dns_domain"].as_str().unwrap_or("").into(),
        );
        row.insert("http_method".into(), "".into());
        row.insert("http_ua".into(), "".into());
        let sni = rec["tls_sni"].as_str().unwrap_or("");
        let dns = rec["dns_domain"].as_str().unwrap_or("");
        let src_mac = rec["src_mac"].as_str().unwrap_or("");
        let port = rec["dst_port"].as_i64().unwrap_or(0) as u16;

        // Application classification
        let cls = traffic_core::classifier::classify(sni, dns, port);
        let (app_id, app_name, app_category, confidence) =
            (cls.app_id, cls.app_name, cls.app_category, cls.confidence);

        // Device type inference
        let device_mfg = traffic_core::classifier::infer_device(sni, dns, src_mac);

        row.insert(
            "packets_up".into(),
            rec["packets"].as_i64().unwrap_or(0).into(),
        );
        row.insert("packets_down".into(), 0.into());
        row.insert("bytes_up".into(), rec["bytes"].as_i64().unwrap_or(0).into());
        row.insert("bytes_down".into(), 0.into());
        row.insert(
            "duration_ms".into(),
            ((ls - fs).max(0) / 1_000_000).into(),
        );
        row.insert("pkt_size_hist".into(), "[0,0,0,0,0,0,0]".into());
        row.insert("pkt_iat_mean_us".into(), 0.0.into());
        row.insert("app_id".into(), app_id.into());
        row.insert("app_name".into(), app_name.into());
        row.insert("app_category".into(), app_category.into());
        row.insert("confidence".into(), confidence.into());
        row.insert("src_mac".into(), src_mac.into());
        row.insert("device_manufacturer".into(), device_mfg.into());
        row.insert(
            "device_hostname".into(),
            rec["hostname"].as_str().unwrap_or("").into(),
        );
        row.insert("engines".into(), "".into());
        row.insert("risk_score".into(), 0.into());

        let body = serde_json::to_string(&row)?;
        let query = format!("INSERT INTO {}.flows FORMAT JSONEachRow", &self.database);
        let url = format!(
            "{}?database={}&query={}",
            self.ch_http_url,
            &self.database,
            Self::urlencoding(&query)
        );
        self.http_post_retry(&url, body).await
    }

    /// Store device_info from Python agent (MAC, hostname, vendor_class).
    pub async fn write_device_info(&self, rec: &serde_json::Value) -> Result<(), anyhow::Error> {
        let ip = rec["ip"].as_str().unwrap_or("");
        if ip.is_empty() {
            return Ok(());
        }
        let mac = rec["mac"].as_str().unwrap_or("");
        let hostname = rec["hostname"].as_str().unwrap_or("");
        let vendor_class = rec["vendor_class"].as_str().unwrap_or("");
        let ts = rec["timestamp"].as_f64().unwrap_or(0.0) as i64;

        // Determine manufacturer from vendor_class or MAC
        let manufacturer = traffic_core::classifier::infer_device("", "", mac);
        let vc = vendor_class.to_lowercase();
        let manu2 = if vc.contains("iphone") {
            "Apple"
        } else if vc.contains("xiaomi") || vc.contains("mi ") {
            "Xiaomi"
        } else if vc.contains("huawei") {
            "Huawei"
        } else {
            ""
        };
        let final_mfg = if !manu2.is_empty() {
            manu2
        } else {
            &manufacturer
        };

        let query = format!(
            "INSERT INTO {}.device_info FORMAT JSONEachRow",
            self.database
        );
        let body = serde_json::json!({
            "ip": ip, "mac": mac, "hostname": hostname, "vendor_class": vendor_class,
            "manufacturer": final_mfg, "first_seen": ts,
        });
        let url = format!(
            "{}?database={}&query={}",
            self.ch_http_url,
            self.database,
            Self::urlencoding(&query)
        );
        let body_str = body.to_string();
        self.http_post_retry(&url, body_str).await
    }

    /// Write an anomaly alert event to ClickHouse.
    pub async fn write_anomaly_alert(
        &self,
        event: &crate::anomaly::AnomalyEvent,
    ) -> Result<(), anyhow::Error> {
        if event.src_ip.is_empty() {
            return Ok(());
        }
        let query = format!(
            "INSERT INTO {}.anomaly_alerts FORMAT JSONEachRow",
            self.database
        );
        let url = format!(
            "{}?database={}&query={}",
            self.ch_http_url,
            self.database,
            Self::urlencoding(&query)
        );
        let body = serde_json::json!({
            "timestamp": event.timestamp,
            "src_ip": event.src_ip,
            "src_mac": event.src_mac,
            "risk_score": event.risk_score,
            "reason": event.reason,
            "details": event.details,
            "resolved": event.resolved,
        });
        self.http_post_retry(&url, body.to_string()).await
    }

    /// Store an HTTP request/response record from mitmproxy.
    pub async fn write_http_session(&self, rec: &serde_json::Value) -> Result<(), anyhow::Error> {
        let rtype = rec["type"].as_str().unwrap_or("");
        let ts = rec["timestamp"].as_f64().unwrap_or(0.0);
        let ts_str =
            chrono::DateTime::from_timestamp(ts as i64, (ts.fract() * 1_000_000_000.0) as u32)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S.%3f").to_string())
                .unwrap_or_default();

        if rtype == "http_request" {
            let body = serde_json::json!({
                "timestamp": ts_str,
                "host": rec["host"].as_str().unwrap_or(""),
                "path": rec["path"].as_str().unwrap_or(""),
                "method": rec["method"].as_str().unwrap_or(""),
                "status_code": 0,
                "user_agent": rec["user_agent"].as_str().unwrap_or(""),
                "content_type": rec["content_type"].as_str().unwrap_or(""),
                "content_length": rec["content_length"].as_i64().unwrap_or(0).max(0) as u32,
                "scheme": rec["scheme"].as_str().unwrap_or(""),
                "port": rec["port"].as_i64().unwrap_or(0) as u16,
                "src_ip": "mitmproxy",
            });
            let query = format!(
                "INSERT INTO {}.http_sessions FORMAT JSONEachRow",
                self.database
            );
            let url = format!(
                "{}?database={}&query={}",
                self.ch_http_url,
                self.database,
                Self::urlencoding(&query)
            );
            self.http_post_retry(&url, body.to_string()).await?;
        }
        Ok(())
    }
}
