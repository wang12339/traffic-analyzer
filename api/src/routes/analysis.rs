use crate::routes::*;
use actix_web::{web, HttpResponse};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use utoipa::ToSchema;

struct DeviceInsight {
    mac: String,
    domains: Vec<String>,
    apps: Vec<String>,
    bytes: f64,
    flows: u64,
    dest_set: HashSet<String>,
}

#[derive(Serialize, ToSchema)]
pub struct LiveSnapshot {
    pub timestamp: String,
    pub devices: Vec<LiveDevice>,
}
#[derive(Serialize, ToSchema)]
pub struct LiveDevice {
    pub ip: String,
    pub mac: String,
    pub flows: u64,
    pub bytes_total: f64,
    pub destinations: Vec<DestInfo>,
    pub apps: Vec<String>,
    pub new_dests: Vec<String>,
}
#[derive(Serialize, ToSchema)]
pub struct DestInfo {
    pub dest: String,
    pub app: String,
}

#[utoipa::path(
    get,
    path = "/api/live",
    responses(
        (status = 200, description = "Live traffic snapshot", body = LiveSnapshot),
    ),
    tag = "Live"
)]
pub async fn get_live(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let sql = format!(
        "SELECT src_ip,sni,dns_domain,app_name,sum(bytes_up+bytes_down) as b,any(src_mac) as m \
         FROM {}.flows WHERE timestamp>=now()-toIntervalMinute(5) AND (src_ip LIKE '192.168.%' OR src_ip LIKE '10.%' OR (ipv4StringToNum(src_ip) BETWEEN ipv4StringToNum('172.16.0.0') AND ipv4StringToNum('172.31.255.255')))
         GROUP BY src_ip,sni,dns_domain,app_name ORDER BY src_ip", state.database);
    let rows = match ch_query::<serde_json::Value>(&state, &sql).await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(api_err(&e)),
    };
    let mut devs: BTreeMap<String, LiveDevice> = BTreeMap::new();
    let mut seen_dests: HashMap<String, HashSet<String>> = HashMap::new();
    let mut base_cache: HashMap<String, HashSet<String>> = HashMap::new();
    for row in &rows {
        let ip = row["src_ip"].as_str().unwrap_or("").to_string();
        let mac = row["m"].as_str().unwrap_or("").to_string();
        let sni = row["sni"].as_str().unwrap_or("");
        let dns = row["dns_domain"].as_str().unwrap_or("");
        let app = row["app_name"].as_str().unwrap_or("");
        let b = row["b"].as_f64().unwrap_or(0.0);
        let e = devs.entry(ip.clone()).or_insert(LiveDevice {
            ip: ip.clone(),
            mac,
            flows: 0,
            bytes_total: 0.0,
            destinations: vec![],
            apps: vec![],
            new_dests: vec![],
        });
        e.flows += 1;
        e.bytes_total += b;
        let dest = if !sni.is_empty() {
            sni.to_string()
        } else if !dns.is_empty() {
            dns.to_string()
        } else {
            continue;
        };
        let seen = seen_dests.entry(ip.clone()).or_default();
        if !seen.contains(&dest) {
            seen.insert(dest.clone());
            e.destinations.push(DestInfo {
                dest,
                app: app.to_string(),
            });
        }
        if !app.is_empty() && !e.apps.contains(&app.to_string()) {
            e.apps.push(app.to_string());
        }
    }
    for dev in devs.values_mut() {
        if !base_cache.contains_key(&dev.ip) {
            let bsql = format!(
                "SELECT DISTINCT sni as d FROM {}.flows WHERE src_ip='{}' AND timestamp>=now()-toIntervalDay(1) AND timestamp<now()-toIntervalMinute(5) AND sni!='' \
                 UNION ALL SELECT DISTINCT dns_domain as d FROM {}.flows WHERE src_ip='{}' AND timestamp>=now()-toIntervalDay(1) AND timestamp<now()-toIntervalMinute(5) AND dns_domain!=''",
                state.database, dev.ip, state.database, dev.ip
            );
            let known: HashSet<String> = match ch_query::<serde_json::Value>(&state, &bsql).await {
                Ok(rows) => rows
                    .iter()
                    .filter_map(|v| v["d"].as_str().map(String::from))
                    .collect(),
                Err(_) => HashSet::new(),
            };
            base_cache.insert(dev.ip.clone(), known);
        }
        let baseline = &base_cache[&dev.ip];
        for d in &dev.destinations {
            if !baseline.contains(&d.dest) {
                dev.new_dests.push(d.dest.clone());
            }
        }
    }
    HttpResponse::Ok().json(ApiResponse::ok(LiveSnapshot {
        timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
        devices: devs.into_values().collect(),
    }))
}

#[utoipa::path(
    get,
    path = "/api/device/{ip}/current",
    params(
        ("ip" = String, Path, description = "Device IP address"),
    ),
    responses(
        (status = 200, description = "Current active connections"),
    ),
    tag = "Devices"
)]
pub async fn get_device_current(
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let ip = path.into_inner();
    let eip = ch_escape(&ip);
    let sql = format!(
        "SELECT sni,dns_domain,app_name,count() as flows,sum(bytes_up+bytes_down) as bytes,\
         any(engines) as engines \
         FROM {}.flows WHERE src_ip='{}' AND timestamp>=now()-toIntervalMinute(5) \
         GROUP BY sni,dns_domain,app_name ORDER BY bytes DESC LIMIT 20",
        state.database, eip
    );
    match ch_query::<serde_json::Value>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/device/{ip}/anomalies",
    params(
        ("ip" = String, Path, description = "Device IP address"),
    ),
    responses(
        (status = 200, description = "First-seen destinations"),
    ),
    tag = "Devices"
)]
pub async fn get_device_anomalies(
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let ip = path.into_inner();
    let eip = ch_escape(&ip);
    let recent_sql = format!(
        "SELECT sni as d FROM {}.flows WHERE src_ip='{}' AND timestamp>=now()-toIntervalMinute(5) AND sni!='' \
         UNION ALL SELECT dns_domain as d FROM {}.flows WHERE src_ip='{}' AND timestamp>=now()-toIntervalMinute(5) AND dns_domain!=''",
        state.database, eip, state.database, eip
    );
    let base_sql = format!(
        "SELECT DISTINCT sni as d FROM {}.flows WHERE src_ip='{}' AND timestamp>=now()-toIntervalDay(1) AND timestamp<now()-toIntervalMinute(5) AND sni!='' \
         UNION ALL SELECT DISTINCT dns_domain as d FROM {}.flows WHERE src_ip='{}' AND timestamp>=now()-toIntervalDay(1) AND timestamp<now()-toIntervalMinute(5) AND dns_domain!=''",
        state.database, eip, state.database, eip
    );
    let (recent, baseline) = match tokio::join!(
        ch_query::<serde_json::Value>(&state, &recent_sql),
        ch_query::<serde_json::Value>(&state, &base_sql),
    ) {
        (Ok(r), Ok(b)) => (r, b),
        (Err(e), _) | (_, Err(e)) => return HttpResponse::InternalServerError().json(api_err(&e)),
    };
    let known: HashSet<String> = baseline
        .iter()
        .filter_map(|v| v["d"].as_str().map(String::from))
        .collect();
    let first_seen: Vec<String> = recent
        .iter()
        .filter_map(|v| {
            let d = v["d"].as_str()?;
            if !d.is_empty() && !known.contains(d) {
                Some(d.to_string())
            } else {
                None
            }
        })
        .collect();
    HttpResponse::Ok().json(ApiResponse::ok(
        serde_json::json!({"ip":ip,"first_seen":first_seen,"baseline_size":known.len()}),
    ))
}

#[utoipa::path(
    get,
    path = "/api/device/{ip}/trends",
    params(
        ("ip" = String, Path, description = "Device IP address"),
        ("since" = Option<String>, Query, description = "Time range (e.g. 1h, 24h)"),
    ),
    responses(
        (status = 200, description = "Device bandwidth timeline"),
    ),
    tag = "Devices"
)]
pub async fn get_device_trends(
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
    q: web::Query<TimeQuery>,
) -> HttpResponse {
    let ip = path.into_inner();
    let se = since_expr(q.since.as_deref().unwrap_or("24h"));
    let sql = format!(
        "SELECT toStartOfMinute(timestamp) as bucket,\
         sum(bytes_up+bytes_down) as bytes,count() as flows,\
         countIf(protocol='TCP') as tcp,countIf(protocol='UDP') as udp,\
         sum(if(protocol='TCP',bytes_up+bytes_down,0)) as tcp_bytes,\
         sum(if(protocol='UDP',bytes_up+bytes_down,0)) as udp_bytes \
         FROM {}.flows WHERE src_ip='{}' AND timestamp>={} GROUP BY bucket ORDER BY bucket",
        state.database,
        ch_escape(&ip),
        se
    );
    match ch_query::<serde_json::Value>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

/// TLS fingerprint diversity for a device — detects TLS implementation changes.
#[utoipa::path(
    get,
    path = "/api/device/{ip}/tls-fingerprints",
    params(
        ("ip" = String, Path, description = "Device IP address"),
    ),
    responses(
        (status = 200, description = "TLS fingerprint distribution"),
    ),
    tag = "Devices"
)]
pub async fn get_device_tls_fingerprints(
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let ip = path.into_inner();
    let sql = format!(
        "SELECT tls_signature_hash,ja3,ja3s,tls_version,count() as cnt \
         FROM {}.flows WHERE src_ip='{}' AND tls_signature_hash!='' \
         AND timestamp>=now()-toIntervalDay(1) \
         GROUP BY tls_signature_hash,ja3,ja3s,tls_version \
         ORDER BY cnt DESC LIMIT 20",
        state.database,
        ch_escape(&ip),
    );
    let count_sql = format!(
        "SELECT countDistinct(tls_signature_hash) as distinct_sigs \
         FROM {}.flows WHERE src_ip='{}' AND tls_signature_hash!='' \
         AND timestamp>=now()-toIntervalDay(1)",
        state.database,
        ch_escape(&ip),
    );
    match tokio::join!(
        ch_query::<serde_json::Value>(&state, &sql),
        ch_one::<serde_json::Value>(&state, &count_sql),
    ) {
        (Ok(rows), Ok(count)) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "distinct_signatures": count["distinct_sigs"],
            "fingerprints": rows,
        }))),
        (Err(e), _) | (_, Err(e)) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/device/{ip}",
    params(
        ("ip" = String, Path, description = "Device IP address"),
    ),
    responses(
        (status = 200, description = "Device detail by app", body = Vec<DeviceDetailRow>),
    ),
    tag = "Devices"
)]
pub async fn get_device_detail(
    state: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let ip = path.into_inner();
    let eip = ch_escape(&ip);
    let sql = format!(
        "SELECT src_ip,app_name,app_category,count() as flow_count,\
        sum(bytes_up+bytes_down) as total_bytes,any(sni) as sni,any(dns_domain) as dns_domain \
        FROM {}.flows WHERE src_ip='{}' AND timestamp>=now()-toIntervalDay(1) \
        GROUP BY src_ip,app_name,app_category ORDER BY total_bytes DESC LIMIT 50",
        state.database, eip
    );
    match ch_query::<DeviceDetailRow>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/insights",
    responses(
        (status = 200, description = "AI-driven device insights"),
    ),
    tag = "Analysis"
)]
pub async fn get_insights(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let sql = format!(
        "SELECT src_ip,app_name,sni,dns_domain,src_mac,sum(bytes_up+bytes_down) as bytes,count() as flows \
         FROM {}.flows WHERE timestamp>=now()-toIntervalMinute(5) AND (src_ip LIKE '192.168.%' OR src_ip LIKE '10.%')
         GROUP BY src_ip,app_name,sni,dns_domain,src_mac ORDER BY src_ip", state.database);
    let rows = match ch_query::<serde_json::Value>(&state, &sql).await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(api_err(&e)),
    };
    let mut device_map: HashMap<String, DeviceInsight> = HashMap::new();
    for row in &rows {
        let ip = row["src_ip"].as_str().unwrap_or("").to_string();
        let mac = row["src_mac"].as_str().unwrap_or("").to_string();
        let app = row["app_name"].as_str().unwrap_or("").to_string();
        let sni = row["sni"].as_str().unwrap_or("").to_string();
        let dns = row["dns_domain"].as_str().unwrap_or("").to_string();
        let bytes = row["bytes"].as_f64().unwrap_or(0.0);
        let flows = row["flows"].as_i64().unwrap_or(0) as u64;
        let entry = device_map.entry(ip).or_insert_with(|| DeviceInsight {
            mac,
            domains: vec![],
            apps: vec![],
            bytes: 0.0,
            flows: 0,
            dest_set: HashSet::new(),
        });
        entry.apps.push(app.clone());
        entry.bytes += bytes;
        entry.flows += flows;
        if !sni.is_empty() {
            entry.domains.push(sni.clone());
            entry.dest_set.insert(sni);
        }
        if !dns.is_empty() {
            entry.domains.push(dns.clone());
            entry.dest_set.insert(dns);
        }
    }
    // Deduplicate by MAC: keep the IP with most traffic for each MAC
    let mut mac_primary: HashMap<String, (String, f64)> = HashMap::new();
    for (ip, insight) in &device_map {
        let entry = mac_primary
            .entry(insight.mac.clone())
            .or_insert_with(|| (ip.clone(), 0.0));
        if insight.bytes > entry.1 {
            *entry = (ip.clone(), insight.bytes);
        }
    }
    let primary_ips: HashSet<String> = mac_primary.values().map(|(ip, _)| ip.clone()).collect();
    let proxy_macs: HashSet<&str> = ["82:75:35", "e2:08:f4", "5a:e2:02"]
        .iter()
        .cloned()
        .collect();

    let mut device_profiles = Vec::new();
    let mut alerts = Vec::new();
    for (ip, insight) in &device_map {
        let mac_prefix = if insight.mac.len() >= 8 {
            &insight.mac[..8]
        } else {
            ""
        };
        if !primary_ips.contains(ip) || proxy_macs.contains(mac_prefix) {
            continue;
        }
        let dests: Vec<String> = insight.dest_set.iter().cloned().collect();
        let uniq_apps: Vec<String> = {
            let mut s: Vec<String> = insight.apps.clone();
            s.sort();
            s.dedup();
            s.into_iter()
                .filter(|a| !a.is_empty() && a != "Unknown")
                .collect()
        };
        let (dev_type, os, conf) = profile_device(&uniq_apps, &dests, &insight.mac);
        let model = identify_device_model(&uniq_apps, &dests, &insight.mac, "");
        let ip_esc = ch_escape(&ip);
        let base_sql = format!(
            "SELECT COUNT(DISTINCT sni)+COUNT(DISTINCT dns_domain) as c FROM {}.flows \
             WHERE src_ip='{}' AND timestamp>=now()-toIntervalDay(1) AND timestamp<now()-toIntervalMinute(5)",
            state.database, ip_esc
        );
        let baseline_size = ch_one::<serde_json::Value>(&state, &base_sql)
            .await
            .map(|v| v["c"].as_i64().unwrap_or(0) as usize)
            .unwrap_or(0);
        let mut first_seen = Vec::new();
        if baseline_size > 0 {
            for d in &dests {
                let check_sql = format!(
                    "SELECT count() as c FROM {}.flows WHERE src_ip='{}' AND \
                     (sni='{}' OR dns_domain='{}') AND timestamp<now()-toIntervalMinute(5) LIMIT 1",
                    state.database,
                    ip_esc,
                    ch_escape(d),
                    ch_escape(d)
                );
                if let Ok(rows) = ch_query::<serde_json::Value>(&state, &check_sql).await {
                    if rows.first().and_then(|v| v["c"].as_i64()).unwrap_or(0) == 0 {
                        first_seen.push(d.clone());
                    }
                }
            }
        }
        let risk = behavior_score(
            first_seen.len(),
            dests.len(),
            uniq_apps.len(),
            baseline_size,
            insight.flows,
        );
        if risk > 50.0 {
            alerts.push(serde_json::json!({
                "ip": ip, "risk": risk as u32,
                "reason": if first_seen.len() > 5 { format!("大量新目标 ({}个首次访问)", first_seen.len()) }
                          else { format!("行为偏离度 {:.0}%", risk) },
                "type": dev_type, "os": os, "model": model,
            }));
        }
        device_profiles.push(serde_json::json!({
            "ip": ip, "mac": insight.mac, "type": dev_type, "os": os, "confidence": conf,
            "apps": uniq_apps, "active_destinations": dests.len(), "baseline_size": baseline_size,
            "first_seen": first_seen, "risk_score": risk as u32, "bytes_total": insight.bytes, "flows_total": insight.flows,
        }));
    }
    device_profiles.sort_by(|a, b| {
        b["risk_score"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["risk_score"].as_u64().unwrap_or(0))
    });
    alerts.sort_by(|a, b| {
        b["risk"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["risk"].as_u64().unwrap_or(0))
    });
    let total_devices = device_profiles.len();
    let high_risk = device_profiles
        .iter()
        .filter(|d| d["risk_score"].as_u64().unwrap_or(0) > 50)
        .count();
    let apple_devs = device_profiles
        .iter()
        .filter(|d| d["os"].as_str() == Some("iOS") || d["os"].as_str() == Some("macOS"))
        .count();
    let android_devs = device_profiles
        .iter()
        .filter(|d| d["os"].as_str() == Some("Android"))
        .count();
    let win_devs = device_profiles
        .iter()
        .filter(|d| d["os"].as_str() == Some("Windows"))
        .count();
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "summary": {
            "active_devices": total_devices, "high_risk_devices": high_risk,
            "os_breakdown": { "iOS/macOS": apple_devs, "Android": android_devs, "Windows": win_devs, "Other": total_devices - apple_devs - android_devs - win_devs },
            "total_alerts": alerts.len(),
        },
        "devices": device_profiles, "alerts": alerts,
    })))
}

#[utoipa::path(
    get,
    path = "/api/analysis/wechat",
    responses(
        (status = 200, description = "WeChat traffic analysis"),
    ),
    tag = "Analysis"
)]
pub async fn get_wechat_analysis(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let db = &state.database;
    let day = "now()-toIntervalDay(1)";
    let wc = "(app_name='WeChat' OR app_name='微信')";
    let sql_summary = format!(
        "SELECT count() as flows,sum(bytes_up+bytes_down) as bytes,round(avg(duration_ms)) as avg_ms,\
        count(DISTINCT src_ip) as devices,count(DISTINCT dst_ip) as servers FROM {}.flows WHERE {} AND timestamp>={}",
        db, wc, day
    );
    let sql_devices = format!(
        "SELECT src_ip,any(device_manufacturer) as mfg,count() as flows,\
        round(sum(bytes_up+bytes_down)) as bytes,round(avg(duration_ms)) as avg_ms \
        FROM {}.flows WHERE {} AND timestamp>={} AND src_ip LIKE '192.168.%' GROUP BY src_ip ORDER BY bytes DESC LIMIT 10",
        db, wc, day
    );
    let sql_types = format!(
        "SELECT multiIf(duration_ms<100,'heartbeat',duration_ms<1000,'short',duration_ms<5000,'msg',\
        duration_ms<30000,'file','media') as conn_type,count() as c,round(avg(bytes_up+bytes_down)) as avg_bytes,\
        round(sum(bytes_up+bytes_down)) as total_bytes FROM {}.flows WHERE {} AND timestamp>={} GROUP BY conn_type ORDER BY c DESC",
        db, wc, day
    );
    let sql_hourly = format!(
        "SELECT toHour(timestamp) as h,count() as flows,round(sum(bytes_up+bytes_down)) as bytes,\
        count(DISTINCT src_ip) as devices FROM {}.flows WHERE {} AND timestamp>={} GROUP BY h ORDER BY h",
        db, wc, day
    );
    let sql_domains = format!(
        "SELECT dns_domain,count() as hits,count(DISTINCT src_ip) as devices \
        FROM {}.flows WHERE {} AND timestamp>={} AND dns_domain!='' GROUP BY dns_domain ORDER BY hits DESC LIMIT 10",
        db, wc, day
    );
    let sql_total = format!(
        "SELECT count() as f,sum(bytes_up+bytes_down) as b FROM {}.flows WHERE timestamp>={}",
        db, day
    );
    let (r1, r2, r3, r4, r5, r6) = tokio::join!(
        ch_query::<serde_json::Value>(&state, &sql_summary),
        ch_query::<serde_json::Value>(&state, &sql_devices),
        ch_query::<serde_json::Value>(&state, &sql_types),
        ch_query::<serde_json::Value>(&state, &sql_hourly),
        ch_query::<serde_json::Value>(&state, &sql_domains),
        ch_query::<serde_json::Value>(&state, &sql_total),
    );
    match (r1, r2, r3, r4, r5, r6) {
        (Ok(sr), Ok(dev), Ok(types), Ok(hr), Ok(dns), Ok(tr)) => {
            let sum = sr.first().cloned().unwrap_or_default();
            let tot = tr.first().cloned().unwrap_or_default();
            let tb = tot["b"].as_f64().unwrap_or(1.0);
            let wb = sum["bytes"].as_f64().unwrap_or(0.0);
            let pct = if tb > 0.0 {
                (wb / tb * 100.0) as u32
            } else {
                0
            };
            HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                "summary": { "total_connections": sum["flows"], "total_bytes": sum["bytes"],
                    "percent_of_total": pct, "total_flows": tot["f"], "avg_duration_ms": sum["avg_ms"],
                    "devices": sum["devices"], "servers": sum["servers"], },
                "devices": dev, "connection_types": types, "hourly": hr, "domains": dns,
            })))
        }
        (Err(e), _, _, _, _, _)
        | (_, Err(e), _, _, _, _)
        | (_, _, Err(e), _, _, _)
        | (_, _, _, Err(e), _, _)
        | (_, _, _, _, Err(e), _)
        | (_, _, _, _, _, Err(e)) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/http",
    responses(
        (status = 200, description = "HTTP session list"),
    ),
    tag = "Analysis"
)]
pub async fn get_http_sessions(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let sql = format!(
        "SELECT timestamp,host,method,path,status_code,content_type,content_length,user_agent          FROM {}.http_sessions ORDER BY timestamp DESC LIMIT 100",
        state.database
    );
    match ch_query::<serde_json::Value>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/topology",
    responses(
        (status = 200, description = "Network topology data"),
    ),
    tag = "Analysis"
)]
pub async fn get_topology(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let sql = format!(
        "SELECT src_ip,dst_ip,app_name,count() as w,sum(bytes_up+bytes_down) as b          FROM {}.flows WHERE timestamp>=now()-toIntervalHour(1) AND src_ip LIKE '192.168.%'          AND dst_port IN (80,443,8080)         GROUP BY src_ip,dst_ip,app_name ORDER BY b DESC LIMIT 200",
        state.database
    );
    match ch_query::<serde_json::Value>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

/// Timeline: hourly app usage and visited websites.
#[utoipa::path(
    get,
    path = "/api/timeline",
    responses(
        (status = 200, description = "Hourly timeline"),
    ),
    tag = "Analysis"
)]
pub async fn get_timeline(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let sql1 = format!(
        "SELECT toHour(timestamp) as h,app_name,count() as c          FROM {}.flows WHERE timestamp>=now()-toIntervalDay(1)          AND app_name!='' AND app_name!='Unknown'          GROUP BY h,app_name ORDER BY h,c DESC",
        state.database
    );
    let sql2 = format!(
        "SELECT toHour(timestamp) as h,sni,dns_domain,count() as c          FROM {}.flows WHERE timestamp>=now()-toIntervalDay(1)          AND (sni!='' OR dns_domain!='')          GROUP BY h,sni,dns_domain ORDER BY h,c DESC LIMIT 500",
        state.database
    );
    let (r1, r2) = tokio::join!(
        crate::ch_query::<serde_json::Value>(&state, &sql1),
        crate::ch_query::<serde_json::Value>(&state, &sql2),
    );
    match (r1, r2) {
        (Ok(apps), Ok(sites)) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "hourly_apps": apps, "visited_sites": sites,
        }))),
        _ => HttpResponse::InternalServerError().json(api_err("timeline failed")),
    }
}

#[utoipa::path(
    get,
    path = "/api/alerts",
    responses(
        (status = 200, description = "Active alerts"),
    ),
    tag = "Analysis"
)]
pub async fn get_alerts(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let sql = format!(
        "SELECT src_ip,count(DISTINCT sni)+count(DISTINCT dns_domain) as dests,         countDistinct(app_name) as apps,sum(bytes_up+bytes_down) as bytes          FROM {}.flows WHERE timestamp>=now()-toIntervalHour(1)          AND src_ip LIKE '192.168.%'          GROUP BY src_ip HAVING dests>10 OR bytes>10000000 ORDER BY bytes DESC LIMIT 20",
        state.database
    );
    match ch_query::<serde_json::Value>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/health",
    responses(
        (status = 200, description = "Service is healthy"),
        (status = 503, description = "Service unavailable"),
    ),
    tag = "Health"
)]
pub async fn health(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let sql = format!(
        "SELECT count() as total_flows,0 as total_bytes,0 as apps,0 as devices,0 as snis,0 as domains,0 as fps,0 as tcp_flows,0 as udp_flows,0 as throughput_mbps FROM {}.flows",
        state.database
    );
    match ch_one::<StatsRow>(&state, &sql).await {
        Ok(r) => HttpResponse::Ok().json(serde_json::json!({"status":"ok","flows":r.total_flows})),
        Err(e) => HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"status":"error","message":e})),
    }
}

#[utoipa::path(
    get,
    path = "/api/admin/status",
    responses(
        (status = 200, description = "Admin status"),
    ),
    tag = "Admin"
)]
pub async fn get_admin_status(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let uptime = (chrono::Utc::now() - state.started_at).num_seconds().max(0);
    let sql_f = format!(
        "SELECT count() as c, max(timestamp) as t FROM {}.flows",
        state.database
    );
    let sql_h = format!("SELECT count() as c FROM {}.http_sessions", state.database);
    let (r1, r2) = tokio::join!(
        ch_one::<serde_json::Value>(&state, &sql_f),
        ch_one::<serde_json::Value>(&state, &sql_h),
    );
    let mut resp = serde_json::json!({
        "uptime_seconds": uptime, "version": "1.0.0",
    });
    if let Ok(f) = r1 {
        resp["flows"] = f["c"].clone();
        resp["last_flow"] = f["t"].clone();
    }
    if let Ok(h) = r2 {
        resp["http_sessions"] = h["c"].clone();
    }
    HttpResponse::Ok().json(ApiResponse::ok(resp))
}
