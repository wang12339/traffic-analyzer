use crate::routes::*;
use actix_web::{HttpResponse, web};

#[utoipa::path(
    get,
    path = "/api/stats",
    params(TimeQuery),
    responses(
        (status = 200, description = "Aggregated traffic statistics", body = StatsResponse),
    ),
    tag = "Stats"
)]
pub async fn get_stats(state: web::Data<Arc<AppState>>, q: web::Query<TimeQuery>) -> HttpResponse {
    let se = since_expr(q.since.as_deref().unwrap_or("24h"));
    let sql = format!(
        "SELECT count() as total_flows,sum(bytes_up+bytes_down) as total_bytes,\
        countDistinct(app_id) as apps,\
        countDistinct(if(src_ip LIKE '192.168.%' OR src_ip LIKE '10.%', src_ip, NULL)) as devices,\
        countDistinct(if(sni!='',sni,NULL)) as snis,\
        countDistinct(if(dns_domain!='',dns_domain,NULL)) as domains,\
        count()/greatest(1,dateDiff('second',min(timestamp),max(timestamp))) as fps \
        FROM {}.flows WHERE timestamp >= {}",
        state.database, se
    );
    match ch_one::<StatsRow>(&state, &sql).await {
        Ok(r) => HttpResponse::Ok().json(ApiResponse::ok(StatsResponse {
            total_flows: r.total_flows,
            total_bytes: r.total_bytes,
            active_apps: r.apps,
            unique_devices: r.devices,
            unique_snis: r.snis,
            unique_domains: r.domains,
            flows_per_sec: r.fps,
        })),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/flows",
    params(FlowQuery),
    responses(
        (status = 200, description = "List of flows", body = Vec<FlowRow>),
    ),
    tag = "Flows"
)]
pub async fn get_flows(state: web::Data<Arc<AppState>>, q: web::Query<FlowQuery>) -> HttpResponse {
    let limit = q.limit.unwrap_or(100).min(1000);
    let se = since_expr(q.since.as_deref().unwrap_or("1h"));
    let mut cond = format!("timestamp >= {}", se);
    if let Some(ref ip) = q.search_ip {
        if !ip.is_empty() {
            cond.push_str(&format!(
                " AND (src_ip LIKE '%{}%' OR dst_ip LIKE '%{}%')",
                ip, ip
            ));
        }
    }
    if let Some(ref d) = q.search_domain {
        if !d.is_empty() {
            cond.push_str(&format!(
                " AND (sni LIKE '%{}%' OR dns_domain LIKE '%{}%')",
                d, d
            ));
        }
    }
    if let Some(a) = q.app_id {
        if a > 0 {
            cond.push_str(&format!(" AND app_id={}", a));
        }
    }
    let sql = format!(
        "SELECT timestamp,src_ip,dst_ip,src_port,dst_port,protocol,\
        sni,dns_domain,app_name,app_category,confidence,\
        bytes_up,bytes_down,packets_up,packets_down,duration_ms,src_mac \
        FROM {}.flows WHERE {} ORDER BY timestamp DESC LIMIT {}",
        state.database, cond, limit
    );
    match ch_query::<FlowRow>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/apps",
    params(TimeQuery),
    responses(
        (status = 200, description = "Application traffic breakdown", body = Vec<AppRow>),
    ),
    tag = "Apps"
)]
pub async fn get_apps(state: web::Data<Arc<AppState>>, q: web::Query<TimeQuery>) -> HttpResponse {
    let se = since_expr(q.since.as_deref().unwrap_or("24h"));
    let sql = format!(
        "SELECT app_id,app_name,app_category,count() as flow_count,\
        sum(bytes_up+bytes_down) as total_bytes,countDistinct(src_ip) as device_count \
        FROM {}.flows WHERE timestamp>={} GROUP BY app_id,app_name,app_category ORDER BY total_bytes DESC LIMIT 100",
        state.database, se
    );
    match ch_query::<AppRow>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/devices",
    params(TimeQuery),
    responses(
        (status = 200, description = "Device traffic summary", body = Vec<DeviceRow>),
    ),
    tag = "Devices"
)]
pub async fn get_devices(
    state: web::Data<Arc<AppState>>,
    q: web::Query<TimeQuery>,
) -> HttpResponse {
    let se = since_expr(q.since.as_deref().unwrap_or("24h"));
    let sql = format!(
        "SELECT src_ip,count() as flows,sum(bytes_up+bytes_down) as bytes_total,\
        countDistinct(app_name) as app_count,max(timestamp) as last_seen,\
        any(src_mac) as src_mac,countDistinct(if(sni!='',sni,NULL)) as sni_count \
        FROM {}.flows WHERE timestamp>={} GROUP BY src_ip ORDER BY bytes_total DESC LIMIT 100",
        state.database, se
    );
    match ch_query::<DeviceRow>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/dns",
    params(TimeQuery),
    responses(
        (status = 200, description = "DNS query statistics", body = Vec<DnsRow>),
    ),
    tag = "DNS"
)]
pub async fn get_dns(state: web::Data<Arc<AppState>>, q: web::Query<TimeQuery>) -> HttpResponse {
    let se = since_expr(q.since.as_deref().unwrap_or("24h"));
    let sql = format!(
        "SELECT dns_domain,count() as count,countDistinct(src_ip) as clients \
        FROM {}.flows WHERE dns_domain!='' AND timestamp>={} GROUP BY dns_domain ORDER BY count DESC LIMIT 100",
        state.database, se
    );
    match ch_query::<DnsRow>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/sni",
    params(TimeQuery),
    responses(
        (status = 200, description = "SNI statistics", body = Vec<SniRow>),
    ),
    tag = "SNI"
)]
pub async fn get_sni(state: web::Data<Arc<AppState>>, q: web::Query<TimeQuery>) -> HttpResponse {
    let se = since_expr(q.since.as_deref().unwrap_or("24h"));
    let sql = format!(
        "SELECT sni,count() as count,countDistinct(src_ip) as clients \
        FROM {}.flows WHERE sni!='' AND timestamp>={} GROUP BY sni ORDER BY count DESC LIMIT 100",
        state.database, se
    );
    match ch_query::<SniRow>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/trends",
    params(TimeQuery),
    responses(
        (status = 200, description = "Traffic trend time series", body = Vec<TrendRow>),
    ),
    tag = "Trends"
)]
pub async fn get_trends(state: web::Data<Arc<AppState>>, q: web::Query<TimeQuery>) -> HttpResponse {
    let se = since_expr(q.since.as_deref().unwrap_or("24h"));
    let sql = format!(
        "SELECT toStartOfMinute(timestamp) as bucket,count() as flows,\
        sum(bytes_up+bytes_down) as bytes FROM {}.flows WHERE timestamp>={} GROUP BY bucket ORDER BY bucket",
        state.database, se
    );
    match ch_query::<TrendRow>(&state, &sql).await {
        Ok(rows) => HttpResponse::Ok().json(ApiResponse::ok(rows)),
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/export/csv",
    params(FlowQuery),
    responses(
        (status = 200, description = "CSV file with flow data", content_type = "text/csv", body = String),
        (status = 500, description = "Query failed")
    ),
    tag = "Export"
)]
pub async fn export_csv(
    state: web::Data<Arc<AppState>>,
    query: web::Query<FlowQuery>,
) -> HttpResponse {
    let since = query.since.as_deref().unwrap_or("1h");
    let se = since_expr(since);
    let mut cond = format!("timestamp >= {}", se);
    if let Some(ref ip) = query.search_ip {
        if !ip.is_empty() {
            cond.push_str(&format!(
                " AND (src_ip LIKE '%{}%' OR dst_ip LIKE '%{}%')",
                ip, ip
            ));
        }
    }
    if let Some(ref d) = query.search_domain {
        if !d.is_empty() {
            cond.push_str(&format!(
                " AND (sni LIKE '%{}%' OR dns_domain LIKE '%{}%')",
                d, d
            ));
        }
    }
    if let Some(a) = query.app_id {
        if a > 0 {
            cond.push_str(&format!(" AND app_id={}", a));
        }
    }
    let sql = format!(
        "SELECT timestamp,src_ip,dst_ip,app_name,sni,dns_domain,bytes_up+bytes_down as bytes,protocol         FROM {}.flows WHERE {} ORDER BY timestamp DESC LIMIT 10000",
        state.database, cond
    );
    match ch_query::<serde_json::Value>(&state, &sql).await {
        Ok(rows) => {
            let mut csv = String::from("timestamp,src_ip,dst_ip,app,domain,bytes,protocol\n");
            for r in &rows {
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    r["timestamp"].as_str().unwrap_or(""),
                    r["src_ip"].as_str().unwrap_or(""),
                    r["dst_ip"].as_str().unwrap_or(""),
                    r["app_name"].as_str().unwrap_or(""),
                    r["sni"].as_str().unwrap_or("").replace(",", ";"),
                    r["bytes"].as_f64().unwrap_or(0.0) as u64,
                    r["protocol"].as_str().unwrap_or(""),
                ));
            }
            HttpResponse::Ok().content_type("text/csv").body(csv)
        }
        Err(e) => HttpResponse::InternalServerError().json(api_err(&e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/summary",
    responses(
        (status = 200, description = "24-hour traffic summary"),
    ),
    tag = "Summary"
)]
pub async fn get_summary(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let sql_t = format!(
        "SELECT count() as total,sum(bytes_up+bytes_down) as bytes,count(DISTINCT src_ip) as devices,        count(DISTINCT app_name) as apps FROM {}.flows WHERE timestamp>=now()-toIntervalDay(1)",
        state.database
    );
    let sql_w = format!(
        "SELECT app_name,count() as c,round(sum(bytes_up+bytes_down)/1024/1024,1) as mb         FROM {}.flows WHERE timestamp>=now()-toIntervalDay(1) AND app_name!='' AND app_name!='Unknown'         GROUP BY app_name ORDER BY mb DESC LIMIT 5",
        state.database
    );
    let sql_h = format!(
        "SELECT toHour(timestamp) as h,count() as c FROM {}.flows         WHERE timestamp>=now()-toIntervalDay(1) GROUP BY h ORDER BY c DESC LIMIT 3",
        state.database
    );
    let (r1, r2, r3) = tokio::join!(
        ch_one::<serde_json::Value>(&state, &sql_t),
        ch_query::<serde_json::Value>(&state, &sql_w),
        ch_query::<serde_json::Value>(&state, &sql_h),
    );
    match (r1, r2, r3) {
        (Ok(t), Ok(w), Ok(h)) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
            "total_flows": t["total"], "total_mb": (t["bytes"].as_f64().unwrap_or(0.0)/1024.0/1024.0*100.0).round()/100.0,
            "devices": t["devices"], "apps": t["apps"],
            "top_apps": w, "peak_hours": h,
        }))),
        _ => HttpResponse::InternalServerError().json(api_err("summary failed")),
    }
}
