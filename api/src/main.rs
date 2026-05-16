mod routes;

use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{middleware, web, App, HttpResponse, HttpServer};
use clap::Parser;
use reqwest::Client as HttpClient;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use routes::AppState;

/// 日志中间件：给每个请求分配 trace ID，记录方法和耗时。
async fn tracing_middleware<B: MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, actix_web::Error> {
    let method = req.method().to_string();
    let path = req.path().to_string();
    let request_id = uuid::Uuid::new_v4().to_string();
    let start = std::time::Instant::now();

    // Capture AppState from the request before consuming it
    let state = req.app_data::<web::Data<AppState>>().cloned();

    let span =
        tracing::info_span!("request", request_id = %request_id, method = %method, path = %path);
    let _guard = span.enter();

    let res = next.call(req).await?;
    let status = res.status().as_u16();
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    info!("{} {} -> {} ({:.1}ms)", method, path, status, duration_ms);

    // Update metrics
    if let Some(s) = &state {
        s.total_requests.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut pc) = s.path_counts.lock() {
            *pc.entry(path).or_insert(0) += 1;
        }
    }

    Ok(res)
}

/// 认证中间件：API_KEY 环境变量设置时检查 X-API-Key 头部。
async fn auth_middleware<B: MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, actix_web::Error> {
    let api_key = req
        .app_data::<web::Data<AppState>>()
        .map(|d| d.api_key.clone())
        .unwrap_or_default();
    // 免认证路径：健康检查、API 文档。所有来源均需认证（不再对 loopback 放行）。
    if api_key.is_empty() || req.path() == "/api/health" || req.path().starts_with("/api/docs/") {
        return next.call(req).await;
    }
    let key = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if key == api_key {
        return next.call(req).await;
    }
    warn!(
        "Auth failure: method={}, path={}, peer={:?}",
        req.method(),
        req.path(),
        req.peer_addr(),
    );
    let res = HttpResponse::Unauthorized()
        .json(serde_json::json!({"success": false, "error": "invalid api key"}));
    Err(actix_web::error::InternalError::from_response("", res).into())
}

use routes::*;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_target(false)
        .init();
    let args = routes::Args::parse();
    info!("API: listen={}, ch={}", args.listen, args.clickhouse);
    let http = HttpClient::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    // Require API_KEY: default to a random key (logged at startup) instead of empty.
    // Set API_KEY env var explicitly to use a known value.
    let api_key = std::env::var("API_KEY").unwrap_or_else(|_| {
        let key = uuid::Uuid::new_v4().to_string();
        info!(
            "No API_KEY set — generated random key for this session: {}",
            key
        );
        info!("Set API_KEY env var to use a persistent key (e.g. export API_KEY=my-key)");
        key
    });
    let state = web::Data::new(AppState {
        http,
        ch_url: args.clickhouse,
        database: args.db_name,
        api_key,
        started_at: chrono::Utc::now(),
        resolved_ips: std::sync::Mutex::new(std::collections::HashSet::new()),
        total_requests: AtomicU64::new(0),
        path_counts: Mutex::new(HashMap::new()),
        ch_errors: AtomicU64::new(0),
    });
    match ch_one::<serde_json::Value>(&*state, "SELECT 1 as v").await {
        Ok(_) => info!("CH OK"),
        Err(e) => warn!("CH: {}", e),
    }
    // Rate limiting: 30 requests/second per IP, burst up to 60
    let rate_limiter = GovernorConfigBuilder::default()
        .requests_per_second(30)
        .burst_size(60)
        .finish()
        .expect("rate limiter config");

    HttpServer::new(move || {
        let cors = if let Ok(origins) = std::env::var("ALLOWED_ORIGINS") {
            let mut c = Cors::default()
                .allow_any_method()
                .allow_any_header()
                .supports_credentials()
                .max_age(3600);
            for o in origins.split(',') {
                c = c.allowed_origin(o.trim());
            }
            c
        } else {
            warn!("ALLOWED_ORIGINS not set — CORS denied by default. Set ALLOWED_ORIGINS env var (comma-separated) to allow cross-origin requests.");
            Cors::default()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600)
        };
        App::new()
            .wrap(cors)
            .wrap(middleware::from_fn(tracing_middleware))
            .wrap(middleware::from_fn(auth_middleware))
            .wrap(Governor::new(&rate_limiter))
            .app_data(state.clone())
            // Health & status
            .route("/api/health", web::get().to(analysis::health))
            .route(
                "/api/admin/status",
                web::get().to(analysis::get_admin_status),
            )
            .route("/api/metrics", web::get().to(analysis::get_metrics))
            // Data queries
            .route("/api/stats", web::get().to(queries::get_stats))
            .route("/api/flows", web::get().to(queries::get_flows))
            .route("/api/apps", web::get().to(queries::get_apps))
            .route("/api/devices", web::get().to(queries::get_devices))
            .route("/api/dns", web::get().to(queries::get_dns))
            .route("/api/sni", web::get().to(queries::get_sni))
            .route("/api/trends", web::get().to(queries::get_trends))
            .route("/api/export/csv", web::get().to(queries::export_csv))
            .route("/api/summary", web::get().to(queries::get_summary))
            // Analysis & insights
            .route("/api/live", web::get().to(analysis::get_live))
            .route(
                "/api/device/{ip}",
                web::get().to(analysis::get_device_detail),
            )
            .route(
                "/api/device/{ip}/current",
                web::get().to(analysis::get_device_current),
            )
            .route(
                "/api/device/{ip}/anomalies",
                web::get().to(analysis::get_device_anomalies),
            )
            .route(
                "/api/device/{ip}/trends",
                web::get().to(analysis::get_device_trends),
            )
            .route(
                "/api/device/{ip}/tls-fingerprints",
                web::get().to(analysis::get_device_tls_fingerprints),
            )
            .route("/api/insights", web::get().to(analysis::get_insights))
            .route(
                "/api/analysis/wechat",
                web::get().to(analysis::get_wechat_analysis),
            )
            .route("/api/http", web::get().to(analysis::get_http_sessions))
            .route("/api/topology", web::get().to(analysis::get_topology))
            .route("/api/timeline", web::get().to(analysis::get_timeline))
            .route("/api/alerts", web::get().to(analysis::get_alerts))
            .route("/api/anomalies", web::get().to(analysis::get_anomalies))
            .route("/api/anomalies/{ip}/resolve", web::post().to(analysis::resolve_anomalies))
            // Geo IP lookup
            .route("/api/geo-lookup", web::get().to(geo::geo_lookup))
            // Agent management
            .route("/api/agent/status", web::get().to(agent::agent_status))
            .route("/api/agent/start", web::post().to(agent::agent_start))
            .route("/api/agent/stop", web::post().to(agent::agent_stop))
            .route("/api/agent/restart", web::post().to(agent::agent_restart))
            .route("/api/agent/logs/{lines}", web::get().to(agent::agent_logs))
            // Swagger UI
            .service(
                SwaggerUi::new("/api/docs/{_:.*}")
                    .url("/api/docs/openapi.json", routes::doc::ApiDoc::openapi()),
            )
    })
    .bind(&args.listen)?
    .run()
    .await?;
    Ok(())
}
