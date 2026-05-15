mod routes;

use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{App, HttpServer, HttpResponse, middleware, web};
use clap::Parser;
use reqwest::Client as HttpClient;
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use routes::AppState;

/// 认证中间件：API_KEY 环境变量设置时检查 X-API-Key 头部
async fn auth_middleware<B: MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, actix_web::Error> {
    let api_key = req
        .app_data::<web::Data<Arc<AppState>>>()
        .map(|d| d.api_key.clone())
        .unwrap_or_default();
    if api_key.is_empty() || req.path() == "/api/health" {
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
    let state = Arc::new(AppState {
        http,
        ch_url: args.clickhouse,
        database: args.db_name,
        api_key: std::env::var("API_KEY").unwrap_or_default(),
        started_at: chrono::Utc::now(),
    });
    match ch_one::<serde_json::Value>(&state, "SELECT 1 as v").await {
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
            // 开发模式默认宽松（可通过设置 ALLOWED_ORIGINS 环境变量限制）
            Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600)
        };
        App::new()
            .wrap(cors)
            .wrap(middleware::from_fn(auth_middleware))
            .wrap(Governor::new(&rate_limiter))
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(state.clone()))
            // Health & status
            .route("/api/health", web::get().to(analysis::health))
            .route(
                "/api/admin/status",
                web::get().to(analysis::get_admin_status),
            )
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
