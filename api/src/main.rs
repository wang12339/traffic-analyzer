mod routes;

use std::sync::Arc;
use actix_cors::Cors;
use actix_web::{web, App, HttpServer, middleware};
use clap::Parser;
use reqwest::Client as HttpClient;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use routes::*;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into())).with_target(false).init();
    let args = routes::Args::parse();
    info!("API: listen={}, ch={}", args.listen, args.clickhouse);
    let http = HttpClient::builder().timeout(std::time::Duration::from_secs(10)).build()?;
    let state = Arc::new(AppState { http, ch_url: args.clickhouse, database: args.db_name, api_key: std::env::var("API_KEY").unwrap_or_default() });
    match ch_one::<serde_json::Value>(&state, "SELECT 1 as v").await { Ok(_) => info!("CH OK"), Err(e) => warn!("CH: {}", e) }
    HttpServer::new(move || {
        let cors = Cors::default().allow_any_origin().allow_any_method().allow_any_header().max_age(3600);
        App::new()
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(state.clone()))
            // Health & status
            .route("/api/health", web::get().to(analysis::health))
            .route("/api/admin/status", web::get().to(analysis::get_admin_status))
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
            .route("/api/device/{ip}", web::get().to(analysis::get_device_detail))
            .route("/api/device/{ip}/current", web::get().to(analysis::get_device_current))
            .route("/api/device/{ip}/anomalies", web::get().to(analysis::get_device_anomalies))
            .route("/api/insights", web::get().to(analysis::get_insights))
            .route("/api/analysis/wechat", web::get().to(analysis::get_wechat_analysis))
            .route("/api/http", web::get().to(analysis::get_http_sessions))
            .route("/api/topology", web::get().to(analysis::get_topology))
            .route("/api/timeline", web::get().to(analysis::get_timeline))
            .route("/api/alerts", web::get().to(analysis::get_alerts))
            // Agent management
            .route("/api/agent/status", web::get().to(agent::agent_status))
            .route("/api/agent/start", web::post().to(agent::agent_start))
            .route("/api/agent/stop", web::post().to(agent::agent_stop))
            .route("/api/agent/restart", web::post().to(agent::agent_restart))
            .route("/api/agent/logs/{lines}", web::get().to(agent::agent_logs))
    }).bind(&args.listen)?.run().await?;
    Ok(())
}
