use utoipa::OpenApi;

use crate::routes::analysis::{self, DestInfo, LiveDevice, LiveSnapshot};
use crate::routes::*;
use crate::routes::{agent, queries};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Traffic Analyzer",
        description = "Real-time network traffic analysis API for OpenWrt"
    ),
    paths(
        queries::get_stats,
        queries::get_flows,
        queries::get_apps,
        queries::get_devices,
        queries::get_dns,
        queries::get_sni,
        queries::get_trends,
        queries::export_csv,
        queries::get_summary,
        analysis::health,
        analysis::get_admin_status,
        analysis::get_live,
        analysis::get_device_detail,
        analysis::get_device_current,
        analysis::get_device_anomalies,
        analysis::get_insights,
        analysis::get_wechat_analysis,
        analysis::get_http_sessions,
        analysis::get_topology,
        analysis::get_timeline,
        analysis::get_alerts,
        agent::agent_status,
        agent::agent_start,
        agent::agent_stop,
        agent::agent_restart,
        agent::agent_logs,
    ),
    components(
        schemas(
            StatsResponse,
            FlowRow,
            AppRow,
            DeviceRow,
            DnsRow,
            SniRow,
            TrendRow,
            DeviceDetailRow,
            LiveSnapshot,
            LiveDevice,
            DestInfo,
            FlowQuery,
            TimeQuery,
        )
    ),
    tags(
        (name = "Health", description = "Service health and admin status"),
        (name = "Stats", description = "Aggregated traffic statistics"),
        (name = "Flows", description = "Detailed flow records"),
        (name = "Apps", description = "Application traffic breakdown"),
        (name = "Devices", description = "Device-level traffic and details"),
        (name = "DNS", description = "DNS query statistics"),
        (name = "SNI", description = "SNI/TLS hostname statistics"),
        (name = "Trends", description = "Traffic trend time series"),
        (name = "Export", description = "CSV data export"),
        (name = "Summary", description = "Summary and overview"),
        (name = "Live", description = "Real-time traffic snapshot"),
        (name = "Analysis", description = "Deep traffic analysis"),
        (name = "Admin", description = "Administrative endpoints"),
        (name = "Agent", description = "Remote agent management"),
    )
)]
pub struct ApiDoc;
