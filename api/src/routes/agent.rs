use crate::routes::*;
use actix_web::{HttpResponse, web};

use std::process::Command as Shell;

fn router_ssh(cmd: &str) -> String {
    let output = Shell::new("sshpass")
        .args([
            "-p",
            "admin",
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "root@192.168.66.1",
            cmd,
        ])
        .output();
    match output {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if !err.is_empty() {
                format!("{}\n{}", out, err)
            } else {
                out
            }
        }
        Err(e) => format!("SSH error: {}", e),
    }
}

#[utoipa::path(
    get,
    path = "/api/agent/status",
    responses(
        (status = 200, description = "Agent process status"),
    ),
    tag = "Agent"
)]
pub async fn agent_status() -> HttpResponse {
    let status = router_ssh("ps | grep agent | grep -v grep || echo 'stopped'");
    let log = router_ssh("tail -5 /tmp/agent.log 2>/dev/null || echo 'no log'");
    let iface =
        router_ssh("cat /proc/net/dev | grep br-lan | awk '{print $1, $2, $10}' || echo 'unknown'");
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
        "status": if status.contains("agent") { "running" } else { "stopped" },
        "pid": status.lines().next().unwrap_or(""),
        "interface": iface.trim(),
        "log": log,
    })))
}

#[utoipa::path(
    post,
    path = "/api/agent/start",
    responses(
        (status = 200, description = "Agent started"),
    ),
    tag = "Agent"
)]
pub async fn agent_start() -> HttpResponse {
    let r = router_ssh(
        "killall agent 2>/dev/null; sleep 1; nohup /root/agent -n br-lan -s 192.168.66.186:9100 > /tmp/agent.log 2>&1 &",
    );
    HttpResponse::Ok().json(ApiResponse::ok(
        serde_json::json!({"result": "started", "detail": r}),
    ))
}

#[utoipa::path(
    post,
    path = "/api/agent/stop",
    responses(
        (status = 200, description = "Agent stopped"),
    ),
    tag = "Agent"
)]
pub async fn agent_stop() -> HttpResponse {
    let r = router_ssh("killall agent 2>/dev/null");
    HttpResponse::Ok().json(ApiResponse::ok(
        serde_json::json!({"result": "stopped", "detail": r}),
    ))
}

#[utoipa::path(
    post,
    path = "/api/agent/restart",
    responses(
        (status = 200, description = "Agent restarted"),
    ),
    tag = "Agent"
)]
pub async fn agent_restart() -> HttpResponse {
    let r = router_ssh(
        "killall agent 2>/dev/null; sleep 2; nohup /root/agent -n br-lan -s 192.168.66.186:9100 > /tmp/agent.log 2>&1 &",
    );
    HttpResponse::Ok().json(ApiResponse::ok(
        serde_json::json!({"result": "restarted", "detail": r}),
    ))
}

#[utoipa::path(
    get,
    path = "/api/agent/logs/{lines}",
    params(
        ("lines" = String, Path, description = "Number of log lines to retrieve"),
    ),
    responses(
        (status = 200, description = "Agent log output"),
    ),
    tag = "Agent"
)]
pub async fn agent_logs(path: web::Path<String>) -> HttpResponse {
    let lines = path.into_inner();
    let n: usize = lines.parse().unwrap_or(20);
    let log = router_ssh(&format!("tail -{} /tmp/agent.log 2>/dev/null", n));
    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({"log": log})))
}
