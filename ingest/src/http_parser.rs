//! Minimal HTTP request parser — extracts method, host, and user-agent.
//! Only used for cleartext HTTP traffic (port 80, 8080, etc.).

/// Parsed HTTP request metadata.
#[derive(Debug, Clone, Default)]
pub struct HttpRequestMeta {
    pub method: String,
    pub host: String,
    pub uri_stem: String,    // first 64 chars of path, for classification only
    pub user_agent: String,
}

/// Attempt to extract HTTP request info from a TCP payload.
/// Returns None if the payload doesn't look like an HTTP request.
pub fn parse_http_request(buf: &[u8]) -> Option<HttpRequestMeta> {
    if buf.len() < 8 {
        return None;
    }

    // Check for common HTTP methods
    let method = if buf.starts_with(b"GET ") {
        "GET"
    } else if buf.starts_with(b"POST ") {
        "POST"
    } else if buf.starts_with(b"PUT ") {
        "PUT"
    } else if buf.starts_with(b"DELETE ") {
        "DELETE"
    } else if buf.starts_with(b"HEAD ") {
        "HEAD"
    } else if buf.starts_with(b"OPTIONS ") {
        "OPTIONS"
    } else if buf.starts_with(b"PATCH ") {
        "PATCH"
    } else if buf.starts_with(b"CONNECT ") {
        "CONNECT"
    } else {
        return None;
    };

    // Convert to string (best-effort)
    let s = std::str::from_utf8(buf).ok()?;
    let lines: Vec<&str> = s.splitn(10, "\r\n").collect();
    if lines.is_empty() {
        return None;
    }

    // First line: METHOD /path HTTP/1.1
    let req_line = lines[0];
    let parts: Vec<&str> = req_line.splitn(3, ' ').collect();
    let uri = if parts.len() >= 2 { parts[1] } else { "/" };
    let uri_stem = uri.chars().take(64).collect::<String>();

    let mut host = String::new();
    let mut user_agent = String::new();

    for line in &lines[1..] {
        if line.is_empty() {
            break;
        }
        if line.len() > 4 {
            let lower = line.to_lowercase();
            if lower.starts_with("host:") {
                host = line[5..].trim().to_string();
            } else if lower.starts_with("user-agent:") {
                user_agent = line[11..].trim().chars().take(128).collect();
            }
        }
        if !host.is_empty() && !user_agent.is_empty() {
            break;
        }
    }

    Some(HttpRequestMeta {
        method: method.to_string(),
        host,
        uri_stem,
        user_agent,
    })
}

/// Parse a CONNECT request (HTTP proxy) to extract target host.
pub fn parse_connect_request(buf: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(buf).ok()?;
    if !s.starts_with("CONNECT ") {
        return None;
    }
    // CONNECT host:port HTTP/1.1
    let rest = s.trim_start_matches("CONNECT ");
    let host_port = rest.splitn(2, ' ').next()?;
    let host = host_port.split(':').next()?;
    if host.is_empty() { None } else { Some(host.to_string()) }
}

#[test]
fn test_http_parse() {
    let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n";
    let parsed = parse_http_request(req).unwrap();
    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.host, "example.com");
    assert_eq!(parsed.user_agent, "curl/8.0");

    let connect = b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n";
    assert_eq!(parse_connect_request(connect).as_deref(), Some("api.example.com"));
}
