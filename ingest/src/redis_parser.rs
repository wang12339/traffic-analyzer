//! Redis RESP protocol parser — extracts commands and detects dangerous operations.
//! Supports inline commands and RESP arrays (typical for redis-cli and most clients).

use std::str;

/// Redis command metadata.
pub struct RedisCommand {
    pub command: String, // uppercase command name (e.g. "AUTH", "GET", "FLUSHALL")
    pub has_auth: bool,  // whether this is an AUTH command
    pub db_index: Option<u32>, // SELECT db index
    pub dangerous: bool, // FLUSHALL, CONFIG, SLAVEOF, DEBUG, etc.
}

/// Dangerous Redis commands that indicate recon/attack behavior.
const DANGEROUS_CMDS: &[&str] = &[
    "FLUSHALL",
    "FLUSHDB",
    "CONFIG",
    "SLAVEOF",
    "REPLICAOF",
    "DEBUG",
    "SHUTDOWN",
    "BGREWRITEAOF",
    "BGSAVE",
    "MONITOR",
    "CLIENT",
    "SLOWLOG",
    "OBJECT",
    "EVAL",
    "EVALSHA",
    "SCRIPT",
    "MODULE",
    "ACL",
    "ROLE",
    "MIGRATE",
    "RESTORE",
    "SORT",
    "KEYS",
    "SCAN",
];

/// Parse a Redis command from TCP payload.
/// Handles both inline commands and RESP protocol arrays.
pub fn parse_command(buf: &[u8]) -> Option<RedisCommand> {
    if buf.is_empty() {
        return None;
    }

    let text = str::from_utf8(buf).ok()?;

    // Inline command: plain text ending with \r\n or \n
    if !text.starts_with('*') {
        let line = text.trim_end_matches("\r\n").trim_end_matches('\n');
        if line.is_empty() {
            return None;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }
        let cmd = parts[0].to_uppercase();
        let cmd_clone = cmd.clone();
        return Some(RedisCommand {
            command: cmd_clone,
            has_auth: parts[0].eq_ignore_ascii_case("AUTH"),
            db_index: if parts[0].eq_ignore_ascii_case("SELECT") && parts.len() > 1 {
                parts[1].parse::<u32>().ok()
            } else {
                None
            },
            dangerous: DANGEROUS_CMDS.iter().any(|d| d.eq_ignore_ascii_case(&cmd)),
        });
    }

    // RESP array: *N\r\n$L\r\n...command...\r\n
    // Find the first element after the array header
    let rest = text.strip_prefix('*')?;
    let count_end = rest.find("\r\n")?;
    let _count: usize = rest[..count_end].parse().ok()?;
    let payload = &rest[count_end + 2..];

    // First bulk string is the command
    if let Some(cmd_str) = parse_resp_bulk_string(payload) {
        let cmd = cmd_str.to_uppercase();
        let rest_after_cmd = if payload.starts_with('$') {
            // Find \r\n after the command string
            let s = payload.strip_prefix('$')?;
            let len_end = s.find("\r\n")?;
            let strlen: usize = s[..len_end].parse().ok()?;
            &payload[1 + len_end + 2 + strlen + 2..]
        } else {
            ""
        };

        // Check for SELECT command to extract db index
        let db_index = if cmd == "SELECT" {
            if let Some(arg) = parse_resp_bulk_string(rest_after_cmd) {
                arg.parse::<u32>().ok()
            } else {
                None
            }
        } else {
            None
        };

        let cmd_clone = cmd.clone();
        return Some(RedisCommand {
            command: cmd_clone,
            has_auth: cmd_str.eq_ignore_ascii_case("AUTH"),
            db_index,
            dangerous: DANGEROUS_CMDS.iter().any(|d| d.eq_ignore_ascii_case(&cmd)),
        });
    }

    None
}

/// Parse a RESP bulk string: $L\r\n<data>\r\n
fn parse_resp_bulk_string(s: &str) -> Option<String> {
    let s = s.strip_prefix('$')?;
    let len_end = s.find("\r\n")?;
    let strlen: usize = s[..len_end].parse().ok()?;
    let data_start = len_end + 2;
    let data_end = data_start + strlen;
    if data_end > s.len() {
        return None;
    }
    Some(s[data_start..data_end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inline_auth() {
        let r = parse_command(b"AUTH mypassword\r\n").unwrap();
        assert_eq!(r.command, "AUTH");
        assert!(r.has_auth);
    }

    #[test]
    fn test_inline_get() {
        let r = parse_command(b"GET mykey\r\n").unwrap();
        assert_eq!(r.command, "GET");
        assert!(!r.dangerous);
    }

    #[test]
    fn test_resp_command() {
        let r = parse_command(b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n").unwrap();
        assert_eq!(r.command, "SET");
    }

    #[test]
    fn test_resp_auth() {
        let r = parse_command(b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n").unwrap();
        assert_eq!(r.command, "AUTH");
        assert!(r.has_auth);
    }

    #[test]
    fn test_dangerous_flushall() {
        let r = parse_command(b"FLUSHALL\r\n").unwrap();
        assert!(r.dangerous);
        assert_eq!(r.command, "FLUSHALL");
    }

    #[test]
    fn test_dangerous_config() {
        let r = parse_command(b"*2\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n").unwrap();
        assert!(r.dangerous);
        assert_eq!(r.command, "CONFIG");
    }

    #[test]
    fn test_select_db() {
        let r = parse_command(b"*2\r\n$6\r\nSELECT\r\n$1\r\n5\r\n").unwrap();
        assert_eq!(r.command, "SELECT");
        assert_eq!(r.db_index, Some(5));
    }

    #[test]
    fn test_empty_input() {
        assert!(parse_command(b"").is_none());
        assert!(parse_command(b"\r\n").is_none());
    }

    #[test]
    fn test_safe_commands() {
        let r = parse_command(b"PING\r\n").unwrap();
        assert_eq!(r.command, "PING");
        assert!(!r.dangerous);

        let r = parse_command(b"*1\r\n$4\r\nINFO\r\n").unwrap();
        assert_eq!(r.command, "INFO");
        assert!(!r.dangerous);
    }
}
