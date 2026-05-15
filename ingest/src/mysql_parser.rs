//! MySQL protocol parser — extracts handshake metadata and command types.
//! Detects dangerous SQL operations (DROP, ALTER, TRUNCATE, etc.).

use std::str;

/// MySQL handshake metadata (from server greeting).
pub struct MysqlHandshake {
    pub server_version: String,
    pub connection_id: u32,
    pub auth_plugin: String,
}

/// MySQL command metadata (from client commands).
pub struct MysqlCommand {
    pub command_type: String, // "QUERY", "INIT_DB", "PING", "QUIT", "STMT_PREPARE"
    pub query_summary: String, // first 40 chars of query
    pub dangerous: bool,      // DROP, ALTER, TRUNCATE, GRANT, etc.
}

/// Parse MySQL server handshake from TCP payload.
/// Handshake starts with protocol_version (usually 0x0a = 10).
pub fn parse_handshake(buf: &[u8]) -> Option<MysqlHandshake> {
    if buf.len() < 4 {
        return None;
    }
    // Protocol version: 10 (MySQL 5.x/8.x), 11 (MariaDB)
    let _proto_ver = buf[0];
    if _proto_ver != 10 && _proto_ver != 11 {
        return None;
    }

    // Server version: null-terminated string
    let null_pos = buf[1..].iter().position(|&b| b == 0)?;
    let version = str::from_utf8(&buf[1..1 + null_pos]).ok()?;

    // Connection ID: 4 bytes after version string + null
    let mut pos = 1 + null_pos + 1;
    if pos + 4 > buf.len() {
        return None;
    }
    let conn_id = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
    pos += 4;

    // Auth plugin data part 1: 8 bytes
    if pos + 8 > buf.len() {
        return None;
    }
    pos += 8;

    // Filler (1 byte = 0x00)
    if pos >= buf.len() {
        return None;
    }
    pos += 1;

    // Capability flags (2 bytes, lower 16 bits)
    if pos + 2 > buf.len() {
        return None;
    }
    let _cap_lower = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    // Character set (1 byte)
    if pos >= buf.len() {
        return None;
    }
    pos += 1;

    // Status flags (2 bytes)
    if pos + 2 > buf.len() {
        return None;
    }
    pos += 2;

    // Capability flags (2 bytes, upper 16 bits)
    if pos + 2 > buf.len() {
        return None;
    }
    let cap_flags = (u16::from_le_bytes([buf[pos], buf[pos + 1]]) as u32) << 16 | _cap_lower as u32;
    pos += 2;

    // Length of auth plugin data (1 byte)
    let auth_data_len = if pos < buf.len() {
        buf[pos] as usize
    } else {
        0
    };
    if auth_data_len > 0 {
        pos += 1;
        // Skip remaining auth data (auth_data_len - 8)
        if auth_data_len > 8 {
            pos += auth_data_len - 8;
        }
    }

    // Auth plugin name (null-terminated, only if CLIENT_PLUGIN_AUTH is set)
    let auth_plugin = if cap_flags & 0x00080000 != 0 && pos < buf.len() {
        let rest = &buf[pos..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        str::from_utf8(&rest[..end])
            .unwrap_or("mysql_native_password")
            .to_string()
    } else {
        "mysql_native_password".to_string()
    };

    let version_str = version.split('-').next().unwrap_or(version).to_string();

    Some(MysqlHandshake {
        server_version: version_str,
        connection_id: conn_id,
        auth_plugin,
    })
}

/// Parse MySQL command packet from client.
/// Command packet format: length(3) + seq(1) + command(1) + payload
/// But in our raw TCP stream, we get the payload after the header.
/// MySQL command IDs:
///   0x00 = COM_SLEEP, 0x01 = COM_QUIT, 0x02 = COM_INIT_DB
///   0x03 = COM_QUERY, 0x04 = COM_FIELD_LIST, 0x05 = COM_CREATE_DB
///   0x06 = COM_DROP_DB, 0x07 = COM_REFRESH, 0x08 = COM_SHUTDOWN
///   0x09 = COM_STATISTICS, 0x0E = COM_PING, 0x16 = COM_STMT_PREPARE
///   0x17 = COM_STMT_EXECUTE, 0x1A = COM_STMT_CLOSE
pub fn parse_command(buf: &[u8]) -> Option<MysqlCommand> {
    if buf.is_empty() {
        return None;
    }

    let cmd_id = buf[0];
    let cmd_name = match cmd_id {
        0x01 => "QUIT",
        0x02 => "INIT_DB",
        0x03 => "QUERY",
        0x04 => "FIELD_LIST",
        0x05 => "CREATE_DB",
        0x06 => "DROP_DB",
        0x07 => "REFRESH",
        0x08 => "SHUTDOWN",
        0x09 => "STATISTICS",
        0x0E => "PING",
        0x16 => "STMT_PREPARE",
        0x17 => "STMT_EXECUTE",
        0x18 => "STMT_SEND_LONG_DATA",
        0x19 => "STMT_CLOSE",
        0x1A => "STMT_FETCH",
        0x1B => "STMT_RESET",
        0x1C => "SET_OPTION",
        _ => "UNKNOWN",
    };

    // Extract query text (for QUERY, INIT_DB, STMT_PREPARE)
    let query_summary = if buf.len() > 1 {
        let s = str::from_utf8(&buf[1..]).unwrap_or("");
        s.chars().take(40).collect::<String>()
    } else {
        String::new()
    };

    // Detect dangerous operations
    let upper = query_summary.to_uppercase();
    let dangerous = cmd_id == 0x06  // DROP_DB
        || upper.starts_with("DROP ")
        || upper.starts_with("ALTER ")
        || upper.starts_with("TRUNCATE ")
        || upper.starts_with("GRANT ")
        || upper.starts_with("REVOKE ")
        || upper.starts_with("CREATE USER")
        || upper.starts_with("KILL ")
        || upper.contains("INTO OUTFILE")
        || upper.contains("INTO DUMPFILE")
        || upper.contains("LOAD_FILE")
        || (cmd_id == 0x17 && !upper.is_empty()); // STMT_EXECUTE (could be anything)

    Some(MysqlCommand {
        command_type: cmd_name.to_string(),
        query_summary,
        dangerous,
    })
}
