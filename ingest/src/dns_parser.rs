//! Minimal DNS query parser — extracts queried domain names from UDP payload.

/// Extract the first query name from a DNS request payload.
/// Returns None if the packet is not a valid DNS query or parsing fails.
pub fn parse_dns_query(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    // Standard DNS header: ID(2) + flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos];
        if len == 0 {
            pos += 1;
            break;
        }
        // Compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            // Pointer to elsewhere in the message — skip
            pos += 2;
            break;
        }
        pos += 1;
        if pos + len as usize > buf.len() {
            return None;
        }
        match std::str::from_utf8(&buf[pos..pos + len as usize]) {
            Ok(s) => labels.push(s),
            Err(_) => return None,
        }
        pos += len as usize;
    }

    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

#[test]
fn test_dns_parse() {
    // Minimal DNS query for "example.com"
    let mut buf = vec![
        0x00, 0x01, // transaction ID
        0x01, 0x00, // flags: standard query
        0x00, 0x01, // 1 question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counts
        // Question: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // end of domain
        0x00, 0x01, // type A
        0x00, 0x01, // class IN
    ];
    assert_eq!(parse_dns_query(&buf).as_deref(), Some("example.com"));

    // Invalid: too short
    assert!(parse_dns_query(&[0]).is_none());
}
