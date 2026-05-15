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
            break; // end of domain name
        }
        // Compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            break; // compression pointer, skip
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_query(labels: &[&[u8]]) -> Vec<u8> {
        let mut buf = vec![
            0x00, 0x01, // transaction ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // 1 question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counts
        ];
        for label in labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label);
        }
        buf.push(0x00); // end of domain
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
        buf
    }

    #[test]
    fn test_basic_query() {
        let buf = make_query(&[b"example", b"com"]);
        assert_eq!(parse_dns_query(&buf).as_deref(), Some("example.com"));
    }

    #[test]
    fn test_multiple_labels() {
        let buf = make_query(&[b"a", b"b", b"c", b"example", b"com"]);
        assert_eq!(parse_dns_query(&buf).as_deref(), Some("a.b.c.example.com"));
    }

    #[test]
    fn test_short_buffer() {
        assert!(parse_dns_query(&[]).is_none());
        assert!(parse_dns_query(&[0u8; 11]).is_none());
    }

    #[test]
    fn test_empty_question_count() {
        let buf = vec![
            0x00, 0x01, // transaction ID
            0x01, 0x00, // flags
            0x00, 0x00, // QDCOUNT = 0 (no questions)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_dns_query(&buf).is_none());
    }

    #[test]
    fn test_compression_pointer() {
        // A response with a compression pointer (top 2 bits set)
        let mut buf = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, // Compression pointer in answer: c00c
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
        ];
        // The question should still be parseable
        let result = parse_dns_query(&buf);
        assert_eq!(result.as_deref(), Some("example.com"));
    }
}
