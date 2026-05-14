//! TLS 1.2/1.3 ClientHello parser — extracts SNI, JA3, TLS version.
//! Handles records that may span multiple TCP segments (via buffered input).

use sha2::{Digest, Sha256};

const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const TLS_EXT_SNI: u16 = 0x0000;
const TLS_EXT_ALPN: u16 = 0x0010;
const TLS_EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const TLS_EXT_EC_POINT_FORMATS: u16 = 0x000b;
const TLS_EXT_KEY_SHARE: u16 = 0x0033;
const TLS_EXT_PSK_MODES: u16 = 0x002d;
const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const TLS_EXT_COMPRESS_CERT: u16 = 0x001b;
const TLS_EXT_APPLICATION_LAYER: u16 = 0x0017;
const TLS_EXT_STATUS_REQUEST: u16 = 0x0005;
const TLS_EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const TLS_EXT_SCT: u16 = 0x0012;
const TLS_EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const TLS_EXT_SESSION_TICKET: u16 = 0x0023;
const TLS_EXT_QUIC_TRANSPORT: u16 = 0x0039;
const TLS_EXT_ENCRYPT_THEN_MAC: u16 = 0x0016;
const TLS_EXT_PADDING: u16 = 0x0015;
const TLS_EXT_RENEGOTIATION_INFO: u16 = 0xff01;
const TLS_EXT_POST_HANDSHAKE_AUTH: u16 = 0x0032;
const TLS_EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
const TLS_EXT_EARLY_DATA: u16 = 0x002a;
const TLS_EXT_COOKIE: u16 = 0x002c;
const TLS_EXT_CERT_AUTHORITIES: u16 = 0x002f;
const TLS_EXT_OID_FILTERS: u16 = 0x003a;

/// Parsed TLS ClientHello metadata.
#[derive(Debug, Clone, Default)]
pub struct TlsClientHello {
    pub sni: String,
    pub ja3: String,
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

/// Parse a TLS ClientHello from a TCP payload buffer.
/// Returns None if the buffer doesn't contain (or start with) a ClientHello.
pub fn parse_client_hello(buf: &[u8]) -> Option<TlsClientHello> {
    if buf.len() < 6 || buf[0] != TLS_CONTENT_HANDSHAKE {
        return None;
    }

    let tls_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if tls_len < 4 || tls_len > buf.len() - 5 {
        return None;
    }

    let handshake = &buf[5..5 + tls_len];
    if handshake.is_empty() || handshake[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    let hs_len = (handshake[1] as usize) << 16 | (handshake[2] as usize) << 8 | handshake[3] as usize;
    if hs_len < 34 || hs_len > handshake.len() - 4 {
        return None;
    }

    let ch = &handshake[4..4 + hs_len];
    let tls_version = u16::from_be_bytes([ch[0], ch[1]]);

    // ─── Parse ClientHello body ───
    let mut pos = 34; // version(2) + random(32)

    // Session ID
    if pos >= ch.len() { return None; }
    let sid_len = ch[pos] as usize;
    pos += 1 + sid_len;

    // Cipher Suites
    if pos + 2 > ch.len() { return None; }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > ch.len() { return None; }
    let cipher_suites: Vec<u16> = if cs_len % 2 == 0 {
        ch[pos..pos + cs_len].chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
    } else {
        vec![]
    };
    pos += cs_len;

    // Compression Methods
    if pos >= ch.len() { return None; }
    let comp_len = ch[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > ch.len() {
        // No extensions — still valid, no SNI
        let ja3 = compute_ja3(&tls_version, &cipher_suites, &[], &[], &[]);
        return Some(TlsClientHello {
            sni: String::new(),
            ja3,
            tls_version,
            cipher_suites,
            extensions: vec![],
            supported_groups: vec![],
            ec_point_formats: vec![],
        });
    }

    let ext_total_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;
    if ext_end > ch.len() { return None; }

    let mut sni = String::new();
    let mut extensions = Vec::with_capacity(32);
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();

    while pos + 4 <= ext_end && pos + 4 <= ch.len() {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        // Skip padding extension (often huge, up to ~512 bytes)
        if ext_type == TLS_EXT_PADDING {
            pos += ext_len;
            continue;
        }

        extensions.push(ext_type);

        if ext_type == TLS_EXT_SNI && ext_len > 5 {
            let sni_list_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
            if pos + 3 + sni_list_len <= ch.len() && pos + 3 < ch.len() {
                let name_type = ch[pos + 2];
                let name_len = u16::from_be_bytes([ch[pos + 3], ch[pos + 4]]) as usize;
                if name_type == 0x00 && name_len > 0 && pos + 5 + name_len <= ch.len() {
                    if let Ok(n) = std::str::from_utf8(&ch[pos + 5..pos + 5 + name_len]) {
                        sni = n.to_string();
                    }
                }
            }
        } else if ext_type == TLS_EXT_SUPPORTED_GROUPS && ext_len > 2 {
            let glen = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
            if glen % 2 == 0 && pos + 2 + glen <= ch.len() {
                supported_groups = ch[pos + 2..pos + 2 + glen]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
            }
        } else if ext_type == TLS_EXT_EC_POINT_FORMATS && ext_len > 0 {
            let flen = ch[pos] as usize;
            if pos + 1 + flen <= ch.len() {
                ec_point_formats = ch[pos + 1..pos + 1 + flen].to_vec();
            }
        }

        pos += ext_len;
    }

    let ja3 = compute_ja3(&tls_version, &cipher_suites, &extensions, &supported_groups, &ec_point_formats);

    Some(TlsClientHello {
        sni,
        ja3,
        tls_version,
        cipher_suites,
        extensions,
        supported_groups,
        ec_point_formats,
    })
}

fn compute_ja3(
    version: &u16,
    ciphers: &[u16],
    extensions: &[u16],
    groups: &[u16],
    points: &[u8],
) -> String {
    // JA3 format: version,ciphers;extensions;groups;points
    let cs = ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-");
    let exts = extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-");
    let grps = groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-");
    let pts = points.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("-");

    let raw = format!("{},{};{};{};{}", version, cs, exts, grps, pts);
    let hash = hex::encode(Sha256::digest(raw.as_bytes()));
    hash
}

/// Parse a TLS ServerHello for JA3S (server response fingerprint).
#[derive(Debug, Clone, Default)]
pub struct TlsServerHello {
    pub ja3s: String,
    pub cipher_suite: u16,
    pub tls_version: u16,
}

pub fn parse_server_hello(buf: &[u8]) -> Option<TlsServerHello> {
    if buf.len() < 6 || buf[0] != TLS_CONTENT_HANDSHAKE {
        return None;
    }
    let tls_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if tls_len < 4 || tls_len > buf.len() - 5 { return None; }

    let handshake = &buf[5..5 + tls_len];
    if handshake.is_empty() || handshake[0] != TLS_HANDSHAKE_SERVER_HELLO { return None; }

    let hs_len = (handshake[1] as usize) << 16 | (handshake[2] as usize) << 8 | handshake[3] as usize;
    if hs_len < 38 || hs_len > handshake.len() - 4 { return None; }

    let sh = &handshake[4..4 + hs_len];
    let tls_version = u16::from_be_bytes([sh[0], sh[1]]);
    let cipher_suite = u16::from_be_bytes([sh[34], sh[35]]);

    // For JA3S: version,ciphersuite;extensions
    let mut pos = 36 + 1 + sh[36] as usize; // version + random + session_id
    if pos + 2 > sh.len() {
        let raw = format!("{},{};", tls_version, cipher_suite);
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));
        return Some(TlsServerHello { ja3s: hash, cipher_suite, tls_version });
    }

    let ext_len = u16::from_be_bytes([sh[pos], sh[pos + 1]]) as usize;
    pos += 2;
    let exts_end = pos + ext_len;
    let mut exts = Vec::new();
    while pos + 4 <= sh.len().min(exts_end) {
        let ext_type = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
        exts.push(ext_type);
        let elen = u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]) as usize;
        pos += 4 + elen;
    }

    let exts_str = exts.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-");
    let raw = format!("{},{};{}", tls_version, cipher_suite, exts_str);
    let hash = hex::encode(Sha256::digest(raw.as_bytes()));
    Some(TlsServerHello { ja3s: hash, cipher_suite, tls_version })
}
