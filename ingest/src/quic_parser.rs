//! QUIC Initial packet parser — extracts SNI from QUIC (UDP/443) TLS handshakes.
//!
//! QUIC v1 (RFC 9000) uses Initial packets to carry the TLS ClientHello.
//! The ClientHello is encrypted with initial keys derived from the
//! Destination Connection ID using a well-known salt.
//!
//! References:
//!   RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport
//!   RFC 9001 — Using TLS to Secure QUIC
//!   RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use ring::{aead, hkdf};

/// QUIC v1 initial salt (RFC 9001 §5.2)
const QUIC_V1_INITIAL_SALT: [u8; 20] =
    *b"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";

const QUIC_V1: u32 = 0x0000_0001;

/// Parsed QUIC Initial metadata.
#[derive(Debug, Clone, Default)]
pub struct QuicInitial {
    pub sni: String,
    pub ja3: String,
    pub version: u32,
    pub scid: Vec<u8>,
    pub dcid: Vec<u8>,
}

/// Try to extract the TLS ClientHello from a QUIC Initial packet.
/// Returns `Some(QuicInitial)` on success, `None` if not a valid QUIC Initial.
pub fn parse_quic_initial(buf: &[u8]) -> Option<QuicInitial> {
    if buf.len() < 7 {
        tracing::debug!("QUIC: buffer too short: {} bytes", buf.len());
        return None;
    }

    // Byte 0: Long header check (top 2 bits must be 1 for long header)
    if buf[0] & 0xC0 != 0xC0 {
        tracing::debug!("QUIC: not long header: byte=0x{:02x}", buf[0]);
        return None;
    }

    // Extract packet type from bits 4-5
    let packet_type = (buf[0] >> 4) & 0x03;
    if packet_type != 0 {
        tracing::debug!("QUIC: not Initial packet (type={})", packet_type);
        return None; // Not an Initial packet
    }

    // Fixed bit (bit 3) must be 1
    if buf[0] & 0x08 == 0 {
        tracing::debug!("QUIC: fixed bit not set");
        return None;
    }

    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != QUIC_V1 {
        tracing::debug!("QUIC: unsupported version: 0x{:08x}", version);
        return None; // Only support QUIC v1
    }

    let mut pos = 5usize;
    tracing::debug!(
        "QUIC Initial header OK, version=0x{:08x}, total_len={}",
        version,
        buf.len()
    );

    // Destination Connection ID length
    if pos >= buf.len() {
        return None;
    }
    let dcid_len = buf[pos] as usize;
    pos += 1;
    if pos + dcid_len > buf.len() {
        tracing::debug!("QUIC: DCID overflow");
        return None;
    }
    let dcid = buf[pos..pos + dcid_len].to_vec();
    pos += dcid_len;

    // Source Connection ID length
    if pos >= buf.len() {
        return None;
    }
    let scid_len = buf[pos] as usize;
    pos += 1;
    if pos + scid_len > buf.len() {
        tracing::debug!("QUIC: SCID overflow");
        return None;
    }
    let scid = buf[pos..pos + scid_len].to_vec();
    pos += scid_len;

    // Token (Initial packets only, preceded by variable-length integer)
    if pos >= buf.len() {
        return None;
    }
    let (token_len, consumed) = match read_quic_varint(&buf[pos..]) {
        Some((l, c)) => (l as usize, c),
        None => {
            tracing::debug!("QUIC: token length varint parse failed");
            return None;
        }
    };
    pos += consumed;
    if pos + token_len > buf.len() {
        tracing::debug!("QUIC: token overflow");
        return None;
    }
    pos += token_len; // Skip token

    // QUIC Long Header Payload Length (variable-length integer)
    if pos >= buf.len() {
        return None;
    }
    let (payload_len, consumed) = match read_quic_varint(&buf[pos..]) {
        Some((l, c)) => (l as usize, c),
        None => {
            tracing::debug!("QUIC: payload length varint parse failed");
            return None;
        }
    };
    pos += consumed;

    if pos >= buf.len() {
        tracing::debug!("QUIC: no protected payload at pos={}", pos);
        return None;
    }

    let protected = &buf[pos..];
    tracing::debug!(
        "QUIC: dcid={:02x?} scid={:02x?} protected_payload={}, payload_len_field={}",
        &dcid[..dcid.len().min(8)],
        &scid[..scid.len().min(8)],
        protected.len(),
        payload_len
    );

    // Derive initial keys from DCID
    let (key, iv, hp) = derive_initial_keys(&dcid)?;

    // Remove header protection to get the packet number
    let (pn, payload_start) = remove_header_protection(protected, &hp)?;

    // The sample for header protection is at bytes 4..20 of the protected payload
    // After header protection removal, the packet number follows the header
    // Then the encrypted payload

    // Decrypt the payload (AEAD)
    let encrypted = &protected[payload_start..];
    if encrypted.len() < 16 {
        tracing::debug!(
            "QUIC: encrypted too short for AEAD: {} bytes",
            encrypted.len()
        );
        return None; // Need at least tag
    }
    tracing::debug!(
        "QUIC: decrypting {} bytes (pn={:02x?})",
        encrypted.len(),
        pn
    );

    let plaintext = match decrypt_payload(encrypted, &key, &iv, &pn, &dcid, &scid) {
        Some(p) => {
            tracing::debug!("QUIC: decrypted {} bytes", p.len());
            p
        }
        None => {
            tracing::debug!("QUIC: AEAD decryption FAILED");
            return None;
        }
    };

    // Extract CRYPTO frame from the plaintext
    let sni = extract_sni_from_crypto(&plaintext);
    if sni.is_some() {
        tracing::debug!("QUIC: extracted SNI: {}", sni.as_ref().unwrap());
    } else {
        tracing::debug!(
            "QUIC: no SNI found in CRYPTO frame, plaintext_len={}",
            plaintext.len()
        );
    }
    sni.map(|s| QuicInitial {
        sni: s.to_string(),
        ja3: String::new(),
        version,
        scid,
        dcid,
    })
}

/// Build TLS 1.3 HkdfLabel bytes for HKDF-Expand-Label (RFC 8446 §7.1).
fn hkdf_expand_label(
    prk: &hkdf::Prk,
    label: &[u8],
    context: &[u8],
    out_len: u16,
) -> Option<Vec<u8>> {
    // HkdfLabel:
    //   uint16 length
    //   opaque label<7..255> = "tls13 " + label
    //   opaque context<0..255>
    let label_prefix = b"tls13 ";
    let mut hkdf_label =
        Vec::with_capacity(2 + 1 + label_prefix.len() + label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&out_len.to_be_bytes()); // length
    hkdf_label.push((label_prefix.len() + label.len()) as u8); // label length
    hkdf_label.extend_from_slice(label_prefix); // "tls13 "
    hkdf_label.extend_from_slice(label); // label
    hkdf_label.push(context.len() as u8); // context length
    hkdf_label.extend_from_slice(context); // context

    let mut out = vec![0u8; out_len as usize];
    prk.expand(&[&hkdf_label[..]], hkdf::HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut out))
        .ok()?;
    Some(out)
}

/// Derive QUIC v1 initial keys from the Destination Connection ID (RFC 9001 §5.2).
/// Returns (key_128, iv_96, header_protection_key).
fn derive_initial_keys(dcid: &[u8]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    tracing::debug!(
        "QUIC: deriving keys from dcid={:02x?} (len={})",
        &dcid[..dcid.len().min(8)],
        dcid.len()
    );

    // Step 1: initial_secret = HKDF-Extract(initial_salt, dcid)
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &QUIC_V1_INITIAL_SALT);
    let initial_secret = salt.extract(dcid);

    // Step 2: client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    let client_secret = hkdf_expand_label(&initial_secret, b"client in", b"", 32)?;
    let client_prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_secret);

    // Step 3: key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
    let key_raw = hkdf_expand_label(&client_prk, b"quic key", b"", 16)?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&key_raw);

    // iv = HKDF-Expand-Label(client_initial_secret, "quic iv", "", 12)
    let iv_raw = hkdf_expand_label(&client_prk, b"quic iv", b"", 12)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_raw);

    // hp = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16)
    let hp_raw = hkdf_expand_label(&client_prk, b"quic hp", b"", 16)?;
    let mut hp = [0u8; 16];
    hp.copy_from_slice(&hp_raw);

    tracing::debug!(
        "QUIC: keys derived ok, key={:02x?} iv={:02x?} hp={:02x?}",
        &key[..],
        &iv[..],
        &hp[..]
    );
    Some((key, iv, hp))
}

/// Remove QUIC header protection to reveal the packet number.
/// Returns (packet_number_as_bytes, payload_start_offset).
fn remove_header_protection(protected: &[u8], hp_key: &[u8; 16]) -> Option<(Vec<u8>, usize)> {
    if protected.len() < 5 {
        return None;
    }

    // The header protection sample is bytes 4..20 of the protected payload
    let sample_end = 20.min(protected.len());
    if sample_end < 4 {
        return None;
    }
    let sample = &protected[4..sample_end];

    // Encrypt the sample with AES-ECB using the header protection key
    let cipher = aes::Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = GenericArray::clone_from_slice(&sample[..16]);
    cipher.encrypt_block(&mut block);
    let mask = block.as_slice();

    // Header protection mask for long headers:
    // mask[0] & 0x0F XORs protected byte 0 lower 4 bits (reserved + PN length)
    // mask[1..1+pn_len] XORs the packet number bytes
    // Recover the first byte to get PN length from bits 1-0
    let first_byte = protected[0] ^ (mask[0] & 0x0F);
    let pn_len = ((first_byte & 0x03) + 1) as usize;
    if protected.len() < 1 + pn_len {
        return None;
    }

    // Decrypt packet number bytes using mask bytes 1..1+pn_len
    let mut pn_bytes = Vec::with_capacity(pn_len);
    for i in 0..pn_len {
        if 1 + i < protected.len() {
            pn_bytes.push(protected[1 + i] ^ mask[1 + i]);
        }
    }

    // Payload starts after the packet number
    let payload_start = 1 + pn_len;

    Some((pn_bytes, payload_start))
}

/// Decrypt the QUIC Initial payload using AES-128-GCM.
fn decrypt_payload(
    encrypted: &[u8],
    key: &[u8; 16],
    iv: &[u8; 12],
    pn: &[u8],
    dcid: &[u8],
    scid: &[u8],
) -> Option<Vec<u8>> {
    if encrypted.len() < 16 {
        return None;
    }

    // Separate ciphertext and tag
    let ct_len = encrypted.len() - 16;
    let ciphertext = &encrypted[..ct_len];
    let tag = &encrypted[ct_len..];

    // Build the nonce: IV XOR packet number (padded to 4 bytes)
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);
    // XOR the last 4 bytes of IV with the packet number
    let pn_val = if pn.len() >= 4 {
        u32::from_be_bytes([
            pn[pn.len() - 4],
            pn[pn.len() - 3],
            pn[pn.len() - 2],
            pn[pn.len() - 1],
        ])
    } else {
        // Pad with leading zeros
        let mut buf = [0u8; 4];
        for i in 0..pn.len() {
            buf[4 - pn.len() + i] = pn[i];
        }
        u32::from_be_bytes(buf)
    };
    for i in 0..4 {
        nonce[8 + i] ^= ((pn_val >> (24 - i * 8)) & 0xFF) as u8;
    }

    // Build AAD (Additional Authenticated Data)
    // For QUIC Initial: type(1) + version(4) + dcil+dcid + scil+scid + token length(4) + length(4) + pn
    // We reconstruct from the original packet header
    let mut aad = Vec::new();
    aad.push(0xC0); // Initial type byte (unprotected form)
    aad.extend_from_slice(&QUIC_V1.to_be_bytes());
    aad.push(dcid.len() as u8);
    aad.extend_from_slice(dcid);
    aad.push(scid.len() as u8);
    aad.extend_from_slice(scid);
    // No token
    aad.extend_from_slice(&[0u8; 4]); // token length = 0
    // Payload length (before encryption): ct_len + tag_len(16) + pn_len
    let total_len = 1 + pn.len() + ct_len; // pn_byte + pn + ciphertext
    aad.extend_from_slice(&(total_len as u32).to_be_bytes());
    // Packet number
    aad.extend_from_slice(pn);

    // Decrypt using AES-128-GCM
    let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, key).ok()?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let mut in_out = ciphertext.to_vec();
    in_out.extend_from_slice(tag);
    match key.open_in_place(nonce, aead::Aad::from(&aad), &mut in_out) {
        Ok(plaintext) => {
            let plain_len = plaintext.len();
            if plain_len > 0 {
                Some(plaintext[..plain_len].to_vec())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Extract SNI from a QUIC packet's frames (skip non-CRYPTO frames).
fn extract_sni_from_crypto(plaintext: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos < plaintext.len() {
        let frame_type = plaintext[pos];
        // Frame types: 0x00=PADDING, 0x01=PING, 0x02=ACK, 0x06=CRYPTO, 0x1c=CONNECTION_CLOSE, etc.
        if frame_type == 0x00 {
            // PADDING: skip all consecutive 0x00 bytes
            while pos < plaintext.len() && plaintext[pos] == 0x00 {
                pos += 1;
            }
            continue;
        }
        if frame_type == 0x01 || frame_type == 0x02 || frame_type == 0x03 {
            // PING (1 byte) or ACK (varies) — skip
            pos += 1;
            if frame_type == 0x02 {
                // ACK: skip varint Largest Acknowledged + varint ACK Delay + varint ACK Range Count + varint First ACK Range
                for _ in 0..5 {
                    let (_, c) = read_quic_varint(&plaintext[pos..])?;
                    pos += c;
                }
                // ACK Range Count ranges: each is a varint Gap + varint Range
                let (range_count, _) = read_quic_varint(&plaintext[pos..])?;
                pos += 1; // we already consumed the count byte
                for _ in 0..range_count as usize {
                    let (_, c) = read_quic_varint(&plaintext[pos..])?;
                    pos += c;
                    let (_, c) = read_quic_varint(&plaintext[pos..])?;
                    pos += c;
                }
            }
            continue;
        }

        // CRYPTO Frame (RFC 9000 §19.6): type 0x06
        if frame_type == 0x06 {
            let mut inner_pos = pos + 1;
            let (offset, consumed) = read_quic_varint(&plaintext[inner_pos..])?;
            inner_pos += consumed;
            let (data_len, consumed) = read_quic_varint(&plaintext[inner_pos..])?;
            inner_pos += consumed;

            if offset == 0 && data_len > 0 && inner_pos + data_len as usize <= plaintext.len() {
                let crypto_data = &plaintext[inner_pos..inner_pos + data_len as usize];
                // Parse TLS ClientHello
                if let Some(ch) = crate::tls_parser::parse_client_hello(crypto_data) {
                    if !ch.sni.is_empty() {
                        return Some(ch.sni);
                    }
                }
            }
            // Even if this CRYPTO frame didn't yield SNI, there might be another CRYPTO frame
            // (QUIC can send multiple CRYPTO frames in one packet for fragmented handshakes)
            inner_pos += data_len as usize;
            pos = inner_pos;
            continue;
        }

        // Unknown frame type — skip 1 byte and try next
        pos += 1;
    }
    None
}

/// Read a QUIC variable-length integer (RFC 9000 §16).
/// Returns (value, bytes_consumed).
fn read_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let prefix = buf[0] >> 6;
    let len = 1usize << prefix; // 1, 2, 4, or 8 bytes

    if buf.len() < len {
        return None;
    }

    let mask = match len {
        1 => 0x3F,
        2 => 0x3FFF,
        4 => 0x3FFFFFFF,
        8 => 0x3FFFFFFFFFFFFFFF,
        _ => return None,
    };

    let mut value = 0u64;
    for i in 0..len {
        value = (value << 8) | buf[i] as u64;
    }
    value &= mask;

    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_quic_varint_1byte() {
        // 0x3F = 63 (6-bit value, 1 byte)
        let buf = [0x3F];
        assert_eq!(read_quic_varint(&buf), Some((63, 1)));

        // 0x00 = 0
        let buf = [0x00];
        assert_eq!(read_quic_varint(&buf), Some((0, 1)));
    }

    #[test]
    fn test_read_quic_varint_2byte() {
        // 0x40 0x00 = 0 (2-byte, prefix 01)
        let buf = [0x40, 0x00];
        assert_eq!(read_quic_varint(&buf), Some((0, 2)));

        // 0x7F 0xFF = 16383 (max 2-byte)
        let buf = [0x7F, 0xFF];
        assert_eq!(read_quic_varint(&buf), Some((16383, 2)));
    }

    #[test]
    fn test_read_quic_varint_4byte() {
        let buf = [0x80, 0x00, 0x00, 0x05];
        let (val, len) = read_quic_varint(&buf).unwrap();
        assert_eq!(val, 5);
        assert_eq!(len, 4);
    }

    #[test]
    fn test_empty_buffer() {
        assert!(parse_quic_initial(&[]).is_none());
    }

    #[test]
    fn test_short_buffer() {
        assert!(parse_quic_initial(&[0xC0, 0x00, 0x00, 0x00, 0x01]).is_none());
    }

    #[test]
    fn test_not_initial_packet() {
        // 0xC4 = 0b11000100: type=01 (not Initial = 00)
        let buf = [0xC4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        assert!(parse_quic_initial(&buf).is_none());
    }
}
