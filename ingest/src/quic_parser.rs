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

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use ring::{aead, hkdf};

/// QUIC v1 initial salt (RFC 9001 §5.2)
const QUIC_V1_INITIAL_SALT: [u8; 20] = *b"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";

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
        return None;
    }

    // Byte 0: Long header check (top 2 bits must be 1 for long header)
    if buf[0] & 0xC0 != 0xC0 {
        return None;
    }

    // Form bit must be 1 (long header)
    if buf[0] & 0x80 == 0 {
        return None;
    }

    // Extract packet type from bits 4-5 (0xC0 = 0b11000000)
    // For Initial: type = 0b00
    let packet_type = (buf[0] >> 4) & 0x03;
    if packet_type != 0 {
        return None; // Not an Initial packet
    }

    // Fixed bit (bit 3) must be 1
    if buf[0] & 0x08 == 0 {
        return None;
    }

    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != QUIC_V1 {
        return None; // Only support QUIC v1
    }

    let mut pos = 5usize;

    // Destination Connection ID length
    if pos >= buf.len() { return None; }
    let dcid_len = buf[pos] as usize;
    pos += 1;
    if pos + dcid_len > buf.len() { return None; }
    let dcid = buf[pos..pos + dcid_len].to_vec();
    pos += dcid_len;

    // Source Connection ID length
    if pos >= buf.len() { return None; }
    let scid_len = buf[pos] as usize;
    pos += 1;
    if pos + scid_len > buf.len() { return None; }
    let scid = buf[pos..pos + scid_len].to_vec();
    pos += scid_len;

    // Token (Initial packets only)
    if pos + 4 > buf.len() { return None; }
    let token_len = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
    pos += 4;
    if pos + token_len > buf.len() { return None; }
    pos += token_len; // Skip token

    // QUIC Long Header Payload Length (4 bytes)
    if pos + 4 > buf.len() { return None; }
    let payload_len = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
    pos += 4;

    // Ensure we have enough data for the protected payload
    if pos + 4 > buf.len() {
        return None;
    }

    let protected = &buf[pos..];

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
        return None; // Need at least tag
    }

    let plaintext = decrypt_payload(encrypted, &key, &iv, &pn, &dcid, &scid)?;

    // Extract CRYPTO frame from the plaintext
    extract_sni_from_crypto(&plaintext).map(|sni| QuicInitial {
        sni: sni.to_string(),
        ja3: String::new(),
        version,
        scid,
        dcid,
    })
}

/// Derive QUIC v1 initial keys from the Destination Connection ID.
/// Returns (key_128, iv_96, header_protection_key).
fn derive_initial_keys(dcid: &[u8]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    // QUIC v1 initial salt is fixed
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &QUIC_V1_INITIAL_SALT);
    let prk = salt.extract(dcid);

    // Derive initial key: "quic key"
    let mut key = [0u8; 16];
    let info_key: &[&[u8]] = &[b"tls13 quic key\0"];
    if prk.expand(info_key, hkdf::HKDF_SHA256)
        .map(|okm| okm.fill(&mut key))
        .is_err()
    {
        return None;
    }

    // Derive initial IV: "quic iv"
    let mut iv = [0u8; 12];
    let info_iv: &[&[u8]] = &[b"tls13 quic iv\0"];
    if prk.expand(info_iv, hkdf::HKDF_SHA256)
        .map(|okm| okm.fill(&mut iv))
        .is_err()
    {
        return None;
    }

    // Derive header protection key: "quic hp"
    let mut hp = [0u8; 16];
    let info_hp: &[&[u8]] = &[b"tls13 quic hp\0"];
    if prk.expand(info_hp, hkdf::HKDF_SHA256)
        .map(|okm| okm.fill(&mut hp))
        .is_err()
    {
        return None;
    }

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

    // Determine packet number length from the first byte
    // The first byte has the protected packet number in the lower 2 bits
    // PN length = (first_byte & 0x03) + 1
    let pn_len = ((protected[0] & 0x03) + 1) as usize;
    if protected.len() < 1 + pn_len {
        return None;
    }

    // The header protection mask is derived from the encrypted sample
    // For long headers: mask covers bytes after the initial byte
    // The packet number bytes are protected by mask[1..1+pn_len]
    // Decrypt packet number bytes
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
        u32::from_be_bytes([pn[pn.len() - 4], pn[pn.len() - 3], pn[pn.len() - 2], pn[pn.len() - 1]])
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

/// Extract SNI from a QUIC CRYPTO frame payload (which contains TLS ClientHello).
fn extract_sni_from_crypto(plaintext: &[u8]) -> Option<String> {
    // CRYPTO Frame (RFC 9000 §19.6):
    // Frame Type (0x06) + Offset (variable) + Length (variable) + Crypto Data
    // The crypto data contains TLS ClientHello (same format as TCP)

    if plaintext.is_empty() || plaintext[0] != 0x06 {
        return None;
    }

    let mut pos = 1usize;

    // Read variable-length offset
    let (offset, consumed) = read_quic_varint(&plaintext[pos..])?;
    pos += consumed;

    // Read variable-length crypto data length
    let (data_len, consumed) = read_quic_varint(&plaintext[pos..])?;
    pos += consumed;

    if offset != 0 && data_len == 0 {
        // Non-first crypto frame (handshake continuation)
        return None;
    }

    if pos + data_len as usize > plaintext.len() {
        return None;
    }

    let crypto_data = &plaintext[pos..pos + data_len as usize];

    // Parse TLS ClientHello from the crypto data
    // (same format as TCP TLS)
    let ch = crate::tls_parser::parse_client_hello(crypto_data)?;
    if ch.sni.is_empty() { None } else { Some(ch.sni) }
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
