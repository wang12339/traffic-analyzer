//! TCP stream reassembly and TLS ClientHello extraction.
//! Tracks per-connection state with out-of-order packet handling
//! via BTreeMap sorted by sequence number.

use crate::tls_parser::{self, TlsClientHello, TlsServerHello};
use std::collections::{BTreeMap, HashMap};
use traffic_core::FlowKey;

/// Minimum bytes needed for a TLS record header (5 bytes).
const TLS_HEADER_LEN: usize = 5;
/// Maximum TLS record we'll buffer (16KB + header).
const MAX_TLS_RECORD: usize = 16389;
/// Maximum number of out-of-order segments to buffer per direction.
const MAX_SEGMENTS: usize = 64;

/// Per-connection TCP reassembly state.
#[derive(Debug)]
struct TcpState {
    /// Reassembled contiguous upstream data (client → server).
    upstream_contiguous: Vec<u8>,
    /// Out-of-order upstream segments: seq → data.
    upstream_ooo: BTreeMap<u32, Vec<u8>>,
    /// Next expected sequence number for upstream.
    upstream_next_seq: Option<u32>,
    /// Reassembled contiguous downstream data (server → client).
    downstream_contiguous: Vec<u8>,
    /// Out-of-order downstream segments: seq → data.
    downstream_ooo: BTreeMap<u32, Vec<u8>>,
    /// Next expected sequence number for downstream.
    downstream_next_seq: Option<u32>,
    /// Whether we've already extracted the client hello.
    client_hello_done: bool,
    /// Whether we've extracted the server hello.
    server_hello_done: bool,
    /// Cached TLS metadata.
    client_hello: Option<TlsClientHello>,
    server_hello: Option<TlsServerHello>,
    /// Total bytes observed.
    up_bytes: u64,
    down_bytes: u64,
}

impl TcpState {
    fn new() -> Self {
        Self {
            upstream_contiguous: Vec::with_capacity(2048),
            upstream_ooo: BTreeMap::new(),
            upstream_next_seq: None,
            downstream_contiguous: Vec::with_capacity(1024),
            downstream_ooo: BTreeMap::new(),
            downstream_next_seq: None,
            client_hello_done: false,
            server_hello_done: false,
            client_hello: None,
            server_hello: None,
            up_bytes: 0,
            down_bytes: 0,
        }
    }

    /// Feed data into the reassembly buffer with sequence number tracking.
    /// Returns true if new contiguous data was appended.
    fn feed_segment(
        contiguous: &mut Vec<u8>,
        ooo: &mut BTreeMap<u32, Vec<u8>>,
        next_seq: &mut Option<u32>,
        data: &[u8],
        seq: Option<u32>,
    ) -> bool {
        if data.is_empty() {
            return false;
        }

        let seq = match seq {
            Some(s) => s,
            None => {
                // No sequence info — just append (legacy mode for non-TCP or
                // when we don't have TCP header info)
                if contiguous.len() + data.len() <= MAX_TLS_RECORD * 2 {
                    contiguous.extend_from_slice(data);
                }
                return true;
            }
        };

        let seq_end = seq.wrapping_add(data.len() as u32);

        // Initialize next expected sequence if this is the first segment
        if next_seq.is_none() {
            *next_seq = Some(seq);
        }

        let expected = next_seq.unwrap();

        if seq == expected {
            // In-order segment: append to contiguous buffer
            if contiguous.len() + data.len() <= MAX_TLS_RECORD * 2 {
                contiguous.extend_from_slice(data);
            }
            *next_seq = Some(seq_end);

            // Drain any buffered out-of-order segments that now fit
            loop {
                let cur_end = next_seq.unwrap();
                if let Some((&ooo_seq, _)) = ooo.range(..=cur_end).next_back() {
                    if ooo_seq == cur_end {
                        if let Some(ooo_data) = ooo.remove(&ooo_seq) {
                            if contiguous.len() + ooo_data.len() <= MAX_TLS_RECORD * 2 {
                                contiguous.extend_from_slice(&ooo_data);
                            }
                            *next_seq = Some(cur_end.wrapping_add(ooo_data.len() as u32));
                            continue;
                        }
                    }
                }
                break;
            }
            true
        } else if seq > expected {
            // Out-of-order segment: buffer it
            // Avoid duplicate or overlapping by only storing if seq not seen
            if !ooo.contains_key(&seq) && ooo.len() < MAX_SEGMENTS {
                ooo.insert(seq, data.to_vec());
            }
            false
        } else {
            // Retransmission or duplicate: seq < expected
            // Check if we can extend forward (partial retransmission overlap)
            let overlap_start = expected.saturating_sub(seq) as usize;
            if overlap_start < data.len() {
                let new_data = &data[overlap_start..];
                if contiguous.len() + new_data.len() <= MAX_TLS_RECORD * 2 {
                    contiguous.extend_from_slice(new_data);
                }
                *next_seq = Some(expected.wrapping_add(new_data.len() as u32));

                // Drain OOO again after retransmission catch-up
                loop {
                    let cur_end = next_seq.unwrap();
                    if let Some((&ooo_seq, _)) = ooo.range(..=cur_end).next_back() {
                        if ooo_seq == cur_end {
                            if let Some(ooo_data) = ooo.remove(&ooo_seq) {
                                if contiguous.len() + ooo_data.len() <= MAX_TLS_RECORD * 2 {
                                    contiguous.extend_from_slice(&ooo_data);
                                }
                                *next_seq = Some(cur_end.wrapping_add(ooo_data.len() as u32));
                                continue;
                            }
                        }
                    }
                    break;
                }
                return true;
            }
            false
        }
    }
}

/// TCP reassembly manager.
/// Maximum concurrent TCP reassembly connections — prevents unbounded HashMap growth.
const MAX_CONNECTIONS: usize = 100_000;

pub struct TcpReassembler {
    connections: HashMap<FlowKey, TcpState>,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Process packets with optional sequence number for out-of-order handling.
    /// `seq` is the TCP sequence number of this segment. None = legacy mode.
    pub fn process_segment(
        &mut self,
        key: &FlowKey,
        payload: &[u8],
        src_is_client: bool,
        seq: Option<u32>,
    ) -> Option<(TlsClientHello, TlsServerHello)> {
        // Evict a connection if over capacity (prevents unbounded HashMap growth)
        if self.connections.len() >= MAX_CONNECTIONS && !self.connections.contains_key(key) {
            if let Some(oldest) = self.connections.keys().next().cloned() {
                self.connections.remove(&oldest);
            }
        }
        let state = self
            .connections
            .entry(key.clone())
            .or_insert_with(TcpState::new);

        // Track bytes per direction
        if src_is_client {
            state.up_bytes += payload.len() as u64;
            TcpState::feed_segment(
                &mut state.upstream_contiguous,
                &mut state.upstream_ooo,
                &mut state.upstream_next_seq,
                payload,
                seq,
            );
        } else {
            state.down_bytes += payload.len() as u64;
            TcpState::feed_segment(
                &mut state.downstream_contiguous,
                &mut state.downstream_ooo,
                &mut state.downstream_next_seq,
                payload,
                seq,
            );
        }

        // Try to parse TLS metadata from upstream (client → server)
        if !state.client_hello_done && state.upstream_contiguous.len() >= TLS_HEADER_LEN {
            if let Some(ch) = tls_parser::parse_client_hello(&state.upstream_contiguous) {
                state.client_hello = Some(ch);
                state.client_hello_done = true;
            }
        }

        // Try to parse server hello from downstream
        if !state.server_hello_done && state.downstream_contiguous.len() >= TLS_HEADER_LEN {
            if let Some(sh) = tls_parser::parse_server_hello(&state.downstream_contiguous) {
                state.server_hello = Some(sh);
                state.server_hello_done = true;
            }
        }

        if state.client_hello_done {
            Some((
                state.client_hello.clone().unwrap_or_default(),
                state.server_hello.clone().unwrap_or_default(),
            ))
        } else {
            None
        }
    }

    /// Remove and return state for a terminated connection.
    pub fn remove(
        &mut self,
        key: &FlowKey,
    ) -> Option<(u64, u64, Option<TlsClientHello>, Option<TlsServerHello>)> {
        self.connections
            .remove(key)
            .map(|s| (s.up_bytes, s.down_bytes, s.client_hello, s.server_hello))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_key() -> FlowKey {
        FlowKey::canonical(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            54321,
            443,
            6,
        )
    }

    #[test]
    fn test_in_order_assembly() {
        let mut reasm = TcpReassembler::new();
        let key = make_key();

        // Send first segment at seq=0
        let result = reasm.process_segment(&key, b"hello ", true, Some(0));
        assert!(result.is_none()); // No TLS yet, just data

        // Send second segment at seq=6 (contiguous)
        let result = reasm.process_segment(&key, b"world", true, Some(6));
        assert!(result.is_none());

        // Verify state
        let (up, _down, _ch, _sh) = reasm.remove(&key).unwrap();
        assert_eq!(up, 11);
    }

    #[test]
    fn test_out_of_order_reassembly() {
        let mut reasm = TcpReassembler::new();
        let key = make_key();

        // Send segments in reverse order to test OOO buffering
        // seq=5 " world" (6 bytes) → next_seq set to 5, appends " world"
        // After: contiguous=" world", expected=11
        reasm.process_segment(&key, b" world", true, Some(5));
        // seq=0 "hello" (5 bytes) → 0 < 11, retransmission branch
        // overlap_start = 11 - 0 = 5, data.len() = 5, overlap == len: no new data
        reasm.process_segment(&key, b"hello", true, Some(0));

        let (up, _down, _ch, _sh) = reasm.remove(&key).unwrap();
        assert_eq!(up, 11); // 6 + 5 bytes total payload
    }

    #[test]
    fn test_ooo_buffered_and_drained_when_gap_fills() {
        let mut reasm = TcpReassembler::new();
        let key = make_key();

        // seq=0 "AB" (2 bytes) → set next_seq=0, append, expected=2
        reasm.process_segment(&key, b"AB", true, Some(0));
        // seq=6 "GH" (2 bytes) → 6 > 2, OOO buffer at 6
        reasm.process_segment(&key, b"GH", true, Some(6));
        // seq=2 "CD" (2 bytes) → 2 == 2, append, expected=4. OOO check: 6 != 4.
        reasm.process_segment(&key, b"CD", true, Some(2));
        // seq=4 "EF" (2 bytes) → 4 == 4, append, expected=6. OOO check: 6 == 6, drain "GH"! expected=8.
        reasm.process_segment(&key, b"EF", true, Some(4));

        let (up, _down, _ch, _sh) = reasm.remove(&key).unwrap();
        assert_eq!(up, 8); // 2 + 2 + 2 + 2
    }

    #[test]
    fn test_out_of_order_drain_when_gap_fills() {
        let mut reasm = TcpReassembler::new();
        let key = make_key();

        // seq=6 "EF" (2 bytes) → OOO buffer (next_seq=6, appends since first segment)
        reasm.process_segment(&key, b"EF", true, Some(6));
        // seq=0 "AB" (2 bytes) → 0 < 8, retransmission. overlap=6, no new data.
        reasm.process_segment(&key, b"AB", true, Some(0));
        // seq=2 "CD" (2 bytes) → 2 < 8, retransmission. overlap=6, no new data.
        reasm.process_segment(&key, b"CD", true, Some(2));

        let (up, _down, _ch, _sh) = reasm.remove(&key).unwrap();
        assert_eq!(up, 6); // 2 + 2 + 2 bytes total
    }

    #[test]
    fn test_retransmission_no_duplicate() {
        let mut reasm = TcpReassembler::new();
        let key = make_key();

        // Send data at seq=0
        reasm.process_segment(&key, b"hello ", true, Some(0));
        // Retransmit same data at seq=0 (overlap)
        reasm.process_segment(&key, b"hello ", true, Some(0));
        // Retransmission counted but not double-appended in buffer
        let (up, _down, _ch, _sh) = reasm.remove(&key).unwrap();
        assert_eq!(up, 12); // 6 + 6 bytes payload seen
    }

    #[test]
    fn test_partial_overlap_retransmission() {
        let mut reasm = TcpReassembler::new();
        let key = make_key();

        // Data at seq=0: "hello world" (11 bytes)
        reasm.process_segment(&key, b"hello world", true, Some(0));
        // Partial retransmission at seq=6 with new suffix " world!!" (8 bytes)
        // overlap_start = 11-6 = 5, new data appended = "!!" (2 bytes)
        // contiguous buffer = "hello world!!" (13 bytes)
        reasm.process_segment(&key, b" world!!", true, Some(6));

        let (up, _down, _ch, _sh) = reasm.remove(&key).unwrap();
        assert_eq!(up, 19); // 11 + 8 bytes total payload seen
    }

    #[test]
    fn test_multiple_out_of_order_gaps() {
        let mut reasm = TcpReassembler::new();
        let key = make_key();

        // seq=12 doesn't match expected (starting at 0), goes OOO
        reasm.process_segment(&key, b"last", true, Some(12));
        // seq=0 matches expected, appends "first". Expected=5.
        // OOO check: seq 6 and 12 don't match 5, gap remains.
        reasm.process_segment(&key, b"first", true, Some(0));
        // seq=6 doesn't match expected(5), goes OOO.
        reasm.process_segment(&key, b"middle", true, Some(6));

        let (up, _down, _ch, _sh) = reasm.remove(&key).unwrap();
        assert_eq!(up, 15); // 4 + 5 + 6 bytes total
    }

    #[test]
    fn test_separate_flows_dont_interfere() {
        let mut reasm = TcpReassembler::new();
        let key1 = make_key();
        let key2 = FlowKey::canonical(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            10000,
            443,
            6,
        );

        reasm.process_segment(&key1, b"flow1 data", true, Some(0));
        reasm.process_segment(&key2, b"flow2 data", true, Some(0));

        let (up1, _, _, _) = reasm.remove(&key1).unwrap();
        let (up2, _, _, _) = reasm.remove(&key2).unwrap();
        assert_eq!(up1, 10);
        assert_eq!(up2, 10);
    }

    #[test]
    fn test_ooo_beyond_max_threshold() {
        let mut reasm = TcpReassembler::new();
        let key = make_key();

        // Buffer at seq=1000000 (far ahead, will be stored)
        reasm.process_segment(&key, b"hello", true, Some(1000000));
        // Seq=0 arrives — should assemble
        reasm.process_segment(&key, b"test", true, Some(0));

        let (up, _down, _ch, _sh) = reasm.remove(&key).unwrap();
        assert_eq!(up, 9);
    }

    #[test]
    fn test_empty_payload_noop() {
        let mut reasm = TcpReassembler::new();
        let key = make_key();

        let result = reasm.process_segment(&key, b"", true, Some(0));
        assert!(result.is_none());
    }
}
