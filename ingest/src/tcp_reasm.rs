//! TCP stream reassembly and TLS ClientHello extraction.
//! Tracks per-connection state so we can handle fragmented TLS handshakes.

use std::collections::HashMap;
use traffic_core::FlowKey;
use crate::tls_parser::{self, TlsClientHello, TlsServerHello};

/// Minimum bytes needed for a TLS record header (5 bytes).
const TLS_HEADER_LEN: usize = 5;
/// Maximum TLS record we'll buffer (16KB + header).
const MAX_TLS_RECORD: usize = 16389;

/// Per-connection TCP reassembly state.
#[derive(Debug)]
struct TcpState {
    /// Buffer for upstream data (client → server).
    upstream_buf: Vec<u8>,
    /// Buffer for downstream data (server → client).
    downstream_buf: Vec<u8>,
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
            upstream_buf: Vec::with_capacity(2048),
            downstream_buf: Vec::with_capacity(1024),
            client_hello_done: false,
            server_hello_done: false,
            client_hello: None,
            server_hello: None,
            up_bytes: 0,
            down_bytes: 0,
        }
    }
}

/// TCP reassembly manager.
pub struct TcpReassembler {
    connections: HashMap<FlowKey, TcpState>,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self { connections: HashMap::new() }
    }

    /// Process packets in the context of a known flow direction.
    /// This is called per-packet with the directionality determined
    /// by the FlowTracker (which knows which IP is "src").
    pub fn process_segment(
        &mut self,
        key: &FlowKey,
        payload: &[u8],
        src_is_client: bool,  // true = this segment came from the client side
    ) -> Option<(TlsClientHello, TlsServerHello)> {
        let state = self.connections.entry(key.clone()).or_insert_with(TcpState::new);

        // Track bytes per direction
        let buf = if src_is_client {
            state.up_bytes += payload.len() as u64;
            &mut state.upstream_buf
        } else {
            state.down_bytes += payload.len() as u64;
            &mut state.downstream_buf
        };

        // Append payload to the appropriate buffer
        if buf.len() + payload.len() > MAX_TLS_RECORD * 2 {
            // Buffer too large, trim old data
            buf.drain(..buf.len().saturating_sub(MAX_TLS_RECORD));
        }
        buf.extend_from_slice(payload);

        // Try to parse TLS metadata from upstream (client → server)
        let mut result = None;
        if !state.client_hello_done && src_is_client && state.upstream_buf.len() >= TLS_HEADER_LEN {
            if let Some(ch) = tls_parser::parse_client_hello(&state.upstream_buf) {
                state.client_hello = Some(ch);
                state.client_hello_done = true;
            }
        }

        // Try to parse server hello from downstream
        if !state.server_hello_done && !src_is_client && state.downstream_buf.len() >= TLS_HEADER_LEN {
            if let Some(sh) = tls_parser::parse_server_hello(&state.downstream_buf) {
                state.server_hello = Some(sh);
                state.server_hello_done = true;
            }
        }

        // If we have both, return them and reset the client hello flag
        if state.client_hello_done {
            result = Some((
                state.client_hello.clone().unwrap_or_default(),
                state.server_hello.clone().unwrap_or_default(),
            ));
            // Don't clear — we may want to reference this again for reporting
        }

        result
    }

    /// Remove and return state for a terminated connection.
    pub fn remove(&mut self, key: &FlowKey) -> Option<(u64, u64, Option<TlsClientHello>, Option<TlsServerHello>)> {
        self.connections.remove(key).map(|s| {
            (s.up_bytes, s.down_bytes, s.client_hello, s.server_hello)
        })
    }

    /// Get bytes tracked for a connection without consuming state.
    pub fn get_bytes(&self, key: &FlowKey) -> Option<(u64, u64)> {
        self.connections.get(key).map(|s| (s.up_bytes, s.down_bytes))
    }

    /// Clean up state for expired flows.
    pub fn remove_expired(&mut self, active_keys: &std::collections::HashSet<FlowKey>) {
        self.connections.retain(|k, _| active_keys.contains(k));
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }
}
