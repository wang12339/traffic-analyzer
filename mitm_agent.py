"""mitmproxy addon: extract HTTP/HTTPS metadata and send to analysis pipeline.
   Features: ring buffer with retry, backpressure awareness, rate limiting."""

import json
import logging
import socket
import time
from collections import deque

from mitmproxy import http

logger = logging.getLogger(__name__)

ANALYSIS_SERVER = ('127.0.0.1', 2055)  # Local UDP ingest
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)

# Ring buffer: holds up to 5000 records during ingest outages
BUFFER_MAX = 5000
_buffer = deque(maxlen=BUFFER_MAX)
# Rate limit: max 200 sends/sec burst
MAX_BURST = 200
_burst_count = 0
_last_burst_reset = time.monotonic()


def _flush_buffer():
    """Flush as many buffered records as rate limit allows."""
    global _burst_count, _last_burst_reset
    now = time.monotonic()
    if now - _last_burst_reset > 1.0:
        _burst_count = 0
        _last_burst_reset = now

    sent = 0
    while _buffer and _burst_count < MAX_BURST:
        record = _buffer[0]
        try:
            sock.sendto(record, ANALYSIS_SERVER)
            _buffer.popleft()
            _burst_count += 1
            sent += 1
        except (BlockingIOError, socket.error):
            break  # Will retry on next call
    if sent > 0:
        logger.debug("Flushed %d buffered records (%d remaining)", sent, len(_buffer))


def _send_or_buffer(record: dict):
    """Try to send immediately; buffer on failure if under limit."""
    global _burst_count, _last_burst_reset
    now = time.monotonic()
    if now - _last_burst_reset > 1.0:
        _burst_count = 0
        _last_burst_reset = now

    data = json.dumps(record).encode()
    if _burst_count < MAX_BURST and len(_buffer) == 0:
        try:
            sock.sendto(data, ANALYSIS_SERVER)
            _burst_count += 1
            return
        except (BlockingIOError, socket.error):
            pass  # Fall through to buffer

    # Buffer the record
    if len(_buffer) < BUFFER_MAX:
        _buffer.append(data)
        if len(_buffer) >= BUFFER_MAX * 0.9:
            logger.warning("Buffer %.0f%% full — ingest may be down", len(_buffer) / BUFFER_MAX * 100)
    else:
        logger.warning("Buffer full — dropping oldest record")
        _buffer.append(data)  # deque will auto-evict oldest


def request(flow: http.HTTPFlow):
    """Capture decrypted HTTPS request metadata."""
    r = flow.request
    host = r.pretty_host
    path = r.path[:128]
    method = r.method
    ua = r.headers.get('User-Agent', '')[:128]
    content_type = r.headers.get('Content-Type', '')
    content_len = len(r.get_text() or '')

    if 'mitmproxy' in host:
        return

    record = {
        'type': 'http_request',
        'timestamp': time.time(),
        'host': host,
        'path': path,
        'method': method,
        'user_agent': ua,
        'content_type': content_type,
        'content_length': content_len,
        'scheme': r.scheme,
        'port': r.port,
    }
    _send_or_buffer(record)
    _flush_buffer()
    # Periodically log buffer health
    if _buffer and len(_buffer) % 100 == 0:
        logger.info("Buffer status: %d/%d records buffered", len(_buffer), BUFFER_MAX)


def response(flow: http.HTTPFlow):
    """Capture response metadata."""
    r = flow.response
    host = flow.request.pretty_host
    path = flow.request.path[:64]

    record = {
        'type': 'http_response',
        'timestamp': time.time(),
        'host': host,
        'path': path,
        'status_code': r.status_code,
        'content_type': r.headers.get('Content-Type', ''),
        'content_length': len(r.get_text() or ''),
    }
    _send_or_buffer(record)
