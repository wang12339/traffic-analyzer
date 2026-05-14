"""mitmproxy addon: extract HTTP/HTTPS metadata and send to analysis pipeline."""
import json
import socket
import time
from mitmproxy import http

ANALYSIS_SERVER = ('127.0.0.1', 2055)  # Local UDP ingest
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def request(flow: http.HTTPFlow):
    """Capture decrypted HTTP/HTTPS request metadata."""
    r = flow.request
    host = r.pretty_host
    path = r.path[:128]  # First 128 chars only
    method = r.method
    ua = r.headers.get('User-Agent', '')[:128]
    content_type = r.headers.get('Content-Type', '')
    content_len = len(r.get_text() or '')

    # Skip mitmproxy's own traffic
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
    try:
        sock.sendto(json.dumps(record).encode(), ANALYSIS_SERVER)
    except:
        pass


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
    try:
        sock.sendto(json.dumps(record).encode(), ANALYSIS_SERVER)
    except:
        pass
