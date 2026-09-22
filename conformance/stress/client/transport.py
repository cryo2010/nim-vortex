#!/usr/bin/env python3
"""Shared transport + config for the vortex load clients.

Owns everything the correctness client (stress_client.py) and the performance
client (conformance/bench/client/bench_client.py) need identically: the VORTEX_*
env config, the deterministic byte generator, request-body compression, and the
transport sessions (httpx for h1/h2, aioquic for h3 via h3.py). Each client adds
its own workload loops and reporting on top. Kept separate so the correctness
verifier and the perf harness never share workload/reporting code -- only the
wire.
"""
import gzip, hashlib, json, os, urllib.parse
from contextlib import asynccontextmanager
from urllib.parse import urlparse
import httpx
try:
    from websockets.exceptions import WebSocketException
except ImportError:
    class WebSocketException(Exception): pass
from h3 import connect_h3, OP_TEXT, ProtocolPinError

WORKLOAD = os.environ.get("VORTEX_WORKLOAD", "requests")
PROTO    = os.environ.get("VORTEX_PROTO", "h2")
SERVER   = os.environ.get("STRESS_SERVER", "sync")
BASE     = os.environ["STRESS_BASE"].rstrip("/")          # e.g. https://server:8443
SECONDS  = int(os.environ.get("VORTEX_SECONDS", "60"))
CLIENTS  = int(os.environ.get("VORTEX_CLIENTS", "3"))
CONC     = int(os.environ.get("VORTEX_CONCURRENCY", "32"))
STREAM   = int(os.environ.get("VORTEX_STREAM_BYTES", str(1 << 30)))
REPORT   = int(os.environ.get("VORTEX_REPORT_SECONDS", "60"))
REQ_COMP  = os.environ.get("VORTEX_REQ_COMPRESSION", "gzip")
RESP_COMP = os.environ.get("VORTEX_RESP_COMPRESSION", "gzip")
CHUNK = 64 * 1024
MB = 1024 * 1024
IS_H3 = PROTO == "h3"
UNIT = {"requests": "requests", "methods": "requests", "ws": "messages",
        "sse": "events", "streamupload": "transfers",
        "streamdownload": "transfers"}.get(WORKLOAD, "ok")
STREAMING = WORKLOAD in ("streamupload", "streamdownload")

xfer = [0]              # cumulative bytes streamed (upload sent / download received)

# --- deterministic byte generator: byte i = i mod 256 (matches the server) ---
_PAT = bytes(range(256))
def gen_chunk(start: int, n: int) -> bytes:
    s = start % 256
    rot = _PAT[s:] + _PAT[:s]
    reps = (n // 256) + 1
    return (rot * reps)[:n]

def expected_sha1() -> str:
    h = hashlib.sha1(); off = 0
    while off < STREAM:
        n = min(CHUNK, STREAM - off); h.update(gen_chunk(off, n)); off += n
    return h.hexdigest()

async def body_gen():
    off = 0
    while off < STREAM:
        n = min(CHUNK, STREAM - off); yield gen_chunk(off, n); off += n
        # h1/h2 (httpx) stream the body -- httpx pulls the next chunk only when
        # it can send the current one (bounded by the socket / h2 window) -- so
        # bytes yielded ~= bytes sent, an accurate live upload rate. h3 (aioquic)
        # buffers the whole body up front, so there yielded != sent; count h3
        # upload progress on completion instead (see the upload workloads).
        if not IS_H3: xfer[0] += n

# --- request-body compression (server decompresses via decompressRequest) ----
def compress(raw: bytes):
    if REQ_COMP in ("", "none"): return raw, None
    if REQ_COMP == "gzip":       return gzip.compress(raw), "gzip"
    if REQ_COMP == "br":
        import brotli; return brotli.compress(raw), "br"
    if REQ_COMP == "zstd":
        import zstandard; return zstandard.ZstdCompressor().compress(raw), "zstd"
    raise SystemExit(f"unknown VORTEX_REQ_COMPRESSION: {REQ_COMP}")

ACCEPT = None if RESP_COMP in ("", "none") else RESP_COMP

# --- typed payload mix (shared with w_requests/w_methods) --------------------
# A fixed boundary so the outer content-type string and the raw multipart bytes
# agree exactly -- the server echoes the content-type verbatim (boundary and
# all) and re-sends the decompressed body, so the boundary must round-trip.
_MP_BOUNDARY = "----vortexstressBoundary7MA4YWxkTrZu0gW"

def _multipart_body(boundary: str) -> bytes:
    """Build raw multipart/form-data bytes BY HAND (no httpx multipart): a couple
    of text fields plus one file part carrying gen_chunk(0, 4096) as
    application/octet-stream, closed with the final terminator boundary. Hand-
    built so the exact bytes get request-compressed and echoed like any other
    body -- httpx's own multipart encoder would own the framing and we could not
    assert the round-trip byte-for-byte."""
    dash = b"--" + boundary.encode()
    parts = []
    parts.append(dash + b"\r\n")
    parts.append(b'Content-Disposition: form-data; name="field1"\r\n\r\n')
    parts.append(b"the quick brown fox\r\n")
    parts.append(dash + b"\r\n")
    parts.append(b'Content-Disposition: form-data; name="field2"\r\n\r\n')
    parts.append(b"jumps over the lazy dog\r\n")
    parts.append(dash + b"\r\n")
    parts.append(b'Content-Disposition: form-data; name="file"; filename="blob.bin"\r\n')
    parts.append(b"Content-Type: application/octet-stream\r\n\r\n")
    parts.append(gen_chunk(0, 4096))
    parts.append(b"\r\n")
    parts.append(dash + b"--\r\n")            # final boundary terminator
    return b"".join(parts)

def payload_mix() -> list:
    """The typed request-body mix, shared with w_requests/w_methods. Returns a
    list of (content_type, raw_bytes). Sizes are chosen to cover the 0-length /
    1-byte framing paths, the <1400 B no-compress threshold, the compressible
    >=1400 B branch per type, and the incompressible store-fallback. Built once
    at startup like the historical mix (os.urandom entries are not deterministic,
    but the round-trip assertions only need self-consistency)."""
    mix = []
    # text/plain length ladder, exactly as the historical mix: empty and single
    # byte (framing), a tiny body, one just above/around the compress threshold,
    # and two large compressible bodies.
    for n in (0, 1, 13, 1280, 64 * 1024, 256 * 1024):
        mix.append(("text/plain", (b"the quick brown fox " * (n // 20 + 1))[:n]))
    mix.append(("text/plain", os.urandom(64 * 1024)))   # incompressible: store fallback
    # ~300 B realistic JSON object (a few string/number/bool/nested fields),
    # padded to ~300 B so it sits below the compress threshold.
    obj = {"user": "alice", "id": 42, "active": True, "score": 3.14,
           "tags": ["a", "b", "c"], "meta": {"role": "admin", "seen": 7},
           "note": "x" * 180}
    mix.append(("application/json", json.dumps(obj).encode()))
    # ~16 KiB JSON array (~100 objects, several fields each) -- JSON-shaped
    # entropy compresses ~5-10x and is well over the 1400 B threshold, so the
    # application/json compression branch runs.
    arr = [{"id": i, "name": f"name-{i:04d}", "ts": f"2026-09-21T00:{i % 60:02d}:00Z",
            "ratio": i * 0.12345, "ok": (i % 2 == 0)} for i in range(100)]
    mix.append(("application/json", json.dumps(arr).encode()))
    # urlencoded with reserved characters (spaces, '&', '=', unicode) so the
    # value escaping is exercised on the wire.
    form = {"q": "the quick & brown = fox", "name": " query with spaces",
            "sym": "a&b=c d", "u": "café naïve ✓"}
    mix.append(("application/x-www-form-urlencoded",
                urllib.parse.urlencode(form).encode()))
    # multipart/form-data: the outer content-type carries the SAME boundary as
    # the hand-built body (see _multipart_body); the server echoes both verbatim.
    mix.append((f"multipart/form-data; boundary={_MP_BOUNDARY}",
                _multipart_body(_MP_BOUNDARY)))
    mix.append(("application/octet-stream", gen_chunk(0, 8192)))
    # typed binary, incompressible: the server must NOT compress a non-compressible
    # response type -- this keeps that branch honest.
    mix.append(("application/octet-stream", os.urandom(64 * 1024)))
    # XML document >= 1400 B (repeated <item> elements): the application/xml
    # compression branch.
    xml = (b'<?xml version="1.0" encoding="UTF-8"?><items>'
           + b"".join(b'<item id="%d">The quick brown fox jumps over the lazy dog</item>' % i
                      for i in range(40))
           + b"</items>")
    mix.append(("application/xml", xml))
    # a few-KB CSV built from a loop.
    csv = b"id,name,value\n" + b"".join(f"{i},name-{i},{i * i}\n".encode()
                                        for i in range(200))
    mix.append(("text/csv", csv))
    # small HTML page snippet -- intentionally can be < 1400 B (no-compress path).
    mix.append(("text/html",
                b"<!doctype html><html><body><h1>hi</h1>"
                b"<p>The quick brown fox.</p></body></html>"))
    return mix

def expected_gets() -> list:
    """The GET-route contract: (path, expected_content_type, expected_body) for
    the typed GET routes, with the exact deterministic bodies the server serves
    byte-for-byte (see the server contract). Cycled by the workloads, one GET per
    iteration, asserting both the content-type and the body exactly."""
    html = (b"<!doctype html><html><head><title>vortex stress</title></head><body>"
            + (b"<p>The quick brown fox jumps over the lazy dog.</p>" * 30)
            + b"</body></html>")
    xml = (b'<?xml version="1.0" encoding="UTF-8"?><items>'
           + b"".join(b'<item id="%d">The quick brown fox jumps over the lazy dog</item>' % i
                      for i in range(40))
           + b"</items>")
    csv = b"id,name,value\n" + b"".join(f"{i},name-{i},{i * i}\n".encode()
                                        for i in range(200))
    return [
        ("/plaintext", "text/plain", b"Hello, World!"),
        ("/json", "application/json", b'{"message":"Hello, World!"}'),
        ("/html", "text/html", html),
        ("/xml", "application/xml", xml),
        ("/csv", "text/csv", csv),
        ("/binary", "application/octet-stream", gen_chunk(0, 8192)),
    ]

# --- transport sessions (httpx for h1/h2, aioquic for h3) --------------------
# The negotiated HTTP version httpx must report for each pinned proto. httpx's
# http2=True enables h2 but still ALPN-negotiates, so it *can* land on h1 if the
# server didn't offer h2; verifying every response's version turns that silent
# downgrade into a hard failure, so an `h2` run can never quietly measure h1.
_PIN_VERSION = {"h1": "HTTP/1.1", "h2": "HTTP/2"}

def _pin_check(r):
    want = _PIN_VERSION.get(PROTO)
    if want is not None and r.http_version != want:
        raise ProtocolPinError(
            f"negotiated {r.http_version}, want {want} (VORTEX_PROTO={PROTO}); "
            f"no fallback allowed")

class HttpxSession:
    """httpx AsyncClient with the H3Session shape (paths relative to BASE)."""
    def __init__(self, c): self.c = c
    async def get(self, path, headers=None):
        r = await self.c.get(BASE + path, headers=headers or {})
        _pin_check(r)
        # Return the response content-type too so the typed workloads can assert
        # the server echoed / served the right type (the verbatim string,
        # multipart boundary included).
        return r.status_code, r.headers.get("content-type", ""), r.content
    async def request(self, method, path, headers=None, content=b""):
        r = await self.c.request(method, BASE + path, headers=headers or {}, content=content)
        _pin_check(r)
        return r.status_code, r.headers.get("content-type", ""), r.content
    async def stream(self, method, path, headers=None):
        async with self.c.stream(method, BASE + path, headers=headers or {}) as r:
            _pin_check(r)
            yield r.status_code
            # aiter_bytes (content-decoded), not aiter_raw: httpx auto-negotiates
            # Accept-Encoding, so the server may gzip the stream; the sse/download
            # workloads verify the logical payload (SSE framing / plaintext SHA),
            # so decode transparently -- reading raw would feed gzip to the parser.
            async for chunk in r.aiter_bytes():
                yield chunk
    async def upload(self, path, headers, agen):
        r = await self.c.post(BASE + path, content=agen, headers=headers or {})
        _pin_check(r)
        return r.status_code

@asynccontextmanager
async def session():
    if IS_H3:
        u = urlparse(BASE)
        async with connect_h3(u.hostname, u.port or 443) as s:
            yield s
    else:
        async with httpx.AsyncClient(http2=(PROTO == "h2"), verify=False, timeout=60.0) as c:
            yield HttpxSession(c)

async def get_server_stats(s) -> tuple:
    """Sample the server's (rss, heap) bytes from /stats. Raises on a non-2xx or
    an unparseable body; the caller renders that as `n/a` rather than a
    misleading `0MB`, so a regressed /stats can't masquerade as a healthy zero
    footprint and quietly defeat the soak's leak watch."""
    st, _ct, body = await s.get("/stats")
    if st != 200:
        raise RuntimeError(f"/stats -> {st}")
    rss, heap = body.split()
    return int(rss), int(heap)
