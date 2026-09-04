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
import gzip, hashlib, os
from contextlib import asynccontextmanager
from urllib.parse import urlparse
import httpx
try:
    from websockets.exceptions import WebSocketException
except ImportError:
    class WebSocketException(Exception): pass
from h3 import connect_h3, OP_TEXT

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
UNIT = {"requests": "requests", "ws": "messages", "sse": "events",
        "streamupload": "transfers", "streamdownload": "transfers"}.get(WORKLOAD, "ok")
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

# --- transport sessions (httpx for h1/h2, aioquic for h3) --------------------
class HttpxSession:
    """httpx AsyncClient with the H3Session shape (paths relative to BASE)."""
    def __init__(self, c): self.c = c
    async def get(self, path, headers=None):
        r = await self.c.get(BASE + path, headers=headers or {})
        return r.status_code, r.content
    async def request(self, method, path, headers=None, content=b""):
        r = await self.c.request(method, BASE + path, headers=headers or {}, content=content)
        return r.status_code, r.content
    async def stream(self, method, path, headers=None):
        async with self.c.stream(method, BASE + path, headers=headers or {}) as r:
            yield r.status_code
            # aiter_bytes (content-decoded), not aiter_raw: httpx auto-negotiates
            # Accept-Encoding, so the server may gzip the stream; the sse/download
            # workloads verify the logical payload (SSE framing / plaintext SHA),
            # so decode transparently -- reading raw would feed gzip to the parser.
            async for chunk in r.aiter_bytes():
                yield chunk
    async def upload(self, path, headers, agen):
        r = await self.c.post(BASE + path, content=agen, headers=headers or {})
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
    st, body = await s.get("/stats")
    if st != 200:
        raise RuntimeError(f"/stats -> {st}")
    rss, heap = body.split()
    return int(rss), int(heap)
