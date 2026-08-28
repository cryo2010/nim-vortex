#!/usr/bin/env python3
"""Per-workload load client for the vortex stress soaks (conformance/stress/run.sh).

Drives one workload (VORTEX_WORKLOAD) at the vortex server for VORTEX_SECONDS,
verifying it and **discarding** responses so memory stays flat. **Hard fails**
(non-zero exit) on data corruption - checksum mismatch, echo mismatch, a
non-2xx status, or a missing/out-of-order SSE event. A transient connection
error (a reset under high concurrency) is counted and retried on a fresh
connection, not fatal - a soak tolerates connection churn. If *no* iteration
ever succeeds, that is a failure.

Transport is chosen by VORTEX_PROTO: h1/h2 via httpx, **h3 via aioquic** (see
h3.py; httpx has no HTTP/3). Both expose the same session shape, so the
workloads are transport-agnostic. WebSocket-over-HTTP/3 is the one gap (Extended
CONNECT is not yet wired), so `ws` + `h3` prints a skip.

Reports each VORTEX_REPORT_SECONDS in nim-navi's format - status-code tallies
plus the server's RSS and Nim heap (from /stats) and elapsed time:

    [sse h3 chronos] 200x1481767 | RSS 29MB | heap 7MB | t=45s
    [sse h3 chronos] final 200x1493782 | RSS 29MB | heap 6MB | t=60s
    == sse chronos h3 passed (1493782 events) ==
"""
import asyncio, gzip, hashlib, os, sys, time
from collections import Counter
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
            async for chunk in r.aiter_raw():
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

# --- shared state ------------------------------------------------------------
class Fail(Exception):
    """A real, fatal defect (data corruption / bad status). Never retried."""
codes = Counter()
transient = [0]
start = 0.0
deadline = 0.0

def bump(status: int, n: int = 1): codes[status] += n

def fmt_codes() -> str:
    parts = [f"{c}x{n}" for c, n in sorted(codes.items())]
    if transient[0]: parts.append(f"errx{transient[0]}")
    return " ".join(parts) if parts else "0"

async def get_server_stats(s) -> tuple:
    try:
        st, body = await s.get("/stats")
        rss, heap = body.split()
        return int(rss), int(heap)
    except Exception:
        return 0, 0

def report_line(prefix, rss, heap):
    t = int(time.monotonic() - start)
    print(f"[{WORKLOAD} {PROTO} {SERVER}] {prefix}{fmt_codes()} | "
          f"RSS {rss // MB}MB | heap {heap // MB}MB | t={t}s", flush=True)

async def reporter():
    async with session() as s:
        while time.monotonic() < deadline:
            await asyncio.sleep(REPORT)
            rss, heap = await get_server_stats(s)
            report_line("", rss, heap)

async def retrying(worker):
    while time.monotonic() < deadline:
        try:
            await worker()
        except (httpx.TransportError, WebSocketException, ConnectionError, OSError):
            transient[0] += 1
            await asyncio.sleep(0.02)

# --- workloads (transport-agnostic via session) ------------------------------
async def w_requests():
    raw = b"the quick brown fox " * 64
    body, enc = compress(raw)
    hdrs = {}
    if enc: hdrs["content-encoding"] = enc
    if ACCEPT: hdrs["accept-encoding"] = ACCEPT
    get_hdrs = {"accept-encoding": ACCEPT} if ACCEPT else {}
    async def once():
        async with session() as s:
            while time.monotonic() < deadline:
                st, b = await s.get("/plaintext", get_hdrs)
                if st != 200 or b != b"Hello, World!":
                    raise Fail(f"GET /plaintext -> {st}")
                bump(200)
                for meth in ("POST", "PUT"):
                    st, b = await s.request(meth, "/echo", hdrs, body)  # body: compressed
                    if st != 200 or b != raw:
                        raise Fail(f"{meth} /echo -> {st}, {len(b)}B")
                    bump(200)
    await asyncio.gather(*[retrying(once) for _ in range(CONC)])

async def w_ws():
    if IS_H3:                                   # RFC 9220 Extended CONNECT via aioquic
        async def once(i):
            async with session() as s:
                ws = await s.ws_open("/ws")
                if ws.status != 200: raise Fail(f"ws-h3 handshake {ws.status}")
                n = 0
                while time.monotonic() < deadline:
                    msg = f"msg-{i}-{n}".encode()
                    ws.send(OP_TEXT, msg)
                    op, payload = await ws.recv()
                    if op != OP_TEXT or payload != msg:
                        raise Fail(f"ws-h3 echo mismatch: op={op} {payload!r}")
                    bump(200); n += 1
        await asyncio.gather(*[retrying(lambda i=i: once(i)) for i in range(CONC)])
        return
    import websockets
    ws_url = BASE.replace("https://", "wss://").replace("http://", "ws://") + "/ws"
    ssl_ctx = None
    if ws_url.startswith("wss://"):
        import ssl
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
    async def once(i):
        n = 0
        async with websockets.connect(ws_url, ssl=ssl_ctx, max_size=None) as ws:
            while time.monotonic() < deadline:
                msg = f"msg-{i}-{n}"
                await ws.send(msg)
                if await ws.recv() != msg: raise Fail("ws echo mismatch")
                bump(200); n += 1
    await asyncio.gather(*[retrying(lambda i=i: once(i)) for i in range(CONC)])

async def read_lines(gen):
    """Yield decoded lines from a byte-chunk async generator (SSE framing)."""
    buf = b""
    async for chunk in gen:
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.rstrip(b"\r").decode("utf-8", "replace")

async def w_sse():
    total = 100     # must match the server's sseTotal
    async def once():
        async with session() as s:
            got, last = 0, None
            while got < total:                       # reconnect on the server's drop
                hdrs = {"accept": "text/event-stream"}
                if last is not None: hdrs["last-event-id"] = str(last)
                gen = s.stream("GET", "/sse", hdrs)
                st = await gen.__anext__()
                if st != 200: raise Fail(f"sse status {st}")
                progressed, cur_id = False, None
                async for line in read_lines(gen):
                    if line.startswith("id:"): cur_id = int(line[3:].strip())
                    elif line.startswith("data:") and cur_id is not None:
                        if cur_id != got: raise Fail(f"sse out of order: {cur_id} != {got}")
                        got += 1; last = cur_id; cur_id = None; progressed = True
                        bump(200)
                if not progressed: raise Fail("sse made no progress")
    await asyncio.gather(*[retrying(once) for _ in range(CONC)])

async def w_streamupload():
    sha = expected_sha1()
    async def once():
        async with session() as s:
            st = await s.upload("/upload", {"x-sha1": sha}, body_gen())
            if st == 400: raise Fail("server rejected the SHA-1 (400)")
            if st != 200: raise Fail(f"upload -> {st}")
            bump(200)
    await retrying(once)

async def w_streamdownload():
    want = expected_sha1()
    async def once():
        async with session() as s:
            gen = s.stream("GET", "/download")
            st = await gen.__anext__()
            if st != 200: raise Fail(f"download status {st}")
            h = hashlib.sha1(); got = 0
            async for chunk in gen:
                h.update(chunk); got += len(chunk)
            if got != STREAM or h.hexdigest() != want:
                raise Fail(f"download mismatch: {got} bytes, sha {h.hexdigest()} != {want}")
            bump(200)
    await retrying(once)

WORKLOADS = {
    "requests": w_requests, "ws": w_ws, "sse": w_sse,
    "streamupload": w_streamupload, "streamdownload": w_streamdownload,
}

async def main():
    global deadline, start
    if WORKLOAD not in WORKLOADS:
        print(f"unknown VORTEX_WORKLOAD: {WORKLOAD}", file=sys.stderr); return 2
    start = time.monotonic()
    deadline = start + SECONDS
    rep = asyncio.ensure_future(reporter())
    try:
        # workers self-stop at the deadline; wait_for is a safety net so a stalled
        # await (e.g. a peer flow-control stall) can never hang the harness.
        await asyncio.wait_for(
            asyncio.gather(*[WORKLOADS[WORKLOAD]() for _ in range(CLIENTS)]),
            timeout=SECONDS + 60)
    except Fail as e:
        print(f"FAIL {WORKLOAD}: {e} ({fmt_codes()})", file=sys.stderr); return 1
    except asyncio.TimeoutError:
        print(f"WARN {WORKLOAD}: workers did not stop within deadline+60s "
              f"({fmt_codes()})", file=sys.stderr)
    finally:
        rep.cancel()
    total = sum(n for c, n in codes.items() if 200 <= c < 300)
    async with session() as s:
        rss, heap = await get_server_stats(s)
    report_line("final ", rss, heap)
    if total == 0:
        print(f"FAIL {WORKLOAD}: no successful iterations (errx{transient[0]})",
              file=sys.stderr); return 1
    print(f"== {WORKLOAD} {SERVER} {PROTO} passed ({total} {UNIT}) ==", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
