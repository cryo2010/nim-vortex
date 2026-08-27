#!/usr/bin/env python3
"""Per-workload load client for the vortex stress soaks (conformance/stress/run.sh).

Drives one workload (VORTEX_WORKLOAD) at the vortex server for VORTEX_SECONDS,
verifying it and **discarding** responses so memory stays flat. **Hard fails**
(non-zero exit) on data corruption - checksum mismatch, echo mismatch, a
non-2xx status, or a missing/out-of-order SSE event. A transient connection
error (a reset under high concurrency) is counted and retried on a fresh
connection, not fatal - a soak tolerates connection churn. If *no* iteration
ever succeeds, that is a failure.

  requests        GET/POST/PUT /echo with bodies + req/resp compression
  ws              persistent WebSocket echo, verified
  sse             subscribe /sse; survive the mid-stream drop; reconnect with
                  Last-Event-ID; assert all N events arrive in id order
  streamupload    stream STREAM_BYTES up to /upload with x-sha1; expect 200
  streamdownload  stream /download; hash; compare to the deterministic expected

h1/h2 go through httpx (http2=PROTO==h2). HTTP/3 is not supported by httpx, so
h3 cells print a skip (h3 saturation lives in `nimble h3load`).
"""
import asyncio, gzip, hashlib, os, sys, time
import httpx
try:
    from websockets.exceptions import WebSocketException
except ImportError:
    class WebSocketException(Exception): pass

WORKLOAD = os.environ.get("VORTEX_WORKLOAD", "requests")
PROTO    = os.environ.get("VORTEX_PROTO", "h2")
BASE     = os.environ["STRESS_BASE"].rstrip("/")          # e.g. https://server:8443
SECONDS  = int(os.environ.get("VORTEX_SECONDS", "60"))
CLIENTS  = int(os.environ.get("VORTEX_CLIENTS", "3"))
CONC     = int(os.environ.get("VORTEX_CONCURRENCY", "32"))
STREAM   = int(os.environ.get("VORTEX_STREAM_BYTES", str(1 << 30)))
REPORT   = int(os.environ.get("VORTEX_REPORT_SECONDS", "60"))
REQ_COMP  = os.environ.get("VORTEX_REQ_COMPRESSION", "gzip")
RESP_COMP = os.environ.get("VORTEX_RESP_COMPRESSION", "gzip")
CHUNK = 64 * 1024

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

async def body_gen():                             # async: httpx AsyncClient streams it
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

ACCEPT = None if RESP_COMP in ("", "none") else RESP_COMP   # server compresses response

# --- shared state ------------------------------------------------------------
class Fail(Exception):
    """A real, fatal defect (data corruption / bad status). Never retried."""
stats = {"ok": 0, "transient": 0, "bytes": 0}
deadline = 0.0

def new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(http2=(PROTO == "h2"), verify=False, timeout=60.0)

async def reporter():
    while time.monotonic() < deadline:
        await asyncio.sleep(REPORT)
        left = max(0, int(deadline - time.monotonic()))
        print(f"  [{WORKLOAD}] ok={stats['ok']} transient={stats['transient']} "
              f"bytes={stats['bytes']} ({left}s left)", flush=True)

async def retrying(worker):
    """Run `worker` until the deadline, reopening on transient transport errors.
    `Fail` (a real defect) and anything else propagate immediately."""
    while time.monotonic() < deadline:
        try:
            await worker()
        except (httpx.TransportError, WebSocketException, ConnectionError, OSError):
            stats["transient"] += 1
            await asyncio.sleep(0.02)

# --- workloads ---------------------------------------------------------------
async def w_requests():
    raw = b"the quick brown fox " * 64
    body, enc = compress(raw)
    hdrs = {}
    if enc: hdrs["content-encoding"] = enc
    if ACCEPT: hdrs["accept-encoding"] = ACCEPT
    get_hdrs = {"accept-encoding": ACCEPT} if ACCEPT else {}
    async def once():
        async with new_client() as c:
            while time.monotonic() < deadline:
                r = await c.get(BASE + "/plaintext", headers=get_hdrs)
                if r.status_code != 200 or r.text != "Hello, World!":
                    raise Fail(f"GET /plaintext -> {r.status_code}")
                stats["ok"] += 1
                for meth in ("POST", "PUT"):
                    r = await c.request(meth, BASE + "/echo", content=body, headers=hdrs)
                    if r.status_code != 200 or r.content != raw:
                        raise Fail(f"{meth} /echo -> {r.status_code}, {len(r.content)}B")
                    stats["ok"] += 1
    await asyncio.gather(*[retrying(once) for _ in range(CONC)])

async def w_ws():
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
                got = await ws.recv()
                if got != msg: raise Fail(f"ws echo mismatch: {got!r} != {msg!r}")
                stats["ok"] += 1; n += 1
    await asyncio.gather(*[retrying(lambda i=i: once(i)) for i in range(CONC)])

async def w_sse():
    total = 100     # must match the server's sseTotal
    async def once():
        async with new_client() as c:
            got = 0
            last = None
            while got < total:                       # reconnect on the server's drop
                hdrs = {"accept": "text/event-stream"}
                if last is not None: hdrs["last-event-id"] = str(last)
                progressed = False
                async with c.stream("GET", BASE + "/sse", headers=hdrs) as r:
                    if r.status_code != 200: raise Fail(f"sse status {r.status_code}")
                    cur_id = None
                    async for line in r.aiter_lines():
                        if line.startswith("id:"): cur_id = int(line[3:].strip())
                        elif line.startswith("data:") and cur_id is not None:
                            if cur_id != got: raise Fail(f"sse out of order: {cur_id} != {got}")
                            got += 1; last = cur_id; cur_id = None; progressed = True
                if not progressed: raise Fail("sse made no progress")
            stats["ok"] += 1
    await asyncio.gather(*[retrying(once) for _ in range(CONC)])

async def w_streamupload():
    sha = expected_sha1()
    async def once():
        async with new_client() as c:
            r = await c.post(BASE + "/upload", content=body_gen(),
                             headers={"x-sha1": sha})   # chunked; server streams onBody
            if r.status_code == 400: raise Fail("server rejected the SHA-1 (400)")
            if r.status_code != 200: raise Fail(f"upload -> {r.status_code}")
            stats["ok"] += 1; stats["bytes"] += STREAM
    await retrying(once)                          # one big transfer per copy

async def w_streamdownload():
    want = expected_sha1()
    async def once():
        async with new_client() as c:
            h = hashlib.sha1(); got = 0
            async with c.stream("GET", BASE + "/download") as r:
                if r.status_code != 200: raise Fail(f"download status {r.status_code}")
                async for chunk in r.aiter_raw():
                    h.update(chunk); got += len(chunk)
            if got != STREAM or h.hexdigest() != want:
                raise Fail(f"download mismatch: {got} bytes, sha {h.hexdigest()} != {want}")
            stats["ok"] += 1; stats["bytes"] += STREAM
    await retrying(once)                          # one big transfer per copy

WORKLOADS = {
    "requests": w_requests, "ws": w_ws, "sse": w_sse,
    "streamupload": w_streamupload, "streamdownload": w_streamdownload,
}

async def main():
    global deadline
    if PROTO == "h3":
        print(f"SKIP {WORKLOAD}: HTTP/3 is not supported by the httpx client "
              f"(use `nimble h3load` for h3 saturation).", flush=True)
        return 0
    if WORKLOAD not in WORKLOADS:
        print(f"unknown VORTEX_WORKLOAD: {WORKLOAD}", file=sys.stderr); return 2
    deadline = time.monotonic() + SECONDS
    rep = asyncio.ensure_future(reporter())
    try:
        # CLIENTS client-copies. requests/ws/sse fan out CONC-wide inside each
        # (CLIENTS x CONC total); streamupload/download do one big transfer per
        # copy (CLIENTS concurrent streams).
        await asyncio.gather(*[WORKLOADS[WORKLOAD]() for _ in range(CLIENTS)])
    except Fail as e:
        print(f"FAIL {WORKLOAD}: {e} (ok={stats['ok']} transient={stats['transient']})",
              file=sys.stderr); return 1
    finally:
        rep.cancel()
    if stats["ok"] == 0:
        print(f"FAIL {WORKLOAD}: no successful iterations "
              f"(transient={stats['transient']})", file=sys.stderr); return 1
    print(f"PASS {WORKLOAD}: ok={stats['ok']} transient={stats['transient']} "
          f"bytes={stats['bytes']}", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
