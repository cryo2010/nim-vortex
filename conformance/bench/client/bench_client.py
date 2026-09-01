#!/usr/bin/env python3
"""Per-workload performance client for the vortex benches (conformance/bench/run.sh).

Drives one workload (VORTEX_WORKLOAD) at the vortex server for VORTEX_SECONDS at
max rate and MEASURES it: throughput (req/s | msg/s | evt/s | MB/s) plus latency
percentiles (p50/p90/p99/max) and the server's RSS/heap (from /stats), each
VORTEX_REPORT_SECONDS. Unlike the stress client it does NOT verify payloads and
never fails on data -- a non-2xx is tallied, a transport error is counted and the
loop keeps measuring. It exits non-zero only if it could not measure at all (no
successful operation), so run.sh can flag a broken cell.

Transport (httpx h1/h2, aioquic h3) and config are shared with the stress client
via `transport`. Numbers are for relative/regression tracking and cross-runtime
comparison, not absolute peak -- the pure-Python client caps throughput on cheap
endpoints (aioquic h3 ~50 MB/s; httpx h2 throttles). Use `nimble saturate`
(h2load) / `nimble h3load` for absolute peak req/s.

    [requests h2 chronos] 48210 req/s | p50 0.62ms p90 1.10ms p99 3.4ms max 41ms | 200x2894301 5xx0 | RSS 31MB heap 7MB | t=10s
    == requests chronos h2 bench: 2894301 requests, 48210 req/s avg, p99 3.4ms ==
"""
import asyncio, sys, time
from collections import Counter, deque
import httpx
from transport import (
    WebSocketException, OP_TEXT,
    WORKLOAD, PROTO, SERVER, BASE, SECONDS, CLIENTS, CONC, STREAM, REPORT,
    MB, IS_H3, UNIT, STREAMING, xfer,
    expected_sha1, body_gen, compress, ACCEPT, session, get_server_stats)

# --- measurement state (bounded; latency reservoir cleared each interval) ----
ops = [0]                       # cumulative successful operations
codes = Counter()               # status-code tallies
errors = [0]                    # transport errors that did not stop the run
lat = deque(maxlen=200_000)     # latency samples (seconds) for the current interval
start = 0.0
deadline = 0.0
skipped = [False]               # workload/proto combo not measurable (e.g. h3 upload)
_last = [0.0, 0, 0]             # [report time, ops at report, xfer bytes at report]

def op(dt: float, status: int = 200):
    ops[0] += 1
    codes[status] += 1
    lat.append(dt)

def pct(s, p: float) -> float:
    if not s: return 0.0
    i = min(len(s) - 1, int(p / 100.0 * len(s)))
    return s[i]

def fmt_lat() -> str:
    if not lat: return "p50 - p90 - p99 - max -"
    s = sorted(lat)
    unit, scale = ("s", 1.0) if STREAMING else ("ms", 1000.0)
    f = lambda p: f"{pct(s, p) * scale:.2f}{unit}"
    return f"p50 {f(50)} p90 {f(90)} p99 {f(99)} max {f(100)}"

def fmt_codes() -> str:
    parts = [f"{c}x{n}" for c, n in sorted(codes.items())]
    return " ".join(parts) if parts else "0"

def report_line(prefix: str, rss: int, heap: int):
    now = time.monotonic()
    t = int(now - start)
    dt = now - _last[0] if now > _last[0] else 1e-9
    if STREAMING:
        mb = xfer[0] // MB
        rate = (xfer[0] - _last[2]) / dt / MB
        thru = f"{mb}MB xfer @ {rate:.0f}MB/s"
    else:
        unit = {"requests": "req", "ws": "msg", "sse": "evt"}.get(WORKLOAD, "op")
        rate = (ops[0] - _last[1]) / dt
        thru = f"{rate:.0f} {unit}/s"
    print(f"[{WORKLOAD} {PROTO} {SERVER}] {prefix}{thru} | {fmt_lat()} | "
          f"{fmt_codes()} err{errors[0]} | RSS {rss // MB}MB heap {heap // MB}MB | t={t}s",
          flush=True)
    _last[0], _last[1], _last[2] = now, ops[0], xfer[0]
    lat.clear()                 # percentiles are per-interval

async def reporter():
    async with session() as s:
        while time.monotonic() < deadline:
            await asyncio.sleep(REPORT)
            rss, heap = await get_server_stats(s)
            report_line("", rss, heap)

async def drive(worker):
    # Repeat the worker until the deadline. A transport error does NOT stop the
    # bench (unlike stress): count it and keep measuring, with a tiny backoff so a
    # dead server can't spin. If nothing ever succeeds, main() exits non-zero.
    while time.monotonic() < deadline:
        try:
            await worker()
        except (httpx.TransportError, WebSocketException, ConnectionError, OSError):
            errors[0] += 1
            await asyncio.sleep(0.05)

# --- workloads (measure; no payload verification) ----------------------------
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
                t0 = time.perf_counter()
                st, _ = await s.get("/plaintext", get_hdrs)
                op(time.perf_counter() - t0, st)
                for meth in ("POST", "PUT"):
                    t0 = time.perf_counter()
                    st, _ = await s.request(meth, "/echo", hdrs, body)
                    op(time.perf_counter() - t0, st)
    await asyncio.gather(*[drive(once) for _ in range(CONC)])

async def w_ws():
    if IS_H3:                                   # RFC 9220 Extended CONNECT via aioquic
        async def once(i):
            async with session() as s:
                ws = await s.ws_open("/ws")
                if ws.status != 200:
                    errors[0] += 1; return
                n = 0
                while time.monotonic() < deadline:
                    msg = f"msg-{i}-{n}".encode()
                    t0 = time.perf_counter()
                    ws.send(OP_TEXT, msg)
                    await ws.recv()
                    op(time.perf_counter() - t0); n += 1
        await asyncio.gather(*[drive(lambda i=i: once(i)) for i in range(CONC)])
        return
    import websockets, ssl
    ws_url = BASE.replace("https://", "wss://").replace("http://", "ws://") + "/ws"
    ssl_ctx = None
    if ws_url.startswith("wss://"):
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    async def once(i):
        n = 0
        async with websockets.connect(ws_url, ssl=ssl_ctx, max_size=None) as ws:
            while time.monotonic() < deadline:
                msg = f"msg-{i}-{n}"
                t0 = time.perf_counter()
                await ws.send(msg); await ws.recv()
                op(time.perf_counter() - t0); n += 1
    await asyncio.gather(*[drive(lambda i=i: once(i)) for i in range(CONC)])

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
    seqs_per_conn = 2000
    async def once():
        while time.monotonic() < deadline:
            async with session() as s:
                for _ in range(seqs_per_conn):
                    if time.monotonic() >= deadline: break
                    got, last, prev = 0, None, time.perf_counter()
                    while got < total:               # reconnect on the server's drop
                        hdrs = {"accept": "text/event-stream"}
                        if last is not None: hdrs["last-event-id"] = str(last)
                        gen = s.stream("GET", "/sse", hdrs)
                        st = await gen.__anext__()
                        if st != 200:
                            errors[0] += 1; return
                        cur_id = None
                        async for line in read_lines(gen):
                            if line.startswith("id:"): cur_id = int(line[3:].strip())
                            elif line.startswith("data:") and cur_id is not None:
                                now = time.perf_counter()
                                op(now - prev, st); prev = now      # inter-event delta
                                got += 1; last = cur_id; cur_id = None
    await asyncio.gather(*[drive(once) for _ in range(CONC)])

async def w_streamupload():
    if IS_H3:
        # vortex does not yet ACK h3 request-body flow control, so a large h3
        # upload stalls after the initial window; measuring it would report a
        # stalled 0 MB/s. Skip (mirrors the stress harness), do not fail.
        print(f"[{WORKLOAD} {PROTO} {SERVER}] SKIP: streamupload over h3 "
              f"(request-body flow-control not yet acked)", flush=True)
        skipped[0] = True
        return
    sha = expected_sha1()   # server validates x-sha1 for free; client just times it
    async def once():
        async with session() as s:
            t0 = time.perf_counter()
            st = await s.upload("/upload", {"x-sha1": sha}, body_gen())
            op(time.perf_counter() - t0, st)   # body_gen credits xfer for h1/h2
    await drive(once)

async def w_streamdownload():
    async def once():
        async with session() as s:
            t0 = time.perf_counter()
            gen = s.stream("GET", "/download")
            st = await gen.__anext__()
            async for chunk in gen:            # drain + count bytes; no SHA (client CPU)
                xfer[0] += len(chunk)
            op(time.perf_counter() - t0, st)
    await drive(once)

WORKLOADS = {
    "requests": w_requests, "ws": w_ws, "sse": w_sse,
    "streamupload": w_streamupload, "streamdownload": w_streamdownload,
}

async def main():
    global deadline, start
    if WORKLOAD not in WORKLOADS:
        print(f"unknown VORTEX_WORKLOAD: {WORKLOAD}", file=sys.stderr); return 2
    start = time.monotonic()
    _last[0] = start
    deadline = start + SECONDS
    rep = asyncio.ensure_future(reporter())
    try:
        await asyncio.wait_for(
            asyncio.gather(*[WORKLOADS[WORKLOAD]() for _ in range(CLIENTS)]),
            timeout=SECONDS + 60)
    except asyncio.TimeoutError:
        print(f"WARN {WORKLOAD}: workers did not stop within deadline+60s", file=sys.stderr)
    finally:
        rep.cancel()
    if skipped[0]:
        print(f"== {WORKLOAD} {SERVER} {PROTO} bench: skipped ==", flush=True)
        return 0
    rss, heap = 0, 0
    try:
        async with session() as s:
            rss, heap = await get_server_stats(s)
    except Exception:
        pass
    total = ops[0]
    elapsed = max(time.monotonic() - start, 1e-9)
    report_line("final ", rss, heap)
    if total == 0:
        print(f"COULD NOT MEASURE {WORKLOAD}: no successful operations "
              f"(err{errors[0]})", file=sys.stderr); return 1
    if STREAMING:
        avg = f"{xfer[0] / elapsed / MB:.0f}MB/s avg"
    else:
        unit = {"requests": "req", "ws": "msg", "sse": "evt"}.get(WORKLOAD, "op")
        avg = f"{total / elapsed:.0f} {unit}/s avg"
    print(f"== {WORKLOAD} {SERVER} {PROTO} bench: {total} {UNIT}, {avg} ==", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
