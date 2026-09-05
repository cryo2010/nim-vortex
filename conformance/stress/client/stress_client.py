#!/usr/bin/env python3
"""Per-workload load client for the vortex stress soaks (conformance/stress/run.sh).

Drives one workload (VORTEX_WORKLOAD) at the vortex server for VORTEX_SECONDS,
verifying it and **discarding** responses so memory stays flat. **Hard fails**
(non-zero exit) at once on the first defect - checksum mismatch, echo mismatch,
a non-2xx status, a missing/out-of-order SSE event, or any transport/connection
error (a reset, refused connect, timeout). There is no retry or errx tally: an
error is surfaced immediately with its cause. If *no* iteration ever succeeds,
that too is a failure.

Transport is chosen by VORTEX_PROTO: h1/h2 via httpx, **h3 via aioquic** (see
h3.py; httpx has no HTTP/3). Both expose the same session shape, so the
workloads are transport-agnostic. WebSocket over HTTP/3 (RFC 9220 Extended
CONNECT) is wired for h3 too. The one skipped cell is `streamupload` + `h3`:
vortex does not yet ack HTTP/3 request-body flow control (the h3AckBody gap), so
a large h3 upload stalls; that cell prints a skip and exits 0.

Reports each VORTEX_REPORT_SECONDS in nim-navi's format - status-code tallies
plus the server's RSS and Nim heap (from /stats) and elapsed time:

    [sse h3 chronos] 200x1481767 | RSS 29MB | heap 7MB | t=45s
    [sse h3 chronos] final 200x1493782 | RSS 29MB | heap 6MB | t=60s
    == sse chronos h3 passed (1493782 events) ==
"""
import asyncio, hashlib, os, sys, time
from collections import Counter
import httpx
from transport import (
    WebSocketException, OP_TEXT, ProtocolPinError,
    WORKLOAD, PROTO, SERVER, BASE, SECONDS, CLIENTS, CONC, STREAM, REPORT,
    MB, IS_H3, UNIT, STREAMING, xfer,
    expected_sha1, body_gen, gen_chunk, compress, ACCEPT, session, get_server_stats)

# --- shared state ------------------------------------------------------------
class Fail(Exception):
    """A fatal defect (corruption, bad status, or a transport error). Ends the
    run non-zero at once; never retried or tallied."""
codes = Counter()
_rate = [0.0, 0]       # [last report monotonic, bytes at last report] for MB/s
start = 0.0
deadline = 0.0

def bump(status: int, n: int = 1): codes[status] += n

def fmt_codes() -> str:
    parts = [f"{c}x{n}" for c, n in sorted(codes.items())]
    return " ".join(parts) if parts else "0"

def fmt_xfer(now: float) -> str:
    """A throughput segment for the streaming workloads: cumulative bytes plus
    the MB/s since the last report. `xfer` tracks what actually moved on the
    wire, not what was queued: download counts bytes received; h1/h2 upload
    counts bytes yielded (httpx streams, so yielded ~= sent); h3 upload counts
    STREAM per completed transfer (aioquic buffers the whole body up front, so a
    queued-bytes rate would spike then read 0 while the wire drains). 0 MB/s
    means nothing moved in the interval -- a stall, or (h3 upload) a large
    transfer still in flight with no completion yet."""
    dt, db = now - _rate[0], xfer[0] - _rate[1]
    _rate[0], _rate[1] = now, xfer[0]
    rate = db / dt / MB if dt > 0 else 0.0
    return f" | {xfer[0] // MB}MB xfer @ {rate:.0f}MB/s"

def report_line(prefix, rss, heap):
    now = time.monotonic()
    t = int(now - start)
    seg = fmt_xfer(now) if STREAMING else ""
    # `None` means the /stats sample failed; render "n/a", never a misleading
    # "0MB" -- a soak exists to watch RSS/heap, so a silently-zeroed metric must
    # look broken, not healthy.
    rss_s = "n/a" if rss is None else f"{rss // MB}MB"
    heap_s = "n/a" if heap is None else f"{heap // MB}MB"
    print(f"[{WORKLOAD} {PROTO} {SERVER}] {prefix}{fmt_codes()}{seg} | "
          f"RSS {rss_s} | heap {heap_s} | t={t}s", flush=True)

async def reporter():
    async with session() as s:
        while time.monotonic() < deadline:
            await asyncio.sleep(REPORT)
            try:
                rss, heap = await get_server_stats(s)
            except Exception:
                rss = heap = None      # a bad /stats shows as n/a, not fake 0MB
            report_line("", rss, heap)

async def drive(worker):
    # Call worker repeatedly until the deadline (workers that do one transfer
    # per call repeat here). A transport/connection error is a hard failure:
    # raise it as a fatal Fail at once so the run exits non-zero immediately
    # with the cause, instead of tallying an errx count to sift through later.
    while time.monotonic() < deadline:
        try:
            await worker()
        except ProtocolPinError as e:
            # A protocol-pin violation (silent fallback) is a defect in its own
            # right, not a transport error: surface it verbatim as a hard fail.
            raise Fail(f"protocol pin: {e}") from e
        except (httpx.TransportError, WebSocketException, ConnectionError, OSError) as e:
            raise Fail(f"transport error ({type(e).__name__}): {e}") from e

# --- workloads (transport-agnostic via session) ------------------------------
async def w_requests():
    # Body-size mix, cycled per iteration. A single fixed 1280-byte body only ever
    # exercises one point on the length curve; real traffic is bimodal (empty
    # GETs/echoes, tiny JSON, occasional large payloads). Include 0 and 1 byte to
    # cover the 0-length / single-byte framing paths (chunked vs Content-Length),
    # and an incompressible random body so the codec path sees a non-trivial ratio
    # and its fall-back-to-store branch, not just the best-case compressible one.
    raws = []
    for n in (0, 1, 13, 1280, 64 * 1024, 256 * 1024):
        raws.append((b"the quick brown fox " * (n // 20 + 1))[:n])
    raws.append(os.urandom(64 * 1024))         # incompressible
    prepared = []
    for raw in raws:
        body, enc = compress(raw)
        hdrs = {}
        if enc: hdrs["content-encoding"] = enc
        if ACCEPT: hdrs["accept-encoding"] = ACCEPT
        prepared.append((raw, body, hdrs))
    get_hdrs = {"accept-encoding": ACCEPT} if ACCEPT else {}
    async def once():
        async with session() as s:
            k = 0
            while time.monotonic() < deadline:
                st, b = await s.get("/plaintext", get_hdrs)
                if st != 200 or b != b"Hello, World!":
                    raise Fail(f"GET /plaintext -> {st}")
                bump(200)
                raw, body, hdrs = prepared[k % len(prepared)]; k += 1
                for meth in ("POST", "PUT"):
                    st, b = await s.request(meth, "/echo", hdrs, body)  # body: compressed
                    if st != 200 or b != raw:
                        raise Fail(f"{meth} /echo -> {st}, {len(b)}B (want {len(raw)}B)")
                    bump(200)
    await asyncio.gather(*[drive(once) for _ in range(CONC)])

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
        await asyncio.gather(*[drive(lambda i=i: once(i)) for i in range(CONC)])
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
    batch = 20      # must match the server's sseBatch (events per connection)
    # Sequences per connection before reopening. Reusing one connection avoids
    # the TLS+h2 connect churn that #145 fixed, but a single connection can't
    # live forever: httpx's h2 stack accumulates per-stream state and drops the
    # connection after ~65k SSE streams (vortex serves 300k+ fine -- confirmed
    # with h2load). Each sequence is total/sseBatch = 5 streams, so 2000 keeps a
    # connection to ~10k streams (well under the limit) while reopening only
    # every ~200k events -- negligible churn vs the per-100-events reopening.
    seqs_per_conn = 2000
    async def once():
        while time.monotonic() < deadline:
            async with session() as s:
                for _ in range(seqs_per_conn):
                    if time.monotonic() >= deadline: break
                    got, last = 0, None
                    while got < total:               # reconnect on the server's drop
                        hdrs = {"accept": "text/event-stream"}
                        if last is not None: hdrs["last-event-id"] = str(last)
                        gen = s.stream("GET", "/sse", hdrs)
                        st = await gen.__anext__()
                        if st != 200: raise Fail(f"sse status {st}")
                        progressed, cur_id, this_batch = False, None, 0
                        async for line in read_lines(gen):
                            if line.startswith("id:"): cur_id = int(line[3:].strip())
                            elif line.startswith("data:") and cur_id is not None:
                                if cur_id != got: raise Fail(f"sse out of order: {cur_id} != {got}")
                                got += 1; last = cur_id; cur_id = None; progressed = True
                                this_batch += 1; bump(200)
                        if not progressed: raise Fail("sse made no progress")
                        # Each connection must deliver a full batch before the
                        # server closes (only the final one may be short). A
                        # server that truncates batches (e.g. closes after 1
                        # event) still makes in-order progress, so without this
                        # the documented batch-close-then-resume behavior goes
                        # unverified.
                        if got < total and this_batch != batch:
                            raise Fail(f"sse short batch: {this_batch} events "
                                       f"before close (want {batch}), got={got}")
    await asyncio.gather(*[drive(once) for _ in range(CONC)])

async def w_streamupload():
    sha = expected_sha1()
    # Negative probe: a body carrying a deliberately-wrong x-sha1 must be rejected
    # (400). The happy path only ever asserts the server's 200, so a server that
    # returned 200 unconditionally (dropped/short-circuited the SHA compare) would
    # pass silently. Cheap: a few KB, not the full STREAM.
    async def wrong_sha_gen():
        yield gen_chunk(0, 4096)
    async with session() as s:
        st = await s.upload("/upload", {"x-sha1": "0" * 40}, wrong_sha_gen())
        if st != 400:
            raise Fail(f"upload negative probe: wrong x-sha1 accepted -> {st}")
    async def once():
        async with session() as s:
            st = await s.upload("/upload", {"x-sha1": sha}, body_gen())
            if st == 400: raise Fail("server rejected the SHA-1 (400)")
            if st != 200: raise Fail(f"upload -> {st}")
            bump(200)
            if IS_H3: xfer[0] += STREAM   # h3 only: aioquic buffers the whole
                                          # body up front, so a queued-bytes rate
                                          # spikes then reads 0 while the wire
                                          # drains. Count delivered on completion.
                                          # h1/h2 already count sent bytes in
                                          # body_gen (httpx streams).
    await drive(once)

async def w_streamdownload():
    want = expected_sha1()
    async def once():
        async with session() as s:
            gen = s.stream("GET", "/download")
            st = await gen.__anext__()
            if st != 200: raise Fail(f"download status {st}")
            h = hashlib.sha1(); got = 0
            async for chunk in gen:
                h.update(chunk); got += len(chunk); xfer[0] += len(chunk)
            if got != STREAM or h.hexdigest() != want:
                raise Fail(f"download mismatch: {got} bytes, sha {h.hexdigest()} != {want}")
            bump(200)
    await drive(once)

async def w_methods():
    # Every HTTP method, transport-agnostic (h1/h2/h3). Used by the reverse-proxy
    # interop suite to confirm each method survives the proxy hop. The body-bearing
    # methods (POST/PUT/DELETE/PATCH) carry realistic, varied payloads -- a small
    # JSON-ish document and a few-KiB blob, cycled -- not empty pings, and the h3
    # client advertises Content-Length like httpx does for h1/h2. GET/HEAD/OPTIONS
    # carry no body; HEAD returns headers only; OPTIONS is auto-answered (204/Allow).
    raws = [
        b'{"user":"alice","op":"update","note":"' + b"x" * 240 + b'"}',   # ~290 B
        b"the quick brown fox jumps over the lazy dog. " * 96,            # ~4.3 KiB
    ]
    prepared = []
    for raw in raws:
        body, enc = compress(raw)
        h = {}
        if enc: h["content-encoding"] = enc
        if ACCEPT: h["accept-encoding"] = ACCEPT
        prepared.append((raw, body, h))
    get_hdrs = {"accept-encoding": ACCEPT} if ACCEPT else {}
    async def once():
        async with session() as s:
            k = 0
            while time.monotonic() < deadline:
                st, b = await s.get("/plaintext", get_hdrs)
                if st != 200 or b != b"Hello, World!":
                    raise Fail(f"GET /plaintext -> {st}")
                bump(200)
                raw, body, hdrs = prepared[k % len(prepared)]; k += 1
                for meth in ("POST", "PUT", "DELETE", "PATCH"):
                    st, b = await s.request(meth, "/echo", hdrs, body)
                    if st != 200 or b != raw:
                        raise Fail(f"{meth} /echo -> {st}, {len(b)}B (want {len(raw)}B)")
                    bump(200)
                st, b = await s.request("HEAD", "/echo", get_hdrs)
                if st != 200 or (b or b"") != b"":
                    raise Fail(f"HEAD /echo -> {st}, {len(b or b'')}B (want 0)")
                bump(200)
                st, _ = await s.request("OPTIONS", "/echo", {})
                if st not in (200, 204):
                    raise Fail(f"OPTIONS /echo -> {st}")
                bump(st)
    await asyncio.gather(*[drive(once) for _ in range(CONC)])

WORKLOADS = {
    "requests": w_requests, "methods": w_methods, "ws": w_ws, "sse": w_sse,
    "streamupload": w_streamupload, "streamdownload": w_streamdownload,
}

async def main():
    global deadline, start
    if WORKLOAD not in WORKLOADS:
        print(f"unknown VORTEX_WORKLOAD: {WORKLOAD}", file=sys.stderr); return 2
    # Known-unsupported cell: skip cleanly (exit 0) rather than run into a hang.
    # vortex does not yet ack HTTP/3 request-body flow control (the h3AckBody
    # gap), so a large h3 upload stalls after the initial window. With the
    # timeout-is-a-failure fix below an unskipped stall would (correctly) fail,
    # so this documented gap must be an explicit skip, not a silent run.
    if WORKLOAD == "streamupload" and IS_H3:
        print(f"== {WORKLOAD} {SERVER} {PROTO} skipped "
              f"(h3 request-body flow-control not yet acked) ==", flush=True)
        return 0
    start = time.monotonic()
    _rate[0] = start
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
        # A stall is exactly what this soak exists to catch (peer flow-control
        # deadlock, a stuck stream, a sendFile-pin write-scheduler deadlock), so
        # a workload that does not stop within deadline+60s is a FAILURE, not a
        # warning. Returning here (non-zero) keeps a hang from being reported as
        # a pass once some early iterations happened to succeed.
        print(f"FAIL {WORKLOAD}: workers did not stop within deadline+60s "
              f"(stall) ({fmt_codes()})", file=sys.stderr)
        return 1
    finally:
        rep.cancel()
    total = sum(n for c, n in codes.items() if 200 <= c < 300)
    # A fresh session just for the closing RSS/heap sample; never let a failed
    # connect (server already torn down, a transient QUIC/DNS blip) crash the
    # run with a traceback and mask the real pass/fail verdict below. `None`
    # renders as n/a (see report_line), not a misleading 0MB.
    rss, heap = None, None
    try:
        async with session() as s:
            rss, heap = await get_server_stats(s)
    except Exception:
        pass
    report_line("final ", rss, heap)
    if total == 0:
        print(f"FAIL {WORKLOAD}: no successful iterations", file=sys.stderr); return 1
    print(f"== {WORKLOAD} {SERVER} {PROTO} passed ({total} {UNIT}) ==", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
