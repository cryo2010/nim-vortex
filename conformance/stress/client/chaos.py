#!/usr/bin/env python3
"""Unverified misbehaving-client sidecar for the vortex stress soaks (issue #322).

Runs alongside the verified client (stress_client.py) as a second container per
cell and misbehaves ON PURPOSE: it reads slowly, idles, aborts mid-transfer, and
vanishes abruptly, to load the server's teardown / backpressure / reaping paths
that a well-behaved client never touches. Each of the five styles has a generic
form (the fixed all-routes catalog) and, for some workloads, a targeted form
picked by VORTEX_WORKLOAD (slow/idle/vanishing SSE clients under the sse soak,
half-closing WebSocket clients under ws, mid-body deaths under streamupload,
...). Enabling a style enables BOTH forms; the per-iteration pick pool is the
flattened generic+targeted set, uniformly weighted (see build_pool). This client is **unverified by
construction**: every induced transport error (a reset, a refused read, a
half-open abort, a torn-down connection) is EXPECTED, so the worker loop tallies
it and swallows it. Nothing here hard-fails on a wire error the way the canary's
drive() does -- the canary is the correctness oracle and its contract must stay
untouched, so this file must never import or alter the verified client's failure
semantics. The one thing chaos DOES assert is an fd leak: it samples the server's
open-fd count before and after and fails if teardown leaked descriptors.

    Exit codes
      0  ran, connected at least once, fd assertion passed (induced errors swallowed)
      1  fd leak (final > baseline + SLACK)
      2  internal error / unknown behavior name / missing fd field on /stats
      3  self-watchdog tripped (SECONDS + DRAIN + 45)
      4  never connected once (must not pass silently)

All output goes to stdout with flush=True: run.sh drives this detached and dumps
its logs, and greps the `chaos: baseline` line, so the contract lines must be on
stdout (same tee rationale as stress_client.py).
"""
import asyncio, os, random, socket, sys, time
from collections import Counter
from urllib.parse import urlparse

from transport import (
    PROTO, BASE, SECONDS, REPORT, IS_H3, WORKLOAD,
    gen_chunk, session, get_server_stats)
from h3 import OP_TEXT, OP_CLOSE

# --- knobs (VORTEX_CHAOS*) ---------------------------------------------------
_CHAOS = os.environ.get("VORTEX_CHAOS", "all")
CONC   = int(os.environ.get("VORTEX_CHAOS_CONC", "8"))
SEED   = os.environ.get("VORTEX_CHAOS_SEED", "1")

_ALL = ["slowread", "slowwrite", "idle", "abort", "vanish"]

def parse_behaviors(raw: str):
    """`none` -> [] (nothing to do); `all` -> every behavior; else a case-
    insensitive CSV of the catalog. An unknown name is a config error, not a
    thing to skip silently: exit 2 (same class as a missing fd field), because a
    typo'd behavior would otherwise quietly run a smaller chaos set than asked."""
    v = raw.strip().lower()
    if v in ("", "none"): return []
    if v == "all": return list(_ALL)
    out = []
    for name in v.split(","):
        name = name.strip()
        if not name: continue
        if name not in _ALL:
            print(f"chaos: unknown behavior {name!r} (known: {','.join(_ALL)})",
                  flush=True)
            sys.exit(2)
        if name not in out: out.append(name)
    return out

# --- named constants (calibrated in first runs; NOT knobs) -------------------
# fd slack: a small allowance over the baseline for benign, non-leaking variance
# (a lazily-cached fd, a still-draining background socket sampled mid-teardown).
# A real teardown leak scales with iteration count and dwarfs this; 8 is the
# floor that clears the noise without hiding a leak.
SLACK = 8
# Post-chaos drain: how long to wait after closing everything we own before the
# final fd sample, so the server has time to reap our torn-down connections. h3
# must outlive the 30 s QUIC idle timeout (a vanished/idle QUIC connection is
# only reaped once that timer fires), so it needs the longer wait; TCP resets
# reap promptly, so h1/h2 need far less.
DRAIN = 40 if PROTO == "h3" else 15

# Self-watchdog: chaos must never outlive the cell. SECONDS of work, DRAIN of
# settle, plus 45 s of slack for connect/teardown latency; tripping it means a
# behavior wedged (a stuck await), which is a bug in this sidecar, so exit 3.
WATCHDOG = SECONDS + DRAIN + 45

connects = [0]            # count of successful transport opens across the whole run

# --- behaviors (one iteration each; any may raise -- the caller swallows) -----
# Each behavior draws EVERY timing / count / choice from the per-worker rng it is
# handed, so a fixed VORTEX_CHAOS_SEED replays an identical chaos schedule.

async def b_slowread(rng):
    """Stream /download (sometimes /sse), read a chunk, then dawdle: sleep a
    fraction of a second between chunks for a multi-second budget, then close
    cleanly. Exercises the server's write-scheduler under a slow consumer racing
    the canary's full-rate traffic. h3 caveat: aioquic grants flow-control credit
    on receipt (not on consumption), so h3 slowread is pacing-only (a documented
    degraded mode -- true h3 backpressure would need withheld window updates)."""
    path = "/sse" if rng.random() < 0.25 else "/download"
    hdrs = {"accept": "text/event-stream"} if path == "/sse" else None
    budget = rng.uniform(5.0, 15.0)
    deadline = time.monotonic() + budget
    async with session() as s:
        connects[0] += 1
        gen = s.stream("GET", path, hdrs)
        await gen.__anext__()                 # first item is the status; discard
        async for _chunk in gen:
            if time.monotonic() >= deadline: break
            await asyncio.sleep(rng.uniform(0.1, 0.5))
        await gen.aclose()                    # clean close (the well-behaved exit)

async def b_slowwrite(rng):
    """POST /upload with a deliberately-wrong x-sha1, drip-feeding 4 KiB slices
    with sub-second sleeps for a multi-second budget. The server hashes the
    streamed body and returns 400 on the mismatch; that 400 is EXPECTED and
    swallowed. Exercises long-held streaming-request state / slow-request slot
    occupancy while the canary runs."""
    budget = rng.uniform(5.0, 15.0)
    deadline = time.monotonic() + budget
    slice_n = 4 * 1024
    off = [0]
    async def drip():
        while time.monotonic() < deadline:
            yield gen_chunk(off[0], slice_n); off[0] += slice_n
            await asyncio.sleep(rng.uniform(0.05, 0.25))
    async with session() as s:
        connects[0] += 1
        await s.upload("/upload", {"x-sha1": "0" * 40}, drip())   # 400 expected

async def b_idle(rng):
    """Open a connection and hold it idle 10-30 s, then close cleanly. Half the
    time a WebSocket (keep-alive slot + wsPingInterval ping path), half a plain
    GET /plaintext kept-alive (keep-alive slot / QUIC idle-timeout straddling).
    Uses the same WS libs the verified client uses: the aioquic ws_open on h3,
    the `websockets` package on h1/h2."""
    hold = rng.uniform(10.0, 30.0)
    want_ws = rng.random() < 0.5
    if want_ws and IS_H3:
        async with session() as s:
            connects[0] += 1
            ws = await s.ws_open("/ws")
            try: await asyncio.sleep(hold)
            finally: ws.close()
        return
    if want_ws:
        import ssl, websockets
        ws_url = BASE.replace("https://", "wss://").replace("http://", "ws://") + "/ws"
        ssl_ctx = None
        if ws_url.startswith("wss://"):
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with websockets.connect(ws_url, ssl=ssl_ctx, max_size=None) as ws:
            connects[0] += 1
            await asyncio.sleep(hold)         # do nothing; let the server ping us
        return
    # keep-alive HTTP idle: one GET, then hold the (pooled) connection open doing
    # nothing. httpx keeps the h1/h2 connection in its pool; the h3 session keeps
    # the QUIC connection. Either way the server sees an established-but-silent
    # peer for `hold` seconds.
    async with session() as s:
        connects[0] += 1
        await s.get("/plaintext")
        await asyncio.sleep(hold)

async def b_abort(rng):
    """Read a few chunks of /download then cancel mid-transfer, or occasionally
    abort an upload mid-body. The download abort is the h2 RST_STREAM / h3
    STOP_SENDING path (unread-body window credit, sendFile pin release); the
    upload abort is a client that dies mid-request-body. Both are clean, deliberate
    cancels, not crashes (see b_vanish for the abrupt case)."""
    if rng.random() < 0.25:
        # abort an upload by raising inside the body generator: the server sees
        # the request body truncate mid-stream. httpx/h3 upload surface this as a
        # transport error, which the caller swallows.
        async def boom():
            yield gen_chunk(0, 4 * 1024)
            raise RuntimeError("chaos: abort upload mid-body")
        async with session() as s:
            connects[0] += 1
            await s.upload("/upload", {"x-sha1": "0" * 40}, boom())
        return
    want = rng.randint(1, 32)                  # chunks to read before cancelling
    if IS_H3:
        # h3: read `want` chunks off the raw queue, then STOP_SENDING (+ reset the
        # send side if open) via the additive h3.py API. stream()'s own drain loop
        # would fight the manual abort, so open the raw stream instead.
        async with session() as s:
            connects[0] += 1
            sid, q = s.stream_open("GET", "/download")
            got = 0
            while got < want:
                kind, _val = await q.get()
                if kind == "d": got += 1
                elif kind in ("end", "err"): break   # server finished / reset first
            s.abort_stream(sid)
        return
    # h1/h2: exit the httpx stream context early -- httpx sends RST_STREAM (h2) /
    # drops the connection (h1) on an early aclose. session().stream is an async
    # generator, so aclose() at the target chunk count is the early cancel.
    async with session() as s:
        connects[0] += 1
        gen = s.stream("GET", "/download")
        await gen.__anext__()                 # status
        got = 0
        async for _chunk in gen:
            got += 1
            if got >= want: break
        await gen.aclose()                    # early cancel: RST_STREAM (h2)

async def _vanish(rng, path, headers=None):
    """Shared vanish machinery: abrupt death, no goodbye, on a GET stream of
    `path` -- the server must reap the connection on its own. Parameterized so
    the workload-targeted variants (vanish@sse) reuse the raw-socket / SO_LINGER
    / network_stream / dropped-UDP logic verbatim instead of duplicating it.
    50% of iterations slow-read first (the compound worst case: a stalled slow
    consumer that then vanishes mid-write). Per transport:
      h1  raw asyncio socket, minimal GET, then SO_LINGER=0 close (TCP RST).
          h1 is plain HTTP in this harness, so only run when BASE is http://.
      h2  httpx stream a few chunks, reach the socket via the network_stream
          extension and set SO_LINGER=0 before closing (fallback: abandon the
          client without aclose when the socket is unreachable).
      h3  start the GET then close the UDP transport directly, no
          CONNECTION_CLOSE; the server reaps via the QUIC idle timeout."""
    slow_first = rng.random() < 0.5
    if IS_H3:
        s_cm = session()
        s = await s_cm.__aenter__()
        connects[0] += 1
        try:
            sid, q = s.stream_open("GET", path, headers)
            kind, _val = await q.get()        # status headers; then read a bit
            if slow_first:
                await asyncio.sleep(rng.uniform(1.0, 5.0))
            # Close the UDP transport out from under aioquic: no CONNECTION_CLOSE
            # frame goes out, so the server only learns we are gone when its QUIC
            # idle timer fires. This is the orphaned-QUIC-connection reaping path.
            tr = getattr(s.c, "_transport", None)
            if tr is not None: tr.close()
        finally:
            # Do NOT run the session's clean __aexit__ (it would send a graceful
            # close); we abandoned the transport on purpose. Swallow whatever the
            # torn-down aexit raises.
            try: await s_cm.__aexit__(None, None, None)
            except Exception: pass
        return

    u = urlparse(BASE)
    if u.scheme == "http":
        # h1 raw socket: write a minimal valid HTTP/1.1 GET with a Host header,
        # read a bit, optionally slow-read, then SO_LINGER=(1,0) close for a TCP
        # RST instead of a FIN. Exercises abrupt-peer-death cleanup / RST mid-write.
        host, port = u.hostname, u.port or 80
        reader, writer = await asyncio.open_connection(host, port)
        connects[0] += 1
        try:
            extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n{extra}"
                   f"Connection: close\r\n\r\n").encode()
            writer.write(req); await writer.drain()
            await reader.read(4096)           # read a bit of the response
            if slow_first:
                await asyncio.sleep(rng.uniform(1.0, 5.0))
                await reader.read(4096)
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                _linger_zero())
        finally:
            # close() on a SO_LINGER(1,0) socket sends a RST. transport.abort()
            # would also RST but bypasses our explicit linger; close() honors it.
            try: writer.close()
            except Exception: pass
        return

    # h2 vanish: stream a few chunks, then reach the underlying socket via
    # httpcore's network_stream extension to force SO_LINGER=0, so the close is a
    # RST mid-download. If the extension is unavailable in the resolved
    # httpx/httpcore, fall back to abandoning the client without aclose (the
    # documented degraded h2 vanish -- still an ungraceful drop, just a FIN not a
    # RST).
    s_cm = session()
    s = await s_cm.__aenter__()
    connects[0] += 1
    aclose_ok = True
    try:
        stream_cm = s.c.stream("GET", BASE + path, headers=headers or {})
        r = await stream_cm.__aenter__()
        got = 0
        async for _chunk in r.aiter_raw():
            got += 1
            if got >= rng.randint(1, 8): break
        if slow_first:
            await asyncio.sleep(rng.uniform(1.0, 5.0))
        sock = None
        net = r.extensions.get("network_stream")
        if net is not None:
            sock = net.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _linger_zero())
            try: await stream_cm.__aexit__(None, None, None)
            except Exception: pass
        else:
            # degraded fallback: socket unreachable -- abandon the client without
            # aclose so no graceful GOAWAY/FIN dance runs. Skip the clean session
            # __aexit__ below.
            aclose_ok = False
    finally:
        if aclose_ok:
            try: await s_cm.__aexit__(None, None, None)
            except Exception: pass
        # else: leak the client on purpose (degraded fallback); the process exits
        # soon after chaos anyway, so this abandons at most CONC clients.

async def b_vanish(rng):
    """Generic vanish: abrupt mid-download death (see _vanish)."""
    await _vanish(rng, "/download")

def _linger_zero() -> bytes:
    """struct linger{l_onoff=1, l_linger=0} as raw bytes for SO_LINGER: onoff on,
    timeout 0 => close() sends a RST, not a FIN. Two native ints, packed without
    importing struct for one call."""
    import struct
    return struct.pack("ii", 1, 0)

# --- workload-targeted variants (picked only when VORTEX_WORKLOAD matches) ----
# Same contract as the generic behaviors: one iteration, may raise, the caller
# swallows and tallies. Styles with no targeted form for a workload fall back to
# generic-only via build_pool (requests is generic-only by design).

def _ws_target():
    """(url, ssl_ctx) for the h1/h2 `websockets` client, mirroring the canary's
    w_ws derivation from STRESS_BASE."""
    import ssl
    url = BASE.replace("https://", "wss://").replace("http://", "ws://") + "/ws"
    ctx = None
    if url.startswith("wss://"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return url, ctx

async def b_slowread_ws(rng):
    """ws slowread: burst echoes at the server, then STOP reading the replies
    for several seconds so the echo write side backs up, then close cleanly.
    h1/h2 exert real socket / h2-window backpressure; h3 is pacing-only (the
    H3Client pushes echoes into an unbounded local queue, so not reading exerts
    no backpressure -- the same degraded caveat as generic h3 slowread)."""
    burst = rng.randint(8, 32)
    hold = rng.uniform(3.0, 10.0)
    if IS_H3:
        async with session() as s:
            connects[0] += 1
            ws = await s.ws_open("/ws")
            for n in range(burst): ws.send(OP_TEXT, f"chaos-{n}".encode())
            await asyncio.sleep(hold)         # replies pile up unread
            ws.close()
        return
    import websockets
    url, ctx = _ws_target()
    async with websockets.connect(url, ssl=ctx, max_size=None) as ws:
        connects[0] += 1
        for n in range(burst): await ws.send(f"chaos-{n}")
        await asyncio.sleep(hold)             # never recv(): server writes stall

async def b_abort_ws(rng):
    """ws abort: a clean CLOSE frame mid-echo-burst (the deliberate-goodbye
    counterpart of vanish@ws). h3 sends a bare close frame over the CONNECT
    stream -- H3Ws has no full close handshake, a documented approximation."""
    if IS_H3:
        async with session() as s:
            connects[0] += 1
            ws = await s.ws_open("/ws")
            for _ in range(rng.randint(2, 8)): ws.send(OP_TEXT, b"chaos")
            await ws.recv()
            ws.send(OP_CLOSE, b"")
            ws.close()
        return
    import websockets
    url, ctx = _ws_target()
    async with websockets.connect(url, ssl=ctx, max_size=None) as ws:
        connects[0] += 1
        for _ in range(rng.randint(2, 8)): await ws.send("chaos")
        await ws.recv()
        await ws.close(code=1000)             # close frame mid-burst

async def b_vanish_ws(rng):
    """ws vanish: no close handshake at all. h1/h2 abort the TCP transport under
    the websockets lib (`transport` is the stable attribute on both the legacy
    and the new asyncio client; .abort() is an immediate RST-style drop), with a
    degraded fallback of abandoning the connection without close() (ungraceful
    FIN). h3 drops the UDP transport with the WS stream open, like generic h3
    vanish; the server reaps via the QUIC idle timeout."""
    if IS_H3:
        s_cm = session()
        s = await s_cm.__aenter__()
        connects[0] += 1
        try:
            ws = await s.ws_open("/ws")
            ws.send(OP_TEXT, b"chaos")
            await asyncio.sleep(rng.uniform(0.1, 1.0))
            tr = getattr(s.c, "_transport", None)
            if tr is not None: tr.close()
        finally:
            try: await s_cm.__aexit__(None, None, None)
            except Exception: pass
        return
    import websockets
    url, ctx = _ws_target()
    ws = await websockets.connect(url, ssl=ctx, max_size=None)
    connects[0] += 1
    try:
        for _ in range(rng.randint(1, 6)): await ws.send("chaos")
        await asyncio.sleep(rng.uniform(0.1, 1.0))
    finally:
        tr = getattr(ws, "transport", None)
        if tr is not None: tr.abort()         # no close frame, hard drop
        # else: abandon without close() -- degraded ungraceful drop

async def b_slowread_sse(rng):
    """sse slowread: consume the event stream at a crawl (0.5-2 s between
    chunks) until the server batch-closes, then clean close."""
    budget = time.monotonic() + rng.uniform(5.0, 20.0)   # safety cap
    async with session() as s:
        connects[0] += 1
        gen = s.stream("GET", "/sse", {"accept": "text/event-stream"})
        await gen.__anext__()                 # status
        async for _chunk in gen:
            if time.monotonic() >= budget: break
            await asyncio.sleep(rng.uniform(0.5, 2.0))
        await gen.aclose()

async def b_idle_sse(rng):
    """sse idle: open the stream and read NOTHING for 10-30 s (the server
    stalls mid-batch on write backpressure), then close cleanly. h3 uses the
    raw stream so the drain loop can't auto-consume."""
    hold = rng.uniform(10.0, 30.0)
    hdrs = {"accept": "text/event-stream"}
    if IS_H3:
        async with session() as s:
            connects[0] += 1
            sid, q = s.stream_open("GET", "/sse", hdrs)
            await q.get()                     # status headers only
            await asyncio.sleep(hold)
            s.abort_stream(sid)
        return
    async with session() as s:
        connects[0] += 1
        gen = s.stream("GET", "/sse", hdrs)
        await gen.__anext__()                 # status only; zero consumption
        await asyncio.sleep(hold)
        await gen.aclose()

async def b_abort_sse(rng):
    """sse abort: disconnect mid-batch, then resume with a GARBAGE Last-Event-ID
    exercising the server's parseInt fallback ("banana"/"-1"/"" restart at 0;
    "999999" batch-closes immediately with zero events). Two short clean
    connections per iteration -- the RST case is vanish@sse's job."""
    bad_id = rng.choice(["banana", "-1", "999999", ""])
    async with session() as s:
        connects[0] += 1
        gen = s.stream("GET", "/sse", {"accept": "text/event-stream"})
        await gen.__anext__()
        want = rng.randint(1, 3)
        got = 0
        async for _chunk in gen:
            got += 1
            if got >= want: break
        await gen.aclose()                    # drop mid-batch
        gen = s.stream("GET", "/sse",
                       {"accept": "text/event-stream", "last-event-id": bad_id})
        await gen.__anext__()
        async for _chunk in gen:
            break                             # a token read, then done
        await gen.aclose()

async def b_vanish_sse(rng):
    """sse vanish: abrupt mid-stream death on /sse (see _vanish)."""
    await _vanish(rng, "/sse", {"accept": "text/event-stream"})

async def b_slowwrite_streamupload(rng):
    """streamupload slowwrite: stall-resume, distinct from the generic steady
    drip -- send chunks, go FULLY silent mid-body for 5-10 s, resume and finish;
    the server's 400 (wrong x-sha1) is expected and swallowed."""
    stall = rng.uniform(5.0, 10.0)
    n = 4 * 1024
    head, tail = rng.randint(2, 6), rng.randint(2, 6)
    async def stall_resume():
        off = 0
        for _ in range(head):
            yield gen_chunk(off, n); off += n
        await asyncio.sleep(stall)            # dead air mid-request-body
        for _ in range(tail):
            yield gen_chunk(off, n); off += n
    async with session() as s:
        connects[0] += 1
        await s.upload("/upload", {"x-sha1": "0" * 40}, stall_resume())

async def b_vanish_streamupload(rng):
    """streamupload vanish: die mid-request-body with no goodbye while the
    server is mid-hash. h1: raw socket POST, partial body, SO_LINGER=0 RST.
    h3: a few chunks onto the QUIC stream, then drop the UDP transport. h2
    degraded: cancel the in-flight upload task and abandon the session without
    a clean close (httpx aborts the stream mid-body; the response object never
    exists during the request body, so the socket is unreachable here)."""
    async def forever():
        off = 0
        while True:
            yield gen_chunk(off, 4096); off += 4096
            await asyncio.sleep(0.05)
    if IS_H3:
        s_cm = session()
        s = await s_cm.__aenter__()
        connects[0] += 1
        task = None
        try:
            task = asyncio.ensure_future(
                s.upload("/upload", {"x-sha1": "0" * 40}, forever()))
            await asyncio.sleep(rng.uniform(0.5, 2.0))   # let chunks flow
            tr = getattr(s.c, "_transport", None)
            if tr is not None: tr.close()
        finally:
            if task is not None:
                task.cancel()
                try: await task
                except Exception: pass
            try: await s_cm.__aexit__(None, None, None)
            except Exception: pass
        return

    u = urlparse(BASE)
    if u.scheme == "http":
        host, port = u.hostname, u.port or 80
        reader, writer = await asyncio.open_connection(host, port)
        connects[0] += 1
        try:
            req = (f"POST /upload HTTP/1.1\r\nHost: {host}:{port}\r\n"
                   f"x-sha1: {'0' * 40}\r\ncontent-length: 1048576\r\n"
                   f"\r\n").encode()
            writer.write(req + gen_chunk(0, 16 * 1024))  # partial body only
            await writer.drain()
            await asyncio.sleep(rng.uniform(0.2, 1.0))   # server mid-hash
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                _linger_zero())
        finally:
            try: writer.close()
            except Exception: pass
        return

    # h2: cancel mid-body and abandon the session without its clean __aexit__
    # goodbye (degraded: an abrupt drop, not a RST).
    s_cm = session()
    s = await s_cm.__aenter__()
    connects[0] += 1
    task = asyncio.ensure_future(
        s.upload("/upload", {"x-sha1": "0" * 40}, forever()))
    await asyncio.sleep(rng.uniform(0.5, 2.0))
    task.cancel()
    try: await task
    except Exception: pass

async def b_idle_streamdownload(rng):
    """streamdownload idle: a fully-established download whose consumer reads
    NOTHING for 10-30 s (zero window consumption: the sendFile-pin /
    write-scheduler hold path), then clean close. Distinct from the generic
    slowread trickle, which keeps draining slowly."""
    hold = rng.uniform(10.0, 30.0)
    if IS_H3:
        async with session() as s:
            connects[0] += 1
            sid, q = s.stream_open("GET", "/download")
            await q.get()                     # status headers only
            await asyncio.sleep(hold)
            s.abort_stream(sid)
        return
    async with session() as s:
        connects[0] += 1
        gen = s.stream("GET", "/download")
        await gen.__anext__()
        await asyncio.sleep(hold)
        await gen.aclose()

BEHAVIORS = {
    # generic: every workload, the v1 all-routes catalog
    ("slowread", "generic"): b_slowread,
    ("slowwrite", "generic"): b_slowwrite,
    ("idle", "generic"): b_idle,
    ("abort", "generic"): b_abort,
    ("vanish", "generic"): b_vanish,
    # workload-targeted: live only when VORTEX_WORKLOAD matches. idle@ws is
    # subsumed by generic idle's ws hold; abort@streamupload by generic abort's
    # generator-raise; streamdownload's slowread/abort/vanish by the generic
    # forms (they already target /download); requests is generic-only.
    ("slowread", "ws"): b_slowread_ws,
    ("abort", "ws"): b_abort_ws,
    ("vanish", "ws"): b_vanish_ws,
    ("slowread", "sse"): b_slowread_sse,
    ("idle", "sse"): b_idle_sse,
    ("abort", "sse"): b_abort_sse,
    ("vanish", "sse"): b_vanish_sse,
    ("slowwrite", "streamupload"): b_slowwrite_streamupload,
    ("vanish", "streamupload"): b_vanish_streamupload,
    ("idle", "streamdownload"): b_idle_streamdownload,
}

def build_pool(enabled):
    """The per-iteration pick pool: each enabled style contributes its generic
    entry plus, when one exists for this cell's VORTEX_WORKLOAD, its targeted
    entry, uniformly weighted (generic + targeted at full weight, a user-locked
    decision). An unknown workload matches no targeted key and degrades to
    generic-only, no crash."""
    pool = []
    for style in enabled:
        pool.append((style, "generic"))
        if (style, WORKLOAD) in BEHAVIORS:
            pool.append((style, WORKLOAD))
    return pool

# --- worker loop (swallow-and-tally) -----------------------------------------
_ok  = Counter()          # (behavior) -> completed iterations
_err = Counter()          # (behavior) -> swallowed transport errors

async def worker(i, pool, start, deadline, seed):
    # Per-worker seeded rng so a fixed VORTEX_CHAOS_SEED replays the same schedule
    # per worker (and different seeds diverge): the behavior pick, every timing,
    # and every coin flip draw from this one stream.
    rng = random.Random(f"{seed}:{i}")
    while time.monotonic() < deadline:
        key = rng.choice(pool)                # uniform over generic + targeted
        try:
            await BEHAVIORS[key](rng)
            _ok[key] += 1
        except Exception:
            # Induced errors are the point: a reset, a refused read, a torn-down
            # connection are all EXPECTED. Tally and swallow -- never hard-fail
            # like the canary's drive().
            _err[key] += 1
        # Jitter between iterations so workers don't lock-step and so the schedule
        # stays rng-driven end to end.
        await asyncio.sleep(rng.uniform(0.0, 0.5))

def _fmt_key(key) -> str:
    # Generic entries print as the bare style (vanish=6); targeted entries as
    # workload:style (sse:vanish=4), so the report separates the two forms.
    style, target = key
    return style if target == "generic" else f"{target}:{style}"

def _tally_line(pool, prefix="") -> str:
    ok = " ".join(f"{_fmt_key(k)}={_ok[k]}" for k in pool if _ok[k])
    er = " ".join(f"{_fmt_key(k)}!{_err[k]}" for k in pool if _err[k])
    return f"[chaos {PROTO}] {prefix}ok: {ok or '-'} | err: {er or '-'}"

async def chaos_reporter(pool, start, deadline):
    # Same one-line periodic style as stress_client.py's report_line: a compact
    # tally of completed iterations and swallowed errors per behavior.
    while time.monotonic() < deadline:
        await asyncio.sleep(REPORT)
        t = int(time.monotonic() - start)
        print(f"{_tally_line(pool)} | t={t}s", flush=True)

# --- fd sampling -------------------------------------------------------------
async def sample_fds(retries=1, gap=0.0):
    """Open a fresh session and read the server's open-fd count from /stats.
    Returns the fd int, or None if every attempt failed to connect / parse. A
    successful open here counts as a connect. get_server_stats returns (rss, heap,
    fds); fds is None when /stats lacks the field (an older two-field server) --
    that is a hard config error for chaos (its whole leak assertion needs the
    field), handled by the caller."""
    for attempt in range(retries):
        try:
            async with session() as s:
                connects[0] += 1
                _rss, _heap, fds = await get_server_stats(s)
                return fds
        except Exception:
            if attempt + 1 < retries and gap > 0: await asyncio.sleep(gap)
    return None

_MISSING_FD = object()    # sentinel: connected, but /stats had no fd field

async def sample_fds_strict(retries=1, gap=0.0):
    """As sample_fds, but distinguish `fds is None because the field is absent`
    (a fatal config error -> _MISSING_FD) from `never connected` (-> None)."""
    for attempt in range(retries):
        try:
            async with session() as s:
                connects[0] += 1
                _rss, _heap, fds = await get_server_stats(s)
                return _MISSING_FD if fds is None else fds
        except Exception:
            if attempt + 1 < retries and gap > 0: await asyncio.sleep(gap)
    return None

# Baseline warm-up fan-out: how many connections to open concurrently to force
# the kernel to spread them across every SO_REUSEPORT loop thread before the
# baseline sample (see warm_baseline). Sized well above any plausible core count
# so even a big host's loop set is covered; work per connection is a short,
# aborted /download read.
WARMUP_CONC = int(os.environ.get("VORTEX_CHAOS_WARMUP", "64"))

async def warm_baseline():
    """Drive a concurrent burst of short aborted /download reads so every
    SO_REUSEPORT loop thread runs a handler that genuinely SUSPENDS before we
    sample the baseline.

    Why this matters (the whole point of the fix): the server runs N =
    countProcessors() event-loop threads, and each async/chronos loop thread
    creates its per-thread runtime dispatcher (an epoll/kqueue fd) LAZILY, the
    first time a handler on that loop actually suspends at an await (e.g.
    `await res.write` under download backpressure) -- and holds it for the loop's
    lifetime (freed only at loop teardown; see the adapters' teardown()). Those N
    dispatcher fds are legitimate, permanent per-loop infrastructure, NOT leaked
    connections. Sampling the baseline off a still-quiet server (before any loop
    has suspended a handler) counts ZERO of them; the final sample -- taken after
    the canary and chaos have driven suspending traffic to every loop -- counts
    all N. That gap is exactly N (== the core count), deterministic, acquired
    once early, and flat for the rest of the run -- which is precisely the shape
    we were mis-reading as a "leak". Warming every loop first folds those N fds
    INTO the baseline, so the assertion measures real teardown leakage (which
    scales with iteration count and dwarfs the slack) instead of the one-time
    per-loop dispatcher cost.

    The warm request MUST suspend server-side: a cheap synchronously-completing
    GET (/plaintext, /stats) never touches the dispatcher and warms nothing
    (measured: 64 concurrent /stats GETs left the fd count unchanged, while 64
    aborted /download reads raised it by exactly N and it stayed flat through
    192 more). So each warm connection starts the 1 GiB /download, reads a couple
    of chunks (by which point the server is deep in write backpressure, i.e.
    suspended), then aborts -- the same early-cancel machinery as b_abort,
    bounded and cheap.

    Best-effort: any connect/read error is swallowed (the real gate is the
    baseline sample and the never-connected guard below). Opening many
    connections AT ONCE is what fans them across loops -- a serial loop would keep
    landing on whichever loop the kernel hands the next accept to."""
    async def one():
        try:
            if IS_H3:
                # h3: read a couple of chunks off the raw queue, then STOP_SENDING
                # via the additive h3.py API (same as b_abort's h3 path).
                async with session() as s:
                    connects[0] += 1
                    sid, q = s.stream_open("GET", "/download")
                    got = 0
                    while got < 2:
                        kind, _val = await q.get()
                        if kind == "d": got += 1
                        elif kind in ("end", "err"): break
                    s.abort_stream(sid)
                return
            # h1/h2: read a couple of chunks, then aclose() the stream generator
            # early (RST_STREAM on h2 / connection drop on h1, as in b_abort).
            async with session() as s:
                connects[0] += 1
                gen = s.stream("GET", "/download")
                await gen.__anext__()          # status
                got = 0
                async for _chunk in gen:
                    got += 1
                    if got >= 2: break
                await gen.aclose()             # early cancel: the server unblocks
        except Exception:
            pass
    await asyncio.gather(*[one() for _ in range(WARMUP_CONC)])
    # Let the warm-up connections fully tear down (and the server reap them) so
    # they do not inflate the baseline as transient in-flight sockets; the loops'
    # dispatcher fds we just forced into existence stay.
    await asyncio.sleep(2.0)

# --- main: baseline -> chaos -> drain -> final -> verdict ---------------------
async def run(enabled):
    start = time.monotonic()
    deadline = start + SECONDS
    # The pool line shows which targeted variants are live for this cell's
    # workload (requests / an unknown workload: generic-only).
    pool = build_pool(enabled)
    print(f"chaos: behaviors={','.join(enabled)} workload={WORKLOAD} "
          f"pool={','.join(_fmt_key(k) for k in pool)} seed={SEED} conc={CONC} "
          f"proto={PROTO}", flush=True)

    # Warm every loop thread FIRST so the baseline includes each loop's lazily-
    # created per-thread dispatcher fd (see warm_baseline). Without this the
    # baseline is sampled off a cold server and misses N == core-count legitimate
    # per-loop fds that the final sample then counts, manufacturing a phantom
    # "leak" of exactly N. This retry-wraps its own connect settling, so it also
    # covers the "server still settling right after listening" case the baseline
    # retry used to absorb.
    for _ in range(10):
        await warm_baseline()
        if connects[0] > 0: break
        await asyncio.sleep(1.0)

    # Baseline fd sample, after warm-up, before the verified client launches. The
    # server may still be settling right after "listening", so retry a few times
    # over ~10 s; zero successful connects HERE is not yet fatal (the run may
    # still connect later and the "never connected" guard below is the real gate).
    baseline = await sample_fds_strict(retries=10, gap=1.0)
    if baseline is _MISSING_FD:
        # /stats served but without the fd field: an older server, chaos can't do
        # its one assertion. Config error, exit 2 (same class as unknown behavior).
        print("chaos: /stats has no fd field (server too old); cannot leak-check",
              flush=True)
        return 2
    # run.sh greps the prefix "chaos: baseline"; keep this line EXACT.
    print(f"chaos: baseline fds={baseline}", flush=True)

    rep = asyncio.ensure_future(chaos_reporter(pool, start, deadline))
    try:
        await asyncio.wait_for(
            asyncio.gather(*[worker(i, pool, start, deadline, SEED)
                             for i in range(CONC)]),
            timeout=WATCHDOG)
    except asyncio.TimeoutError:
        # A worker wedged past the watchdog: a stuck await in this sidecar, not a
        # server verdict. Exit 3 so run.sh can tell it apart from a leak.
        rep.cancel()
        print(f"chaos: self-watchdog tripped ({WATCHDOG}s); a behavior wedged",
              flush=True)
        return 3
    finally:
        rep.cancel()

    print(f"{_tally_line(pool, 'final ')} | t={int(time.monotonic() - start)}s",
          flush=True)

    # Drain: let the server reap our torn-down connections before the final
    # sample. h3 must outlive the QUIC idle timeout (DRAIN reflects that).
    await asyncio.sleep(DRAIN)
    final = await sample_fds(retries=5, gap=1.0)

    if connects[0] == 0:
        # Never opened a single transport across the whole run: a misconfigured
        # sidecar (wrong STRESS_BASE, server down) must not pass silently.
        print("chaos: never connected once (no successful transport open); "
              "check STRESS_BASE / server", flush=True)
        return 4
    if final is None:
        # Connected during the run but the final sample could not reach /stats.
        # Treat as a leak-check we couldn't complete rather than a pass; this is an
        # internal-ish error, exit 2.
        print("chaos: final fd sample failed (could not reach /stats)", flush=True)
        return 2

    if final > baseline + SLACK:
        print(f"FAIL chaos: fd leak (baseline {baseline}, final {final}, "
              f"slack {SLACK})", flush=True)
        return 1
    print(f"== chaos sidecar passed (fds {baseline} -> {final}) ==", flush=True)
    return 0

def main():
    enabled = parse_behaviors(_CHAOS)     # exits 2 on an unknown name
    if not enabled:
        # run.sh never launches chaos with none, but a hand-run must not crash.
        print("chaos: nothing to do (VORTEX_CHAOS=none)", flush=True)
        return 0
    try:
        return asyncio.run(run(enabled))
    except SystemExit:
        raise
    except Exception as e:
        # Anything outside the per-iteration swallow scope is an internal error in
        # the sidecar itself (not an induced wire error): surface it and exit 2.
        print(f"chaos: internal error ({type(e).__name__}): {e}", flush=True)
        return 2

if __name__ == "__main__":
    sys.exit(main())
