#!/usr/bin/env python3
"""Load client for the vortex stress soaks (conformance/stress/run.sh).

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
CONNECT) is wired for h3 too. All six workloads -- the five single-workload
soaks plus `mixed` -- run over every transport, `streamupload` over h3 included
(vortex acks HTTP/3 request-body flow control: deliverBody auto-acks the QUIC
stream/connection windows as the handler reads, and any unread remainder is
credited back to the connection window at teardown).

Reports each VORTEX_REPORT_SECONDS in nim-navi's format - status-code tallies,
a per-interval throughput rate (2xx completions/s; the streaming workloads show
MB/s instead), plus the server's RSS, Nim heap, and open-fd count (from /stats)
and elapsed time. The rate makes a throughput dip or a declining trend visible
directly, without diffing cumulative counts across lines:

    [sse h3 chronos] 200x1481767 | 33018 events/s | RSS 29MB | heap 7MB | fds 42 | t=45s
    [sse h3 chronos] final 200x1493782 | 802 events/s | RSS 29MB | heap 6MB | fds 41 | t=60s
    == sse chronos h3 passed (1493782 events) ==

VORTEX_WORKLOAD=mixed runs all five verified workloads at ONE server at the same
time, splitting the cell's worker budget across them (VORTEX_MIX overrides the
split) and reporting each one's own tally, so a dead workload cannot hide in a
healthy sum. See w_mixed.
"""
import asyncio, contextvars, hashlib, os, sys, time, traceback
from collections import Counter
import httpx
from transport import (
    WebSocketException, OP_TEXT, ProtocolPinError,
    WORKLOAD, PROTO, SERVER, BASE, SECONDS, CLIENTS, CONC, STREAM, REPORT,
    MB, IS_H3, UNIT, STREAMING, xfer, xfer_by, xfer_tag, add_xfer,
    expected_sha1, body_gen, gen_chunk, compress, ACCEPT, session, get_server_stats,
    payload_mix, expected_gets)

# --- shared state ------------------------------------------------------------
class Fail(Exception):
    """A fatal defect (corruption, bad status, or a transport error). Ends the
    run non-zero at once; never retried or tallied."""
codes = Counter()
# Which workload the running task belongs to. Exactly WORKLOAD for the five
# single-workload soaks; under `mixed` each slice sets it to its own workload
# before fanning out, and the tasks it creates inherit the context, so every
# tally below lands under the workload that earned it. A contextvar (not a
# parameter) because the counting happens deep inside the shared workload
# coroutines, which must stay byte-for-byte identical in the single-workload
# runs (#394).
TAG = contextvars.ContextVar("workload_tag", default=WORKLOAD)
# Resolved once, here, because it gates two HOT paths (bump's per-slice tally
# and transport's per-slice byte tally). `mixed` is the only run that needs
# either: its progress check is per workload, while a single-workload soak's
# per-tag count is just `codes` again. bump() runs once per echoed request, so
# a contextvar read plus a Counter update per call is not free, and the five
# soaks' numbers must not move because a sixth workload exists (#394).
IS_MIXED = WORKLOAD == "mixed"
if IS_MIXED: xfer_tag[0] = TAG.get      # see transport.add_xfer
ok_by = Counter()      # workload -> successful (2xx) completions
# Streaming transfers STARTED and then abandoned at the deadline, per workload:
# the wait_for expiry (and the teardown-race arm that can replace it) in
# w_streamupload, and the per-chunk deadline return in w_streamdownload. Tallied
# so that a run where nothing completed can say WHY. A 1 GiB transfer takes
# ~125 s on streamupload h3 and ~163 s on streamdownload h3 versus 4-15 s on
# h1/h2, so a short cell at the big default abandons every transfer and used to
# report the generic `no successful iterations` -- which reads as a server defect
# and sent people looking for one that was not there (#393).
abandoned = Counter()
_rate = [0.0, 0]       # [last report monotonic, bytes at last report] for MB/s
_ops = [0.0, 0]        # [last report monotonic, 2xx count at last report] for ops/s
start = 0.0
deadline = 0.0

def bump(status: int, n: int = 1):
    codes[status] += n
    # Per-workload, so `mixed` can check "nothing completed" per slice instead
    # of on the sum: a stalled SSE feed must not hide behind a healthy /echo
    # counter (#394). Under `mixed` only -- for a single-workload soak this is
    # one key whose total is exactly `codes`, bought at a contextvar read per
    # echoed request, so the five soaks keep the hot path they had.
    if 200 <= status < 300 and IS_MIXED: ok_by[TAG.get()] += n

def ok_ops() -> int:
    """Cumulative successful (2xx) completions -- the throughput numerator."""
    return sum(n for c, n in codes.items() if 200 <= c < 300)

def moved(tag: str) -> int:
    """Bytes `tag` actually got on the wire.

    For a single-workload soak that is the cell total, since the cell is the one
    workload. Under `mixed` five workloads share `xfer`, so only the per-slice
    tally answers the question no_progress asks (see transport.add_xfer).
    """
    return xfer_by[tag] if IS_MIXED else xfer[0]

def no_progress(tag: str) -> str:
    """Why `tag` completed nothing -- three different diagnoses, and the generic
    message used to swallow all of them.

    An abandoned transfer alone does NOT mean the size was wrong: a wedged
    server produces exactly the same abandon path (the transfer starts, no
    chunk ever arrives, the deadline cancels it), so "N abandoned" on its own is
    not evidence of anything. What separates them is whether bytes actually
    MOVED:

      - bytes moved > 0: the wire was alive and the transfers were simply too
        big for the run (a 1 GiB body is ~125 s on streamupload h3 and ~163 s on
        streamdownload h3, so a 10 s cell can never finish one). Name the two
        knobs instead of making the operator hunt a defect that is not there.
      - 0 bytes moved: the server delivered nothing at all. That is a stall, not
        a sizing accident, and the next place to look is the server log -- which
        run.sh dumps for a failed cell.
      - 0 bytes moved on an h3 UPLOAD: undecidable here. aioquic buffers the
        whole body up front, so that workload counts bytes only on completion
        (see fmt_xfer) and a transfer in flight is indistinguishable from one
        that never moved. Name both possibilities rather than guessing.

    The bytes-moved figure is in the message either way: it is the number the
    reader needs to check the verdict, and printing it costs nothing (#393).

    Either way it is a FAILURE (exit 1), not a skip: a soak that verified zero
    bytes must not read as a pass -- that is how an unsized cell silently
    becomes permanent missing coverage. run.sh's scaled defaults keep a short
    run from landing here at all; these messages are for the runs that override
    them, and for the genuine stalls.
    """
    n = abandoned[tag]
    if n == 0:
        # Nothing was even started, so there is no transfer to explain.
        return "no successful iterations"
    bytes_moved = moved(tag)
    head = (f"no transfer of {STREAM} bytes completed within {SECONDS} s on "
            f"{PROTO} ({n} abandoned at the deadline, {bytes_moved} bytes moved)")
    if bytes_moved > 0:
        return (f"{head}; the transfers are too big for this run: lower "
                f"VORTEX_STREAM_BYTES or raise VORTEX_SECONDS")
    if tag == "streamupload" and IS_H3:
        return (f"{head}; an h3 upload counts bytes only on completion, so the "
                f"client cannot tell the two cases apart: either the transfers "
                f"are too big for this run (lower VORTEX_STREAM_BYTES or raise "
                f"VORTEX_SECONDS) or the server took nothing; check the server "
                f"log")
    return (f"{head}: the server delivered nothing, a stall rather than a "
            f"sizing problem; check the server log")

def fmt_codes() -> str:
    parts = [f"{c}x{n}" for c, n in sorted(codes.items())]
    return " ".join(parts) if parts else "0"

def leaf_causes(exc):
    """The non-group exceptions inside `exc` (ExceptionGroups nest)."""
    if isinstance(exc, BaseExceptionGroup):
        out = []
        for sub in exc.exceptions: out.extend(leaf_causes(sub))
        return out
    return [exc]

def print_cause(exc):
    """Print a FAIL verdict for `exc` AND its traceback, both to stdout.

    Same rationale as the `Fail` handler in main(): the harness is driven as
    `nimble stress | tee stress.log`, which tees only stdout, so a cause left on
    stderr -- where the interpreter prints an unhandled traceback -- never
    reaches the archived log and the cell shows a bare `FAILED (exit 1)` with no
    reason (#387). The traceback matters as much as the one-liner: "unexpected
    AttributeError" is not a diagnosis without the frame it came from.
    """
    leaves = leaf_causes(exc)
    desc = "; ".join(f"{type(x).__name__}: {x}" for x in leaves[:3])
    if len(leaves) > 3: desc += f"; (+{len(leaves) - 3} more)"
    if isinstance(exc, BaseExceptionGroup): desc = f"{type(exc).__name__}[{desc}]"
    print(f"FAIL {WORKLOAD}: unexpected {desc} ({fmt_codes()}){mix_tail()}", flush=True)
    traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stdout)
    sys.stdout.flush()

def teardown_race(exc) -> bool:
    """True when `exc` is the httpx/httpcore/anyio connection-teardown artifact.

    Tearing a connection down while a request is still in flight -- which is
    what bounding a transfer with `asyncio.wait_for` does at the deadline, and
    what leaving the per-transfer `async with session()` on an undrained body
    does -- runs httpcore's `handle_async_request` `except BaseException` arm,
    which calls `_response_closed()` -> `aclose()` -> anyio's
    `SocketStream.aclose()`. That closes the asyncio transport, yields once
    (`await sleep(0)`) and then calls `transport.abort()`; if the loop ran the
    selector transport's `_call_connection_lost` inside that yield it has
    already set `self._loop = None`, so `_force_close` raises
    `AttributeError: 'NoneType' object has no attribute 'call_soon'`.

    That AttributeError REPLACES the `asyncio.TimeoutError` the caller expected,
    so the deadline arm never ran and a healthy 10 s upload cell failed ~1 run
    in 3 with `FAIL streamupload: unexpected AttributeError` (#390). It is a
    client-library teardown artifact: the server is not involved, and nothing
    about it is a defect under test. The callers accept it ONLY once the
    deadline has actually passed, so a genuine AttributeError in a workload
    still fails the run.
    """
    if isinstance(exc, asyncio.CancelledError):
        return True             # the cancellation itself, if it ever leaks out
    return isinstance(exc, AttributeError) and "call_soon" in str(exc)

def watch_task(name):
    """A done-callback that reports a background task's death on stdout.

    `reporter` and `loop_watchdog` are fire-and-forget: main() cancels both in
    its `finally` and never awaits them, so an exception inside one is never
    retrieved. By then the task is already done, `cancel()` is a no-op, and
    asyncio's "Task exception was never retrieved" notice goes to stderr at
    collection time -- which the harness does not tee (#387). The run silently
    loses its reporting (or its loop-stall detection) and nothing says why: a
    healthy soak and a dead reporter both print zero report lines, which is
    exactly the confusion reporter()'s comment below describes. A dead helper is
    not itself a verdict, so this logs and never touches the exit code.
    """
    def done(task):
        if task.cancelled(): return       # the expected end: main()'s finally
        e = task.exception()
        if e is None: return
        print(f"WARN {name} task died: {type(e).__name__}: {e}", flush=True)
        traceback.print_exception(type(e), e, e.__traceback__, file=sys.stdout)
        sys.stdout.flush()
    return done

def fmt_rate(now: float) -> str:
    """A per-interval throughput segment for the non-streaming workloads: the 2xx
    completion rate since the last report (the streaming workloads show MB/s via
    fmt_xfer instead). Cumulative codes alone hide a dip or a declining trend --
    you'd have to diff successive lines by eye -- so surface the rate directly. 0
    means nothing completed in the interval: a stall."""
    ops = ok_ops()
    dt, dn = now - _ops[0], ops - _ops[1]
    _ops[0], _ops[1] = now, ops
    rate = dn / dt if dt > 0 else 0.0
    return f" | {rate:.0f} {UNIT}/s"

def fmt_xfer(now: float) -> str:
    """A throughput segment for the streaming workloads: cumulative bytes plus
    the MB/s since the last report. `xfer` tracks what actually moved on the
    wire, not what was queued: download counts bytes received; h1/h2 upload
    counts bytes yielded (httpx streams, so yielded ~= sent); h3 upload counts
    STREAM per completed transfer (aioquic buffers the whole body up front, so a
    queued-bytes rate would spike then read 0 while the wire drains). 0 MB/s
    means nothing moved in the interval -- a stall, or (h3 upload) a large
    transfer still in flight with no completion yet, or (upload, final line) the
    workers sitting out a tail too short for another transfer (see
    w_streamupload)."""
    dt, db = now - _rate[0], xfer[0] - _rate[1]
    _rate[0], _rate[1] = now, xfer[0]
    rate = db / dt / MB if dt > 0 else 0.0
    return f" | {xfer[0] // MB}MB xfer @ {rate:.0f}MB/s"

def report_line(prefix, rss, heap, fds):
    now = time.monotonic()
    t = int(now - start)
    # `mixed` has no single unit to rate: it lists every slice's own tally
    # instead, so a dead workload shows as a zero in the line rather than
    # disappearing into a healthy sum (see mix_segments).
    if IS_MIXED:
        seg = " | " + mix_segments(now)
    else:
        seg = fmt_xfer(now) if STREAMING else fmt_rate(now)
    # `None` means the /stats sample failed (or, for fds, an older two-field
    # /stats); render "n/a", never a misleading "0MB"/"0" -- a soak exists to
    # watch RSS/heap/fds, so a silently-zeroed metric must look broken, not healthy.
    rss_s = "n/a" if rss is None else f"{rss // MB}MB"
    heap_s = "n/a" if heap is None else f"{heap // MB}MB"
    fds_s = "n/a" if fds is None else str(fds)
    print(f"[{WORKLOAD} {PROTO} {SERVER}] {prefix}{fmt_codes()}{seg} | "
          f"RSS {rss_s} | heap {heap_s} | fds {fds_s} | t={t}s", flush=True)

async def reporter():
    # One short-lived session per sample, with a hard timeout, and the report
    # line prints NO MATTER WHAT. The previous shape -- one session opened
    # eagerly up front and held for the whole run -- silently killed all
    # reporting on h3: connect_h3's QUIC handshake (unlike httpx's lazy
    # connect) runs in the session's __aenter__, outside the try, and under
    # full load the 97th handshake from this pegged single-threaded process
    # can starve or idle-timeout. The reporter then hung forever (or died as
    # an unretrieved task exception) and a perfectly healthy run looked
    # exactly like a server stall: zero report lines. A soak's reporting must
    # never share fate with one connection's handshake.
    while time.monotonic() < deadline:
        await asyncio.sleep(REPORT)
        rss = heap = fds = None         # a bad /stats shows as n/a, not fake 0MB
        try:
            async def sample():
                async with session() as s:
                    return await get_server_stats(s)
            rss, heap, fds = await asyncio.wait_for(sample(), timeout=REPORT / 2)
        except Exception:
            pass
        report_line("", rss, heap, fds)

async def loop_watchdog():
    # Distinguish a client-side stall from a server-side one. A frozen throughput
    # counter across every worker at once (all connections idle) can mean either
    # the server stopped servicing us OR this client's single event loop was
    # wedged in a blocking call (aioquic crypto, a GC pause, ...) -- and a wedged
    # loop can't process packets, so it trips the peer's idle timeout and looks
    # identical (`connection closed ("Idle timeout")`). A 1s sleep that takes far
    # longer means the loop was blocked; log the lag to stdout so the two cases
    # are separable after the fact (no WARN => the client loop stayed healthy, so
    # the stall was the server's).
    while time.monotonic() < deadline:
        t0 = time.monotonic()
        await asyncio.sleep(1.0)
        lag = time.monotonic() - t0 - 1.0
        if lag > 2.0:
            print(f"WARN client event-loop stalled {lag:.1f}s (t={int(t0 - start)}s)",
                  flush=True)

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

async def ramped(i, worker, conc: int = CONC):
    """`drive` for worker `i` of `conc`, after its share of the WebSocket ramp
    (ws_ramp_delay).

    Only the connection-per-worker WebSocket workload needs this: its workers each
    hold one socket for the whole soak, so without a ramp every handshake in the
    cell lands in the same instant. Staggering only shifts when steady state
    starts; the deadline, the verification and the failure handling are `drive`'s,
    unchanged.
    """
    d = ws_ramp_delay(i, conc)
    if d > 0: await asyncio.sleep(d)
    await drive(worker)

# --- workloads (transport-agnostic via session) ------------------------------
#
# Each takes the number of concurrent workers to fan out, defaulting to the
# single-workload value it has always used (CONC for the request-shaped
# workloads, 1 for the streaming ones, which do one whole transfer per
# iteration and get their parallelism from main()'s CLIENTS copies). The
# default-argument calls are exactly the old code; the parameter exists so the
# `mixed` supervisor can give each workload its share of one worker budget
# instead of every workload the whole of it (#394).
async def w_requests(conc: int = CONC):
    # Typed payload mix, cycled per iteration (payload_mix() from transport). A
    # single fixed body only ever exercises one point on the curve; real traffic
    # is a mix of content-types AND lengths -- text, JSON (object + array),
    # urlencoded + multipart form data, binary, XML, CSV, HTML. The mix covers the
    # 0-length / single-byte framing paths, the <1400 B no-compress threshold, the
    # compressible >=1400 B branch per type, and the incompressible store-fallback.
    # Each body is request-compressed (compress + content-encoding + accept-
    # encoding) AND carries its content-type header; the echo response must return
    # both the exact bytes and that same content-type verbatim (params included).
    prepared = []
    for ctype, raw in payload_mix():
        body, enc = compress(raw)
        hdrs = {"content-type": ctype}
        if enc: hdrs["content-encoding"] = enc
        if ACCEPT: hdrs["accept-encoding"] = ACCEPT
        prepared.append((ctype, raw, body, hdrs))
    gets = expected_gets()
    get_hdrs = {"accept-encoding": ACCEPT} if ACCEPT else {}
    async def once():
        async with session() as s:
            k = 0
            while time.monotonic() < deadline:
                # Cycle the typed GET routes, one per iteration, asserting the
                # served content-type and the exact body bytes.
                path, want_ct, want_body = gets[k % len(gets)]
                st, ct, b = await s.get(path, get_hdrs)
                if st != 200:
                    raise Fail(f"GET {path} -> {st}")
                if ct.lower() != want_ct.lower():
                    raise Fail(f"GET {path} content-type: want {want_ct!r} got {ct!r}")
                if b != want_body:
                    raise Fail(f"GET {path} body {len(b)}B (want {len(want_body)}B)")
                bump(200)
                ctype, raw, body, hdrs = prepared[k % len(prepared)]; k += 1
                for meth in ("POST", "PUT"):
                    st, ct, b = await s.request(meth, "/echo", hdrs, body)  # body: compressed
                    if st != 200 or b != raw:
                        raise Fail(f"{meth} /echo -> {st}, {len(b)}B (want {len(raw)}B)")
                    # Round-trip the content-type verbatim (do NOT strip params --
                    # the multipart boundary must survive); normalize case only.
                    if ct.lower() != ctype.lower():
                        raise Fail(f"{meth} /echo content-type: want {ctype!r} got {ct!r}")
                    bump(200)
    await asyncio.gather(*[drive(once) for _ in range(conc)])

# WebSocket opening-handshake budget and burst shaping.
#
# Every worker opens its socket at t=0, so a cell slams CLIENTS*CONC (96 by
# default) simultaneous handshakes at the server from one asyncio loop. The
# server accepts and upgrades each on whichever SO_REUSEPORT loop thread the
# kernel hashed it to, and these soaks are run deliberately oversubscribed
# (several cells in parallel, host load 20-50), where a single loop thread can be
# descheduled for seconds -- measured: TCP connect stayed under 0.15 s while the
# upgrade for the connections hashed to one starved thread waited 1-5 s, all
# released together the moment that thread was scheduled again. `websockets`
# defaults open_timeout to 10 s, so that cold-start scheduling luck failed an
# otherwise healthy soak inside its first minute, with a server that went on to
# echo tens of thousands of messages a second for the rest of the hour.
#
# So: scale the budget with the burst size and floor it far above the worst case
# observed, and spread the initial handshakes over a few seconds instead of
# opening all of them in one instant. The soak then measures steady-state
# behaviour, which is what it exists to measure; a genuinely wedged upgrade still
# fails the cell, just on a timescale that means something.
WS_OPEN_TIMEOUT = max(60.0, 0.5 * CLIENTS * CONC)
WS_RAMP = min(5.0, max(0.0, SECONDS / 10.0))    # never eat a short smoke run

def ws_ramp_delay(i: int, conc: int = CONC) -> float:
    """How long worker `i` of `conc` waits before its first handshake (0 when not
    ramping). `conc` is the size of the burst being spread, which is the whole
    cell for a `ws` soak and only the ws slice under `mixed`."""
    return WS_RAMP * i / conc if conc > 1 else 0.0

async def w_ws(conc: int = CONC):
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
        await asyncio.gather(*[ramped(i, lambda i=i: once(i), conc)
                               for i in range(conc)])
        return
    import websockets
    ws_url = BASE.replace("https://", "wss://").replace("http://", "ws://") + "/ws"
    ssl_ctx = None
    if ws_url.startswith("wss://"):
        import ssl
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
    async def once(i):
        n = 0
        async with websockets.connect(ws_url, ssl=ssl_ctx, max_size=None,
                                      open_timeout=WS_OPEN_TIMEOUT) as ws:
            while time.monotonic() < deadline:
                msg = f"msg-{i}-{n}"
                await ws.send(msg)
                if await ws.recv() != msg: raise Fail("ws echo mismatch")
                bump(200); n += 1
    await asyncio.gather(*[ramped(i, lambda i=i: once(i), conc) for i in range(conc)])

async def read_lines(gen):
    """Yield decoded lines from a byte-chunk async generator (SSE framing)."""
    buf = b""
    async for chunk in gen:
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.rstrip(b"\r").decode("utf-8", "replace")

async def w_sse(conc: int = CONC):
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
    await asyncio.gather(*[drive(once) for _ in range(conc)])

async def w_streamupload(conc: int = 1):
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
    # The slowest transfer this worker has actually completed, in seconds. The
    # cheapest way to survive a transfer cancelled at the deadline is not to
    # start one that cannot finish, so once there is a measurement to go on, sit
    # out the tail of the run instead. This is only ever an optimization: the
    # FIRST transfer of a cell has nothing to learn from, and a loaded host can
    # make any transfer slower than every one before it, so the deadline can
    # still land mid-upload -- hence the teardown handling below as well.
    # Per worker, not per invocation: the measurement is about this worker's own
    # transfers, so a slice of several workers (under `mixed`) must not inherit
    # another worker's timing. Passed in by the gather below, which is why it is
    # an argument rather than a closure cell.
    async def once(slowest):
        left = deadline - time.monotonic()
        if slowest[0] > 0.0 and left < slowest[0]:
            await asyncio.sleep(max(0.0, left))   # `drive` would spin otherwise
            return
        # One abandonment per call, counted once. The TimeoutError arm below
        # `return`s from inside `async with session()`, and leaving that block
        # tears a connection down with the request still in flight -- the exact
        # teardown race (#390) the outer arm exists for. So the outer arm can
        # fire on a transfer the inner one already tallied, and the pair counted
        # ONE abandoned transfer as two: the `no transfer ... (N abandoned)`
        # diagnosis then overstated N, on the only line a reader has to go on.
        counted = [False]
        try:
            async with session() as s:
                # `drive` checks the deadline only BETWEEN transfers, so bound
                # this one by the time actually left -- see w_streamdownload's
                # per-chunk check for why. On expiry, abandon it uncounted:
                # leaving the `async with` tears the connection (and the stream)
                # down, and neither bump(200) nor the xfer tally below runs for a
                # transfer we did not verify. Truncating body_gen instead would
                # send a short body and trip the 400 check below as if the server
                # were at fault.
                t0 = time.monotonic()
                try:
                    st = await asyncio.wait_for(
                        s.upload("/upload", {"x-sha1": sha}, body_gen()),
                        timeout=max(0.0, deadline - time.monotonic()))
                except asyncio.TimeoutError:
                    abandoned[TAG.get()] += 1     # started, never finished: see `abandoned`
                    counted[0] = True             # the `return` below unwinds
                                                  # through the outer arm; do not
                                                  # let it count this one twice
                    return
                if st == 400: raise Fail("server rejected the SHA-1 (400)")
                if st != 200: raise Fail(f"upload -> {st}")
                bump(200)
                slowest[0] = max(slowest[0], time.monotonic() - t0)
                if IS_H3: add_xfer(STREAM)    # h3 only: aioquic buffers the whole
                                              # body up front, so a queued-bytes rate
                                              # spikes then reads 0 while the wire
                                              # drains. Count delivered on completion.
                                              # h1/h2 already count sent bytes in
                                              # body_gen (httpx streams).
        except (AttributeError, asyncio.CancelledError) as e:
            # Past the deadline, the cancellation above (and the session exit it
            # unwinds through) can surface as httpcore/anyio's teardown
            # AttributeError instead of the asyncio.TimeoutError the arm above
            # expects -- see teardown_race for the exact frame chain. Treat that
            # as the expiry it is, uncounted, exactly like the TimeoutError.
            # BEFORE the deadline this is a real defect and still fails the run
            # (#390).
            if time.monotonic() < deadline or not teardown_race(e):
                raise
            # The deadline expiry by its other route (#390) -- unless the arm
            # above already recorded this very transfer and we are only passing
            # back through its session teardown.
            if not counted[0]:
                abandoned[TAG.get()] += 1
    # One whole transfer per iteration, so a worker here is a transfer in
    # flight; `conc` of them, each with its own `slowest`. A single-workload
    # soak runs conc=1 and gets its parallelism from main()'s CLIENTS copies,
    # exactly as before.
    await asyncio.gather(*[drive(lambda s=[0.0]: once(s)) for _ in range(conc)])

async def w_streamdownload(conc: int = 1):
    want = expected_sha1()
    async def transfer() -> bool:
        """One whole transfer. True when it was abandoned at the deadline (see
        the per-chunk check below), False when it completed and was verified."""
        async with session() as s:
            gen = s.stream("GET", "/download")
            st = await gen.__anext__()
            if st != 200: raise Fail(f"download status {st}")
            h = hashlib.sha1(); got = 0
            async for chunk in gen:
                h.update(chunk); got += len(chunk); add_xfer(len(chunk))
                # The streaming workloads are the only ones whose unit of work is
                # a whole transfer; every other `once()` checks the deadline per
                # iteration itself. `drive` checks it only between transfers, and
                # one 1 GiB transfer over h3 on a loaded host runs 2-3 minutes --
                # far past main()'s deadline+60s safety net, which was sized for
                # workloads that stop within one request. So the last transfer of
                # a soak overran it and a clean hour was reported as a "stall"
                # (measured: 125 s/transfer on streamupload h3, 163 s on
                # streamdownload h3, versus 4-15 s on h1/h2, which is the only
                # reason those cells passed). Abandon an in-flight transfer at the
                # deadline instead: leave the body undrained -- exiting the
                # per-transfer session below resets the stream -- and neither
                # verify nor count it. This does not blunt the stall detector: a
                # genuinely wedged stream delivers no chunk, so it never reaches
                # here and main()'s wait_for still catches it.
                if time.monotonic() >= deadline:
                    return True
            if got != STREAM or h.hexdigest() != want:
                raise Fail(f"download mismatch: {got} bytes, sha {h.hexdigest()} != {want}")
            bump(200)
            return False
    async def once():
        try:
            # Tally the abandonment (see `abandoned`): with nothing completed,
            # "the transfers were too big for the run" and "the server never
            # served one" are different diagnoses and must read differently.
            if await transfer():
                abandoned[TAG.get()] += 1
        except (AttributeError, asyncio.CancelledError) as e:
            # The same teardown race as the upload's (#390), reached by the other
            # route: abandoning the body above leaves the response in flight, so
            # closing the session unwinds through httpcore's `except
            # BaseException` arm and can raise anyio's `transport.abort()`
            # AttributeError instead of returning. Accepted only past the
            # deadline -- the only time this workload abandons a transfer -- so a
            # real AttributeError still fails the run. See teardown_race.
            if time.monotonic() < deadline or not teardown_race(e):
                raise
            # The same abandonment the `return True` above reports, reached by
            # the teardown race instead; transfer() never returned, so this
            # cannot double-count it.
            abandoned[TAG.get()] += 1
    # `conc` transfers in flight; 1 for a single-workload soak (its parallelism
    # comes from main()'s CLIENTS copies), its slice's share under `mixed`.
    await asyncio.gather(*[drive(once) for _ in range(conc)])

async def w_methods():
    # Every HTTP method, transport-agnostic (h1/h2/h3). Used by the reverse-proxy
    # interop suite to confirm each method survives the proxy hop. The body-bearing
    # methods (POST/PUT/DELETE/PATCH) carry the same typed payload mix as
    # w_requests (payload_mix() -- text, JSON, urlencoded + multipart form data,
    # binary, XML, CSV, HTML), cycled, not empty pings, and the h3 client
    # advertises Content-Length like httpx does for h1/h2. Each carries its
    # content-type header and the echo must return that type verbatim (params
    # included). GET/HEAD/OPTIONS carry no body; HEAD returns headers only (empty
    # body, no type assertion); OPTIONS is auto-answered (204/Allow).
    prepared = []
    for ctype, raw in payload_mix():
        body, enc = compress(raw)
        h = {"content-type": ctype}
        if enc: h["content-encoding"] = enc
        if ACCEPT: h["accept-encoding"] = ACCEPT
        prepared.append((ctype, raw, body, h))
    get_hdrs = {"accept-encoding": ACCEPT} if ACCEPT else {}
    async def once():
        async with session() as s:
            k = 0
            while time.monotonic() < deadline:
                st, _ct, b = await s.get("/plaintext", get_hdrs)
                if st != 200 or b != b"Hello, World!":
                    raise Fail(f"GET /plaintext -> {st}")
                bump(200)
                ctype, raw, body, hdrs = prepared[k % len(prepared)]; k += 1
                for meth in ("POST", "PUT", "DELETE", "PATCH"):
                    st, ct, b = await s.request(meth, "/echo", hdrs, body)
                    if st != 200 or b != raw:
                        raise Fail(f"{meth} /echo -> {st}, {len(b)}B (want {len(raw)}B)")
                    # Content-type verbatim (params kept, case normalized only).
                    if ct.lower() != ctype.lower():
                        raise Fail(f"{meth} /echo content-type: want {ctype!r} got {ct!r}")
                    bump(200)
                st, _ct, b = await s.request("HEAD", "/echo", get_hdrs)
                if st != 200 or (b or b"") != b"":
                    raise Fail(f"HEAD /echo -> {st}, {len(b or b'')}B (want 0)")
                bump(200)
                st, _ct, _ = await s.request("OPTIONS", "/echo", {})
                if st not in (200, 204):
                    raise Fail(f"OPTIONS /echo -> {st}")
                bump(st)
    await asyncio.gather(*[drive(once) for _ in range(CONC)])

# --- mixed: all five verified workloads at one server ------------------------
# Every soak before this one drove ONE workload at a server, so nothing ever
# checked the bytes when a 1 GiB upload, a sendFile download, an idle SSE feed
# and a busy /echo stream share a server process -- which is where several
# recent fixes lived (loop-thread starvation and deadline credit, QUIC idle reap
# next to a busy upload, h2 flow-control fairness between a bulk stream and many
# small ones). The chaos sidecar already produces mixed traffic, but it is
# unverified by design: it swallows its errors and asserts only the fd count
# (#394).
#
# The default split of one cell's worker budget. `requests` takes the bulk of
# the request-shaped share because its workers are the cheapest and its /echo +
# typed-GET path is what every other route competes with.
#
# The two STREAMING entries are different in kind: their number is not a share
# of the budget but a presence flag (see MIX_FIXED), so their default weight is
# written as the 10 it has always been and read only as "> 0, so run it".
MIX_DEFAULT = (("requests", 40), ("ws", 20), ("sse", 20),
               ("streamupload", 10), ("streamdownload", 10))
# The slices fixed at exactly ONE worker per client when present, mirroring the
# dedicated streamupload / streamdownload soaks: one worker there is one WHOLE
# transfer in flight, and those soaks take their parallelism from main()'s
# CLIENTS copies rather than from CONC. The first cut gave each a tenth of CONC,
# i.e. 3 + 3 per client and 9 + 9 per cell at the default 3x32 -- three times
# the dedicated soaks' parallelism -- and that is what forced the mixed transfer
# size down to 2 MiB at every duration. A 2 MiB body is neither of the two
# interactions a mixed cell exists to exercise (a long transfer running next to
# short requests; a bulk buffer competing for the server's write path), so the
# allocation was buying nine small transfers at the cost of the thing under
# test. One in flight per client, at the same size the dedicated soaks run, is
# the trade that keeps both (#394).
MIX_FIXED = ("streamupload", "streamdownload")
MIX_FNS = {}                    # workload -> coroutine; filled from WORKLOADS below

def mix_fail(msg: str):
    """A VORTEX_MIX / VORTEX_CONCURRENCY config error: on stdout, exit 2.

    `raise SystemExit(msg)` writes to stderr and exits 1, which is wrong twice
    over: the harness is driven as `nimble stress | tee stress.log` and tees
    stdout only, so the reason would never reach the archived log (#387), and 1
    is the soak-failed code -- a mistyped knob is a config error, the same class
    as run.sh's own `exit 2`.
    """
    print(msg, flush=True)
    raise SystemExit(2)

def parse_mix() -> list:
    """The mix as [(workload, weight)], from VORTEX_MIX when it is set.

    Form: `requests=40,ws=20,sse=20,streamupload=10,streamdownload=10`. Every
    key must name one of the five verified workloads; an omitted one keeps its
    default, a repeated one is rejected (the later value would silently win, so
    the knob would not mean what it says), and an explicit `0` drops that
    workload from the cell entirely -- the one way to run a subset, and then it
    is not checked for progress either, since it was never asked to make any.

    The numbers are WEIGHTS, normalized by the sum of the weights that compete
    for the same workers, not percentages: `requests=100` alone does not mean
    "100%", it means "requests takes all of the request-shaped share" (the other
    two keep their defaults, so the real split is 100/20/20 -> 71/14/14). They
    need not add to 100, though the defaults do because a reader expects it.

    For `streamupload` / `streamdownload` the weight is PRESENCE-ONLY: any value
    > 0 means "run this slice", at the one worker per client MIX_FIXED pins it
    to, and 0 drops it. Weighting a slice that is fixed at one worker would have
    nothing to weigh.

    A malformed knob exits 2 rather than running something other than what was
    asked for (see mix_fail).
    """
    raw = os.environ.get("VORTEX_MIX", "").strip()
    share = dict(MIX_DEFAULT)
    seen = set()
    for item in raw.split(","):
        item = item.strip()
        if not item: continue
        k, eq, v = item.partition("=")
        k, v = k.strip(), v.strip()
        if not eq:
            mix_fail(f"bad VORTEX_MIX entry {item!r}: want name=weight")
        if k not in share:
            mix_fail(f"unknown VORTEX_MIX workload {k!r}; want one of "
                     f"{', '.join(w for w, _ in MIX_DEFAULT)}")
        if k in seen:
            mix_fail(f"VORTEX_MIX names {k!r} twice ({raw!r}): the second "
                     f"weight would silently win, so the knob would not mean "
                     f"what it says. Give each workload at most one weight.")
        # isascii() first: str.isdigit() is True for superscripts and other
        # non-ASCII digit forms that int() then rejects with a ValueError
        # traceback instead of this message (`VORTEX_MIX=requests=4\u00b2`).
        if not (v.isascii() and v.isdigit()):
            mix_fail(f"bad VORTEX_MIX weight for {k}: {v!r} "
                     f"(want a non-negative decimal integer)")
        seen.add(k)
        share[k] = int(v)
    out = [(k, share[k]) for k, _ in MIX_DEFAULT if share[k] > 0]
    if not out:
        mix_fail(f"VORTEX_MIX={raw!r} leaves no workload to run")
    return out

def split_mix(budget: int, shares: list) -> list:
    """Hand `budget` workers out over `shares`, as [(workload, workers)].

    The streaming slices present take exactly ONE worker each -- one whole
    transfer in flight per client, which is what the dedicated streamupload /
    streamdownload soaks run (see MIX_FIXED).

    The request-shaped slices present (requests, ws, sse) then split what is
    left -- `budget` minus one per streaming slice -- by their weights,
    normalized by the sum of just THOSE weights, allocated by largest remainder
    so the rounding loss is spread instead of piling on one workload and leaving
    workers idle (30 left at the default 40/20/20 is 15/8/7, not 15/7/7 with one
    idle). Every one of them gets at least one worker, paid for out of the
    largest allocations, because a slice with zero workers drives nothing and
    would then fail the cell's own per-slice progress check (`VORTEX_MIX=
    requests=1000` at a small budget rounds its two companions to zero).

    The total is EXACTLY `budget` whenever at least one request-shaped slice is
    present, and exactly the number of streaming slices when none is (a slice
    fixed at one transfer in flight has nowhere to spend the rest, and inventing
    workers for it would change what is being measured). It is never MORE than
    `budget`: `budget` < len(shares) is refused by mix_fail here rather than
    overshot, since a mixed cell must neither drop a slice -- that would claim
    coverage it does not have -- nor quietly run wider than it was told to.
    """
    if budget < len(shares):
        mix_fail(f"VORTEX_CONCURRENCY={budget} is below the {len(shares)} "
                 f"workloads in the mix "
                 f"({', '.join(k for k, _ in shares)}): a mixed cell cannot "
                 f"drop a slice (it would claim coverage it does not have) and "
                 f"will not run more workers than it was given. Raise "
                 f"VORTEX_CONCURRENCY to at least {len(shares)}, or drop a "
                 f"workload with VORTEX_MIX=<name>=0.")
    out = {k: 1 for k, _ in shares}                  # the floor: every slice drives
    rest = [(k, w) for k, w in shares if k not in MIX_FIXED]
    extra = budget - len(shares)                     # >= 0, checked above
    if rest and extra > 0:
        # Largest remainder over everything the request-shaped slices share,
        # which is `extra` plus the one worker each already holds.
        left = extra + len(rest)
        total_w = sum(w for _, w in rest) or len(rest)
        exact = [(k, left * w / total_w) for k, w in rest]
        alloc = {k: int(x) for k, x in exact}
        spare = left - sum(alloc.values())
        # Stable sort, so a remainder tie goes to the earlier (higher-weight)
        # workload and a given VORTEX_MIX always splits the same way.
        for k, _x in sorted(exact, key=lambda kv: kv[1] - int(kv[1]), reverse=True):
            if spare <= 0: break
            alloc[k] += 1; spare -= 1
        for k in [k for k, n in alloc.items() if n == 0]:
            donor = max(alloc, key=lambda j: alloc[j])
            alloc[donor] -= 1; alloc[k] = 1
        out.update(alloc)
    return [(k, out[k]) for k, _ in shares]

# Resolved once, and only for the cell that needs it: parsing VORTEX_MIX (and
# rejecting a malformed one) under a single-workload soak would be noise.
MIX_SLICES = split_mix(CONC, parse_mix()) if IS_MIXED else []

async def w_mixed():
    """All five verified workloads at one server, concurrently.

    One slice per workload, each the UNCHANGED single-workload coroutine handed
    its share of this client's worker budget (VORTEX_CONCURRENCY). main() runs
    CLIENTS copies of this, so the cell splits exactly
    VORTEX_CLIENTS x VORTEX_CONCURRENCY workers -- a `mixed` cell is not a
    five-times-heavier cell.

    The streaming slices present take one worker each, i.e. ONE transfer in
    flight per client, exactly as their dedicated soaks run; the request-shaped
    slices split the rest by weight (see split_mix). So VORTEX_CONCURRENCY must
    be at least the number of slices present -- 5 for the default mix, fewer
    once VORTEX_MIX drops some -- and a smaller one is refused with exit 2
    rather than silently overshot.

    Each slice tags itself before fanning out, and the tasks it creates inherit
    that context, so the counters, the report segment and the progress check all
    see the workload that earned each completion instead of the sum.

    Connections are per worker and per call exactly as in the single-workload
    soaks -- the streaming slices open their own session per transfer, the
    request/sse slices hold one per worker, the ws slice one socket per worker --
    so this is all five workloads at one SERVER, not down one connection. That
    is both the existing behaviour and the more interesting case (#394).
    """
    async def run_slice(tag, n):
        TAG.set(tag)            # inherited by every task this slice creates
        await MIX_FNS[tag](n)
    await asyncio.gather(*[run_slice(tag, n) for tag, n in MIX_SLICES])

def fmt_mb(b: int) -> str:
    """Bytes as MB for a report segment, with one decimal under 10 MB.

    A whole-number MB is what a soak-sized figure wants, but floor division
    printed `0MB` for every sub-MiB VORTEX_STREAM_BYTES -- so a mixed cell run
    at, say, 512 KiB reported its verified transfers as having moved nothing,
    which is exactly the reading the per-slice tally exists to prevent."""
    mb = b / MB
    return f"{mb:.1f}MB" if mb < 10 else f"{b // MB}MB"

# How each workload renders its own cumulative tally in a `mixed` report line
# and pass banner. Unit words, not a shared rate: the five are not commensurable,
# and a headline ops/s over all of them would hide a dead slice in the sum.
_MIX_SEG = {
    "requests":       lambda n: f"req {n}",
    "ws":             lambda n: f"ws {n} msgs",
    "sse":            lambda n: f"sse {n} ev",
    "streamupload":   lambda n: f"up {n} xfers {fmt_mb(n * STREAM)}",
    "streamdownload": lambda n: f"down {n} xfers {fmt_mb(n * STREAM)}",
}
# Which slices show their per-interval delta as a RATE rather than a raw count.
# The request-shaped ones complete thousands per interval, where a raw delta is
# unreadable and a rate is directly comparable to the single-workload soaks'
# `N requests/s` segment; a mixed cell's streaming slices complete single
# digits, where the count is the information and `(+0)` is the thing worth
# seeing.
_MIX_RATE = frozenset(("requests", "ws", "sse"))
_mix_last = Counter()           # tag -> ok_by[tag] at the previous report line
_mix_at = [0.0]                 # monotonic time of that line

def mix_segments(now=None) -> str:
    """The per-workload tally segment for `mixed`.

    Cumulative only when `now` is None (the pass banner), cumulative plus the
    delta since the previous report line when it is given (the report lines).
    Measured, h3 + sync server, 10 s at the mixed default size, t=11s:

        req 8820 (+340/s) | ws 17378 msgs (+803/s) | sse 219600 ev (+10052/s)
        | up 6 xfers 12MB (+0) | down 3 xfers 6.0MB (+3)

    The delta is what makes a stalled slice visible. A cumulative count only
    ever goes up, so a slice that died at t=30s still reads as a healthy
    five-figure total for the rest of the run, and spotting it means diffing
    successive lines by eye -- the same reason the single-workload soaks print a
    rate (fmt_rate) next to their cumulative codes.

    There is deliberately no "stalled for N intervals" verdict on top of this. A
    wedged slice does not merely stop counting: it blocks w_mixed's gather, the
    cell then overruns main()'s deadline+60 s wait_for, and that already fails
    the run as the stall it is -- exactly as it does for the five single-workload
    soaks. A second stall detector here would be a second opinion about the same
    event, with its own threshold to tune and its own false positives on a
    loaded host.

    The streaming slices show completed transfers and the bytes those verified
    (a partial transfer is never counted, so count * VORTEX_STREAM_BYTES is
    exactly what moved and was checksummed).
    """
    dt = (now - _mix_at[0]) if now is not None else 0.0
    parts = []
    for t, _ in MIX_SLICES:
        n = ok_by[t]
        seg = _MIX_SEG[t](n)
        if now is not None:
            d = n - _mix_last[t]
            if t in _MIX_RATE:
                seg += f" (+{d / dt if dt > 0 else 0.0:.0f}/s)"
            else:
                seg += f" (+{d})"
            _mix_last[t] = n
        parts.append(seg)
    # One interval for every slice, so the stamp moves after the whole line.
    if now is not None: _mix_at[0] = now
    return " | ".join(parts)

def mix_tail() -> str:
    """The per-slice tallies appended to a `mixed` FAIL line, else "".

    A hard failure returns from main() before its final report line, so without
    this the only record of what each slice had achieved when the defect hit --
    which were healthy, which were already dead -- is lost, and that record is
    most of why a mixed cell is worth running (#394)."""
    return f" [{mix_segments()}]" if IS_MIXED else ""

WORKLOADS = {
    "requests": w_requests, "methods": w_methods, "ws": w_ws, "sse": w_sse,
    "streamupload": w_streamupload, "streamdownload": w_streamdownload,
    "mixed": w_mixed,
}
# The five `mixed` fans out, under the names VORTEX_MIX uses (`methods` is the
# proxy suite's, not part of the stress matrix).
MIX_FNS.update({k: WORKLOADS[k] for k, _ in MIX_DEFAULT})

async def main():
    global deadline, start
    if WORKLOAD not in WORKLOADS:
        print(f"unknown VORTEX_WORKLOAD: {WORKLOAD}", flush=True); return 2
    start = time.monotonic()
    _rate[0] = _ops[0] = _mix_at[0] = start
    deadline = start + SECONDS
    rep = asyncio.ensure_future(reporter())
    rep.add_done_callback(watch_task("reporter"))
    wd = asyncio.ensure_future(loop_watchdog())
    wd.add_done_callback(watch_task("loop_watchdog"))
    try:
        # workers self-stop at the deadline; wait_for is a safety net so a stalled
        # await (e.g. a peer flow-control stall) can never hang the harness.
        await asyncio.wait_for(
            asyncio.gather(*[WORKLOADS[WORKLOAD]() for _ in range(CLIENTS)]),
            timeout=SECONDS + 60)
    except Fail as e:
        # The failure cause must land on stdout next to the "== ... passed =="
        # verdict lines (report_line, the pass line) -- not stderr. The harness is
        # driven as `nimble stress | tee stress.log`, which tees only stdout, so a
        # cause on stderr is lost to the terminal and the log shows a bare
        # `FAILED (exit 1)` with no reason. Keep the verdict and its cause together.
        # mix_tail: a `mixed` cell records every slice's tally next to the
        # cause, since the run ends here without reaching the final report line
        # and "which slice was already dead" is half the diagnosis (#394).
        print(f"FAIL {WORKLOAD}: {e} ({fmt_codes()}){mix_tail()}", flush=True)
        return 1
    except asyncio.TimeoutError:
        # A stall is exactly what this soak exists to catch (peer flow-control
        # deadlock, a stuck stream, a sendFile-pin write-scheduler deadlock), so
        # a workload that does not stop within deadline+60s is a FAILURE, not a
        # warning. Returning here (non-zero) keeps a hang from being reported as
        # a pass once some early iterations happened to succeed.
        print(f"FAIL {WORKLOAD}: workers did not stop within deadline+60s "
              f"(stall) ({fmt_codes()}){mix_tail()}", flush=True)
        return 1
    except BaseExceptionGroup as eg:
        # `asyncio.gather` re-raises only the FIRST exception, never a group, so
        # this is not about gather itself; it is about a library in the stack
        # (aioquic and httpx both use asyncio.TaskGroup, which raises
        # ExceptionGroup on 3.11+, and the client image is python:3.12-slim)
        # handing us a group. Neither the `Fail` nor the `TimeoutError` handler
        # above matches a group that merely CONTAINS one, so without this the
        # real cause only ever reached stderr. BaseExceptionGroup also covers the
        # ExceptionGroup case (a subclass) and, unlike `except Exception`, a
        # group whose leaves are all BaseExceptions. ^C stays an interrupt: split
        # the interrupts back out and re-raise them after reporting the rest.
        interrupts, rest = eg.split((KeyboardInterrupt, SystemExit))
        if rest is None: raise
        print_cause(rest)
        if interrupts is not None: raise interrupts
        return 1
    except Exception as e:
        # The catch-all the two handlers above were missing: an AttributeError in
        # a workload, a RuntimeError out of aioquic/httpx internals, a KeyError
        # in reporting. These used to propagate out of asyncio.run, which prints
        # the traceback to stderr and exits 1, so the tee'd log recorded a bare
        # `FAILED (exit 1)` and the cell was undiagnosable after the fact (#387).
        # KeyboardInterrupt and SystemExit are BaseExceptions and still
        # propagate: a ^C or an explicit exit must not read as a soak failure.
        print_cause(e)
        return 1
    finally:
        rep.cancel(); wd.cancel()
    total = ok_ops()
    # A fresh session just for the closing RSS/heap sample; never let a failed
    # connect (server already torn down, a transient QUIC/DNS blip) crash the
    # run with a traceback and mask the real pass/fail verdict below. `None`
    # renders as n/a (see report_line), not a misleading 0MB.
    rss, heap, fds = None, None, None
    try:
        async with session() as s:
            rss, heap, fds = await get_server_stats(s)
    except Exception:
        pass
    report_line("final ", rss, heap, fds)
    if IS_MIXED:
        # PER WORKLOAD, never on the sum: a stalled SSE feed must not hide
        # behind a healthy /echo counter, which is the whole reason this cell is
        # worth running (#394). Every dead slice is named, not just the first:
        # each is its own diagnosis and they are cheap to print.
        dead = [t for t, _ in MIX_SLICES if ok_by[t] == 0]
        if dead:
            for t in dead:
                print(f"FAIL {WORKLOAD}: {t}: {no_progress(t)}", flush=True)
            return 1
        print(f"== {WORKLOAD} {SERVER} {PROTO} passed ({mix_segments()}) ==",
              flush=True)
        return 0
    if total == 0:
        print(f"FAIL {WORKLOAD}: {no_progress(WORKLOAD)}", flush=True); return 1
    print(f"== {WORKLOAD} {SERVER} {PROTO} passed ({total} {UNIT}) ==", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
