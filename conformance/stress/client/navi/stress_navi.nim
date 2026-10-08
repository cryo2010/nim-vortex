## Compiled navi load client for the vortex stress soaks (VORTEX_CLIENT=navi).
##
## The Nim counterpart of `client/stress_client.py`: it drives one workload
## (VORTEX_WORKLOAD) at the vortex stress server for VORTEX_SECONDS, verifying
## every response and discarding it, and **hard fails** (exit 1) on the first
## defect -- a wrong status, an echo mismatch, a served body that is not the
## contract's bytes, a content-type that did not round-trip, a protocol-pin
## violation, or any transport error. Zero successful iterations is also a
## failure, never a pass.
##
## Why a second client at all: the Python canary is one asyncio loop behind the
## GIL with QUIC done in Python, so on the hot cells the harness measures aioquic
## at least as much as it measures vortex, and the client's own teardown races
## land in the log as vortex failures (#390). navi is also an independent HTTP
## implementation, so where the two agree a vortex pass means more. Python stays
## the default and the interop reference: it is the harness's only non-ngtcp2
## QUIC stack, while vortex and navi share ngtcp2 + nghttp3, so a navi h3 pass is
## not foreign-stack evidence. See conformance/stress/README.md.
##
## The output grammar is the Python client's, unchanged, because the harness is
## read by watchers that match exact line forms: the three-token
## `[<workload> <proto> <server>]` report prefix, the `final ` line, the
## `== <workload> <server> <proto> passed (...) ==` banner, `FAIL <workload>: ...`
## and the exit codes 0/1/2. The client is named by run.sh's cell banner and by
## the one `client: navi/<backend> <ref>` header line below -- never by a fourth
## token, which would break every existing grep.
##
## One source, two backends: `-d:useChronos` selects `navi/chronos`, otherwise
## `navi/asyncdispatch`. Both export `sleep(ms): Future[void]` and `waitFor`, so
## the only thing that needs a shim is starting a background helper
## (`fireAndForget` below).
##
## ADDING A WORKLOAD: write one `proc wX(st: State, conc: int,
## tag: string) {.async.}` in the workloads section and add one arm to the `case`
## in `runWorkload`. The shared scaffolding is already here -- `mkClient` (one
## pinned connection), `warmUp` (the h3 Alt-Svc leg), `pinCheck` (per-response
## version assertion), `driveLoop` (repeat-until-deadline with the transport-error
## wrap), `sampleStats`, the reporter, the loop-lag watchdog and the
## deadline+60 s stall net -- and the tallies, the payload catalogue, the
## deterministic generator and every line format live in `common.nim`.

import std/[strutils, tables]
import common

when defined(useChronos):
  import navi/chronos
else:
  import navi/asyncdispatch

# --- backend shim ------------------------------------------------------------

template fireAndForget(fut: untyped) =
  ## Start a background helper and never await it. The helpers self-stop at the
  ## deadline and the process exits as soon as the verdict is printed, so there
  ## is nothing to cancel; what differs between the backends is only the name of
  ## the "I am deliberately not awaiting this" marker. chronos's `asyncSpawn`
  ## raises a Defect if the future fails, which is why every helper body below
  ## catches its own errors and degrades to a WARN line instead.
  when defined(useChronos): asyncSpawn fut
  else: asyncCheck fut

proc awaitAll(futs: seq[Future[void]]) {.async.} =
  ## Wait for every future in `futs`, FIRST FAILURE WINS: the moment any one of
  ## them has failed, its error is raised here without waiting for the rest.
  ## That is `asyncio.gather`'s contract, and the one the Python canary relies
  ## on for "hard-fails on the first defect". Awaiting the futures one by one
  ## would not give it: a `Fail` raised inside a worker is stored in THAT
  ## worker's future, nothing in a worker calls `quit`, and a sequential loop
  ## parked on worker 0 only sees worker 5's echo mismatch when worker 0 itself
  ## returns -- at the deadline, hours later in a soak, during which the cell
  ## keeps hammering a server already known to be corrupting bodies. Worse, a
  ## later error in worker 0 would then be the one reported, and the real cause
  ## never printed.
  ##
  ## Polled rather than raced with the backend's `one`/`race`, which are spelled
  ## and typed differently on the two backends; 50 ms of latency on a clean
  ## finish is nothing next to a cell's seconds. The other futures are left to
  ## run: the process exits on the verdict, exactly as Python's does.
  while true:
    var pending = false
    for f in futs:
      if f.finished:
        if f.failed: raise f.error
      else:
        pending = true
    if not pending: return
    await sleep(50)

# --- client factory and the protocol pin -------------------------------------

proc mkClient(cfg: Config, totalMs = 60_000, readMs = 0): Navi =
  ## One navi client, configured like the Python canary's session so the two
  ## measure the same thing:
  ##
  ## * `http` pinned to exactly the cell's version. On h1/h2 navi enforces that
  ##   itself (a mismatch raises `ProtocolError`, which `driveLoop` reports as
  ##   the pin violation it is); on h3 the Alt-Svc discovery leg is exempted
  ##   internally, so there `warmUp` and `pinCheck` on every response are the
  ##   live checks.
  ## * verification off: the stress server's cert is self-signed, CN=localhost,
  ##   SAN `server` (`verify = false` in httpx terms; `tls.verify` is navi's
  ##   legacy inverse accessor for this field).
  ## * `throwHttpErrors = false`, so a non-2xx is a tally and a `Fail` with the
  ##   status in it, not an exception whose message hides the code.
  ## * retries OFF. navi retries 408/413/429/5xx by default, which would mask
  ##   exactly the failures this soak exists to catch: httpx has no retries, so
  ##   the Python canary fails on the first 503 and this must too.
  ## * redirects off, matching httpx's `follow_redirects=False`: a redirect from
  ##   a stress route is a defect, and following it would verify the wrong body.
  ## * `timeouts.total = totalMs` (60 s by default) bounds a whole exchange,
  ##   which for a buffered request is what the Python client's `timeout=60.0`
  ##   amounts to. It is NOT httpx's per-read idle budget: httpx restarts its
  ##   60 s on every chunk, navi's `total` is an absolute deadline that
  ##   `api.stream` carries onto the body reads. The SSE client therefore asks
  ##   for `readMs` (navi's per-read idle bound) and no total instead, so a
  ##   batch that keeps arriving slowly on a loaded host is not cut off at the
  ##   one-minute mark; the streaming workloads use `total` deliberately, as
  ##   their abandon mechanism, and the WebSocket opener uses it as its open
  ##   budget (see `wsOpenBudgetMs`).
  ## * navi's own h2 PING keepalive (20 s, `timeouts.h2KeepAlive`) stays on. It
  ##   has no httpx equivalent; a connection that answers no PING is exactly the
  ##   stall this soak hunts, so it is left as navi ships it.
  var nc = initNaviConfig()
  nc.http =
    case cfg.proto
    of "h1": {H1}
    of "h2": {H2}
    else: {H3}
  nc.tls.insecureSkipVerify = true
  nc.throwHttpErrors = false
  nc.maxRedirects = 0
  nc.retry.limit = 0
  nc.timeouts.total = totalMs
  nc.timeouts.read = readMs
  newNavi(nc)

proc q(s: string): string = "'" & s & "'"
  ## Quote a value inside a failure message, the way Python's `!r` does, so an
  ## empty or space-padded content-type is visible in the log.

proc pinCheck(st: State, res: Response) =
  ## Every response's negotiated version must equal the cell's protocol. A cell
  ## exists to exercise one protocol, so a silent fallback is a defect in its own
  ## right -- an `h2` run must never quietly measure h1. Same wording as
  ## transport.py's _pin_check so the two logs read identically.
  if res.httpVersion != st.cfg.expectVersion:
    raise newFail("protocol pin: negotiated " & res.httpVersion & ", want " &
      st.cfg.expectVersion & " (VORTEX_PROTO=" & st.cfg.proto &
      "); no fallback allowed")

proc warmUp(st: State, api: Navi) {.async.} =
  ## The h3 Alt-Svc discovery leg, run once per connection before the measured
  ## phase. navi reaches HTTP/3 by upgrading on an origin's `Alt-Svc: h3`, so the
  ## first request on a fresh client necessarily lands on h2 (that bootstrap is
  ## exempt from the `{H3}` pin); hit /plaintext until the version is the pinned
  ## one. Nothing to do on h1/h2, where ALPN settles it on the first request and
  ## `pinCheck` catches a downgrade.
  ##
  ## A connection that never upgrades fails the cell rather than silently
  ## measuring h2 under an h3 banner -- the same reason the per-response pin
  ## exists. The cap is deliberately small: the upgrade is one extra round trip,
  ## and a server that needs ten is already broken.
  if not st.cfg.isH3: return
  for _ in 0 ..< 5:
    let res = await api.request(GET, st.cfg.base & "/plaintext")
    if res.httpVersion == st.cfg.expectVersion: return
  raise newFail("protocol pin: never negotiated " & st.cfg.expectVersion &
    " on /plaintext (VORTEX_PROTO=" & st.cfg.proto &
    "); the server did not advertise Alt-Svc: h3")

template driveLoop(st: State, body: untyped) =
  ## Repeat `body` until the deadline. A transport or protocol error is a HARD
  ## failure: it is re-raised as a `Fail` at once so the run exits non-zero with
  ## its cause, instead of tallying an error count to sift through later.
  ##
  ## A template, not a proc taking a closure: it expands inside the caller's
  ## `{.async.}` body, so there is no closure for the chronos async transform to
  ## gcsafe-check and no per-iteration allocation. Everything a worker raises
  ## itself is already a `Fail`; anything else out of `api.request` came from
  ## navi, which is what makes the blanket wrap below accurate rather than lazy.
  while monoNow() < st.deadline:
    try:
      body
    except Fail as e:
      raise e
    except ProtocolError as e:
      # navi enforces the `config.http` pin itself on h1/h2 (a `{H2}` client
      # whose ALPN came back http/1.1 raises before any response exists), so
      # `pinCheck` never sees that case. Name it as the pin violation it is,
      # not as a network fault: a silent downgrade must read like one.
      raise newFail("protocol pin: " & e.msg)
    except CatchableError as e:
      raise newFail("transport error (" & $e.name & "): " & e.msg)

# --- /stats sampling, the reporter and the watchdogs -------------------------

proc sampleStats(st: State, totalMs: int): Future[(int, int, int)] {.async.} =
  ## One `(rss, heap, fds)` sample from /stats over a FRESH connection. Fresh on
  ## purpose: the Python client learned the hard way that a reporter holding one
  ## long-lived connection shares fate with that connection's handshake, and a
  ## perfectly healthy run then looks exactly like a server stall (zero report
  ## lines). The third field is tolerated as optional so this still works against
  ## an older two-field /stats.
  ##
  ## No pin check here: this is a measurement connection, not part of the soak,
  ## and on h3 it would have to pay the Alt-Svc leg again for a sample that is
  ## never verified. An unparseable or non-200 /stats raises, and the caller
  ## renders `n/a` rather than a misleading `0MB`.
  let api = mkClient(st.cfg, totalMs)
  var body = ""
  var status = 0
  var err = ""
  try:
    let res = await api.request(GET, st.cfg.base & "/stats")
    status = res.status
    body = res.body
  except CatchableError as e:
    err = $e.name & ": " & e.msg
  await api.close()
  if err.len > 0: raise newFail("/stats: " & err)
  if status != 200: raise newFail("/stats -> " & $status)
  let parts = body.splitWhitespace()
  if parts.len < 2: raise newFail("/stats unparseable: " & q(body))
  result = (parseInt(parts[0]), parseInt(parts[1]),
            if parts.len > 2: parseInt(parts[2]) else: -1)

proc segment(st: State, now: float): string =
  ## The throughput segment of a report line. The streaming workloads show
  ## cumulative bytes and MB/s, everything else the per-interval completion rate.
  ##
  ## `mixed` has no single unit to rate, so it lists every slice's
  ## own tally instead: a dead workload then shows as a zero in the line rather
  ## than disappearing into a healthy sum (see common.mixSegments).
  if st.cfg.isMixed: " | " & st.mixSegments(now, withDelta = true)
  elif st.cfg.streaming: st.fmtXfer(now)
  else: st.fmtRate(now)

proc reporter(st: State) {.async.} =
  ## Print a report line every VORTEX_REPORT_SECONDS, whatever /stats does. The
  ## line prints even when the sample failed, with `n/a` in the memory fields: a
  ## soak exists to watch RSS/heap/fds, so a regressed /stats must look broken
  ## rather than report a healthy zero footprint.
  try:
    while monoNow() < st.deadline:
      await sleep(st.cfg.report * 1000)
      # A sleep that ends on or past the deadline prints nothing: the `final `
      # line main prints covers that last interval, and an interval line here
      # would both duplicate its tally and leave the final line's rate at zero
      # (its window would be the few milliseconds between the two). Python's
      # reporter is cancelled at that moment, which is the same outcome.
      if monoNow() >= st.deadline or st.workersDone: break
      var rss = -1
      var heap = -1
      var fds = -1
      try:
        # Half the interval, as the Python client's `REPORT / 2`: a sample that
        # outlives its own report cadence is useless and would push every later
        # line late. No floor, or a 1 s cadence would hand the sample the whole
        # interval and do exactly that.
        let s = await sampleStats(st, st.cfg.report * 1000 div 2)
        rss = s[0]; heap = s[1]; fds = s[2]
      except CatchableError: discard
      st.reportLine("", rss, heap, fds, st.segment(monoNow()))
      emit st.selfLine()           # the client's own footprint; see selfLine
  except CatchableError as e:
    # A dead reporter is not itself a verdict, but it must not be silent: a
    # healthy soak and a dead reporter both print zero report lines, which is
    # exactly the confusion the fresh-connection comment above describes.
    emit "WARN reporter task died: " & $e.name & ": " & e.msg

proc loopWatchdog(st: State) {.async.} =
  ## Tell a client-side stall from a server-side one. A throughput counter frozen
  ## across every worker at once can mean the server stopped servicing us OR that
  ## this client's event loop was wedged (a blocking call, a GC pause) -- and a
  ## wedged loop cannot process packets, so it trips the peer's idle timeout and
  ## reads identically. A 1 s sleep that takes far longer means the loop was
  ## blocked; log the lag on stdout so the two cases stay separable after the
  ## fact (no WARN => the client loop stayed healthy, so the stall was the
  ## server's).
  var tick = 0
  try:
    while monoNow() < st.deadline:
      let t0 = monoNow()
      await sleep(1000)
      let lag = monoNow() - t0 - 1.0
      if lag > 2.0:
        emit "WARN client event-loop stalled " & formatFloat(lag, ffDecimal, 1) &
          "s (t=" & $int(t0 - st.start) & "s)"
      inc tick
      # An explicit ORC cycle collection every VORTEX_NAVI_COLLECT_SECONDS
      # (default 1). Not optional in practice: the runtime's own trigger is a
      # root-count threshold that GROWS by 1.5x every time a collection frees
      # less than half of what it touched (lib/system/orc.nim, collectCycles),
      # and in an async program the roots are mostly live futures, so every
      # collection looks "ineffective", the threshold climbs without bound and
      # the collector effectively stops. Measured on an `sse` h1 cell at ~16k
      # short streams a second: the live heap swung between 35 MB and 12.8 GB
      # and the container reached 15 GB RSS in 120 s, all of it collectable
      # (it was freed whenever a collection did run). A soak client cannot
      # leave that to an adaptive heuristic tuned for batch programs; one
      # collection a second bounds the garbage to one second of churn, and the
      # cost is a few milliseconds that the lag check above would report if it
      # ever grew.
      if st.cfg.collectEvery > 0 and tick mod st.cfg.collectEvery == 0:
        GC_runOrc()
  except CatchableError as e:
    emit "WARN loop_watchdog task died: " & $e.name & ": " & e.msg

proc stallNet(st: State) {.async.} =
  ## The `deadline + 60 s` safety net. A stall is exactly what this soak exists
  ## to catch (a peer flow-control deadlock, a stuck stream, a write-scheduler
  ## deadlock), so workers that do not stop by then are a FAILURE, not a warning:
  ## otherwise a hang reports as a pass once some early iterations happened to
  ## succeed. Polled once a second rather than slept through in one go, so a
  ## finished run is never held open by its own watchdog.
  try:
    while monoNow() < st.deadline + 60.0:
      if st.workersDone: return
      await sleep(1000)
    if st.workersDone: return
    emit "FAIL " & st.cfg.workload & ": workers did not stop within deadline+60s " &
      "(stall) (" & st.fmtCodes() & ")" & st.mixTail()
    quit(1)
  except CatchableError as e:
    emit "WARN stall_net task died: " & $e.name & ": " & e.msg

# --- workloads ---------------------------------------------------------------

type Prepared = object
  ## One catalogue entry, ready to send: the content-type as it must round-trip,
  ## the RAW (pre-compression) bytes the echo must return, the actual request
  ## body (compressed when VORTEX_REQ_COMPRESSION says so) and the headers.
  ctype: string
  raw: string
  body: string
  hdrs: Headers

proc prepare(cfg: Config): seq[Prepared] =
  ## Compress and header up the whole typed catalogue once per workload copy.
  ##
  ## `accept-encoding` is set EXPLICITLY per request, to the single codec
  ## VORTEX_RESP_COMPRESSION names, so the server compresses the response with
  ## the codec the cell is named after instead of picking from navi's default
  ## `gzip, deflate, br, zstd`. Confirmed against navi's request builder: that
  ## default is added only when the caller supplied no `accept-encoding`
  ## (core/request.nim), so a per-request header replaces it outright and the
  ## cell never silently measures a different codec.
  ##
  ## `content-type` is likewise sent verbatim and must come back verbatim,
  ## multipart boundary included. navi infers a content-type only from a TYPED
  ## body (a JsonNode, a Multipart, ...) and only when the caller set none; a raw
  ## `string` body infers nothing, so the catalogue's own boundary string is what
  ## goes on the wire rather than a navi-generated one.
  for entry in payloadMix():
    let (ctype, raw) = entry
    let (body, enc) = compressBody(cfg, raw)
    var h = initHeaders()
    h.add("content-type", ctype)
    if enc.len > 0: h.add("content-encoding", enc)
    if cfg.accept.len > 0: h.add("accept-encoding", cfg.accept)
    result.add Prepared(ctype: ctype, raw: raw, body: body, hdrs: h)

proc requestsOnce(st: State, prepared: seq[Prepared],
                  gets: seq[(string, string, string)], getHdrs: Headers,
                  tag: string) {.async.} =
  ## One worker: ONE connection (one `Navi`) held for the whole soak, exactly
  ## like the Python client's session-per-worker `once()`. Each iteration GETs
  ## the next typed route and asserts the status, the content-type and the exact
  ## body, then POSTs and PUTs the next catalogue body to /echo and asserts the
  ## echoed bytes are the RAW pre-compression ones and the echoed content-type is
  ## the sent one verbatim.
  ##
  ## The client is closed only on the clean path on purpose: a defect raises
  ## `Fail`, which ends the process with its verdict, so there is nothing left to
  ## reclaim and an `await` in a `finally` would only add a second failure mode
  ## at the exact moment the first one matters.
  let api = mkClient(st.cfg)
  await warmUp(st, api)
  var k = 0
  while monoNow() < st.deadline:
    # Cycle the typed GET routes, one per iteration, asserting the served
    # content-type and the exact body bytes.
    let (path, wantCt, wantBody) = gets[k mod gets.len]
    var res = await api.request(GET, st.cfg.base & path, headers = getHdrs)
    st.pinCheck(res)
    if res.status != 200:
      raise newFail("GET " & path & " -> " & $res.status)
    let ct = res.headers.get("content-type", "")
    if ct.toLowerAscii != wantCt.toLowerAscii:
      raise newFail("GET " & path & " content-type: want " & q(wantCt) &
        " got " & q(ct))
    if res.body != wantBody:
      raise newFail("GET " & path & " body " & $res.body.len & "B (want " &
        $wantBody.len & "B)")
    st.bump(200, tag)
    let p = prepared[k mod prepared.len]
    inc k
    for meth in [POST, PUT]:
      res = await api.request(meth, st.cfg.base & "/echo", headers = p.hdrs,
                              body = p.body)          # body: compressed
      st.pinCheck(res)
      if res.status != 200 or res.body != p.raw:
        raise newFail($meth & " /echo -> " & $res.status & ", " &
          $res.body.len & "B (want " & $p.raw.len & "B)")
      # Round-trip the content-type verbatim (do NOT strip params -- the
      # multipart boundary must survive); normalize case only.
      let ect = res.headers.get("content-type", "")
      if ect.toLowerAscii != p.ctype.toLowerAscii:
        raise newFail($meth & " /echo content-type: want " & q(p.ctype) &
          " got " & q(ect))
      st.bump(200, tag)
  await api.close()

proc requestsWorker(st: State, prepared: seq[Prepared],
                    gets: seq[(string, string, string)], getHdrs: Headers,
                    tag: string) {.async.} =
  driveLoop(st):
    await requestsOnce(st, prepared, gets, getHdrs, tag)

proc wRequests(st: State, conc: int, tag: string) {.async.} =
  ## The buffered GET/POST/PUT workload: `conc` workers, one connection each.
  ##
  ## A single fixed body only ever exercises one point on the curve; real traffic
  ## is a mix of content-types AND lengths -- text, JSON (object + array),
  ## urlencoded + multipart form data, binary, XML, CSV, HTML. The catalogue
  ## covers the 0-length / single-byte framing paths, the <1400 B no-compress
  ## threshold, the compressible >=1400 B branch per type, and the
  ## incompressible store-fallback (see common.payloadMix).
  let prepared = prepare(st.cfg)
  let gets = expectedGets()
  var getHdrs = initHeaders()
  if st.cfg.accept.len > 0: getHdrs.add("accept-encoding", st.cfg.accept)
  var futs: seq[Future[void]]
  for _ in 0 ..< conc:
    futs.add requestsWorker(st, prepared, gets, getHdrs, tag)
  await awaitAll(futs)          # first failure wins, as asyncio.gather does

# --- ws ----------------------------------------------------------------------

proc wsUrl(base: string): string =
  ## STRESS_BASE with its scheme swapped to the WebSocket one, plus /ws: the same
  ## string the Python canary builds. navi's `websocket` accepts http/https too,
  ## but spelling ws/wss here keeps the two clients' URLs identical in a log and
  ## makes the transports' TLS requirement explicit -- h1 Upgrade works either
  ## way, while the Extended CONNECT tunnels (h2 RFC 8441, h3 RFC 9220) are only
  ## reachable over `wss`.
  if base.startsWith("https://"): "wss://" & base["https://".len .. ^1] & "/ws"
  elif base.startsWith("http://"): "ws://" & base["http://".len .. ^1] & "/ws"
  else: base & "/ws"

# The opening-handshake budget and the burst shaping, ported from the Python
# canary's WS_OPEN_TIMEOUT / WS_RAMP with the same arithmetic. The reasoning is
# the host's, not the client's, so it applies unchanged to a compiled client:
#
# every worker would otherwise open its socket at t=0, so a cell slams
# CLIENTS*CONC (96 by default) simultaneous handshakes at the server. The server
# accepts and upgrades each on whichever SO_REUSEPORT loop thread the kernel
# hashed it to, and these soaks are run deliberately oversubscribed (several
# cells in parallel, host load 20-50), where a single loop thread can be
# descheduled for seconds -- measured: TCP connect stayed under 0.15 s while the
# upgrade for the connections hashed to one starved thread waited 1-5 s, all
# released together the moment that thread was scheduled again. A 10 s opener
# timeout failed an otherwise healthy soak inside its first minute, with a server
# that went on to echo tens of thousands of messages a second for the rest of the
# hour.
#
# So: scale the budget with the burst size, floor it far above the worst case
# observed, and spread the initial handshakes over a few seconds instead of
# opening all of them in one instant. The soak then measures steady state, which
# is what it exists to measure; a genuinely wedged upgrade still fails the cell,
# just on a timescale that means something.

proc wsRampDelay(seconds, i, conc: int): float =
  ## How long worker `i` of `conc` waits before its FIRST handshake (0 when there
  ## is no burst to spread). `conc` is the size of the burst, which is the whole
  ## cell for a `ws` soak and only the ws slice under `mixed`, exactly as the
  ## Python client's ws_ramp_delay takes it. The ramp is capped at 5 s and scales
  ## down with VORTEX_SECONDS so it can never eat a short smoke run.
  let ramp = min(5.0, max(0.0, float(seconds) / 10.0))
  if conc > 1: ramp * float(i) / float(conc) else: 0.0

proc wsOpenBudgetMs(cfg: Config): int =
  ## The opener budget in ms: max(60 s, 0.5 s per socket in the cell).
  ##
  ## This is handed to `mkClient` as the navi TOTAL timeout, which is the right
  ## field for it only because of where navi applies it: `websocket` wraps the
  ## whole OPEN (connect, TLS, the h1 Upgrade exchange or the h2/h3 Extended
  ## CONNECT stream) in one `guard(config.totalMs, ...)` and then hands back a
  ## `WebSocket` that owns the transport outright. The echo loop's
  ## `send`/`receive` go straight to that transport and are NOT bounded by the
  ## total budget, so an hour-long soak is not cut off after its first minute --
  ## the mistake a `request`-shaped reading of `timeouts.total` would make here.
  ## (`timeouts.read` stays at navi's default of off, so a `receive` parks until
  ## the server answers; a server that never answers is caught by the
  ## deadline+60 s stall net, which is the check that exists for it.)
  int(max(60.0, 0.5 * float(cfg.clients) * float(cfg.conc)) * 1000.0)

proc wsOnce(st: State, i: int, tag: string) {.async.} =
  ## One worker: ONE WebSocket held for the whole soak, echoing `msg-<i>-<n>` and
  ## byte-comparing every reply, as the Python canary's `once(i)` does.
  ##
  ## The transport is chosen by the `config.http` pin `mkClient` applies, so the
  ## three protos exercise three different handshakes against the same /ws route
  ## and the same echo contract: h1 is the RFC 6455 Upgrade, h2 is Extended
  ## CONNECT with `:protocol=websocket` (RFC 8441) and h3 is the same over QUIC
  ## (RFC 9220, dialled directly -- a WebSocket has no Alt-Svc leg, so `warmUp`
  ## has nothing to do here and is deliberately not called). navi raises when the
  ## pinned transport cannot be used (an h2 cell whose ALPN came back http/1.1,
  ## an h3 cell on a build without -d:naviHttp3) and when the server rejects the
  ## handshake, and `driveLoop` turns either into a hard failure: a cell that
  ## cannot open its socket must fail, not quietly tally nothing.
  let api = mkClient(st.cfg, wsOpenBudgetMs(st.cfg))
  let ws = await api.websocket(wsUrl(st.cfg.base))
  var n = 0
  while monoNow() < st.deadline:
    let msg = "msg-" & $i & "-" & $n
    await ws.send(msg)
    let rep = await ws.receive()
    if rep.kind == wmClose:
      # A peer close is how a socket ends as the soak winds down (the server is
      # being torn down, or it answered a close of ours), so past the deadline it
      # is the normal end of the worker. Before the deadline it is the server
      # dropping a healthy connection mid-echo, which is exactly the defect this
      # cell exists to catch.
      if monoNow() >= st.deadline: break
      raise newFail("ws echo mismatch: peer closed (code " & $rep.closeCode &
        ") after " & $n & " round trips")
    if rep.kind != wmText or rep.data != msg:
      # Text in, text out, byte for byte: a binary reply, a truncated one, or one
      # carrying another worker's message all mean the echo is not an echo.
      raise newFail("ws echo mismatch: kind=" & $rep.kind & " " &
        $rep.data.len & "B " & q(rep.data) & " (want " & q(msg) & ")")
    st.bump(200, tag)
    inc n
  await ws.close()
  await api.close()

proc wsWorker(st: State, i, conc: int, tag: string) {.async.} =
  let d = wsRampDelay(st.cfg.seconds, i, conc)
  if d > 0: await sleep(int(d * 1000.0))
  driveLoop(st):
    await wsOnce(st, i, tag)

proc wWs(st: State, conc: int, tag: string) {.async.} =
  ## The WebSocket echo workload: `conc` workers, one socket each, their
  ## handshakes staggered over the ramp. Every round trip is one verified
  ## `messages` tally.
  var futs: seq[Future[void]]
  for i in 0 ..< conc:
    futs.add wsWorker(st, i, conc, tag)
  await awaitAll(futs)

# --- sse ---------------------------------------------------------------------

const
  sseTotal = 100   ## must match stress_server.nim's sseTotal
  sseBatch = 20    ## must match stress_server.nim's sseBatch: events per
                   ## connection before the server closes and the client resumes

type SseGate = ref object
  ## The per-stream version pin for SSE, strict on every stream.
  ##
  ## navi reaches h3 by learning `Alt-Svc: h3` from an h2/h1 response, and that
  ## cache lives on the `Navi` that learned it, so a cold client starts on h2
  ## however hard `config.http` is pinned. `warmUp` primes the cache on each
  ## worker's client before the first stream and RAISES unless h3 was actually
  ## reached, so by the time a stream is opened h2 is no longer a bootstrap, it
  ## is a fallback -- and a fallback is a pin violation, exactly as the Python
  ## client's per-response check treats it. (navi's own `VersionGate` tolerates
  ## h2 until the first h3 stream because its harness has no warm-up; this one
  ## does.) `sawExpected` only backs the belt in `sseWorker` that a worker which
  ## never negotiated the pinned version fails the cell.
  sawExpected: bool

proc gateSample(g: SseGate, st: State, got: string) =
  if got.len == 0: return
  if got == st.cfg.expectVersion:
    g.sawExpected = true
  else:
    raise newFail("protocol pin: /sse negotiated " & got & ", want " &
      st.cfg.expectVersion & " (VORTEX_PROTO=" & st.cfg.proto &
      "); no fallback allowed")

proc sseConnection(st: State, api: Navi, g: SseGate, tag: string,
                   got0, last0: int): Future[(int, int)] {.async.} =
  ## ONE connection of a sequence: resume at `last0` (-1 for a fresh sequence),
  ## verify and count the batch the server delivers before it closes, and return
  ## the new `(got, last)`.
  ##
  ## This drives `api.stream` and parses the `text/event-stream` framing by hand
  ## rather than using navi's `api.sse`, the one place this client deliberately
  ## reaches below a navi convenience. Three reasons, in order:
  ##
  ##  1. `api.sse` reconnects transparently, and the batch boundary is the whole
  ##     point of this cell: the server closes after every `sseBatch` events and
  ##     must resume at `Last-Event-ID + 1`. A transparent reconnect hides the
  ##     boundary (so a server that truncated a batch to one event would still
  ##     look in-order and healthy) and, past event 99, spins on the empty stream
  ##     the server returns for an exhausted sequence. `reconnect = false` fixes
  ##     both of those but neither 2 nor 3.
  ##  2. `api.sse` builds its OWN `Navi` internally (`newNavi(client.config)`),
  ##     with its own pool and -- on an h3 build -- its own cold Alt-Svc cache. So
  ##     a stream opened with `reconnect = false` can never be h3 at all: the
  ##     first request on a cold cache goes out on h2 and there is no reconnect to
  ##     upgrade on, and the h3 cell would only ever measure h2. Nothing a caller
  ##     can pass fixes it; the cache is not reachable from outside (nim-navi
  ##     #466).
  ##  3. Each `api.sse` call is therefore also a fresh pool and a fresh TLS
  ##     handshake, five connects per 100-event sequence: the connect churn #145
  ##     took out of this cell.
  ##
  ## Driving `api.stream` on the worker's own warmed-up client fixes all three at
  ## once, and is what the Python canary does too (`s.stream("GET", "/sse", hdrs)`
  ## plus its own `read_lines`), so both clients verify the same framing from the
  ## same vantage point. The parser is small because the contract is small: the
  ## server emits exactly `id: <n>`, then `data: event <n>`, then a blank line.
  var h = initHeaders()
  h.add("accept", "text/event-stream")
  if last0 >= 0: h.add("last-event-id", $last0)
  # accept-encoding is deliberately left to navi's default (which navi then
  # decodes transparently), matching the Python client: httpx auto-negotiates it
  # here too and this cell verifies the logical framing, not the codec. The codec
  # under test is pinned on the `requests` cell, which is where it is the subject.
  let sr = await api.stream(GET, st.cfg.base & "/sse", h)
  g.gateSample(st, sr.httpVersion)
  if sr.status != 200:
    await sr.close()
    raise newFail("sse status " & $sr.status)
  var got = got0
  var last = last0
  var thisBatch = 0
  var buf = ""
  var curId = -1
  var ended = false
  while not ended:
    let chunk = await sr.readChunk()
    if chunk.len == 0: ended = true     # body complete: the server closed the batch
    else: buf.add chunk
    var pos = 0
    while true:
      let nl = buf.find('\n', pos)
      if nl < 0: break                  # a partial trailing line waits for the next chunk
      var line = buf[pos ..< nl]
      pos = nl + 1
      if line.len > 0 and line[^1] == '\r': line.setLen(line.len - 1)
      if line.startsWith("id:"):
        try: curId = parseInt(line[3 .. ^1].strip())
        except ValueError:
          raise newFail("sse non-numeric id " & q(line))
      elif line.startsWith("data:") and curId >= 0:
        # The id is checked against the running count, not merely against the
        # previous id: that is what proves a resume landed on exactly
        # `Last-Event-ID + 1` rather than one event to either side of it.
        if curId != got:
          raise newFail("sse out of order: " & $curId & " != " & $got)
        inc got
        last = curId
        curId = -1
        inc thisBatch
        st.bump(200, tag)
    if pos > 0: buf = buf[pos .. ^1]
  # Closed here, after the body ended, never mid-read: closing a stream with a
  # read still parked orphans that read's future and crashes the dispatcher at
  # teardown (navi's own SSE worker carries the same note). A fully drained handle
  # is already finished, so this is the idempotent no-op that keeps the error
  # paths above -- which DO close mid-read, and then fail the run -- honest.
  await sr.close()
  if thisBatch == 0:
    # A connection that answered 200 and then delivered nothing is a stall, and
    # without this the sequence loop would reopen against it forever.
    raise newFail("sse made no progress")
  if got < sseTotal and thisBatch != sseBatch:
    # Every connection but the last must deliver a FULL batch before the server
    # closes. A server that truncates batches (closing after one event, say)
    # still makes in-order progress, so without this check the documented
    # close-then-resume behaviour goes unverified.
    raise newFail("sse short batch: " & $thisBatch & " events before close (want " &
      $sseBatch & "), got=" & $got)
  result = (got, last)

proc sseWorker(st: State, tag: string) {.async.} =
  ## One worker: ONE client held for the whole soak, running 100-event sequences
  ## back to back until the deadline. A sequence is `sseTotal` events read across
  ## `sseTotal div sseBatch` connections, each resuming where the last was cut.
  ##
  ## The Python client reopens its session every `seqs_per_conn = 2000` sequences.
  ## That constant is NOT ported: it works around httpx's h2 stack, which
  ## accumulates per-stream state and drops the connection after ~65k SSE streams
  ## (vortex itself serves 300k+, confirmed with h2load). navi has no such limit,
  ## so this worker never reopens -- which also means an h3 worker pays the
  ## Alt-Svc leg exactly once. Add a reopen here only if a navi equivalent of that
  ## limit is ever actually measured.
  # No total deadline, a 60 s per-read idle bound instead (see mkClient): a
  # 20-event batch that keeps arriving slowly must not be cut off at a minute.
  let api = mkClient(st.cfg, totalMs = 0, readMs = 60_000)
  await warmUp(st, api)
  let g = SseGate()
  driveLoop(st):
    var got = 0
    var last = -1
    # No deadline check inside a sequence, matching the Python client: a sequence
    # is ~100 events over five short connections, and finishing the one in flight
    # keeps the batch checks above meaningful instead of reporting a deliberately
    # truncated last batch as a defect.
    while got < sseTotal:
      let r = await sseConnection(st, api, g, tag, got, last)
      got = r[0]
      last = r[1]
  if not g.sawExpected:
    raise newFail("protocol pin: never negotiated " & st.cfg.expectVersion &
      " on /sse over the whole run (VORTEX_PROTO=" & st.cfg.proto & ")")
  await api.close()

proc wSse(st: State, conc: int, tag: string) {.async.} =
  ## The Server-Sent Events workload: `conc` workers, one client each, every
  ## verified event one `events` tally.
  var futs: seq[Future[void]]
  for _ in 0 ..< conc:
    futs.add sseWorker(st, tag)
  await awaitAll(futs)

# --- streaming and mixed workloads -------------------------------------------

const streamSlackMs = 2_000
  ## How far PAST the cell's own deadline a transfer's navi total timeout is set.
  ##
  ## Each transfer is bounded by the time left in the run, because a worker here
  ## is one whole transfer in flight and the loop can only check the deadline
  ## BETWEEN transfers: one 1 GiB transfer runs minutes, far past the
  ## deadline+60 s stall net, which was sized for workloads that stop within one
  ## request. The slack exists so the expiry is unambiguously past the deadline
  ## when it fires: the cancellation path's error is accepted ONLY past the
  ## deadline (#390's lesson -- before it, the very same exception is a real
  ## defect and must still fail the cell), and a timeout landing a millisecond
  ## EARLY would be read as that defect. Two seconds is far below the 60 s net.

proc timeLeftMs(st: State): int =
  ## Milliseconds left in the run, floored at 0.
  max(0, int((st.deadline - monoNow()) * 1000.0))

proc mkUploadClient(st: State): Navi =
  ## One client for one UPLOAD, with a total timeout of the time LEFT in the run
  ## plus the slack above -- not `mkClient`'s 60 s default, which would abandon
  ## a healthy 1 GiB h3 transfer as a timeout at the one minute mark and report
  ## a sizing accident as a server stall. An upload is one `await` on one
  ## request, so a timer is the only way to bound it by the deadline.
  ##
  ## A client per transfer, not per worker, matching the Python canary's
  ## `async with session()` inside its transfer: the cell is meant to measure
  ## connections opened per transfer, and abandoning a transfer at the deadline
  ## has to tear the connection down with the request still in flight. The cost
  ## on h3 is one extra Alt-Svc discovery leg per transfer (navi reaches h3 by
  ## upgrading on an origin's `Alt-Svc`, and a fresh `Navi` has not learned it
  ## yet), which is noise next to a multi-megabyte body.
  mkClient(st.cfg, st.timeLeftMs() + streamSlackMs)

proc mkDownloadClient(st: State): Navi =
  ## One client for one DOWNLOAD, with NO total timeout. The download loop checks
  ## the deadline on every chunk and abandons the transfer itself (closing the
  ## stream resets it), so a timer would add nothing to the abandon path, and a
  ## stream that stops delivering chunks is the stall net's to catch.
  ##
  ## Not having the timer also matters for memory, which is why this is a
  ## separate factory rather than a flag. On navi's asyncdispatch backend the
  ## total-timeout guard races the request against `sleepAsync(totalMs)` and
  ## never clears the timer when the request wins, so a completed request stays
  ## reachable -- `Response`, body, stream buffers -- until the timer fires
  ## (nim-navi #468). With the timer set to the time left in the run, every
  ## download's buffers were pinned until the END of the run: measured ~1.1 MB
  ## per 64 MiB transfer retained, 87 -> 543 MB of live heap over a 120 s cell,
  ## and a 30-minute mixed soak OOM-killed at t=529 s with the server flat at
  ## 114 MB. The chronos backend cancels its timer and did not show it, which is
  ## why chronos is the default backend; an asyncdispatch build still pins the
  ## upload client's small request state and the 60 s `requests` client's
  ## responses for their timer windows (a plateau, not a leak), visible on the
  ## `client:` footprint line.
  mkClient(st.cfg, totalMs = 0)

proc pinCheck(st: State, sr: StreamResponse) =
  ## The protocol pin for a STREAMING response. Same check and same wording as
  ## the buffered overload above; a `StreamResponse` is a separate type because
  ## its body is still in flight when its status and headers are already here,
  ## so it cannot simply be passed to that one.
  if sr.httpVersion != st.cfg.expectVersion:
    raise newFail("protocol pin: negotiated " & sr.httpVersion & ", want " &
      st.cfg.expectVersion & " (VORTEX_PROTO=" & st.cfg.proto &
      "); no fallback allowed")

proc uploadProbe(st: State) {.async.} =
  ## The negative probe, once per workload copy: a few-KB body carrying a
  ## deliberately wrong `x-sha1` must be REJECTED with 400.
  ##
  ## The happy path only ever asserts the server's 200, so a server that
  ## returned 200 unconditionally -- a dropped or short-circuited SHA compare --
  ## would pass every upload cell silently. Cheap on purpose: 4 KiB, not the
  ## whole VORTEX_STREAM_BYTES, and streamed through a `BodyProducer` like the
  ## real thing so it exercises the same request path.
  ##
  ## Not tallied either way. A 400 here is the correct answer, and counting it
  ## would put a `400x3` in every upload cell's codes, which is exactly what a
  ## reader scans that field for.
  let api = mkUploadClient(st)
  await warmUp(st, api)
  var sent = false
  var h = initHeaders()
  h.add("x-sha1", repeat('0', 40))
  h.add("content-type", "application/octet-stream")
  let res = await api.request(POST, st.cfg.base & "/upload", headers = h,
    body = BodyProducer(proc(): string =
      if sent: return ""          # "" is end of body
      sent = true
      genChunk(0, 4096)))
  st.pinCheck(res)
  await api.close()
  if res.status != 400:
    raise newFail("upload negative probe: wrong x-sha1 accepted -> " &
      $res.status)

proc uploadWorker(st: State, tag, sha: string) {.async.} =
  ## One whole transfer per iteration, so a worker here IS a transfer in flight.
  ##
  ## The body is streamed by a `BodyProducer` handing over 64 KiB chunks of the
  ## deterministic generator, and the bytes are counted AS THEY ARE HANDED OVER:
  ## navi pulls the next chunk only when it can send the current one (bounded by
  ## the socket, the h2 window or the QUIC flow-control credit), so yielded is
  ## sent and the live upload rate is accurate on all three protocols. That is
  ## the one place this client is strictly better than the Python canary, where
  ## aioquic buffers the whole body up front and the h3 arm has to count on
  ## completion instead -- which is why `noProgress` here has no "undecidable"
  ## case to report.
  ##
  ## Deadline handling, in the order it matters:
  ##
  ## * Do not START a transfer that cannot finish. Once this worker has
  ##   completed one, it knows its own slowest, and sitting out the tail of the
  ##   run is cheaper than tearing down a transfer at the deadline. Per worker,
  ##   not per cell: a slice of several workers (under `mixed`) must not inherit
  ##   another worker's timing.
  ## * The FIRST transfer has nothing to learn from, and a loaded host can make
  ##   any transfer slower than every one before it, so the deadline can still
  ##   land mid-upload. Then the navi total timeout fires (see `streamSlackMs`),
  ##   the client is closed -- which tears the connection down with the request
  ##   still in flight -- and the transfer is tallied as `abandoned`: never
  ##   verified, never counted. Truncating the producer instead would send a
  ##   short body and trip the 400 check below as if the server were at fault.
  ## * Whatever that teardown raises is accepted ONLY past the deadline. Before
  ##   it, the same exception is a real transport defect and still fails the cell
  ##   (#390 on the Python side was exactly this arm, too wide).
  var slowest = 0.0
  while monoNow() < st.deadline:
    let left = st.deadline - monoNow()
    if slowest > 0.0 and left < slowest:
      # Sleep out the tail rather than spinning the loop: the worker is done.
      await sleep(max(0, int(left * 1000.0)) + 50)
      return
    let api = mkUploadClient(st)
    var off = 0
    let t0 = monoNow()
    try:
      await warmUp(st, api)
      var h = initHeaders()
      h.add("x-sha1", sha)
      h.add("content-type", "application/octet-stream")
      let res = await api.request(POST, st.cfg.base & "/upload", headers = h,
        body = BodyProducer(proc(): string =
          if off >= st.cfg.streamBytes: return ""     # "" is end of body
          let n = min(chunkSize, st.cfg.streamBytes - off)
          result = genChunk(off, n)
          off += n
          st.addXfer(n, tag)))
      st.pinCheck(res)
      if res.status == 400: raise newFail("server rejected the SHA-1 (400)")
      if res.status != 200: raise newFail("upload -> " & $res.status)
      st.bump(200, tag)
      slowest = max(slowest, monoNow() - t0)
    except Fail as e:
      raise e
    except ProtocolError as e:
      raise newFail("protocol pin: " & e.msg)   # see driveLoop
    except CatchableError as e:
      if monoNow() < st.deadline:
        raise newFail("transport error (" & $e.name & "): " & e.msg)
      st.abandon(tag)
    # Closed even on the abandon path, and that is the point: it is what resets
    # the stream. A failure here is never the verdict (a real defect already
    # raised above), so it must not replace one.
    try: await api.close()
    except CatchableError: discard

proc wStreamUpload(st: State, conc: int, tag: string) {.async.} =
  ## The streamed-upload workload. `conc` is 1 for a dedicated soak -- its
  ## parallelism comes from VORTEX_CLIENTS, since one worker is one whole
  ## transfer in flight -- and the slice's share under `mixed`.
  # The digest of the whole stream, before the probe so the loop pays for it
  # once and up front: the server hashes what it received and answers 400 on a
  # mismatch, so this header is the entire verification of an upload. Memoised
  # on the State, and that matters -- see common.streamDigest for the 26-of-30
  # seconds this used to cost a 1 GiB cell.
  let sha = st.streamDigest()
  await uploadProbe(st)
  var futs: seq[Future[void]]
  for _ in 0 ..< conc:
    futs.add uploadWorker(st, tag, sha)
  await awaitAll(futs)

proc downloadWorker(st: State, tag, want: string) {.async.} =
  ## One whole transfer per iteration, drained in chunks and never buffered: each
  ## chunk is hashed, counted and discarded, so a 1 GiB transfer costs one chunk
  ## of memory.
  ##
  ## The deadline is checked PER CHUNK, not per transfer. The streaming workloads
  ## are the only ones whose unit of work is a whole transfer, and one big
  ## transfer over h3 on a loaded host runs minutes -- far past the deadline+60 s
  ## stall net, which was sized for workloads that stop within one request. So
  ## the last transfer of a soak overran it and a clean run reported as a
  ## "stall". An in-flight transfer is abandoned at the deadline instead: the
  ## body is left undrained, closing the handle resets the stream, and the
  ## transfer is neither verified nor counted. This does not blunt the stall
  ## detector -- a genuinely wedged stream delivers no chunk at all, so it never
  ## reaches the check and the stall net still catches it.
  ##
  ## The server sends no `x-sha1` for /download (that is navi's own server
  ## contract, not vortex's), so `want` is computed client-side from the
  ## generator and the length is verified alongside it: a truncated body with a
  ## matching prefix must not pass.
  while monoNow() < st.deadline:
    let api = mkDownloadClient(st)
    try:
      await warmUp(st, api)
      let sr = await api.stream(GET, st.cfg.base & "/download")
      st.pinCheck(sr)
      if sr.status != 200:
        raise newFail("download status " & $sr.status)
      var d = initDigest()
      var got = 0
      var dropped = false
      while true:
        let chunk = await sr.readChunk()
        if chunk.len == 0: break           # end of body
        d.update(chunk)
        got += chunk.len
        st.addXfer(chunk.len, tag)
        if monoNow() >= st.deadline:
          dropped = true
          break
      if dropped:
        # Tallied BEFORE the teardown, so a close that itself raises cannot send
        # this transfer through the handler below and count one abandonment as
        # two -- the `no transfer ... (N abandoned)` diagnosis then overstates N
        # on the only line a reader has to go on.
        st.abandon(tag)
        try: await sr.close()
        except CatchableError: discard
      else:
        let dig = d.hex()
        if got != st.cfg.streamBytes or dig != want:
          raise newFail("download mismatch: " & $got & " bytes, sha " & dig &
            " != " & want)
        st.bump(200, tag)
    except Fail as e:
      raise e
    except ProtocolError as e:
      raise newFail("protocol pin: " & e.msg)   # see driveLoop
    except CatchableError as e:
      # Accepted only past the deadline, exactly as in the upload worker: before
      # it, a read error or a timeout is a real defect and fails the cell.
      if monoNow() < st.deadline:
        raise newFail("transport error (" & $e.name & "): " & e.msg)
      st.abandon(tag)
    try: await api.close()
    except CatchableError: discard

proc wStreamDownload(st: State, conc: int, tag: string) {.async.} =
  ## The streamed-download workload. `conc` is 1 for a dedicated soak (see
  ## `wStreamUpload`), the slice's share under `mixed`.
  let want = st.streamDigest()      # memoised; see common.streamDigest
  var futs: seq[Future[void]]
  for _ in 0 ..< conc:
    futs.add downloadWorker(st, tag, want)
  await awaitAll(futs)

# `wMixed` fans out through `runWorkload`, which is defined below it (it needs
# every workload in scope), so it is forward-declared here. Going through the
# dispatcher rather than naming the five procs is deliberate: a slice runs the
# UNCHANGED single-workload proc, and that is the one place that decides which.
#
# The effect pragma is NOT decoration. A forward declaration carries no inferred
# effects, so the compiler assumes the worst -- `raises: [Exception]` and not
# gcsafe -- and chronos's async transform, which effect-checks the coroutine body
# it generates, then refuses `wMixed` twice over ("can raise an unlisted
# exception: Exception", "not GC-safe as it calls runWorkload"). So the claim has
# to be made explicitly, and it has to differ per backend: a chronos `{.async.}`
# proc has a bounded raises list, while an asyncdispatch one is `raises:
# [Exception]` by construction, so pinning `raises: [CatchableError]` under
# asyncdispatch breaks that build instead. One pragma alias, two definitions, and
# the two sites below (declaration and definition, as Nim requires) stay in step.
when defined(useChronos):
  {.pragma: dispatcher, gcsafe, raises: [CatchableError].}
else:
  {.pragma: dispatcher, gcsafe.}

proc runWorkload(st: State, conc: int, tag: string): Future[void] {.dispatcher.}

proc wMixed(st: State, conc: int, tag: string) {.async.} =
  ## Every workload in the mix at one server, concurrently.
  ##
  ## One slice per workload, each the UNCHANGED single-workload proc handed its
  ## share of this client's worker budget and its OWN tag, so the counters, the
  ## report segment and the per-slice progress check all see the workload that
  ## earned each completion instead of the sum. `main` runs VORTEX_CLIENTS copies
  ## of this, so the cell splits exactly CLIENTS x CONCURRENCY workers: a `mixed`
  ## cell is not a five-times-heavier cell.
  ##
  ## `conc` is unused here and that is not an oversight: the split was resolved
  ## once in `main` (`splitMix(cfg.conc, parseMix(cfg.mix))`) so a malformed
  ## VORTEX_MIX is a config error before anything connects, and every copy must
  ## fan out the same way.
  ##
  ## Connections are per worker and per transfer exactly as in the dedicated
  ## soaks -- the streaming slices open their own client per transfer, the
  ## request slice holds one per worker -- so this is all of them at one SERVER,
  ## not down one connection. That is both the existing behaviour and the more
  ## interesting case (#394).
  var futs: seq[Future[void]]
  for (slice, n) in st.slices:
    futs.add runWorkload(st, n, slice)
  await awaitAll(futs)

const knownWorkloads = [
  "requests",
  "ws",
  "sse",
  "streamupload",
  "streamdownload",
  "mixed",
]
  ## Every workload this binary can run; anything else is a config error
  ## (exit 2), checked in `main` before a connection is opened or a catalogue
  ## built. One name per line, in `runWorkload`'s own order, so adding a
  ## workload is a one-line diff here and a one-line diff there.

proc runWorkload(st: State, conc: int, tag: string): Future[void]
    {.dispatcher.} =
  ## Dispatch on VORTEX_WORKLOAD: `conc` workers under the tally tag `tag` (the
  ## workload's own name for a single-workload cell, the slice's name under
  ## `mixed`). One `case` arm per workload, so adding one is a two-line change.
  ##
  ## The `gcsafe` here is ASSERTED, not proven, and the cast below is what pays
  ## for it. The forward declaration above has to claim gcsafe or chronos
  ## refuses `wMixed` (see the note there), but navi's own asyncdispatch
  ## internals are GcUnsafe -- its dispatcher is a global -- so claiming it
  ## without the cast breaks the asyncdispatch build instead. The claim is true
  ## in the only sense that matters here: this binary runs one event loop on one
  ## thread (--threads:on is navi's build requirement, not a thread pool), and
  ## every piece of mutable state a workload touches hangs off the `State` ref
  ## that is passed in, never off a global.
  {.cast(gcsafe).}:
    # On `tag`, NOT on cfg.workload: for the five single-workload
    # cells the two are the same string, but a `mixed` cell asks this for each
    # slice by name, which is what lets a slice run the unchanged workload proc.
    case tag
    of "requests": result = wRequests(st, conc, tag)
    of "ws": result = wWs(st, conc, tag)
    of "sse": result = wSse(st, conc, tag)
    of "streamupload": result = wStreamUpload(st, conc, tag)
    of "streamdownload": result = wStreamDownload(st, conc, tag)
    of "mixed": result = wMixed(st, conc, tag)
    else: raise newFail("unknown VORTEX_WORKLOAD: " & tag)

# --- main --------------------------------------------------------------------

proc workersPerClient(cfg: Config): int =
  ## How many workers ONE copy of the workload fans out, i.e. the Python
  ## client's per-workload default for `conc`.
  ##
  ## It is VORTEX_CONCURRENCY for every workload but the two streaming ones,
  ## where it is 1: a worker there is one WHOLE transfer in flight, so 32 of them
  ## per client would put 96 concurrent multi-megabyte transfers on the wire at
  ## the default 3x32 and the cell would measure 96-way contention rather than
  ## the transfer. Those soaks take their parallelism from VORTEX_CLIENTS
  ## instead. Measured before this was right: a 10 s h3 upload cell moved 4.1 GB
  ## and completed NOTHING, because all 96 transfers were still in flight at the
  ## deadline and every one of them was abandoned.
  ##
  ## `mixFixed` is the same pair for the same reason -- a mixed slice of these
  ## two is pinned at one worker per client -- so the list is shared rather than
  ## written twice.
  if cfg.workload in mixFixed: 1 else: cfg.conc

proc main() {.async.} =
  let cfg = loadConfig()
  let st = newState(cfg)
  # One header line names the client under measurement. The report prefix
  # deliberately stays three tokens (watcher compatibility), so this line and
  # run.sh's cell banner are what identify a navi run in an archived log.
  emit "client: navi/" & backendName & " " & naviRef
  if cfg.workload notin knownWorkloads:
    # Same message and exit code as the Python client's, so `nimble stress`
    # reads the same either way.
    emit "unknown VORTEX_WORKLOAD: " & cfg.workload
    quit(2)
  if cfg.isMixed:
    # Resolved HERE, before a connection is opened or a catalogue built, so a
    # malformed VORTEX_MIX or a VORTEX_CONCURRENCY below the slice count is a
    # config error (exit 2) rather than a cell that dies mid-flight. Once, not
    # per copy: every copy of the workload must fan out the same way.
    st.slices = splitMix(cfg.conc, parseMix(cfg.mix))
  # The whole-stream digest, BEFORE the clocks start and before the loop-lag
  # watchdog exists. It is a synchronous pure-Nim SHA-1 over VORTEX_STREAM_BYTES
  # (~4 s for 1 GiB) with the event loop blocked; computed inside the measured
  # window it opened every 1 GiB streaming cell with a spurious `WARN client
  # event-loop stalled` at t=0, the one line that exists to tell a client stall
  # from a server stall, and under `mixed` it delayed every other slice's
  # fan-out by that much. Memoised on the State, so the workers pay nothing.
  var needsDigest = cfg.streaming
  for (slice, _) in st.slices:
    if slice in mixFixed: needsDigest = true
  if needsDigest: discard st.streamDigest()
  st.start = monoNow()
  st.rateAt = st.start
  st.opsAt = st.start
  st.mixAt = st.start
  st.deadline = st.start + float(cfg.seconds)
  fireAndForget reporter(st)
  fireAndForget loopWatchdog(st)
  fireAndForget stallNet(st)
  try:
    # CLIENTS copies of the workload, each fanning out CONCURRENCY workers with
    # one connection per worker: the shape the Python canary measures today.
    var futs: seq[Future[void]]
    for _ in 0 ..< cfg.clients:
      futs.add runWorkload(st, workersPerClient(cfg), cfg.workload)
    await awaitAll(futs)
  except Fail as e:
    # The cause must land on STDOUT next to the verdict lines, not on stderr: the
    # harness is driven as `nimble stress | tee stress.log`, which tees stdout
    # only, so a cause on stderr is lost and the cell shows a bare
    # `FAILED (exit 1)` with no reason (#387).
    st.workersDone = true
    emit "FAIL " & cfg.workload & ": " & e.msg & " (" & st.fmtCodes() & ")" &
      st.mixTail()
    quit(1)
  except Exception as e:
    # The catch-all: an error from the client's own code rather than from a
    # request. `Exception`, not `CatchableError`, so a Defect (an index or range
    # error, an assertion) lands here too: the binary is deliberately built
    # WITHOUT --panics:on, because with it a Defect is fatal at the raise site,
    # prints only to stderr and never reaches this line -- which is the exact
    # #387 shape (a bare `FAILED (exit 1)`, no `FAIL <workload>:` cause on
    # stdout) this handler exists to prevent. The trace matters as much as the
    # one-liner -- "unexpected IndexDefect" is not a diagnosis without the frame
    # it came from -- and it goes on stdout for the same teeing reason, which is
    # why the binary is built with --stackTrace:on --lineTrace:on
    # --stackTraceMsgs:on even in release. (chronos does not route a Defect
    # through a future at all, so this arm is the asyncdispatch build's.)
    st.workersDone = true
    emit "FAIL " & cfg.workload & ": unexpected " & $e.name & ": " & e.msg &
      " (" & st.fmtCodes() & ")" & st.mixTail()
    emit getStackTrace(e)
    quit(1)
  st.workersDone = true
  # A fresh sample just for the closing RSS/heap/fds figure; a failed connect
  # (server already torn down, a transient blip) must never crash the run and
  # mask the verdict below. -1 renders as n/a, not a misleading 0MB.
  var rss = -1
  var heap = -1
  var fds = -1
  try:
    let s = await sampleStats(st, 10_000)
    rss = s[0]; heap = s[1]; fds = s[2]
  except CatchableError: discard
  st.reportLine("final ", rss, heap, fds, st.segment(monoNow()))
  emit st.selfLine()
  if cfg.isMixed:
    # PER WORKLOAD, never on the sum: a stalled download slice must
    # not hide behind a healthy /echo counter, which is the whole reason this
    # cell is worth running (#394). Every dead slice is named, not just the
    # first: each is its own diagnosis and they are cheap to print.
    var dead: seq[string]
    for (slice, _) in st.slices:
      if st.okBy.getOrDefault(slice, 0) == 0: dead.add slice
    if dead.len > 0:
      for slice in dead:
        emit "FAIL " & cfg.workload & ": " & slice & ": " & st.noProgress(slice)
      quit(1)
    emit "== " & cfg.workload & " " & cfg.server & " " & cfg.proto & " passed (" &
      st.mixSegments(0.0, withDelta = false) & ") =="
    quit(0)
  let total = st.okOps()
  if total == 0:
    emit "FAIL " & cfg.workload & ": " & st.noProgress(cfg.workload)
    quit(1)
  emit "== " & cfg.workload & " " & cfg.server & " " & cfg.proto & " passed (" &
    $total & " " & cfg.unit & ") =="
  quit(0)

waitFor main()
