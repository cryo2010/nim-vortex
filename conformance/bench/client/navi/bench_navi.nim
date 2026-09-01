## Cross-language bench load client, built on navi (github.com/cryo2010/nim-navi).
##
## Drives ONE workload (VORTEX_WORKLOAD) at a target server for VORTEX_SECONDS
## over VORTEX_PROTO (h1|h2|h3) and MEASURES it: throughput (req/s | msg/s |
## evt/s | MB/s) + latency percentiles (p50/p90/p99/max) + error/non-2xx tallies.
## One uniform client for every workload x protocol (h3 needs a -d:naviHttp3
## build). Emits a machine-readable RESULT line the harness parses, plus a human
## line each VORTEX_REPORT_SECONDS. Never verifies payloads; exits non-zero only
## if it could not measure at all (status=nomeasure).
import std/[os, strutils, times, monotimes, asyncdispatch, algorithm, options]
import navi/asyncdispatch

let
  base       = getEnv("STRESS_BASE", "https://server:8443").strip(trailing = true, chars = {'/'})
  workload   = getEnv("VORTEX_WORKLOAD", "requests")
  proto      = getEnv("VORTEX_PROTO", "h2")
  framework  = getEnv("BENCH_FRAMEWORK", "vortex")
  serverLbl  = getEnv("STRESS_SERVER", "sync")
  seconds    = parseInt(getEnv("VORTEX_SECONDS", "10"))
  reportSecs = max(1, parseInt(getEnv("VORTEX_REPORT_SECONDS", "10")))
  conc       = max(1, parseInt(getEnv("VORTEX_CONCURRENCY", "32")))
  clients    = max(1, parseInt(getEnv("VORTEX_CLIENTS", "3")))
  streamBytes = parseInt(getEnv("VORTEX_STREAM_BYTES", $(1 shl 30)))

const
  CHUNK = 64 * 1024
  MB = 1024 * 1024
  LAT_CAP = 200_000

let isH3 = proto == "h3"

# --- metrics (single-threaded async: increments interleave safely at awaits) --
var
  ops = 0
  errs = 0
  non2xx = 0
  xfer = 0                 # bytes moved (streaming workloads)
  lat: seq[float]          # per-interval latency samples (seconds), bounded
  skipped = false
  deadline: MonoTime
  startT: MonoTime
  lastT: MonoTime
  lastOps = 0
  lastXfer = 0

proc record(dt: float, status = 200) =
  inc ops
  if status < 200 or status >= 300: inc non2xx
  if lat.len < LAT_CAP: lat.add dt

# deterministic payload: byte i = i mod 256 (matches the server's /download)
let pat = block:
  var s = newString(256)
  for i in 0 .. 255: s[i] = char(i)
  s
proc genChunk(start, n: int): string =
  result = newString(n)
  for i in 0 ..< n: result[i] = pat[(start + i) and 255]

proc mkCfg(): NaviConfig =
  result = initNaviConfig()
  result.tls.verify = false
  result.throwHttpErrors = false        # tally non-2xx, never raise
  result.http =
    case proto
    of "h1": {H1}
    of "h2": {H1, H2}
    of "h3": {H1, H2, H3}               # H3 opt-in; only reached in a -d:naviHttp3 build
    else: {H1, H2}

proc pct(sorted: seq[float], p: float): float =
  if sorted.len == 0: return 0.0
  sorted[min(sorted.len - 1, int(p / 100.0 * float(sorted.len)))]

proc unitFor(): string =
  case workload
  of "requests": "req/s"
  of "ws": "msg/s"
  of "sse": "evt/s"
  of "streamupload", "streamdownload": "MB/s"
  else: "op/s"

proc streaming(): bool = workload in ["streamupload", "streamdownload"]

proc report(prefix: string) =
  let now = getMonoTime()
  let t = inMilliseconds(now - startT).float / 1000.0
  let dt = max(1e-9, inMilliseconds(now - lastT).float / 1000.0)
  var thru: float
  if streaming():
    thru = (xfer - lastXfer).float / dt / MB.float
  else:
    thru = (ops - lastOps).float / dt
  var s = lat
  s.sort()
  let scale = if streaming(): 1.0 else: 1000.0      # streaming latency in s, else ms
  let u = if streaming(): "s" else: "ms"
  stderr.writeLine "[" & workload & " " & proto & " " & framework & "] " & prefix &
    formatFloat(thru, ffDecimal, 0) & " " & unitFor() &
    " | p50 " & formatFloat(pct(s, 50) * scale, ffDecimal, 2) & u &
    " p90 " & formatFloat(pct(s, 90) * scale, ffDecimal, 2) & u &
    " p99 " & formatFloat(pct(s, 99) * scale, ffDecimal, 2) & u &
    " max " & formatFloat(pct(s, 100) * scale, ffDecimal, 2) & u &
    " | ops " & $ops & " err " & $errs & " non2xx " & $non2xx &
    " | t=" & formatFloat(t, ffDecimal, 0) & "s"
  lastT = now; lastOps = ops; lastXfer = xfer
  # reservoir is bounded (LAT_CAP) and NOT cleared, so the final RESULT line
  # carries whole-run percentiles the harness table can read.

# --- workloads ---------------------------------------------------------------
proc wRequests() {.async.} =
  let api = newNavi(mkCfg())
  let body = "the quick brown fox " & "x".repeat(1024)
  while getMonoTime() < deadline:
    try:
      var t0 = getMonoTime()
      let r1 = await api.get("/plaintext")
      record(inMilliseconds(getMonoTime() - t0).float / 1000.0, r1.status)
      for _ in 0 .. 1:
        t0 = getMonoTime()
        let r2 = await api.post("/echo", body = body)
        record(inMilliseconds(getMonoTime() - t0).float / 1000.0, r2.status)
    except CatchableError:
      inc errs
      await sleepAsync(50)
  await api.close()

proc wStreamDownload() {.async.} =
  let api = newNavi(mkCfg())
  while getMonoTime() < deadline:
    try:
      let t0 = getMonoTime()
      let sr = await api.stream(GET, "/download")
      await sr.drain(proc(data: string) {.async.} = xfer += data.len)
      record(inMilliseconds(getMonoTime() - t0).float / 1000.0, sr.status)
    except CatchableError:
      inc errs
      await sleepAsync(50)
  await api.close()

proc wStreamUpload() {.async.} =
  if isH3:                       # vortex doesn't ack h3 request-body flow control
    skipped = true
    stderr.writeLine "[" & workload & " " & proto & " " & framework &
      "] SKIP: streamupload over h3"
    return
  let api = newNavi(mkCfg())
  while getMonoTime() < deadline:
    try:
      var off = 0
      let producer: BodyProducer = proc(): string =
        if off >= streamBytes: return ""
        let n = min(CHUNK, streamBytes - off)
        result = genChunk(off, n); off += n; xfer += n
      var hdrs = initHeaders()
      hdrs.add("x-sha1", "skip")          # server validates if it wants; bench skips
      let t0 = getMonoTime()
      let r = await api.request(POST, "/upload", headers = hdrs, bodyStream = producer)
      record(inMilliseconds(getMonoTime() - t0).float / 1000.0, r.status)
    except CatchableError:
      inc errs
      await sleepAsync(50)
  await api.close()

proc wSse() {.async.} =
  let api = newNavi(mkCfg())
  while getMonoTime() < deadline:
    try:
      let s = await api.sse("/sse")           # navi handles reconnect + Last-Event-ID
      var prev = getMonoTime()
      while getMonoTime() < deadline:
        let ev = await s.next()
        if ev.isNone: break
        let now = getMonoTime()
        record(inMilliseconds(now - prev).float / 1000.0); prev = now
      await s.close()
    except CatchableError:
      inc errs
      await sleepAsync(50)
  await api.close()

proc wWs() {.async.} =
  if proto != "h1":               # navi ws is HTTP/1.1 Upgrade only
    skipped = true
    stderr.writeLine "[" & workload & " " & proto & " " & framework &
      "] SKIP: websocket only over h1"
    return
  let api = newNavi(mkCfg())
  let wsUrl = base.replace("https://", "wss://").replace("http://", "ws://") & "/ws"
  try:
    let ws = await api.websocket(wsUrl)
    var n = 0
    while getMonoTime() < deadline:
      let msg = "msg-" & $n
      let t0 = getMonoTime()
      await ws.send(msg)
      discard await ws.receive()
      record(inMilliseconds(getMonoTime() - t0).float / 1000.0); inc n
    await ws.close()
  except CatchableError:
    inc errs
  await api.close()

proc worker() {.async.} =
  case workload
  of "requests": await wRequests()
  of "streamdownload": await wStreamDownload()
  of "streamupload": await wStreamUpload()
  of "sse": await wSse()
  of "ws": await wWs()
  else: (skipped = true)

proc reporter() {.async.} =
  while getMonoTime() < deadline:
    await sleepAsync(reportSecs * 1000)
    if getMonoTime() < deadline: report("")

proc main() {.async.} =
  startT = getMonoTime(); lastT = startT
  deadline = startT + initDuration(seconds = seconds)
  asyncCheck reporter()                 # fire-and-forget; self-stops at deadline
  var ws: seq[Future[void]]
  # ws/streamupload use one connection per worker; requests/sse/download fan out
  let n = if workload == "streamupload": clients else: clients * conc
  for _ in 0 ..< n: ws.add worker()
  await all(ws)
  report("final ")
  let elapsed = max(1e-9, inMilliseconds(getMonoTime() - startT).float / 1000.0)
  let status =
    if skipped: "skip"
    elif ops == 0 and errs > 0: "nomeasure"
    else: "ok"
  let thru =
    if streaming(): xfer.float / elapsed / MB.float
    else: ops.float / elapsed
  var s = lat; s.sort()
  let scale = if streaming(): 1000.0 else: 1000.0    # RESULT latency always in ms
  echo "RESULT framework=", framework, " proto=", proto, " workload=", workload,
    " unit=", unitFor(), " throughput=", formatFloat(thru, ffDecimal, 1),
    " p50_ms=", formatFloat(pct(s, 50) * scale, ffDecimal, 3),
    " p90_ms=", formatFloat(pct(s, 90) * scale, ffDecimal, 3),
    " p99_ms=", formatFloat(pct(s, 99) * scale, ffDecimal, 3),
    " max_ms=", formatFloat(pct(s, 100) * scale, ffDecimal, 3),
    " ops=", ops, " err=", errs, " non2xx=", non2xx, " status=", status
  if status == "nomeasure": quit(1)

waitFor main()
