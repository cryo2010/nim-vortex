## Self-driving scenario harness for the valgrind / helgrind / tsan CI matrix.
##
## One process: it starts a real vortex server (via `start`, non-blocking) and
## drives it with a real client in the same process, then shuts down cleanly and
## exits 0. A memory/thread tool (valgrind memcheck, helgrind, tsan) wraps the
## whole `nim c -r` invocation, so the server side runs fully instrumented.
##
## Axes (all chosen by the build/run, not hard-coded here):
##   backend  -d:backend=sync|async|chronos   (which adapter, if any)
##   scenario  $SCENARIO env                    (which code path to exercise)
##   mm        --mm:orc|arc                     (passed by the workflow)
##
## Built with -d:plainHttp so no OpenSSL is linked: the tools then run without
## crypto-instruction (SIGILL) trouble or an OpenSSL suppression file. Scenarios
## are therefore cleartext (h1, h2c, ws://); TLS/h3 memory-safety is covered by
## the existing conformance jobs (h2spec/h3spec/testssl), not here.
##
## HTTP/2 scenarios drive the server with a `curl --http2-prior-knowledge` child
## (there is no h2 client in the stdlib); only this harness process is under the
## tool, which is what we want -- the child curl is not traced.

import std/[net, posix, os, osproc, strutils, httpcore]

const backend {.strdefine.}: string = "sync"
const isAsync = backend == "async" or backend == "chronos"

import vortex/[settings, request, server, routing]
when backend == "chronos":
  import vortex/chronos
elif backend == "async":
  import vortex/asyncdispatch

# --- tiny client helpers (inlined; harness lives outside tests/) --------------

proc setRecvTimeout(s: Socket, ms: int) =
  var tv: Timeval
  tv.tv_sec = posix.Time(ms div 1000)
  tv.tv_usec = Suseconds((ms mod 1000) * 1000)
  discard setsockopt(s.getFd, SOL_SOCKET, SO_RCVTIMEO, addr tv, SockLen(sizeof(tv)))

proc recvUntilClose(s: Socket, timeoutMs = 3000): string =
  s.setRecvTimeout(timeoutMs)
  var buf = newString(16384)
  while true:
    let n = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if n <= 0: break
    result.add buf.substr(0, n - 1)

proc recvN(s: Socket, n: int, timeoutMs = 3000): string =
  s.setRecvTimeout(timeoutMs)
  result = newString(n)
  var got = 0
  while got < n:
    let k = recv(s.getFd, addr result[got], n - got, cint(0))
    if k <= 0: raise newException(IOError, "short read")
    got += k

proc fail(msg: string) =
  stderr.writeLine "SCENARIO FAIL: " & msg
  quit 1

# --- payloads -----------------------------------------------------------------

const
  bodyText = "the quick brown fox jumps over the lazy dog. ".repeat(48)  # ~2 KB
  downChunk = "0123456789abcdef".repeat(256)                              # 4 KB
  downCount = 32                                                          # 128 KB
  upBody = "u".repeat(128 * 1024)                                         # 128 KB

# --- handlers -----------------------------------------------------------------
# ws/sse/shutdown use the core (future-agnostic) API in every backend; only the
# request/response paths where the adapter adds a distinct path (root deferral,
# streamed upload pull-loop, awaitable streamed download) are written async in
# the async/chronos builds.

proc wsEcho(req: Request, res: Response) {.gcsafe.} =
  let ws = req.acceptWebSocket()
  ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
    ws.send(data, kind)

proc sseH(req: Request, res: Response) {.gcsafe.} =
  res.withSse(s):
    for i in 0 ..< 8:
      discard s.send("event " & $i, event = "tick", id = $i)

proc slowH(req: Request, res: Response) {.gcsafe.} =
  # In-flight work on the worker pool: exercises the graceful-drain path.
  req.blocking:
    sleep(40)
    res.send(Http200, "slow-done")

when isAsync:
  proc rootH(req: Request, res: Response) {.async.} =
    res.send(Http200, bodyText)
  proc downH(req: Request, res: Response) {.async.} =
    res.stream(Http200, "text/plain"):
      for i in 0 ..< downCount:
        await res.write(downChunk)
  proc upH(req: Request, res: Response) {.async.} =
    # The async pull-loop auto-acks an empty 200 on clean exit (consuming the
    # whole body); no explicit response needed.
    req.stream(chunk):
      discard chunk
else:
  proc rootH(req: Request, res: Response) {.gcsafe.} =
    res.send(Http200, bodyText)
  proc downH(req: Request, res: Response) {.gcsafe.} =
    res.stream(Http200, "text/plain"):
      for i in 0 ..< downCount:
        discard res.write(downChunk)
  proc upH(req: Request, res: Response) {.gcsafe.} =
    var total = 0
    req.stream(chunk, last):
      total += chunk.len
      if last: res.send(Http200, "up:" & $total)

proc buildRouter(): Router =
  result = newRouter()
  result.get("/", rootH)
  result.get("/down", downH)
  result.get("/sse", sseH)
  result.get("/ws", wsEcho)
  result.get("/slow", slowH)
  result.stream(HttpPost, "/up", upH)

# --- client workloads ---------------------------------------------------------

proc reps(default: int): int =
  let e = getEnv("REPS")
  if e.len > 0: (try: parseInt(e) except: default) else: default

proc h1Get(port: Port, path: string, acceptEncoding = ""): string =
  ## One keep-alive-less GET; returns the full raw response.
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  var req = "GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
  if acceptEncoding.len > 0: req.add "Accept-Encoding: " & acceptEncoding & "\r\n"
  req.add "\r\n"
  s.send(req)
  s.recvUntilClose()

proc runHttp1(port: Port, compressed: bool, n: int) =
  for i in 0 ..< n:
    let resp = h1Get(port, "/", if compressed: "gzip" else: "")
    if "200" notin resp.splitLines()[0]: fail("http1: no 200: " & resp[0..min(60,resp.high)])
    if compressed and "content-encoding: gzip" notin resp.toLowerAscii:
      fail("http1c: response not gzip-encoded")

proc runHttp2(port: Port, compressed: bool, n: int) =
  let curl = findExe("curl")
  if curl.len == 0: fail("http2 scenario needs curl")
  let enc = if compressed: " -H 'Accept-Encoding: gzip'" else: ""
  for i in 0 ..< n:
    let (outp, rc) = execCmdEx(curl & " -s --http2-prior-knowledge" & enc &
      " -w '|%{http_code}|%{http_version}' http://127.0.0.1:" & $port & "/")
    if rc != 0: fail("http2: curl rc=" & $rc)
    if "|200|2" notin outp: fail("http2: expected |200|2, got: " & outp.strip)

proc runStreamDown(port: Port, compressed: bool, n: int) =
  for i in 0 ..< n:
    let resp = h1Get(port, "/down", if compressed: "gzip" else: "")
    let i2 = resp.find("\r\n\r\n")
    if i2 < 0: fail("streamdown: no header terminator")
    if "200" notin resp.splitLines()[0]: fail("streamdown: no 200")
    if not compressed:
      # chunked, uncompressed: dechunk and check total size
      var body = resp[i2+4 .. ^1]; var pos = 0; var total = 0
      while true:
        let nl = body.find("\r\n", pos)
        if nl < 0: break
        let sz = try: parseHexInt(body[pos ..< nl].strip) except: -1
        if sz <= 0: break
        total += sz; pos = nl + 2 + sz + 2
      if total != downCount * downChunk.len:
        fail("streamdown: size " & $total & " != " & $(downCount*downChunk.len))

proc runStreamUp(port: Port, n: int) =
  for i in 0 ..< n:
    let s = newSocket(buffered = false)
    s.connect("127.0.0.1", port)
    s.send("POST /up HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
           "Content-Length: " & $upBody.len & "\r\n\r\n")
    s.send(upBody)
    let resp = s.recvUntilClose()
    s.close()
    # sync acks with the byte count; the async pull-loop auto-acks an empty 200.
    when isAsync:
      if "200" notin resp.splitLines()[0]: fail("streamup: no 200: " &
        resp[0..min(80, resp.high)])
    else:
      if ("up:" & $upBody.len) notin resp: fail("streamup: bad ack: " &
        resp[0..min(80, resp.high)])

proc runSse(port: Port, n: int) =
  for i in 0 ..< n:
    let s = newSocket(buffered = false)
    s.connect("127.0.0.1", port)
    s.send("GET /sse HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    let resp = s.recvUntilClose(2000)
    s.close()
    if "text/event-stream" notin resp.toLowerAscii: fail("sse: not event-stream")
    if "event: tick" notin resp: fail("sse: no tick event")

proc wsFrame(payload: string): string =
  ## Client->server masked text frame.
  result = "\x81" & char(0x80 or payload.len)
  let mask = [0x21'u8, 0x43, 0x65, 0x87]
  for m in mask: result.add char(m)
  for i in 0 ..< payload.len: result.add char(uint8(payload[i]) xor mask[i and 3])

proc runWs(port: Port, n: int) =
  for i in 0 ..< n:
    let s = newSocket(buffered = false)
    s.connect("127.0.0.1", port)
    s.send("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
           "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
           "Sec-WebSocket-Version: 13\r\n\r\n")
    s.setRecvTimeout(2000)
    var hdr = ""
    while not hdr.endsWith("\r\n\r\n"):
      let one = s.recvN(1)
      hdr.add one
    if "101" notin hdr: fail("ws: no 101 upgrade")
    let msg = "hello-" & $i
    s.send(wsFrame(msg))
    let h = s.recvN(2)
    let ln = int(uint8(h[1]) and 0x7f)
    let echoed = if ln > 0: s.recvN(ln) else: ""
    s.close()
    if echoed != msg: fail("ws: echo mismatch: " & echoed & " != " & msg)

# The shutdown scenario runs an in-flight /slow request on a background thread
# while the main thread closes the server, exercising the graceful-drain and
# force-close paths (the C4/C5 UAF territory).
var shutdownThread: Thread[Port]
proc slowClient(port: Port) {.thread.} =
  try:
    let s = newSocket(buffered = false)
    s.connect("127.0.0.1", port)
    s.send("GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    discard s.recvUntilClose(3000)
    s.close()
  except CatchableError: discard

proc runShutdown(n: int) =
  # Each iteration starts a fresh server, puts a request in flight + an idle
  # keep-alive conn, then closes mid-flight (graceful-drain / force-close, the
  # C4/C5 UAF territory). Looping also lets the fd check catch a close() that
  # fails to free the loop's epoll/eventfd/listen sockets.
  for i in 0 ..< n:
    # Hold the router for the server's lifetime (the handler is stored as a raw,
    # non-owned (proc, env) pair, so the caller owns it); freed at iteration end,
    # after close(). Building it inline would drop it while the server still runs.
    let r = buildRouter()
    let srv = newVortex(r.toHandler, initVortexConfig(numThreads = 1,
      workerThreads = 2), r.streamPredicate).start(0)
    let port = srv.port
    let idle = newSocket(buffered = false)
    idle.connect("127.0.0.1", port)
    idle.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    discard idle.recvUntilClose(500)
    createThread(shutdownThread, slowClient, port)
    sleep(15)                       # let it reach the worker
    srv.close()                     # drain in-flight, GOAWAY, force-close idle
    joinThread(shutdownThread)
    idle.close()

# --- fd-leak check ------------------------------------------------------------
# Count the process's open fds (Linux only; -1 elsewhere -> the check is skipped
# on the macOS dev box). A per-connection/per-request fd leak in the server
# shows up as growth across the measured loop, beyond a small warmup-settled
# baseline. Complements valgrind --track-fds (which reports fds open at exit).

proc openFdCount(): int =
  when defined(linux):
    result = 0
    for _ in walkDir("/proc/self/fd"): inc result   # consistent method both ends
  else:
    result = -1

proc checkFds(name: string, base, after: int) =
  const slack = 3           # allow small non-determinism; a real leak grows ~n
  if base > 0 and after > base + slack:
    fail("fd leak: " & name & " grew " & $base & " -> " & $after & " open fds")

proc runScenario(sc: string, port: Port, n: int) =
  case sc
  of "http1": runHttp1(port, false, n)
  of "http1c": runHttp1(port, true, n)
  of "http2": runHttp2(port, false, n)
  of "http2c": runHttp2(port, true, n)
  of "streamup": runStreamUp(port, n)
  of "streamdown": runStreamDown(port, false, n)
  of "streamdownc": runStreamDown(port, true, n)
  of "sse": runSse(port, n)
  of "ws": runWs(port, n)
  else: fail("unknown SCENARIO: " & sc)

# --- main ---------------------------------------------------------------------

let scenario = getEnv("SCENARIO", "http1")

if scenario == "shutdown":
  runShutdown(1)                    # warmup (settle lazy allocations)
  let base = openFdCount()
  runShutdown(6)                    # measured: each cycle must free its fds
  checkFds("shutdown", base, openFdCount())
  echo "scenario ok: ", scenario, " (", backend, ")"
  quit 0

let compressed = scenario.endsWith("c") and (scenario.startsWith("http") or
                 scenario.startsWith("streamdown"))
let rt = buildRouter()              # held for the server's lifetime (see runShutdown)
let srv = newVortex(rt.toHandler, initVortexConfig(
  numThreads = 1, workerThreads = 2, compress = compressed),
  rt.streamPredicate).start(0)
let port = srv.port

let total = reps(20)
runScenario(scenario, port, min(4, total))    # warmup: settle lazy fds
let base = openFdCount()
runScenario(scenario, port, total)            # measured
checkFds(scenario, base, openFdCount())

srv.close()
echo "scenario ok: ", scenario, " (", backend, ")"
quit 0
