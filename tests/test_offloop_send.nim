## Off-loop sends from a thread the application owns (#409). The off-loop
## branch of `send` drops a duplicate response with a first-send latch. Before
## #409 the latch was a thread-wide bool that only the worker trampolines
## reset, so a single app-owned thread that kept `Response` handles from
## several deferred requests and answered them in turn sent the first one and
## silently dropped every later one: those requests hung until the response
## timeout. The latch is now keyed on the handle. Here one long-lived thread
## (created once for the whole file) waits until a batch of handles is stashed,
## then answers each of them, twice: every request must get exactly one
## response. Those handles carry no pin release, so the repeat `send` pushes
## and the LOOP drops it as a second response for an answered request.
##
## The latch only covers a worker task's OWN handle, whose first answer
## releases the task's pin. A `blocking:` body may also answer a kept handle,
## and that must not make the trampoline believe its own request went
## unanswered: the default 500 it then pushed carried the task's pin release a
## second time, tripping the pin-release assertion inside the loop's outbox
## pass. That AssertionDefect is swallowed (R11), so it shows up as the rest of
## the outbox batch being lost: here a second blocking task's response
## (`/late`, on connection Z) that lands in the same batch while the loop
## thread is held by a slow plain handler (`/stall`). The cases check Z gets
## its answer, that Z's pin counter is back to zero (the `totalPins` hook, read
## on the loop thread by `/pins`), and that every connection still serves a
## follow-up request.
##
## The last suites (#420) read a kept handle's request and response accessors
## from a worker task it does not belong to and from the app-owned thread.
## Neither has a snapshot of that request, and the accessors outside
## `withCarrier` (clientCertSubject, isSecure, url, query, json, params,
## param, res.responded, res.headers, res.trailers, setParams, onBody, ...)
## reached the loop-owned connection table there: its loop-thread assertion
## (#343) fired (a 500 from the worker, the process ended on the app thread),
## and under -d:danger they read it unsynchronised. Each now returns its
## empty/default value. A `blocking:` body over an HTTP/2 Extended CONNECT
## also reads the `:protocol` pseudo-header from its snapshot now, instead of
## the live stream. The last suite checks a `blocking:` body's OWN handle:
## `res.responded` reads the task's latch (false, then true after its send),
## and a write through its own `res.headers` / `res.trailers` asserts with
## assertions on (the default, -d:release included: a 500) and is dropped
## silently with assertions off (-d:danger or --assertions:off).

import std/[unittest, net, posix, strutils, httpcore, atomics, json, tables]
from std/os import sleep
import vortex/[settings, request, server]
import vortex/http2/frames
from vortex/connection import conn, totalPins
import ./helper
import ./h2client

const
  batch = 3                      ## deferred requests per test
  maxStash = 64

var stash: array[maxStash, Response] # handle words only: plain, no GC'd fields
var stashed: Atomic[int]         # handles written to `stash` so far
var target: Atomic[int]          # answer up to this many once all are stashed
var answeredCount: Atomic[int]   # handles the app thread has answered
var stopApp: Atomic[bool]
var appThread: Thread[void]

var keptRes: Response            # the kept handle the worker bodies answer
var keptReady: Atomic[bool]
var xFd, zFd: Atomic[int32]      # connections of the /work-* and /late requests
var xGen, zGen: Atomic[uint32]

proc answerOwnThenKept(res: Response, variant: int) {.gcsafe.} =
  ## The body of a `blocking:` task that answers its own request and then the
  ## kept handle (#409 review). Variant 1 answers its own request again
  ## afterwards, variant 2 raises after both answers.
  sleep(100)                     # land behind the loop's /stall
  res.send(Http200, "own")
  {.cast(gcsafe).}:
    let k = keptRes
  k.send(Http200, "kept-answered")
  if variant == 1:
    res.send(Http200, "OWN-AGAIN")
  elif variant == 2:
    raise newException(ValueError, "after both answers")

var keptReqs: array[2, Request]  # #420: kept handles by HTTP version (1, 2)
var keptResps: array[2, Response]
var keptReqReady: array[2, Atomic[bool]]
var probeSlot: Atomic[int]       # the slot the app thread probes (-1: none)
var appProbeRes: Response        # the handle the app thread answers with
var ownAfter: Atomic[int]        # res.responded after a body's own send (1/0)

proc probeAccessors(q: Request, r: Response): string {.gcsafe.} =
  ## Read every accessor that resolved live loop state outside withCarrier,
  ## from a thread holding no snapshot of `q`'s request (#420). Each one is
  ## reported on its own, so a build without the guard names every accessor
  ## that tripped the loop-thread assertion (#343) instead of stopping at the
  ## first.
  template field(name: string, expr: untyped) =
    try:
      result.add name & "=" & $(expr) & ";"
    except Exception:
      result.add name & "=TRIP;"
  field("cert", q.clientCertSubject)
  field("secure", q.isSecure)
  field("scheme", q.scheme)
  field("fwdProto", q.forwardedProto)
  field("fwdHost", q.forwardedHost)
  field("clientIp", q.clientIp)
  field("url", q.url.path & "?" & q.url.query)
  field("query", q.query.len)
  field("json", $q.json)
  field("params", q.params.len)
  field("param", q.param("id"))
  field("setParams", (q.setParams(@[("id", "overwritten")]); "ok"))
  field("onBody", (q.onBody(proc(c: openArray[char], last: bool) {.gcsafe.} =
    discard); "ok"))
  # isWebSocketUpgrade / isWebSocketIntent / acceptWebSocket are not probed
  # here: off the loop with no snapshot `method` reads HttpGet, which
  # short-circuits them before any `:protocol` read, so they would pass with
  # the guard reverted. Their snapshot path is the /ws-blocking case below.
  field("responded", r.responded)
  # A write goes to a discarding sink: the next hand-out is empty again.
  field("headers", (r.headers["X-Off-Loop"] = "leaked"; r.headers.len))
  field("trailers", (r.trailers["X-Off-Loop"] = "leaked"; r.trailers.len))

const probeExpected = "cert=;secure=false;scheme=http;fwdProto=;fwdHost=;" &
  "clientIp=;url=?;query=0;json={};params=0;param=;setParams=ok;onBody=ok;" &
  "responded=true;headers=0;trailers=0;"

proc noteX(req: Request) =
  xFd.store(req.fd); xGen.store(req.gen)

proc pinsOf(res: Response, fd: int32, gen: uint32): string =
  let c = conn(res.core, fd, gen)
  if c == nil: "gone" else: $c.totalPins

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.path.startsWith("/keep-req"):
    # #420: keep both halves, unanswered. On the loop thread the accessors
    # see the real request, so the off-loop defaults below are not the
    # request's own values.
    req.setParams(@[("id", "7")])
    let slot = req.httpVersion - 1
    {.cast(gcsafe).}:
      keptReqs[slot] = req
      keptResps[slot] = res
    keptReqReady[slot].store(true)
    return
  case req.path
  of "/keep":
    {.cast(gcsafe).}:
      keptRes = res
    keptReady.store(true)
  of "/work-own-kept":
    noteX(req)
    req.blocking:
      answerOwnThenKept(res, 0)
  of "/work-own-kept-own":
    noteX(req)
    req.blocking:
      answerOwnThenKept(res, 1)
  of "/work-own-kept-raise":
    noteX(req)
    req.blocking:
      answerOwnThenKept(res, 2)
  of "/late":
    zFd.store(req.fd); zGen.store(req.gen)
    req.blocking:
      sleep(250)                 # pushed while the loop is still in /stall
      res.send(Http200, "late")
  of "/stall":
    sleep(500)                   # holds the loop: the outbox piles up one batch
    res.send(Http200, "stalled")
  of "/again":
    req.blocking:
      res.send(Http200, "again")
  of "/loop-view-1", "/loop-view-2":
    # The kept request read on the loop thread: its live values.
    let slot = (if req.path.endsWith("1"): 0 else: 1)
    {.cast(gcsafe).}:
      let q = keptReqs[slot]
    res.send(Http200, q.url.path & "?" & q.url.query & ";" &
                      $q.query.len & ";" & $q.json & ";" & q.param("id"))
  of "/probe-kept-1", "/probe-kept-2":
    # A worker task reading a kept handle that is not its own.
    if req.path.endsWith("1"):
      req.blocking:
        {.cast(gcsafe).}:
          let q = keptReqs[0]
          let r = keptResps[0]
        res.send(Http200, probeAccessors(q, r))
    else:
      req.blocking:
        {.cast(gcsafe).}:
          let q = keptReqs[1]
          let r = keptResps[1]
        res.send(Http200, probeAccessors(q, r))
  of "/probe-app-1", "/probe-app-2":
    # The app-owned thread reads the kept handle and answers this one.
    {.cast(gcsafe).}:
      appProbeRes = res
    probeSlot.store(if req.path.endsWith("1"): 0 else: 1)
  of "/release-1", "/release-2":
    # Answer the kept handle on the loop: none of the off-loop writes (headers,
    # trailers, params) reached it.
    let slot = (if req.path.endsWith("1"): 0 else: 1)
    {.cast(gcsafe).}:
      let q = keptReqs[slot]
      let r = keptResps[slot]
    r.send(Http200, "kept-done param=" & q.param("id"))
    res.send(Http200, "released")
  of "/ws-blocking":
    # An Extended CONNECT read from its own `blocking:` body: the snapshot
    # answers it; the live h2 stream is loop-only.
    req.blocking:
      let up = req.isWebSocketUpgrade
      let intent = req.isWebSocketIntent
      let ws = req.acceptWebSocket()
      res.send(Http200, $up & "," & $intent & "," & $ws.isAlive)
  of "/own-responded":
    # A `blocking:` body asking whether it has answered its OWN request yet:
    # off the loop that reads the task's first-send latch (#420 review), so
    # it is false before the send and true after, on every build. A blanket
    # `true` there turned this guarded send into the fallback 500.
    ownAfter.store(-1)
    req.blocking:
      if not res.responded: res.send(Http200, "answered")
      ownAfter.store(if res.responded: 1 else: 0)
  of "/own-after":
    res.send(Http200, $ownAfter.load)
  of "/own-headers":
    # res.headers from a `blocking:` body's own handle: with assertions on
    # (the default, -d:release included) it asserts and the Defect answers
    # 500; with assertions off (-d:danger, --assertions:off) the write is
    # discarded.
    req.blocking:
      res.headers["X-Own"] = "set-in-blocking"
      res.send(Http200, "sent")
  of "/own-trailers":
    req.blocking:
      res.trailers["X-Own"] = "set-in-blocking"
      res.send(Http200, "sent")
  of "/pins":
    res.send(Http200, pinsOf(res, zFd.load, zGen.load) & "," &
                      pinsOf(res, xFd.load, xGen.load))
  of "/defer":
    # Keep the handle and answer nothing here: the app thread answers it.
    {.cast(gcsafe).}:
      let i = stashed.load
      stash[i] = res
      stashed.store(i + 1)       # single loop thread: no concurrent writer
  else:
    res.send(Http200, "pong")

proc appMain() {.thread.} =
  ## The application's own thread: never a vortex worker, so no worker task
  ## is ever latched on it. It answers every stashed handle in turn, each one
  ## twice (the loop must drop the second response).
  var done = 0
  while not stopApp.load:
    let slot = probeSlot.load
    if slot >= 0:
      probeSlot.store(-1)
      {.cast(gcsafe).}:
        let q = keptReqs[slot]
        let r = keptResps[slot]
        let a = appProbeRes
      a.send(Http200, probeAccessors(q, r))
      continue
    let t = target.load
    if t > done and stashed.load >= t:
      for i in done ..< t:
        {.cast(gcsafe).}:
          let r = stash[i]
        r.send(Http200, "answered-" & $i)
        r.send(Http200, "DUPLICATE-" & $i)
      done = t
      answeredCount.store(done)
    else:
      sleep(1)

proc countOf(s, sub: string): int =
  var p = s.find(sub)
  while p >= 0:
    inc result
    p = s.find(sub, p + sub.len)

proc readAll(s: Socket, firstMs, quietMs: int): string =
  ## Wait up to `firstMs` for the first bytes, then keep reading until the
  ## socket stays quiet for `quietMs`: everything the server sent, including
  ## any spurious second response right behind the first.
  s.setRecvTimeout(firstMs)
  var tmp = newString(65536)
  var n = recv(s.getFd, addr tmp[0], tmp.len, cint(0))
  if n <= 0: return ""
  result.add tmp.substr(0, n - 1)
  s.setRecvTimeout(quietMs)
  while true:
    n = recv(s.getFd, addr tmp[0], tmp.len, cint(0))
    if n <= 0: break
    result.add tmp.substr(0, n - 1)

proc bodyOf(frames: seq[Frame], sid: uint32): string =
  for f in frames:
    if f.typ == uint8(ftData) and f.streamId == sid: result.add f.payload

proc headersOn(frames: seq[Frame], sid: uint32): int =
  for f in frames:
    if f.typ == uint8(ftHeaders) and f.streamId == sid: inc result

proc get(s: Socket, path: string) =
  s.send("GET " & path & " HTTP/1.1\r\nHost: offloop.test\r\n\r\n")

template ownThenKept(port: Port, useH2: bool, path: string) =
  ## One finding-1 scenario: A keeps a handle, Z runs a slow blocking task, X
  ## runs the `path` body (own answer + kept answer + variant), and Y holds the
  ## loop thread so X's messages and Z's answer share one outbox batch. A
  ## template so its `check`s fail the enclosing test.
  keptReady.store(false)
  let a = connectTimeout(port)
  let z = connectTimeout(port)
  let y = connectTimeout(port)
  var xs: Socket
  var xc: H2TestConn
  if useH2: xc = newH2TestConn(port)
  else: xs = connectTimeout(port)
  defer:
    a.close(); z.close(); y.close()
    if useH2: xc.close() else: xs.close()
  a.get("/keep")
  for i in 0 ..< 200:
    if keptReady.load: break
    sleep(10)
  check keptReady.load
  z.get("/late")
  sleep(30)
  if useH2:
    var buf = ""
    buf.addRequest(1, [(":method", "GET"), (":scheme", "http"),
                       (":path", path), (":authority", "localhost")])
    xc.sendAll(buf)
  else:
    xs.get(path)
  sleep(30)
  y.get("/stall")

  let yr = y.readAll(3000, 100)
  check yr.endsWith("stalled")
  let ar = a.readAll(3000, 200)
  checkpoint "A got: " & ar.escape
  check ar.countOf("HTTP/1.1 ") == 1
  check ar.endsWith("kept-answered")
  if useH2:
    var fr = xc.readFrames(3000, until = proc(fs: seq[Frame]): bool =
      fs.hasResponse(1))
    fr.add xc.readFrames(300)
    check fr.headersOn(1) == 1
    check fr.bodyOf(1) == "own"
    check fr.goawayError() == -1
  else:
    let xr = xs.readAll(3000, 200)
    checkpoint "X got: " & xr.escape
    check xr.countOf("HTTP/1.1 ") == 1
    check xr.endsWith("own")
  # Z's answer rode the same outbox batch as X's messages: a duplicate pin
  # release for X aborted that batch and lost it, leaving Z pinned.
  let zr = z.readAll(3000, 100)
  checkpoint "Z got: " & zr.escape
  check zr.endsWith("late")
  # Direct: no pin left on Z or X.
  y.get("/pins")
  let pr = y.readAll(3000, 100)
  checkpoint "pins (Z,X): " & pr.escape
  check pr.endsWith("\r\n\r\n0,0")
  # Indirect: every connection still serves a follow-up, X a blocking one.
  if useH2:
    var buf = ""
    buf.addRequest(3, [(":method", "GET"), (":scheme", "http"),
                       (":path", "/again"), (":authority", "localhost")])
    xc.sendAll(buf)
    let fr = xc.readFrames(3000, until = proc(fs: seq[Frame]): bool =
      fs.bodyOf(3) == "again")
    check fr.bodyOf(3) == "again"
  else:
    xs.get("/again")
    check xs.readAll(3000, 100).endsWith("again")
  z.get("/ping")
  check z.readAll(3000, 100).endsWith("pong")
  a.get("/ping")
  check a.readAll(3000, 100).endsWith("pong")

probeSlot.store(-1)
createThread(appThread, appMain)

withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, workerThreads = 4), srv):
  let port = srv.port

  suite "off-loop send from one app-owned thread (#409)":
    test "HTTP/1.1: one thread answers several kept handles, the loop drops repeats":
      let base = stashed.load
      target.store(base + batch)
      var socks: seq[Socket]
      for i in 0 ..< batch:
        let s = connectTimeout(port)
        s.send("GET /defer HTTP/1.1\r\nHost: offloop.test\r\n\r\n")
        socks.add s
      defer:
        for s in socks: s.close()
      for i in 0 ..< batch:
        let raw = socks[i].readAll(3000, 300)
        checkpoint "connection " & $i & " got: " & raw.escape
        check raw.startsWith("HTTP/1.1 200")
        check raw.countOf("HTTP/1.1 ") == 1       # no second response
        check raw.endsWith("answered-" & $(base + i))
        check "DUPLICATE" notin raw
      check answeredCount.load == base + batch
      # Each connection is still in sync: the next request gets exactly its
      # own response, with nothing queued ahead of it.
      for s in socks:
        s.send("GET /ping HTTP/1.1\r\nHost: offloop.test\r\n\r\n")
        let raw = s.readAll(3000, 200)
        check raw.countOf("HTTP/1.1 ") == 1
        check raw.endsWith("pong")

    test "HTTP/2: one thread answers several kept streams, the loop drops repeats":
      let base = stashed.load
      target.store(base + batch)
      var c = newH2TestConn(port)
      defer: c.close()
      var sids: seq[uint32]
      var buf = ""
      for i in 0 ..< batch:
        let sid = uint32(2 * i + 1)
        sids.add sid
        buf.addRequest(sid, [(":method", "GET"), (":scheme", "http"),
                             (":path", "/defer"), (":authority", "localhost")])
      c.sendAll(buf)
      let frames = c.readFrames(3000, until = proc(fs: seq[Frame]): bool =
        for sid in sids:
          if not fs.hasResponse(sid): return false
        true)
      var all = frames
      all.add c.readFrames(300)                     # anything stray behind them
      for i, sid in sids:
        check all.headersOn(sid) == 1
        check all.bodyOf(sid) == "answered-" & $(base + i)
      for f in all:
        if f.typ == uint8(ftData): check "DUPLICATE" notin f.payload
      check all.goawayError() == -1
      # The connection still serves a fresh stream normally.
      let probe = uint32(2 * batch + 1)
      var p = ""
      p.addRequest(probe, [(":method", "GET"), (":scheme", "http"),
                           (":path", "/ping"), (":authority", "localhost")])
      c.sendAll(p)
      let pf = c.readFrames(3000, until = proc(fs: seq[Frame]): bool =
        fs.bodyOf(probe) == "pong")
      check pf.bodyOf(probe) == "pong"

  suite "blocking: body answering its own and a kept handle (#409)":
    for useH2 in [false, true]:
      let proto = if useH2: "HTTP/2" else: "HTTP/1.1"
      test proto & ": own, then kept":
        ownThenKept(port, useH2, "/work-own-kept")
      test proto & ": own, kept, own again":
        ownThenKept(port, useH2, "/work-own-kept-own")
      test proto & ": own, kept, then raises":
        ownThenKept(port, useH2, "/work-own-kept-raise")

  suite "request accessors off the loop with no snapshot (#420)":
    test "HTTP/1.1: a kept handle read from a foreign worker task and the app thread":
      keptReqReady[0].store(false)
      let k = connectTimeout(port)
      defer: k.close()
      const body = "{\"k\":1}"
      k.send("POST /keep-req/h1?a=1&b=2 HTTP/1.1\r\nHost: offloop.test\r\n" &
             "Content-Type: application/json\r\nContent-Length: " &
             $body.len & "\r\n\r\n" & body)
      for i in 0 ..< 200:
        if keptReqReady[0].load: break
        sleep(10)
      check keptReqReady[0].load
      let o = connectTimeout(port)
      defer: o.close()
      o.get("/loop-view-1")
      let lv = o.readAll(3000, 100)
      checkpoint "loop view: " & lv.escape
      check lv.endsWith("/keep-req/h1?a=1&b=2;2;{\"k\":1};7")
      o.get("/probe-kept-1")
      let wr = o.readAll(3000, 100)
      checkpoint "worker probe: " & wr.escape
      check wr.startsWith("HTTP/1.1 200")
      check wr.endsWith(probeExpected)
      o.get("/probe-app-1")
      let ar = o.readAll(3000, 100)
      checkpoint "app-thread probe: " & ar.escape
      check ar.startsWith("HTTP/1.1 200")
      check ar.endsWith(probeExpected)
      o.get("/release-1")
      check o.readAll(3000, 100).endsWith("released")
      let kr = k.readAll(3000, 100)
      checkpoint "kept: " & kr.escape
      check kr.startsWith("HTTP/1.1 200")
      check kr.endsWith("kept-done param=7")
      check "x-off-loop" notin kr.toLowerAscii
      k.get("/ping")
      check k.readAll(3000, 100).endsWith("pong")

    test "HTTP/2: a kept stream read from a foreign worker task and the app thread":
      keptReqReady[1].store(false)
      var k = newH2TestConn(port)
      defer: k.close()
      var buf = ""
      buf.addRequest(1, [(":method", "GET"), (":scheme", "http"),
                         (":path", "/keep-req/h2?a=1&b=2"),
                         (":authority", "localhost")])
      k.sendAll(buf)
      for i in 0 ..< 200:
        if keptReqReady[1].load: break
        sleep(10)
      check keptReqReady[1].load
      let o = connectTimeout(port)
      defer: o.close()
      o.get("/loop-view-2")
      let lv = o.readAll(3000, 100)
      checkpoint "loop view: " & lv.escape
      check lv.endsWith("/keep-req/h2?a=1&b=2;2;{};7")
      o.get("/probe-kept-2")
      let wr = o.readAll(3000, 100)
      checkpoint "worker probe: " & wr.escape
      check wr.startsWith("HTTP/1.1 200")
      check wr.endsWith(probeExpected)
      o.get("/probe-app-2")
      let ar = o.readAll(3000, 100)
      checkpoint "app-thread probe: " & ar.escape
      check ar.startsWith("HTTP/1.1 200")
      check ar.endsWith(probeExpected)
      o.get("/release-2")
      check o.readAll(3000, 100).endsWith("released")
      let fr = k.readFrames(3000, until = proc(fs: seq[Frame]): bool =
        fs.bodyOf(1) == "kept-done param=7")
      check fr.headersOn(1) == 1
      check fr.bodyOf(1) == "kept-done param=7"
      for f in fr:
        if f.typ == uint8(ftHeaders) and f.streamId == 1:
          for (n, v) in decodeHeaders(f.payload):
            check n != "x-off-loop"
      check fr.goawayError() == -1

    test "HTTP/2: a blocking: body reads its Extended CONNECT from the snapshot":
      var c = newH2TestConn(port)
      defer: c.close()
      let status = c.extendedConnect(1, "/ws-blocking")
      check status == "200"
      let data = c.streamData(1, proc(acc: string): bool = acc.len >= 15)
      checkpoint "body: " & data.escape
      # Upgrade and intent read true from the snapshot; nothing is accepted
      # off the loop thread.
      check data == "true,true,false"

  suite "a blocking: body's own handle off the loop (#420 review)":
    test "res.responded reads the task's own latch: false, then true":
      let o = connectTimeout(port)
      defer: o.close()
      o.get("/own-responded")
      let r = o.readAll(3000, 100)
      checkpoint "own: " & r.escape
      check r.startsWith("HTTP/1.1 200")
      check r.endsWith("answered")
      # The worker stores ownAfter after its send is pushed, so the client
      # can read the response first; poll (bounded, about 2 s) past -1.
      var after = ""
      for _ in 0 ..< 14:           # ~150 ms a round (100 ms quiet + 50)
        o.get("/own-after")
        after = o.readAll(3000, 100)
        if not after.endsWith("\r\n\r\n-1"): break
        sleep(50)
      checkpoint "after: " & after.escape
      check after.endsWith("\r\n\r\n1")

    for path in ["/own-headers", "/own-trailers"]:
      test "a write through " & path[5 .. ^1] & " from its own blocking: body":
        let o = connectTimeout(port)
        defer: o.close()
        o.get(path)
        let r = o.readAll(3000, 100)
        checkpoint "got: " & r.escape
        when compileOption("assertions"):
          # With assertions on (the default, -d:release included) the
          # developer signal: the assertion fails the body. This is the only
          # branch with teeth for trailers.
          check r.startsWith("HTTP/1.1 500")
        else:
          # Assertions off (-d:danger, --assertions:off): the sink drops the
          # write silently, the send goes out.
          check r.startsWith("HTTP/1.1 200")
          check r.endsWith("sent")
          # A buffered send never emits trailers, so only the header case can
          # tell the sink from the live table here.
          if path == "/own-headers":
            check "x-own" notin r.toLowerAscii
        o.get("/ping")
        check o.readAll(3000, 100).endsWith("pong")

  stopApp.store(true)
  joinThread(appThread)
