## HTTP/1.1 stale request handles (#407). A Request/Response is fd +
## generation + (h1) request serial. The generation alone only changes when the
## connection slot is recycled, so before the serial a handle kept from request
## N resolved to request N+1's state once the keep-alive connection moved on:
## its write/finish/abort/onDrain/headers/trailers/send landed in N+1's
## response, and a late off-loop send answered N+1. Each test keeps a handle
## from one request and uses it while a later request on the same connection is
## in flight (or idle, or from another connection), then checks the later
## request's response is byte-exact and the connection is still in sync.

import std/[unittest, net, posix, strutils, httpcore, atomics]
from std/os import sleep, getTempDir, `/`
import vortex/[settings, request, server, routing, staticfiles]
import ./helper

var stashedReq: Request          # handle words only (no GC'd fields): a plain
var stashedRes: Response         # global is gcsafe to read from the loop
var staleWrite: Atomic[int]      # 1 = a stale write reported success
var staleAlive: Atomic[int]      # 1 = a stale req.isAlive reported true
var staleNotResponded: Atomic[int] # 1 = a stale res.responded reported false
var stalePathLen: Atomic[int]    # what a stale req.path read back
var staleHostLen: Atomic[int]    # what a stale req.header("host") read back
var staleBuffered: Atomic[int]   # what a stale res.bufferedAmount read back
var staleDrainFired: Atomic[int] # a stale onDrain callback ran
var offLoopThread: Thread[void]

proc resetProbes() =
  staleWrite.store(0)
  staleAlive.store(0)
  staleNotResponded.store(0)
  stalePathLen.store(-1)
  staleHostLen.store(-1)
  staleBuffered.store(-1)
  staleDrainFired.store(0)

proc probeReads() {.gcsafe.} =
  ## Read-side accessors through the stale handle: all must read as dead.
  if stashedReq.isAlive: staleAlive.store(1)
  if not stashedRes.responded: staleNotResponded.store(1)
  stalePathLen.store(stashedReq.path.len)
  staleHostLen.store(stashedReq.header("host").len)
  staleBuffered.store(stashedRes.bufferedAmount)

proc hStash(req: Request, res: Response) {.gcsafe.} =
  ## Request N: keep the handles, answer normally.
  stashedReq = req
  stashedRes = res
  res.send(Http200, "first")

proc hPing(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "pong")

proc hVictimStream(req: Request, res: Response) {.gcsafe.} =
  ## Request N+1, streamed. Its own continuation is registered first, so a stale
  ## `onDrain` that aliased this request would replace it (and its closure would
  ## write "FROMSTALE" here); a stale `finish` would terminate this body after
  ## part1, a stale `abort` would close the connection, a stale write would
  ## splice "STALE" into it, a stale trailer would be emitted with it.
  res.sendHead(Http200, "text/plain")
  discard res.write("part1|")
  res.onDrain(proc (r: Response) {.gcsafe.} =
    discard r.write("part2")
    r.finish())
  let s = stashedRes
  if s.write("STALE"): staleWrite.store(1)
  s.onDrain(proc (r: Response) {.gcsafe.} =
    staleDrainFired.atomicInc
    discard r.write("FROMSTALE")
    r.finish())
  s.trailers["X-Stale-Trailer"] = "1"
  s.finish()
  s.abort()
  probeReads()

proc hVictimBuffered(req: Request, res: Response) {.gcsafe.} =
  ## Request N+1, buffered: a stale `res.headers` + `send` would answer it with
  ## the stale body and header, turning its own send into a no-op.
  let s = stashedRes
  s.headers["X-Stale"] = "1"
  s.send(Http200, "STALE")
  probeReads()
  res.send(Http200, "victim")

proc hPoke(req: Request, res: Response) {.gcsafe.} =
  ## Runs on ANOTHER connection while the stashed one sits idle between
  ## requests: a stale send there would write an unsolicited response onto it.
  let s = stashedRes
  s.send(Http200, "STALE-IDLE")
  if s.write("STALE"): staleWrite.store(1)
  s.finish()
  probeReads()
  res.send(Http200, "poked")

proc offLoopStaleSend() {.thread.} =
  {.cast(gcsafe).}:
    stashedRes.send(Http200, "STALE-OFFLOOP")

proc hVictimDeferred(req: Request, res: Response) {.gcsafe.} =
  ## Request N+1, answered from a worker. A thread of the app's own sends
  ## through request N's kept handle first; that outbox message carries N's
  ## serial and must be dropped rather than answer N+1 (which would then also
  ## get its real response as an unsolicited second one).
  {.cast(gcsafe).}:
    createThread(offLoopThread, offLoopStaleSend)
    joinThread(offLoopThread)          # the stale message is queued first
  req.blocking:
    sleep(50)
    res.send(Http200, "victim-deferred")

# A sendFile large enough for several worker chunk reads: the final chunk's
# explicit pipeline resume used to run on top of the finish's own kick, so the
# NEXT pipelined request was reset twice (a latent double reset the serial
# guard on that resume closes; the third of three pipelined files came back
# cut short before).
let filePath = getTempDir() / "stale_handle_407.bin"
var fileContent = newString(1_300_000)
for i in 0 ..< fileContent.len: fileContent[i] = char(ord('a') + (i mod 26))
writeFile(filePath, fileContent)

proc hFile(req: Request, res: Response) {.gcsafe.} =
  {.cast(gcsafe).}:
    res.sendFile(filePath)

var rt = newRouter()
rt.get("/stash", hStash)
rt.get("/file", hFile)
rt.get("/ping", hPing)
rt.get("/victim-stream", hVictimStream)
rt.get("/victim-buffered", hVictimBuffered)
rt.get("/victim-deferred", hVictimDeferred)
rt.get("/poke", hPoke)

proc get(s: Socket, path: string): HttpResp =
  s.send("GET " & path & " HTTP/1.1\r\nHost: stale.test\r\n\r\n")
  s.readHttpResponse()

proc readPipelined(s: Socket, n: int, timeoutMs = 5000): seq[string] =
  ## `n` Content-Length framed responses off one socket, pipelined-safe (the
  ## shared readHttpResponse drops bytes past the first response).
  s.setRecvTimeout(timeoutMs)
  var buf = ""
  var tmp = newString(65536)
  var pos = 0
  template fill() =
    let got = recv(s.getFd, addr tmp[0], tmp.len, cint(0))
    if got <= 0: raise newException(IOError, "eof/timeout at " & $buf.len)
    buf.add tmp.substr(0, got - 1)
  for i in 0 ..< n:
    while buf.find("\r\n\r\n", pos) < 0: fill()
    let he = buf.find("\r\n\r\n", pos)
    let head = buf[pos ..< he]
    check head.startsWith("HTTP/1.1 200")
    var clen = -1
    for line in head.split("\r\n"):
      if line.toLowerAscii.startsWith("content-length:"):
        clen = parseInt(line.split(':', 1)[1].strip)
    check clen >= 0
    pos = he + 4
    while buf.len < pos + clen: fill()
    result.add buf[pos ..< pos + clen]
    pos += clen
  check buf.len == pos                   # nothing stray after the last one

proc checkProbesDead() =
  check staleWrite.load == 0
  check staleAlive.load == 0
  check staleNotResponded.load == 0
  check stalePathLen.load == 0
  check staleHostLen.load == 0
  check staleBuffered.load == 0

withServer(rt.toHandler, initVortexConfig(numThreads = 1, workerThreads = 2),
           srv):
  let port = srv.port

  suite "HTTP/1.1 stale request handles (#407)":
    test "a kept handle cannot write, finish, abort, drain or trail the next streamed request":
      resetProbes()
      let s = connectTimeout(port)
      defer: s.close()
      let a = s.get("/stash")
      check a.ok and a.body == "first"
      let b = s.get("/victim-stream")
      check b.ok
      check b.head.startsWith("HTTP/1.1 200")
      check b.body == "part1|part2"
      check "x-stale-trailer" notin b.trailers.toLowerAscii
      checkProbesDead()
      sleep(50)                          # a loop pass for any queued drain kick
      check staleDrainFired.load == 0
      # The connection is still in sync: no extra bytes, no close.
      let c = s.get("/ping")
      check c.ok and c.body == "pong"

    test "a kept handle cannot set headers on or answer the next buffered request":
      resetProbes()
      let s = connectTimeout(port)
      defer: s.close()
      check s.get("/stash").body == "first"
      let b = s.get("/victim-buffered")
      check b.ok
      check b.body == "victim"
      check "x-stale" notin b.head.toLowerAscii
      checkProbesDead()
      let c = s.get("/ping")
      check c.ok and c.body == "pong"

    test "a late off-loop send through a kept handle does not answer the next request":
      resetProbes()
      let s = connectTimeout(port)
      defer: s.close()
      check s.get("/stash").body == "first"
      let b = s.get("/victim-deferred")
      check b.ok
      check b.body == "victim-deferred"
      let c = s.get("/ping")             # no unsolicited second response queued
      check c.ok and c.body == "pong"

    test "a kept handle used while its connection idles writes nothing onto it":
      resetProbes()
      let s = connectTimeout(port)
      defer: s.close()
      check s.get("/stash").body == "first"
      block:
        let other = connectTimeout(port)
        defer: other.close()
        let p = other.get("/poke")
        check p.ok and p.body == "poked"
      checkProbesDead()
      let c = s.get("/ping")
      check c.ok and c.body == "pong"

    test "a handle from a closed connection cannot reach the slot's next occupant":
      resetProbes()
      block:
        let s1 = connectTimeout(port)
        check s1.get("/stash").body == "first"
        s1.close()
      sleep(50)                          # let the server close (and recycle) it
      let s2 = connectTimeout(port)
      defer: s2.close()
      let b = s2.get("/victim-buffered")
      check b.ok and b.body == "victim"
      check "x-stale" notin b.head.toLowerAscii
      checkProbesDead()
      let b2 = s2.get("/victim-stream")
      check b2.ok and b2.body == "part1|part2"
      check staleDrainFired.load == 0

    test "three pipelined sendFile responses are each byte-exact (final-chunk resume)":
      let s = connectTimeout(port)
      defer: s.close()
      var req = ""
      for i in 0 ..< 3: req.add "GET /file HTTP/1.1\r\nHost: stale.test\r\n\r\n"
      req.add "GET /ping HTTP/1.1\r\nHost: stale.test\r\n\r\n"
      s.send(req)
      var bodies: seq[string]
      try:
        bodies = s.readPipelined(4)
      except IOError as e:
        checkpoint "pipelined read failed: " & e.msg
      check bodies.len == 4
      if bodies.len == 4:
        for i in 0 ..< 3: check bodies[i] == fileContent
        check bodies[3] == "pong"
