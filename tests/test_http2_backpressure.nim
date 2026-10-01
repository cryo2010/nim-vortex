## Regression coverage for the two HTTP/2 backpressure caps that bound what one
## connection can pin, both fixed in #242 but never covered by a test:
##
##   * #235: a buffered (non-streaming) request body is retained until END_STREAM
##     dispatch and its flow-control bytes are credited eagerly (a body larger
##     than the receive window must be, or it could never arrive), so the window
##     does NOT bound buffered memory. An independent per-connection aggregate of
##     un-dispatched buffered bytes does, and the stream that crosses it is
##     refused (RST_STREAM(REFUSED_STREAM), retryable) instead of letting 256
##     trickled POSTs pin maxBodySize each.
##
##   * #236: a connection whose every stream has END_STREAM seen, while the
##     server still owes response bytes parked on an exhausted peer send window,
##     has nothing left to time: the read-idle deadline does not apply (the
##     client owes nothing) and writeTimeout does not either (the owed bytes are
##     in pendingBody, not in the write buffer, so the socket is not stalled).
##     "Response bytes owed but blocked on the peer's window" now arms the body
##     deadline, so a client that absorbs the initial window and goes silent is
##     cut off instead of pinning the fd, the connection slot and the parked
##     buffers forever.
##
## The client here is frame level and flow-control aware: it tracks the credit
## the server grants (connection-level and per-stream WINDOW_UPDATEs) and never
## overruns it, so a refusal in these tests is always the memory cap talking and
## never a FLOW_CONTROL_ERROR.

import std/[unittest, net, posix, os, times, tables, httpcore, strutils]
import vortex/[settings, request, server, staticfiles]
import vortex/http2/frames
import ./helper
import ./h2client

const
  maxBody = 512 * 1024        ## maxBodySize, and so the buffered aggregate cap:
                              ## max(connRecvWindow, maxBody). Any single upload
                              ## must fit, so the cap can never be smaller.
  connWindow = 256 * 1024     ## h2ConnWindow: half the cap, so the uploads below
                              ## only complete because credit stays eager
  streamWindow = 128 * 1024   ## h2StreamWindow (SETTINGS_INITIAL_WINDOW_SIZE)
  frameSize = 16 * 1024       ## <= the server's SETTINGS_MAX_FRAME_SIZE
  tricklers = 32              ## concurrent trickled POST streams
  trickleTotal = 6 * maxBody  ## bytes the trickle test pushes across them (several
                              ## times the cap, so the refusals are not one burst)

proc echoLen(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, $req.body.len)   # buffered route: the body is retained

var srv = newVortex(RequestHandler(echoLen),
                    initVortexConfig(numThreads = 1,
                                     maxBodySize = maxBody,
                                     h2StreamWindow = streamWindow,
                                     h2ConnWindow = connWindow)).start(0)

proc post(path = "/upload"): seq[(string, string)] =
  @[(":method", "POST"), (":scheme", "http"), (":path", path),
    (":authority", "localhost")]

type
  Uploader = object
    ## A frame-level uploader that respects the server's receive windows.
    c: H2TestConn
    connCredit: int                 ## connection-level bytes we may still send
    stream: Table[uint32, int]      ## per-stream bytes we may still send
    sent: Table[uint32, int]        ## bytes accepted onto each stream so far
    seen: seq[Frame]                ## every frame read from the server

proc sendAll(u: var Uploader, data: string) =
  ## posix send with correct partial-write handling: std/net's `send` re-sends
  ## from offset 0 after a partial write (duplicating bytes on the wire) and then
  ## spins forever if the peer has gone.
  var off = 0
  while off < data.len:
    let n = posix.send(u.c.sock.getFd, unsafeAddr data[off], data.len - off, 0)
    if n <= 0: return
    off += n

proc note(u: var Uploader, frames: seq[Frame]) =
  ## Fold the server's flow-control grants into the local credit.
  for f in frames:
    u.seen.add f
    if f.typ == uint8(ftWindowUpdate) and f.payload.len >= 4:
      let grant = int(get32(f.payload, 0))
      if f.streamId == 0: u.connCredit += grant
      elif f.streamId in u.stream: u.stream[f.streamId] += grant

proc drain(u: var Uploader) =
  ## Fold in whatever is already on the socket, without waiting for more. A
  ## 1 ms receive timeout, never 0: SO_RCVTIMEO of zero means "no timeout", so a
  ## drain with nothing to read would block until the server next spoke.
  u.note(u.c.readFrames(1))

proc wait(u: var Uploader, ms: int) =
  ## Block up to `ms` for the next frame (a flow-control grant, or a reset).
  u.note(u.c.readFrames(ms, until = proc(f: seq[Frame]): bool = f.len >= 1))

proc refused(u: Uploader, sid: uint32): bool =
  u.seen.rstError(sid) >= 0

proc newUploader(port: Port): Uploader =
  result.c = newH2TestConn(port)
  result.connCredit = 65535          # the protocol default until the server
                                     # grows it (it does, in its hello)
  result.wait(500)                   # SETTINGS + the connection WINDOW_UPDATE
  result.drain()

proc open(u: var Uploader, sid: uint32, path = "/upload") =
  ## Open a POST stream without END_STREAM: the body is still owed.
  u.stream[sid] = streamWindow
  u.sent[sid] = 0
  var f = ""
  f.addRequest(sid, post(path), endStream = false)
  u.sendAll(f)

proc feed(u: var Uploader, sid: uint32, n = frameSize, last = false): bool =
  ## Send one DATA frame of `n` bytes on `sid`, waiting for flow-control credit.
  ## False once the server refused the stream or the credit never arrived.
  u.drain()                                    # notice a reset promptly
  var waited = 0
  while not u.refused(sid) and
        (u.connCredit < n or u.stream.getOrDefault(sid) < n):
    if waited >= 3000: break
    u.wait(100)
    waited += 100
  if u.refused(sid): return false
  if u.connCredit < n or u.stream.getOrDefault(sid) < n: return false
  var f = ""
  f.addData(sid, 'u'.repeat(n), endStream = last)
  u.sendAll(f)
  u.connCredit -= n
  u.stream[sid] = u.stream[sid] - n
  u.sent[sid] = u.sent[sid] + n
  true

proc settle(u: var Uploader, ms = 600) =
  ## Collect the server's remaining replies so the assertions below see every
  ## RST_STREAM it decided to send.
  u.note(u.c.readFrames(ms))

proc bodyOf(frames: seq[Frame], sid: uint32): string =
  for f in frames:
    if f.typ == uint8(ftData) and f.streamId == sid: result.add f.payload

suite "HTTP/2 buffered-body memory cap (#235)":
  test "concurrent trickled bodies cannot pin more than the cap":
    # 32 POST streams on one connection, each trickled round-robin and none ever
    # ending its body: the classic shape of the ~2 GiB-per-connection vector.
    # The per-stream maxBody check never fires here (no stream gets anywhere near
    # maxBody), so the only thing that can refuse a stream is the aggregate.
    var u = newUploader(srv.port)
    var nextSid = 1'u32
    var live: seq[uint32]
    for i in 0 ..< tricklers:
      live.add nextSid
      u.open(nextSid)
      nextSid += 2
    var pushed = 0
    var refusals = 0
    var opened = tricklers
    while pushed < trickleTotal:
      var progressed = false
      for i in 0 ..< live.len:
        if u.refused(live[i]):
          # A refused stream is retryable, so a real attacker would re-open it
          # at once. Do the same: the connection keeps `tricklers` bodies in
          # flight for the whole run, which is what the cap has to bound.
          inc refusals
          check u.seen.rstError(live[i]) == int(errRefusedStream)
          live[i] = nextSid
          nextSid += 2
          inc opened
          u.open(live[i])
          progressed = true
        elif u.feed(live[i]):
          pushed += frameSize
          progressed = true
        if pushed >= trickleTotal: break
      u.wait(50)                  # let this round's resets reach us before the
      u.drain()                   # next one decides what is still open
      if not progressed: break
    u.settle()

    var held = 0
    for sid in live:
      if not u.refused(sid): held += u.sent.getOrDefault(sid)
    check pushed >= trickleTotal                 # the push really ran its course
    check refusals >= 1                          # the cap spoke
    check held <= maxBody + frameSize            # and memory stayed bounded
    check opened > tricklers                     # streams really were recycled
    check u.seen.goawayError() == -1             # stream level, not connection
    u.c.close()

  test "a cancelled stream releases its reservation for a later upload":
    # The reservation must come back on teardown, or an aborted upload would
    # permanently shrink what the connection can still accept.
    var u = newUploader(srv.port)
    u.open(1)
    var parked = 0
    while parked + frameSize <= maxBody - frameSize:
      check u.feed(1)
      parked += frameSize
    check parked > maxBody div 2                 # most of the cap is held
    var r = ""
    r.addRstStream(1, errCancel)
    u.sendAll(r)

    # A full-size upload now only fits if the cancelled stream gave its
    # reservation back: parked + maxBody is well past the cap.
    u.open(3)
    var sent = 0
    while sent < maxBody:
      check u.feed(3, last = sent + frameSize >= maxBody)
      sent += frameSize
    let fr = u.c.readFrames(3000,
      until = proc(f: seq[Frame]): bool = f.hasResponse(3))
    u.note(fr)
    check fr.hasResponse(3)
    check fr.bodyOf(3) == $maxBody
    check u.seen.rstError(3) == -1
    check u.seen.goawayError() == -1
    u.c.close()

  test "a single upload up to maxBodySize still succeeds (credit stays eager)":
    # maxBodySize is twice h2ConnWindow and four times h2StreamWindow here, so
    # this body can only arrive because a buffered route credits both windows on
    # receipt rather than on dispatch. Deferring that credit (the other candidate
    # fix for #235) would deadlock exactly this upload.
    var u = newUploader(srv.port)
    u.open(1)
    var sent = 0
    while sent < maxBody:
      check u.feed(1, last = sent + frameSize >= maxBody)
      sent += frameSize
    let fr = u.c.readFrames(3000,
      until = proc(f: seq[Frame]): bool = f.hasResponse(1))
    check fr.hasResponse(1)
    check fr.bodyOf(1) == $maxBody
    check fr.goawayError() == -1
    u.c.close()


# --- #236: a response stalled on the peer's flow-control window --------------

const
  peerWindow = 16 * 1024      ## SETTINGS_INITIAL_WINDOW_SIZE the client offers
                              ## (also the max frame size, so one DATA frame
                              ## fills it exactly)
  stallBody = 128 * 1024      ## eight windows of response body
  stallStreams = 3            ## 3 * peerWindow stays inside the default 64 KiB
                              ## connection window, so each stream blocks on its
                              ## OWN send window
  stallFileBytes = 2 * 1024 * 1024
                              ## large enough that sendFile streams it in chunks
                              ## (its first chunk lands through the outbox, after
                              ## the input pass that would have armed a deadline)
  stallTimeout = 2            ## bodyTimeout on the stall server
  grantPauseMs = 400          ## gap between the honest client's WINDOW_UPDATEs

let stallFile = getTempDir() / ("vortex_h2_stall_" & $getCurrentProcessId())
block:
  writeFile(stallFile, 'f'.repeat(stallFileBytes))

proc stallRoutes(path: string): RequestHandler =
  ## Closure over the file path (as tests/test_http2_download.nim does): a gcsafe
  ## handler may not reach a GC'd global.
  proc (req: Request, res: Response) {.gcsafe.} =
    if req.path == "/file": res.sendFile(path)
    else: res.send(Http200, 'b'.repeat(stallBody))

# writeTimeout is off on purpose: the owed bytes never reach the write buffer, so
# only the #236 deadline can end these connections. bodyTimeout is the deadline
# under test.
var stallSrv = newVortex(stallRoutes(stallFile),
                         initVortexConfig(numThreads = 1,
                                          bodyTimeout = stallTimeout,
                                          writeTimeout = 0)).start(0)

proc get(path: string): seq[(string, string)] =
  @[(":method", "GET"), (":scheme", "http"), (":path", path),
    (":authority", "localhost")]

proc sendAll(c: var H2TestConn, data: string) =
  var off = 0
  while off < data.len:
    let n = posix.send(c.sock.getFd, unsafeAddr data[off], data.len - off, 0)
    if n <= 0: return
    off += n

proc dataBytes(frames: seq[Frame]): int =
  for f in frames:
    if f.typ == uint8(ftData): result += f.payload.len

proc goSilent(path: string, streams = 1):
    tuple[served: int, goaway: int, closed: bool] =
  ## Request `streams` large responses, absorb the first window of each, then
  ## never send another byte. A server that does not time the stall holds the
  ## connection (and the parked response buffers) until process exit.
  var c = newH2TestConn(stallSrv.port)
  var f = ""
  f.addSettingFrame(setInitialWindowSize, uint32(peerWindow))
  var sid = 1'u32
  for i in 0 ..< streams:
    f.addRequest(sid, get(path), endStream = true)
    sid += 2
  c.sendAll(f)
  let first = c.readFrames(3000, until = proc(fr: seq[Frame]): bool =
    fr.count(ftData) >= streams)
  result.served = first.dataBytes
  # Silent from here: no WINDOW_UPDATE, no PING, nothing.
  let late = c.readFrames((stallTimeout + 4) * 1000,
    until = proc(fr: seq[Frame]): bool = fr.goawayError() != -1)
  result.goaway = late.goawayError()
  result.closed = c.sock.waitForClose(tries = 8, stepMs = 500)
  c.close()

suite "HTTP/2 zero-window response stall (#236)":
  test "a silent zero-window reader is cut off, with a GOAWAY":
    # Every stream has END_STREAM seen, so no read-side deadline applies, and the
    # owed bytes sit in pendingBody rather than the write buffer, so no write-side
    # one does either. Only the #236 arm ends this.
    let r = goSilent("/big", stallStreams)
    check r.served >= stallStreams * peerWindow - 1   # the windows were absorbed
    check r.served < stallStreams * stallBody         # and the rest is still owed
    check r.goaway == int(errNoError)   # a timeout, not a fault: retryable (#342)
    check r.closed                      # fd and connection slot released

  test "a sendFile download stalls the same way":
    # The chunk that fills pendingBody arrives through the outbox, not through an
    # input event, so the deadline tail in h2Input never runs for it. The sweep
    # has to notice the stall on its own.
    let r = goSilent("/file")
    check r.served >= peerWindow - 1
    check r.served < stallFileBytes
    check r.goaway == int(errNoError)
    check r.closed

  test "a client that keeps granting window is not closed":
    # The same stall shape, except the client returns credit every grantPauseMs:
    # the whole download takes several times bodyTimeout, so a deadline that did
    # not re-arm on progress (or one armed as a total-duration cap) would kill it.
    var c = newH2TestConn(stallSrv.port)
    var f = ""
    f.addSettingFrame(setInitialWindowSize, uint32(peerWindow))
    f.addRequest(1, get("/big"), endStream = true)
    c.sendAll(f)
    var seen: seq[Frame]
    var got = 0
    var rounds = 0
    let started = epochTime()
    while got < stallBody and rounds < 40:
      for x in c.readFrames(1000,
          until = proc(fr: seq[Frame]): bool = fr.count(ftData) >= 1):
        seen.add x
        if x.typ == uint8(ftData) and x.streamId == 1: got += x.payload.len
      if seen.goawayError() != -1: break
      var w = ""
      w.addWindowUpdate(1, peerWindow)
      w.addWindowUpdate(0, peerWindow)
      c.sendAll(w)
      sleep(grantPauseMs)
      inc rounds
    check got == stallBody                               # the download completed
    check epochTime() - started > float(stallTimeout)    # past the deadline
    check seen.goawayError() == -1                       # no false positive
    c.close()

stallSrv.close()
removeFile(stallFile)
srv.close()
echo "http2 backpressure ok"
