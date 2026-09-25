## Regressions for the HTTP/2 streaming-download path, driven frame-by-frame so
## the client controls flow control exactly (curl would hide it).
##
## The client here behaves like a real one on a long download: it reads DATA and
## returns the credit as WINDOW_UPDATEs, keeping the send windows small so the
## server's per-stream backlog never reaches zero.

import std/[unittest, net, httpcore, strutils, atomics, posix, times, oserrors]
import vortex/[settings, request, server, routing]
import vortex/asyncdispatch
import vortex/http2/frames
from vortex/connection import conn
from vortex/http2/codec import h2Stream
import ./h2client

const
  totalBytes = 4 * 1024 * 1024    ## response size the tests download
  writeChunk = 8192               ## producer chunk size
  splitBytes = 512 * 1024         ## body of the one-big-write framing test
  splitWindow = 16 * 1024         ## per-stream window that test advertises
  frameChunks = 48                ## producer chunks of the framing test
  wideGrant = 8 * 1024 * 1024     ## window that never binds (framing test)

var peakPending: Atomic[int]      ## high-water mark of H2Stream.pendingBody.len

proc notePeak(res: Response) =
  ## Sample the RAW pendingBody buffer (not the backlog `len - pendingPos` that
  ## res.bufferedAmount reports): #331 was invisible to backpressure precisely
  ## because the dead prefix does not count towards the backlog. Runs on the
  ## loop thread (an async route), so touching codec state is safe.
  if res.stream == 0: return
  let c = conn(res.core, res.fd, res.gen)
  if c == nil: return
  let st = h2Stream(c, res.stream)
  if st == nil: return
  if st.pendingBody.len > peakPending.load():
    peakPending.store(st.pendingBody.len)

proc bigDownload(req: Request, res: Response) {.async.} =
  res.sendHead(Http200, "application/octet-stream")
  let chunk = repeat('x', writeChunk)
  var sent = 0
  while sent < totalBytes:
    # Low-level bool form (a string arg would resolve to `await res.write`).
    let ok = res.write(chunk.toOpenArray(0, chunk.high))
    sent += writeChunk
    notePeak(res)
    if not ok:
      await res.drained()
      notePeak(res)
  res.finish()

proc patternByte(i: int): char = char(byte(i mod 251))
  ## Deterministic body byte, so a mis-stitched write (the direct-emit prefix
  ## and the parked remainder, #334) shows up as a content mismatch and not just
  ## a wrong length.

proc splitDownload(req: Request, res: Response) {.async.} =
  ## ONE write, larger than both the peer's send window and respHighWater: the
  ## fast path can emit only a prefix straight into the write buffer and the rest
  ## has to be parked in pendingBody and drained by the scheduler (#334).
  res.sendHead(Http200, "application/octet-stream")
  var body = newString(splitBytes)
  for i in 0 ..< splitBytes: body[i] = patternByte(i)
  if not res.write(body.toOpenArray(0, body.high)):
    await res.drained()
  res.finish()

proc chunkDownload(req: Request, res: Response) {.async.} =
  ## Producer chunks of exactly SETTINGS_MAX_FRAME_SIZE with a window that never
  ## binds: one DATA frame per chunk, each exactly max-frame-sized, whether the
  ## bytes went out through the fast path or through pendingBody (#334).
  res.sendHead(Http200, "application/octet-stream")
  let chunk = repeat('y', defaultMaxFrameSize)
  for i in 0 ..< frameChunks:
    if not res.write(chunk.toOpenArray(0, chunk.high)):
      await res.drained()
  res.finish()

var rt = newRouter()
rt.get("/big", bigDownload)
rt.get("/split", splitDownload)
rt.get("/chunks", chunkDownload)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)

const budget = 100
  ## A deliberately tiny control-frame budget so the #335 test needs only a few
  ## thousand benign WINDOW_UPDATEs to trip the old accounting (the 1000 default
  ## would want a much longer download for the same signal).
var budgetSrv = newVortex(rt.toHandler,
  initVortexConfig(numThreads = 1, maxControlFrames = budget)).start(0)

type DlResult = tuple[bytes: int, goaway: int, connUpdates: int]

proc rawSend(c: var H2TestConn, data: string): bool =
  ## Send with a bounded retry, returning false once the peer is gone.
  ## std/net's `Socket.send(string)` cannot be used here: under its default
  ## SafeDisconn flag a disconnect is swallowed silently and the same buffer is
  ## retried forever, so a server that GOAWAYs mid-download (exactly the #335
  ## failure) would spin this thread at 100% CPU instead of failing the check.
  var off = 0
  let limit = epochTime() + 2.0
  while off < data.len:
    let n = posix.send(c.sock.getFd, unsafeAddr data[off], data.len - off, 0)
    if n > 0:
      off += n
    else:
      let e = osLastError().cint
      if e == EINTR: continue
      if (e == EAGAIN or e == EWOULDBLOCK) and epochTime() < limit: continue
      return false
  true

proc download(port: Port, connCreditChunk: int, connGrant = 0): DlResult =
  ## Fetch /big, returning the credit as WINDOW_UPDATEs. `connCreditChunk`
  ## splits the connection-level credit into that many bytes per frame, so a
  ## small value models a client that emits a lot of benign conn updates.
  ## `connGrant` opens the connection window wide up front (what Go, browsers
  ## and nghttp2 do), which leaves the per-stream window as the only thing that
  ## ever blocks the server -- so every later conn update "unblocks nothing".
  var c = newH2TestConn(port)
  # A send timeout, not a blocking send: when the server tears the connection
  # down mid-download (the #335 failure) it stops reading, and the next batch of
  # WINDOW_UPDATEs would otherwise wedge this thread in send() forever instead of
  # failing the assertion.
  var sndTimeout = Timeval(tv_sec: posix.Time(2), tv_usec: 0)
  discard setsockopt(c.sock.getFd, SOL_SOCKET, SO_SNDTIMEO,
                     addr sndTimeout, SockLen(sizeof(sndTimeout)))
  var req = ""
  req.addRequest(1, {":method": "GET", ":scheme": "http",
                     ":path": "/big", ":authority": "localhost"}, endStream = true)
  if connGrant > 0: req.addWindowUpdate(0, connGrant)
  c.sendRaw(req)
  result.goaway = -1
  let deadline = epochTime() + 60.0
  while result.bytes < totalBytes and epochTime() < deadline:
    let frames = c.readFrames(3000,
      until = proc(f: seq[Frame]): bool = f.len >= 1)
    if frames.len == 0: break                 # EOF or a quiet period: give up
    var consumed = 0
    for f in frames:
      if f.typ == uint8(ftData): consumed += f.payload.len
      elif f.typ == uint8(ftGoaway) and f.payload.len >= 8:
        if result.goaway < 0: result.goaway = int(get32(f.payload, 4))
    result.bytes += consumed
    if result.goaway >= 0: break              # torn down: stop before sending
    if consumed > 0:
      var wu = ""
      var left = consumed
      while left > 0:                         # connection credit: many frames
        let n = min(left, connCreditChunk)
        wu.addWindowUpdate(0, n)
        inc result.connUpdates
        left -= n
      # The stream credit goes LAST on purpose: the conn updates ahead of it are
      # then processed while this stream is still blocked on its own send window
      # (nothing queued, nothing unblocked), which is the shape #335 is about.
      wu.addWindowUpdate(1, consumed)
      if not c.rawSend(wu): break   # peer gone: report what we got
  c.close()

type BodyResult = tuple[body: string, sizes: seq[int], endStream: bool]
  ## The concatenated DATA payload, every DATA frame's payload length in order,
  ## and whether the stream was closed with END_STREAM.

proc fetchBody(port: Port, path: string, initialWindow, connGrant: int,
               credit: bool): BodyResult =
  ## Fetch `path` frame by frame. `initialWindow` is advertised as
  ## SETTINGS_INITIAL_WINDOW_SIZE ahead of the request (so it applies to this
  ## stream's send window) and `connGrant` opens the connection window; with
  ## `credit`, every DATA byte is handed back as a stream + connection
  ## WINDOW_UPDATE, which is what lets a small window drain.
  var c = newH2TestConn(port)
  var sndTimeout = Timeval(tv_sec: posix.Time(2), tv_usec: 0)
  discard setsockopt(c.sock.getFd, SOL_SOCKET, SO_SNDTIMEO,
                     addr sndTimeout, SockLen(sizeof(sndTimeout)))
  var req = ""
  var settings = ""
  settings.addSetting(setInitialWindowSize, uint32(initialWindow))
  req.addFrameHeader(settings.len, ftSettings, 0, 0)
  req.add settings
  if connGrant > 0: req.addWindowUpdate(0, connGrant)
  req.addRequest(1, {":method": "GET", ":scheme": "http",
                     ":path": path, ":authority": "localhost"}, endStream = true)
  c.sendRaw(req)
  let deadline = epochTime() + 60.0
  while not result.endStream and epochTime() < deadline:
    let frames = c.readFrames(3000,
      until = proc(f: seq[Frame]): bool = f.len >= 1)
    if frames.len == 0: break                 # EOF or a quiet period: give up
    var consumed = 0
    var gone = false
    for f in frames:
      if f.typ == uint8(ftData):
        consumed += f.payload.len
        result.body.add f.payload
        result.sizes.add f.payload.len
        if (f.flags and flagEndStream) != 0: result.endStream = true
      elif f.typ == uint8(ftGoaway) or f.typ == uint8(ftRstStream):
        gone = true
    if gone or result.endStream: break
    if credit and consumed > 0:
      var wu = ""
      wu.addWindowUpdate(0, consumed)
      wu.addWindowUpdate(1, consumed)
      if not c.rawSend(wu): break             # peer gone: report what we got
  c.close()

suite "HTTP/2 streaming download":
  test "pendingBody stays bounded while the backlog never reaches zero (#331)":
    peakPending.store(0)
    let dl = download(srv.port, connCreditChunk = 1 shl 30)
    check dl.bytes == totalBytes
    check dl.goaway == -1
    # The producer parks at respHighWater (64 KiB) of backlog, so a compacting
    # buffer settles near 2 x respHighWater plus one write chunk. Before #331 the
    # consumed prefix was never reclaimed and this grew to the whole response
    # (4 MiB here, tens of MB per stream on a real download).
    check peakPending.load() > 0              # the sampler actually ran
    check peakPending.load() < 512 * 1024

  test "benign connection WINDOW_UPDATEs during a download do not GOAWAY (#335)":
    # A real client returns its connection credit in many small updates, and
    # most of them "unblock nothing" (the streams are blocked on their own
    # window, or their producer is parked with backlog 0). Those used to be
    # charged against maxControlFrames, which only decayed on new requests, so a
    # long download on one stream tripped GOAWAY(ENHANCE_YOUR_CALM) mid-transfer.
    let dl = download(budgetSrv.port, connCreditChunk = 512,
                      connGrant = totalBytes)
    check dl.connUpdates > budget * 10        # well past the old budget
    check dl.goaway == -1                     # no GOAWAY
    check dl.bytes == totalBytes              # and the body arrived in full

  test "one write larger than the window arrives byte-exact (#334)":
    # write() emits what flow control allows straight from the producer's buffer
    # and parks the rest in pendingBody. The seam between the two is the risk:
    # assert the body is byte-for-byte what was written, in order, and that the
    # framing rules the scheduler applies (never past SETTINGS_MAX_FRAME_SIZE,
    # END_STREAM only on the final frame) still hold on the fast path.
    let r = fetchBody(srv.port, "/split", initialWindow = splitWindow,
                      connGrant = wideGrant, credit = true)
    check r.endStream
    check r.body.len == splitBytes
    var mismatch = -1
    for i in 0 ..< min(r.body.len, splitBytes):
      if r.body[i] != patternByte(i):
        mismatch = i
        break
    check mismatch == -1
    check r.sizes.len > 1                     # really was split into frames
    var oversized = 0
    for i, n in r.sizes:
      if n > defaultMaxFrameSize: inc oversized
    check oversized == 0

  test "a wide window emits one max-sized DATA frame per producer chunk (#334)":
    # The peer window never binds here, so each producer chunk (exactly
    # SETTINGS_MAX_FRAME_SIZE) must leave as exactly one full-sized DATA frame --
    # the same framing the pre-#334 copy-then-schedule path produced. A short or
    # doubled frame would mean the direct emit and the parked remainder disagree
    # about where a frame ends. An empty trailing frame is allowed: finish()
    # emits a bare END_STREAM DATA when the backlog already drained.
    let r = fetchBody(srv.port, "/chunks", initialWindow = wideGrant,
                      connGrant = wideGrant, credit = false)
    check r.endStream
    check r.body.len == frameChunks * defaultMaxFrameSize
    var full, other = 0
    for i, n in r.sizes:
      if n == defaultMaxFrameSize: inc full
      elif not (n == 0 and i == r.sizes.high): inc other
    check full == frameChunks
    check other == 0

budgetSrv.close()
srv.close()
echo "server shut down cleanly"
