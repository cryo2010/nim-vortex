## Regressions for the HTTP/2 streaming-download path, driven frame-by-frame so
## the client controls flow control exactly (curl would hide it).
##
## The client here behaves like a real one on a long download: it reads DATA and
## returns the credit as WINDOW_UPDATEs, keeping the send windows small so the
## server's per-stream backlog never reaches zero.

import std/[unittest, net, httpcore, strutils, atomics, posix, times, oserrors, os]
import vortex/[settings, request, server, routing, staticfiles]
import vortex/asyncdispatch
import vortex/http2/frames
from vortex/connection import conn, fileChunkCap
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

# --- sendFile read-ahead (#340) ---------------------------------------------

const
  fileBytes = 3 * 1024 * 1024     ## the file the read-ahead test downloads
  fileWindow = 32 * 1024          ## per-stream window it advertises
  fileReadAheadBound = 3 * fileChunkCap
    ## fileReadAhead (one chunk) + the chunk that passes the gate + the chunk
    ## already in flight when the gate closes (request.nim: fileReadAhead).

let filePath = getTempDir() / ("vortex_h2_readahead_" & $getCurrentProcessId())
block:
  var body = newString(fileBytes)
  for i in 0 ..< fileBytes: body[i] = patternByte(i)
  writeFile(filePath, body)

var peakBacklog: Atomic[int]      ## high-water mark of stream 1's backlog
var peekRuns: Atomic[int]

proc peekBacklogRoute(req: Request, res: Response) {.gcsafe.} =
  ## Sample the *download* stream's unsent backlog from a second stream on the
  ## same connection. Runs on the loop thread (a plain handler), so it reads codec
  ## state safely, and a pkFileChunk pin does not pause h2 input -- which is what
  ## lets these requests be served while the download is mid-flight.
  let c = conn(res.core, res.fd, res.gen)
  if c != nil:
    let st = h2Stream(c, 1'u32)
    if st != nil:
      let backlog = st.pendingBody.len - st.pendingPos
      if backlog > peakBacklog.load(): peakBacklog.store(backlog)
  peekRuns.store(peekRuns.load() + 1)
  res.send(Http200, "ok")

proc fileRoute(path: string): RequestHandler =
  ## Closure over the path (as tests/test_static_files.nim does): a gcsafe
  ## handler may not reach a GC'd global.
  proc (req: Request, res: Response) {.gcsafe.} =
    res.sendFile(path)

rt.get("/file", fileRoute(filePath))
rt.get("/peek", peekBacklogRoute)

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

proc floodIdleUpdates(port: Port, frames: int): int =
  ## Hold a stream open that can never receive DATA (its window is advertised as
  ## 0), then flood connection-level WINDOW_UPDATEs of increment 1. None of them
  ## unblocks anything and no DATA was ever sent to earn credit for them, so the
  ## budget must still trip. Returns the GOAWAY error code, or -1 if none came.
  var c = newH2TestConn(port)
  var sndTimeout = Timeval(tv_sec: posix.Time(2), tv_usec: 0)
  discard setsockopt(c.sock.getFd, SOL_SOCKET, SO_SNDTIMEO,
                     addr sndTimeout, SockLen(sizeof(sndTimeout)))
  var req = ""
  var settings = ""
  settings.addSetting(setInitialWindowSize, 0'u32)
  req.addFrameHeader(settings.len, ftSettings, 0, 0)
  req.add settings
  req.addRequest(1, {":method": "GET", ":scheme": "http",
                     ":path": "/big", ":authority": "localhost"}, endStream = true)
  for i in 0 ..< frames: req.addWindowUpdate(0, 1)
  discard c.rawSend(req)                      # the peer may close mid-burst
  result = -1
  let deadline = epochTime() + 10.0
  while result < 0 and epochTime() < deadline:
    let got = c.readFrames(3000,
      until = proc(f: seq[Frame]): bool = f.len >= 1)
    if got.len == 0: break
    for f in got:
      if f.typ == uint8(ftData) and f.payload.len > 0:
        result = -2                           # DATA on a zero window: broken test
        break
      if f.typ == uint8(ftGoaway) and f.payload.len >= 8:
        result = int(get32(f.payload, 4))
        break
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

proc fileDownload(port: Port): tuple[body: string, endStream: bool, peeks: int] =
  ## Fetch /file (a sendFile response) with a small per-stream window, and probe
  ## the download stream's backlog from a second stream after every read batch.
  var c = newH2TestConn(port)
  var sndTimeout = Timeval(tv_sec: posix.Time(2), tv_usec: 0)
  discard setsockopt(c.sock.getFd, SOL_SOCKET, SO_SNDTIMEO,
                     addr sndTimeout, SockLen(sizeof(sndTimeout)))
  var req = ""
  var settings = ""
  settings.addSetting(setInitialWindowSize, uint32(fileWindow))
  req.addFrameHeader(settings.len, ftSettings, 0, 0)
  req.add settings
  req.addWindowUpdate(0, wideGrant)          # only the stream window throttles
  req.addRequest(1, {":method": "GET", ":scheme": "http",
                     ":path": "/file", ":authority": "localhost"},
                 endStream = true)
  c.sendRaw(req)
  var nextPeek = 3'u32
  let deadline = epochTime() + 60.0
  while not result.endStream and epochTime() < deadline:
    let frames = c.readFrames(3000,
      until = proc(f: seq[Frame]): bool = f.len >= 1)
    if frames.len == 0: break
    var consumed, consumedFile = 0
    var gone = false
    for f in frames:
      if f.typ == uint8(ftData):
        consumed += f.payload.len
        if f.streamId == 1:
          consumedFile += f.payload.len
          result.body.add f.payload
          if (f.flags and flagEndStream) != 0: result.endStream = true
      elif f.typ == uint8(ftGoaway) or
           (f.typ == uint8(ftRstStream) and f.streamId == 1):
        gone = true
    if gone: break
    var outFrames = ""
    if consumed > 0: outFrames.addWindowUpdate(0, consumed)
    if consumedFile > 0: outFrames.addWindowUpdate(1, consumedFile)
    if not result.endStream:
      outFrames.addRequest(nextPeek, {":method": "GET", ":scheme": "http",
                                      ":path": "/peek", ":authority": "localhost"},
                           endStream = true)
      nextPeek += 2
      inc result.peeks
    if outFrames.len > 0 and not c.rawSend(outFrames): break
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

  test "a WINDOW_UPDATE flood on a stream we send nothing to still GOAWAYs (#335)":
    # The other side of the same fix: benign updates ride credit earned by DATA
    # we sent, so a peer that parks a stream (zero window) and floods updates
    # that unblock nothing has no credit and must trip ENHANCE_YOUR_CALM (11)
    # after maxControlFrames, exactly as the PING and SETTINGS floods do.
    check floodIdleUpdates(budgetSrv.port, frames = budget * 20) == 11

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

  test "sendFile read-ahead keeps the backlog bounded and completes (#340)":
    # A slow reader (32 KiB stream window) against a 3 MiB sendFile: the backlog
    # is bounded and the transfer still completes, byte for byte. The bound is
    # the read-ahead budget plus two chunks -- the chunk that passes the gate,
    # plus the one already in flight, which is always written when it lands. With
    # the gate moved ahead of the write (#340) but the budget left at two chunks
    # this test sees ~960 KiB instead of ~736 KiB.
    peakBacklog.store(0)
    peekRuns.store(0)
    let r = fileDownload(srv.port)
    check r.endStream
    check r.body.len == fileBytes
    var mismatch = -1
    for i in 0 ..< min(r.body.len, fileBytes):
      if r.body[i] != patternByte(i):
        mismatch = i
        break
    check mismatch == -1
    check r.peeks > 20                        # the probe really ran, repeatedly
    check peekRuns.load() > 20
    check peakBacklog.load() > 0              # and saw a real backlog
    check peakBacklog.load() <= fileReadAheadBound

budgetSrv.close()
srv.close()
removeFile(filePath)
echo "server shut down cleanly"
