## Regression for #399: the chunk size a streaming producer picks must not be
## able to deadlock its own HTTP/2 stream.
##
## A `res.write` larger than respHighWater (64 KiB) is accepted whole, so most
## of it parks in the stream's pendingBody. The backpressure verdict was then
## taken on that pre-flush backlog, while the flush in between had already
## pushed up to h2MaxRefillRounds x respHighWater (1 MiB) of it to the socket:
## a 1 MiB chunk was routinely gone by the time `write` returned, and the
## producer was parked with an empty backlog AND an empty write buffer. Nothing
## was left to drain, so no socket drain, no WINDOW_UPDATE and no scheduler pass
## was ever going to run again -- `onDrain` could not fire and the response
## stopped mid-body, with no RST_STREAM and no GOAWAY.
##
## `res.sendFile` had the same hole one layer down, in the read-ahead gate: it
## parked the next disk read on `onDrain` whenever the backlog was already at
## the budget, relying on the write that followed to report backpressure and arm
## it. The last suite below drives that regime directly.
##
## Driven frame by frame (curl would hide the flow control). `credit = false` is
## the shape that reproduces it and the shape curl actually has: a client whose
## window is far larger than the response returns no WINDOW_UPDATE at all, so
## the socket drain is the server's only wake-up. A crediting client papered
## over the stall, because its updates kept re-entering the scheduler.

import std/[unittest, net, posix, times, httpcore, atomics, os]
import vortex/[settings, request, server, routing, staticfiles]
import vortex/asyncdispatch
import vortex/http2/frames
from vortex/connection import respHighWater, conn
from vortex/http2/codec import h2Stream
import ./h2client

const
  totalBytes = 4 * 1024 * 1024    ## response size every write route streams
  wideGrant = 8 * 1024 * 1024     ## a window that never binds
  smallWindow = 16 * 1024         ## a window far below one write chunk
  bigChunk = 1024 * 1024          ## 16 x respHighWater per res.write
  backlogBound = bigChunk + respHighWater
    ## What a parked producer may hold, measured on the RAW pendingBody buffer:
    ## one write chunk (accepted whole) plus the high-water mark the backlog had
    ## to be under for the producer to be invited back at all. The 16 KiB-window
    ## regime below sits at exactly this, every run, so the bound is tight and
    ## has to be `<=`. Resuming a producer whose backlog is still over the mark
    ## would let it append another chunk per drain and blow straight past it:
    ## loosening h2ResumeProducers to 2 x respHighWater peaks at 1196032 and
    ## fails this check.

var peakPending: Atomic[int]      ## high-water mark of H2Stream.pendingBody.len

proc notePeak(res: Response) =
  ## Sample the RAW pendingBody buffer, not the `len - pendingPos` backlog that
  ## res.bufferedAmount reports: the sent-but-not-yet-compacted prefix is real
  ## retention that backpressure cannot see (as in #331), and in the silent
  ## regime res.bufferedAmount understates what the stream holds by about half
  ## (655360 reported against 983040 actually retained). Same sampler as
  ## tests/test_http2_download.nim's. Loop thread (a plain handler or an onDrain
  ## callback), so touching codec state is safe.
  if res.stream == 0: return
  let c = conn(res.core, res.fd, res.gen)
  if c == nil: return
  let st = h2Stream(c, res.stream)
  if st == nil: return
  if st.pendingBody.len > peakPending.load():
    peakPending.store(st.pendingBody.len)

proc patternByte(i: int): char = char(byte(i mod 251))
  ## Deterministic body byte, so a resumed producer that loses or duplicates a
  ## chunk shows up as a content mismatch and not just a wrong length.

proc chunkRoute(chunkLen: int): RequestHandler =
  ## The nim-navi /download shape: sendHead, one res.write per slice, and
  ## re-register res.onDrain whenever write reports backpressure. Closure over
  ## the chunk size (a gcsafe handler may not reach a GC'd global).
  proc (req: Request, res: Response) {.gcsafe.} =
    res.sendHead(Http200, "application/octet-stream")
    var sent = 0
    proc pump(r: Response) {.gcsafe.} =
      while sent < totalBytes:
        let n = min(chunkLen, totalBytes - sent)
        var chunk = newString(n)
        for i in 0 ..< n: chunk[i] = patternByte(sent + i)
        let ok = r.write(chunk.toOpenArray(0, n - 1))
        sent += n
        notePeak(r)
        if not ok:
          r.onDrain(pump)
          return
      r.finish()
    pump(res)

# --- a drain wait that no false verdict armed (#403) ------------------------

const drainChunk = 32 * 1024
  ## Half of respHighWater: a write this size can leave a backlog that is
  ## non-zero (the socket took part of it) yet under the mark, so `write`
  ## returns true and nothing marks the stream backed up.

var drainRegs, drainFires: Atomic[int]
  ## onDrain registrations the sync routes below made, and callbacks fired:
  ## equal once a response is done (each registration fired exactly once).

proc fillChunk(chunk: var string, sent, n: int) =
  for i in 0 ..< n: chunk[i] = patternByte(sent + i)

proc drainedEveryWrite(req: Request, res: Response) {.async.} =
  ## `await res.drained()` after EVERY write, whatever the verdict. The wait is
  ## registered while the stream may hold a small backlog that no false verdict
  ## marked, which is the state h2ResumeProducers never visited (#403).
  res.sendHead(Http200, "application/octet-stream")
  var chunk = newString(drainChunk)
  var sent = 0
  while sent < totalBytes:
    let n = min(drainChunk, totalBytes - sent)
    fillChunk(chunk, sent, n)
    # Low-level bool form on purpose (a string arg resolves to `await res.write`).
    discard res.write(chunk.toOpenArray(0, n - 1))
    sent += n
    await res.drained()
  res.finish()

proc onDrainEveryWrite(req: Request, res: Response) {.gcsafe.} =
  ## The sync shape of the same producer: write one chunk, then resume from
  ## `res.onDrain` unconditionally. Every registration lands on an unmarked
  ## stream, most of them with nothing queued at all, which no drain path
  ## visited either (#403).
  res.sendHead(Http200, "application/octet-stream")
  var sent = 0
  proc pump(r: Response) {.gcsafe.} =
    if sent >= totalBytes:
      r.finish()
      return
    let n = min(drainChunk, totalBytes - sent)
    var chunk = newString(n)
    fillChunk(chunk, sent, n)
    discard r.write(chunk.toOpenArray(0, n - 1))
    sent += n
    drainRegs.atomicInc
    r.onDrain(proc (r2: Response) {.gcsafe.} =
      drainFires.atomicInc
      pump(r2))
  pump(res)

proc endWithPendingDrain(abortIt: bool): RequestHandler =
  ## Register a drain and end the response in the same breath, with a backlog
  ## the 16 KiB window keeps queued: `finish` / `abort` drop the pending
  ## callback, so neither the loop pass the registration queued nor the drain
  ## that follows may fire it after the response is over.
  proc (req: Request, res: Response) {.gcsafe.} =
    res.sendHead(Http200, "application/octet-stream")
    var chunk = newString(drainChunk)
    fillChunk(chunk, 0, drainChunk)
    discard res.write(chunk.toOpenArray(0, drainChunk - 1))
    drainRegs.atomicInc
    res.onDrain(proc (r: Response) {.gcsafe.} = drainFires.atomicInc)
    if abortIt: res.abort() else: res.finish()

var flushSpins: Atomic[int]
  ## Turns of the flush-before-finish loop below: one per drained() it awaited.

proc flushBeforeFinish(req: Request, res: Response) {.async.} =
  ## Flush the whole body before finishing, by awaiting drained() until nothing
  ## is buffered. Against a 16 KiB window that the peer stops crediting, one
  ## 32 KiB write leaves a 16 KiB backlog under the mark that nothing can move,
  ## and the loop must park on it, not spin (#403 review).
  res.sendHead(Http200, "application/octet-stream")
  var chunk = newString(drainChunk)
  fillChunk(chunk, 0, drainChunk)
  discard res.write(chunk.toOpenArray(0, drainChunk - 1))
  while res.bufferedAmount > 0:
    flushSpins.atomicInc
    await res.drained()
  res.finish()

var kicksQueued: Atomic[int]
  ## LoopCore.drainKicks length right after a burst of registrations.

proc manyRegistrations(req: Request, res: Response) {.gcsafe.} =
  ## 1000 onDrain registrations in one handler: each replaces the last, and the
  ## loop pass they are owed must be queued once, not 1000 times.
  res.sendHead(Http200, "application/octet-stream")
  var chunk = newString(1024)
  fillChunk(chunk, 0, chunk.len)
  discard res.write(chunk.toOpenArray(0, chunk.high))
  for i in 0 ..< 1000:
    drainRegs.atomicInc
    res.onDrain(proc (r: Response) {.gcsafe.} =
      drainFires.atomicInc
      r.finish())
  kicksQueued.store(res.core.drainKicks.len)

# --- sendFile in the same regime (#399) -------------------------------------

const
  fileBytes = 16 * 1024 * 1024    ## the sendFile response the bursty reader pulls
  fileGrant = 48 * 1024 * 1024    ## wider than the whole file: curl's shape, so
                                  ## the peer never returns a WINDOW_UPDATE and
                                  ## the socket is the only throttle there is
  burstBytes = 2 * 1024 * 1024    ## bytes the bursty reader drains per gulp
  burstPauseMs = 25               ## and how long it stops reading between gulps
  rcvBufBytes = 2 * 1024 * 1024   ## receive buffer: big enough that one flush
                                  ## can absorb the whole backlog the pause
                                  ## built, which is the coincidence #399 needs

let filePath = getTempDir() / ("vortex_h2_writestall_" & $getCurrentProcessId())
block:
  var body = newString(fileBytes)
  for i in 0 ..< fileBytes: body[i] = patternByte(i)
  writeFile(filePath, body)

proc fileRoute(path: string): RequestHandler =
  ## Closure over the path (as tests/test_http2_download.nim does): a gcsafe
  ## handler may not reach a GC'd global.
  proc (req: Request, res: Response) {.gcsafe.} =
    res.sendFile(path)

var rt = newRouter()
rt.get("/w1m", chunkRoute(bigChunk))        ## 16 x respHighWater per write
rt.get("/w256k", chunkRoute(256 * 1024))    ## 4 x respHighWater per write
rt.get("/w64k", chunkRoute(64 * 1024))      ## exactly respHighWater (control)
rt.get("/file", fileRoute(filePath))
rt.get("/drained-every", drainedEveryWrite)
rt.get("/ondrain-every", onDrainEveryWrite)
rt.get("/ondrain-finish", endWithPendingDrain(abortIt = false))
rt.get("/ondrain-abort", endWithPendingDrain(abortIt = true))
rt.get("/flush-finish", flushBeforeFinish)
rt.get("/many-regs", manyRegistrations)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)

type DlResult = tuple[body: string, endStream: bool, gone: bool]

proc dataBytes(frames: seq[Frame]): int =
  for f in frames:
    if f.typ == uint8(ftData): result += f.payload.len

proc collect(r: var DlResult, frames: seq[Frame]) =
  for f in frames:
    if f.typ == uint8(ftData) and f.streamId == 1:
      r.body.add f.payload
      if (f.flags and flagEndStream) != 0: r.endStream = true
    elif f.typ == uint8(ftGoaway) or
         (f.typ == uint8(ftRstStream) and f.streamId == 1):
      r.gone = true

proc openStream(port: Port, path: string, initialWindow,
                connGrant: int): H2TestConn =
  ## Connect and request `path` on stream 1, advertising `initialWindow` as
  ## SETTINGS_INITIAL_WINDOW_SIZE ahead of the request (so it applies to this
  ## stream's send window) and opening the connection window by `connGrant`.
  result = newH2TestConn(port)
  # A send timeout, not a blocking send: when the server stops reading (it
  # stalls, or tears the connection down) the next WINDOW_UPDATE batch would
  # otherwise wedge this thread in send() forever instead of failing the check.
  var sndTimeout = Timeval(tv_sec: posix.Time(5), tv_usec: 0)
  discard setsockopt(result.sock.getFd, SOL_SOCKET, SO_SNDTIMEO,
                     addr sndTimeout, SockLen(sizeof(sndTimeout)))
  var rcvBuf = cint(rcvBufBytes)
  discard setsockopt(result.sock.getFd, SOL_SOCKET, SO_RCVBUF,
                     addr rcvBuf, SockLen(sizeof(rcvBuf)))
  var req = ""
  var settings = ""
  settings.addSetting(setInitialWindowSize, uint32(initialWindow))
  req.addFrameHeader(settings.len, ftSettings, 0, 0)
  req.add settings
  if connGrant > 0: req.addWindowUpdate(0, connGrant)
  req.addRequest(1, {":method": "GET", ":scheme": "http",
                     ":path": path, ":authority": "localhost"}, endStream = true)
  result.sendRaw(req)

const
  quietMs = 6000     ## no DATA for this long = the stream really is stalled.
                     ## Generous on purpose: the give-up has to be keyed on a
                     ## lack of PROGRESS, not on a short quiet period, or a host
                     ## running a stress soak beside the suite goes red.
  deadlineSecs = 30.0   ## outer wall-clock cap, unchanged: the give-up above is
                        ## what had to be relaxed, not the total budget.

proc fetchBody(port: Port, path: string, initialWindow, connGrant: int,
               credit = true): DlResult =
  ## Fetch `path` frame by frame, returning every DATA byte as a stream and a
  ## connection WINDOW_UPDATE so a small window still drains.
  var c = openStream(port, path, initialWindow, connGrant)
  let deadline = epochTime() + deadlineSecs
  while not result.endStream and epochTime() < deadline:
    let frames = c.readFrames(quietMs,
      until = proc(f: seq[Frame]): bool = f.len >= 1)
    if frames.len == 0: break                 # EOF or no progress: stalled
    let consumed = dataBytes(frames)
    result.collect(frames)
    if result.gone or result.endStream: break
    if credit and consumed > 0:
      var wu = ""
      wu.addWindowUpdate(0, consumed)
      wu.addWindowUpdate(1, consumed)
      if not c.rawSend(wu): break             # peer gone: report what we got
  c.close()

proc burstyFetch(port: Port, path: string): DlResult =
  ## Fetch `path` with a window wider than the whole response and a reader that
  ## alternates a pause with a greedy gulp. That drives the #399 regime for
  ## sendFile: the pause lets the socket fill and the stream's backlog build
  ## past the read-ahead budget, so the next arrived chunk's gate defers its
  ## read, and the gulp then empties the socket, so a write that lands in that
  ## instant flushes the whole backlog and comes back WRITABLE with no drain
  ## left to fire the deferred read. Sends no WINDOW_UPDATE at all, like curl.
  var c = openStream(port, path, fileGrant, fileGrant)
  let deadline = epochTime() + deadlineSecs
  while not result.endStream and epochTime() < deadline:
    sleep(burstPauseMs)                       # stop reading: let it back up
    let frames = c.readFrames(quietMs, until = proc(f: seq[Frame]): bool =
      dataBytes(f) >= burstBytes)             # then drain a whole gulp at once
    if frames.len == 0: break                 # EOF or no progress: stalled
    result.collect(frames)
    if result.gone: break
  c.close()

proc bodyMismatch(body: string): int =
  ## Index of the first byte that is not what the producer wrote, or -1.
  for i in 0 ..< body.len:
    if body[i] != patternByte(i): return i
  -1

template checkBody(r: DlResult, want: int) =
  ## A template, not a proc: `check` has to expand inside the `test` block to
  ## mark it FAILED (from a proc it only sets the process exit code, and the
  ## suite still prints [OK]).
  let res = r
  check res.endStream
  check not res.gone
  check res.body.len == want
  check bodyMismatch(res.body) == -1

template checkBound(floor: int) =
  ## What the producer retained stayed within the bound, and (with a floor of
  ## zero or more) really did back up. The floor is respHighWater where the
  ## peer's window makes the backlog deterministic. In the socket-paced regime
  ## pass -1: how far the producer runs ahead depends on how fast the host's
  ## loopback reader is (112 KiB to 960 KiB across runs on a Mac), and a Linux
  ## loopback with autotuned socket buffers can absorb every 1 MiB chunk inside
  ## the write that produced it, so the sampled peak is legitimately 0 there
  ## (seen on CI). The upper bound is the assertion that matters: a resume
  ## condition loosened by one mark overshoots it in the windowed regime.
  if floor >= 0:
    check peakPending.load() > floor
  check peakPending.load() <= backlogBound

suite "HTTP/2 streamed writes larger than the high-water mark (#399)":
  test "1 MiB per write completes with a silent peer (#399)":
    # The #399 report, as curl sees it: 16 x respHighWater per res.write, a
    # window far wider than the response so the client never sends a
    # WINDOW_UPDATE, and nothing throttling but the server's own write-buffer
    # cap. The producer was parked with nothing pending and the stream stopped
    # after 3 MiB of the 4. The retention bound is checked here too, not just in
    # the windowed regime below: this is the shape where res.bufferedAmount
    # understates what the stream actually holds (it does not count the sent
    # prefix pendingBody has yet to compact away), so sampling the raw buffer is
    # the only way to see it.
    peakPending.store(0)
    checkBody(fetchBody(srv.port, "/w1m", initialWindow = wideGrant,
                        connGrant = wideGrant, credit = false), totalBytes)
    checkBound(floor = -1)

  test "256 KiB per write completes with a silent peer":
    checkBody(fetchBody(srv.port, "/w256k", initialWindow = wideGrant,
                        connGrant = wideGrant, credit = false), totalBytes)

  test "64 KiB per write completes with a silent peer (the control)":
    # Exactly respHighWater per write: this shape always worked (the direct-emit
    # path leaves no backlog, so write kept returning true and the producer
    # never parked) and must keep working.
    checkBody(fetchBody(srv.port, "/w64k", initialWindow = wideGrant,
                        connGrant = wideGrant, credit = false), totalBytes)

  test "1 MiB per write completes with a crediting peer":
    checkBody(fetchBody(srv.port, "/w1m", initialWindow = wideGrant,
                        connGrant = wideGrant), totalBytes)

  test "a 1 MiB-chunk producer against a slow reader stays bounded":
    # Same producer against a 16 KiB stream window, so the backlog is drained in
    # window-sized sips and the WINDOW_UPDATE path -- not the socket drain -- is
    # what has to notice the backlog finally fell under the mark. The producer is
    # parked and resumed repeatedly here, so this is also where the other half of
    # the fix is measured: never stalling must not mean resuming a producer whose
    # backlog is still large.
    peakPending.store(0)
    checkBody(fetchBody(srv.port, "/w1m", initialWindow = smallWindow,
                        connGrant = wideGrant), totalBytes)
    checkBound(floor = respHighWater)

  test "256 KiB per write completes with a small peer window":
    checkBody(fetchBody(srv.port, "/w256k", initialWindow = smallWindow,
                        connGrant = wideGrant), totalBytes)

  test "64 KiB per write completes with a small peer window (the control)":
    checkBody(fetchBody(srv.port, "/w64k", initialWindow = smallWindow,
                        connGrant = wideGrant), totalBytes)

proc resetDrainCounts() =
  drainRegs.store(0)
  drainFires.store(0)

template checkFiredOnce() =
  ## Every registration the route made fired, and none fired twice: the loop
  ## pass a registration queues and the drain event it may also be owed must
  ## not both deliver it. A template so the `check` marks the test FAILED.
  check drainRegs.load() > 0
  check drainFires.load() == drainRegs.load()

suite "a drain wait registered without a false verdict (#403)":
  test "await res.drained() after every 32 KiB write completes (#403)":
    # A GUARD, not a reproduction: the #403 report's shape (a wide window, so
    # the peer's flow control never binds, and a producer that awaits the drain
    # after every write instead of only after a false), but a loopback that
    # takes every 32 KiB chunk inside the write never leaves the small unmarked
    # backlog the bug needs, and on a Mac it does, so this passes with the fix
    # reverted. The bursty reader below is the reproduction.
    checkBody(fetchBody(srv.port, "/drained-every", initialWindow = wideGrant,
                        connGrant = wideGrant, credit = false), totalBytes)

  test "await res.drained() after every write against a bursty reader":
    # The same producer against a reader that pauses, so the socket backs up
    # and the waits land on a non-empty backlog under the mark. With the fix
    # reverted the response stopped at 800 KiB of the 4 MiB.
    checkBody(burstyFetch(srv.port, "/drained-every"), totalBytes)

  test "await res.drained() after every write against a small peer window":
    # Every 32 KiB write returns true and leaves a 16 KiB window-held backlog,
    # under the mark and with no false verdict. The loop pass the wait is owed
    # does not fire it (bytes are still buffered); the WINDOW_UPDATE that moves
    # them runs the resume scan, which the registration marked the stream for.
    checkBody(fetchBody(srv.port, "/drained-every", initialWindow = smallWindow,
                        connGrant = wideGrant), totalBytes)

  test "res.onDrain after every 32 KiB write completes (#403)":
    # The sync shape. Most of these registrations find nothing queued at all,
    # so there is no drain left to fire them and only a pass the loop owes the
    # registration itself can.
    resetDrainCounts()
    checkBody(fetchBody(srv.port, "/ondrain-every", initialWindow = wideGrant,
                        connGrant = wideGrant, credit = false), totalBytes)
    checkFiredOnce()

  test "res.onDrain after every write against a bursty reader":
    resetDrainCounts()
    checkBody(burstyFetch(srv.port, "/ondrain-every"), totalBytes)
    checkFiredOnce()

  test "res.onDrain after every write against a small peer window":
    # Window-blocked: the registration finds a backlog the peer's window holds
    # back, and the WINDOW_UPDATE path has to fire it as well.
    resetDrainCounts()
    checkBody(fetchBody(srv.port, "/ondrain-every", initialWindow = smallWindow,
                        connGrant = wideGrant), totalBytes)
    checkFiredOnce()

  test "finish() drops a drain registered just before it":
    resetDrainCounts()
    checkBody(fetchBody(srv.port, "/ondrain-finish", initialWindow = smallWindow,
                        connGrant = wideGrant), drainChunk)
    sleep(100)                              # let any stray loop pass run
    check drainRegs.load() == 1
    check drainFires.load() == 0

  test "abort() drops a drain registered just before it":
    resetDrainCounts()
    let r = fetchBody(srv.port, "/ondrain-abort", initialWindow = smallWindow,
                      connGrant = wideGrant)
    check r.gone                            # RST_STREAM, not a clean end
    check not r.endStream
    sleep(100)
    check drainRegs.load() == 1
    check drainFires.load() == 0

  test "a flush-before-finish loop parks on a stalled peer, then completes":
    # `while res.bufferedAmount > 0: await res.drained()` against a 16 KiB
    # window the peer stops crediting. The loop pass a registration is owed
    # used to fire it whenever the backlog was under the mark, so each wait
    # resolved on the next zero-timeout pass with the same 16 KiB still
    # buffered and re-registered: ~30k turns a second, a busy loop. It must
    # park until the peer credits the window, then finish.
    flushSpins.store(0)
    var c = openStream(srv.port, "/flush-finish", smallWindow, wideGrant)
    var r: DlResult
    r.collect(c.readFrames(2000, until = proc(f: seq[Frame]): bool =
      dataBytes(f) >= smallWindow))
    check r.body.len == smallWindow         # the window's worth, then stalled
    sleep(100)
    let s0 = flushSpins.load()
    sleep(500)
    let stalledTurns = flushSpins.load() - s0
    check stalledTurns <= 2                 # parked (0 measured), not spinning
    var wu = ""
    wu.addWindowUpdate(1, drainChunk)       # now let the rest through
    check c.rawSend(wu)
    r.collect(c.readFrames(quietMs, until = proc(f: seq[Frame]): bool =
      for x in f:
        if x.typ == uint8(ftData) and (x.flags and flagEndStream) != 0:
          return true
      false))
    check r.endStream
    check not r.gone
    check r.body.len == drainChunk
    check bodyMismatch(r.body) == -1
    c.close()

  test "a burst of registrations queues one loop pass":
    resetDrainCounts()
    kicksQueued.store(-1)
    checkBody(fetchBody(srv.port, "/many-regs", initialWindow = wideGrant,
                        connGrant = wideGrant, credit = false), 1024)
    check kicksQueued.load() == 1           # was 1000: one kick per call
    check drainRegs.load() == 1000
    check drainFires.load() == 1            # the last registration, once

suite "sendFile read-ahead in the #399 regime":
  test "a 16 MiB sendFile completes against a bursty reader (#399)":
    # The read-ahead gate's deferred half. The producer here is the file
    # streamer, not a handler: it parks the next disk read on res.onDrain, so
    # the write that precedes the park has to have reported backpressure for
    # that callback to ever be armed (request.pullAfterWrite).
    #
    # This is a GUARD, not a reproduction: the gate trips about a dozen times
    # per 16 MiB here, and the losing coincidence -- the client emptying the
    # socket after the gate read the backlog but before the write's flush gave
    # up, so the flush pushes the whole backlog and the write comes back
    # writable -- was measured at roughly one trip in a couple of hundred, i.e.
    # a few gigabytes of download per occurrence. With the deferred half
    # reverted this suite still passes. What does catch the state
    # deterministically, wherever it happens, is the debug assertion in
    # h2CheckCounters: a stream must not park a drain callback with nothing
    # queued to fire it.
    checkBody(burstyFetch(srv.port, "/file"), fileBytes)

srv.close()
removeFile(filePath)
echo "server shut down cleanly"
