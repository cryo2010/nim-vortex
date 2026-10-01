## Regression coverage for the unified HTTP/2 stream teardown (#231 and #232,
## both fixed in #242). Every teardown path -- peer RST_STREAM, stream error,
## connection close -- must
##
##   * return the stream's un-credited connection-window bytes, so an abnormal
##     end cannot drain the connection window and deadlock later uploads (#231);
##   * deliver onBody(last=true) to a streaming request sink and fire a parked
##     onRespDrain, so a handler suspended in await req.read() / res.drained()
##     resumes instead of leaking a zombie coroutine (#232).
##
## A streaming-upload route debits `connRecvRemaining` on receipt and defers the
## connection WINDOW_UPDATE to consumption, so a `manualAck` sink that never acks
## leaves every byte owed: exactly the state a browser-initiated cancel used to
## leak.

import std/[unittest, net, httpcore, strutils, atomics, os]
import vortex/[settings, request, server, streaming]
import vortex/http2/frames
import ./h2client

var sinkOpen: Atomic[int]     ## streaming handlers dispatched on /sink
var sinkBytes: Atomic[int]    ## body bytes delivered to the never-acking sink
var sinkEof: Atomic[int]      ## onBody(last=true) deliveries on /sink
var parkArmed: Atomic[int]    ## /park producers parked with an onDrain armed
var drainFired: Atomic[int]   ## parked onRespDrain callbacks invoked

const
  connWindow = 128 * 1024     ## server connection receive window
  streamWindow = 64 * 1024    ## server per-stream receive window
  frameSize = 16 * 1024       ## <= the server's SETTINGS_MAX_FRAME_SIZE
  uploadFrames = 3            ## DATA frames per upload
  uploadBytes = uploadFrames * frameSize   ## 48 KiB, under streamWindow
  parkBytes = 96 * 1024       ## one write past respHighWater: the producer parks

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/sink":
    # manualAck and no ack at all: the bytes are delivered but their
    # connection-window credit stays deferred until teardown reclaims it.
    discard sinkOpen.fetchAdd(1)
    req.onBody(proc(chunk: openArray[char], last: bool) {.gcsafe.} =
      discard sinkBytes.fetchAdd(chunk.len)
      if last: discard sinkEof.fetchAdd(1), manualAck = true)
  of "/park":
    # A streamed response the client refuses to read (it advertised a zero
    # initial window): the first write backs up and the producer parks on its
    # onDrain, the callback a teardown must fire.
    res.sendHead(Http200, "application/octet-stream")
    let body = 'p'.repeat(parkBytes)
    if not res.write(body.toOpenArray(0, body.high)):
      res.onDrain proc(r: Response) {.gcsafe.} =
        discard drainFired.fetchAdd(1)
      discard parkArmed.fetchAdd(1)
  of "/echo":
    res.send(Http200, $req.body.len)
  else:
    res.send(Http200, "ok")

let routes = newStreamRoutes()
routes.streamPath("/sink")

var srv = newVortex(RequestHandler(handler),
                    initVortexConfig(numThreads = 1,
                                     maxBodySize = 1024 * 1024,
                                     h2StreamWindow = streamWindow,
                                     h2ConnWindow = connWindow),
                    routes.predicate()).start(0)

proc head(path: string): seq[(string, string)] =
  @[(":method", "POST"), (":scheme", "http"), (":path", path),
    (":authority", "localhost")]

proc addUpload(buf: var string, sid: uint32, frames = uploadFrames,
               endStream = false) =
  ## `frames` DATA frames of exactly frameSize bytes. One frame per
  ## SETTINGS_MAX_FRAME_SIZE: a single 48 KiB DATA frame is a connection
  ## FRAME_SIZE_ERROR, not an upload.
  let chunk = 'u'.repeat(frameSize)
  for i in 0 ..< frames:
    buf.addData(sid, chunk, endStream = endStream and i == frames - 1)

proc connCredit(frames: seq[Frame]): int =
  ## Total connection-level (stream 0) WINDOW_UPDATE credit in `frames`.
  for f in frames:
    if f.typ == uint8(ftWindowUpdate) and f.streamId == 0 and f.payload.len >= 4:
      result += int(get32(f.payload, 0))

proc bodyOf(frames: seq[Frame], sid: uint32): string =
  for f in frames:
    if f.typ == uint8(ftData) and f.streamId == sid: result.add f.payload

proc waitFor(cond: proc(): bool {.gcsafe.}, ms = 2000): bool =
  ## Poll a loop-thread side effect for up to `ms` milliseconds.
  for _ in 0 ..< ms div 10:
    if cond(): return true
    sleep(10)
  cond()

proc openSink(c: var H2TestConn, sid: uint32) =
  ## Open a /sink stream and wait for its handler to register the body sink.
  ## Sent on its own so the handler really runs before the DATA and the reset:
  ## a stream reset in the same read batch is never dispatched at all.
  let opened = sinkOpen.load()
  var f = ""
  f.addRequest(sid, head("/sink"), endStream = false)
  c.sendAll(f)
  check waitFor(proc(): bool = sinkOpen.load() > opened)

suite "HTTP/2 stream teardown":
  test "RST_STREAM returns an aborted upload's connection credit (#231)":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)        # drain the server hello (its initial
                                     # connection WINDOW_UPDATE included)
    var aborted = 0
    for sid in [1'u32, 3'u32]:
      c.openSink(sid)
      let fed = sinkBytes.load()
      var d = ""
      d.addUpload(sid)
      c.sendAll(d)
      check waitFor(proc(): bool = sinkBytes.load() - fed >= uploadBytes)
      var r = ""
      r.addRstStream(sid, errCancel)
      c.sendAll(r)
      aborted += uploadBytes
    # The reset streams owed `aborted` bytes of connection window. Credit is
    # batched at half the window, so the second reset must push a WINDOW_UPDATE.
    let credited = c.readFrames(2000,
      until = proc(fs: seq[Frame]): bool = fs.connCredit >= aborted)
    check credited.connCredit >= aborted
    check credited.goawayError() == -1

    # And the consequence that matters: a further upload still fits. Together
    # with the aborted bytes it exceeds the connection window, so it can only be
    # accepted because the reset streams gave their grant back.
    var g = ""
    g.addRequest(5, head("/echo"), endStream = false)
    g.addUpload(5, endStream = true)
    c.sendAll(g)
    let fr = c.readFrames(2000,
      until = proc(fs: seq[Frame]): bool = fs.hasResponse(5))
    check fr.hasResponse(5)
    check fr.bodyOf(5) == $uploadBytes
    check fr.goawayError() == -1
    c.close()

  test "RST_STREAM delivers onBody(last=true) to a streaming sink (#232)":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    c.openSink(1)
    let eofs = sinkEof.load()
    var d = ""
    d.addUpload(1, frames = 1)
    c.sendAll(d)
    check waitFor(proc(): bool = sinkBytes.load() > 0)
    check sinkEof.load() == eofs         # no EOF while the upload is open
    var r = ""
    r.addRstStream(1, errCancel)
    c.sendAll(r)
    # Without the terminating callback a handler suspended in await req.read()
    # never resumes and its reader-table entry leaks.
    check waitFor(proc(): bool = sinkEof.load() > eofs)
    c.close()

  test "RST_STREAM fires a producer parked on its drain callback (#232)":
    var c = newH2TestConn(srv.port)
    let armed = parkArmed.load()
    let drained = drainFired.load()
    var f = ""
    f.addSettingFrame(setInitialWindowSize, 0)   # never read the response body
    f.addRequest(1, head("/park"), endStream = true)
    c.sendAll(f)
    check waitFor(proc(): bool = parkArmed.load() > armed)
    check drainFired.load() == drained   # still parked: nothing drained it
    var r = ""
    r.addRstStream(1, errCancel)
    c.sendAll(r)
    # Otherwise a producer suspended in await res.drained() hangs forever and its
    # finally/defer cleanup never runs.
    check waitFor(proc(): bool = drainFired.load() > drained)
    c.close()

  test "a client disconnect fires both parked callbacks (#232)":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    let eofs = sinkEof.load()
    let armed = parkArmed.load()
    let drained = drainFired.load()
    var z = ""
    z.addSettingFrame(setInitialWindowSize, 0)
    c.sendAll(z)
    c.openSink(1)
    var d = ""
    d.addUpload(1, frames = 1)
    c.sendAll(d)
    check waitFor(proc(): bool = sinkBytes.load() > 0)
    var f = ""
    f.addRequest(3, head("/park"), endStream = true)
    c.sendAll(f)
    check waitFor(proc(): bool = parkArmed.load() > armed)
    check sinkEof.load() == eofs
    check drainFired.load() == drained
    c.close()                            # disconnect with both streams open
    check waitFor(proc(): bool = sinkEof.load() > eofs)
    check waitFor(proc(): bool = drainFired.load() > drained)

srv.close()
echo "http2 stream teardown ok"
