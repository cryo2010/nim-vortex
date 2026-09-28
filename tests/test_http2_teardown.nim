## Regression coverage for the unified HTTP/2 stream teardown (#231, fixed in
## #242): every teardown path -- peer RST_STREAM, stream error, connection close
## -- must return the stream's un-credited connection-window bytes, so an
## abnormal end cannot drain the connection window and deadlock later uploads.
##
## A streaming-upload route debits `connRecvRemaining` on receipt and defers the
## connection WINDOW_UPDATE to consumption, so a `manualAck` sink that never acks
## leaves every byte owed: exactly the state a browser-initiated cancel used to
## leak.

import std/[unittest, net, posix, httpcore, strutils, atomics, os]
import vortex/[settings, request, server, streaming]
import vortex/http2/frames
import ./h2client

var sinkOpen: Atomic[int]     ## streaming handlers dispatched on /sink
var sinkBytes: Atomic[int]    ## body bytes delivered to the never-acking sink

const
  connWindow = 128 * 1024     ## server connection receive window
  streamWindow = 64 * 1024    ## server per-stream receive window
  frameSize = 16 * 1024       ## <= the server's SETTINGS_MAX_FRAME_SIZE
  uploadFrames = 3            ## DATA frames per upload
  uploadBytes = uploadFrames * frameSize   ## 48 KiB, under streamWindow

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/sink":
    # manualAck and no ack at all: the bytes are delivered but their
    # connection-window credit stays deferred until teardown reclaims it.
    discard sinkOpen.fetchAdd(1)
    req.onBody(proc(chunk: openArray[char], last: bool) {.gcsafe.} =
      discard sinkBytes.fetchAdd(chunk.len), manualAck = true)
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

proc sendAll(c: var H2TestConn, data: string) =
  ## posix send with correct partial-write handling: std/net's `send` re-sends
  ## from offset 0 after a partial write (duplicating bytes on the wire) and then
  ## spins forever if the peer has gone.
  var off = 0
  while off < data.len:
    let n = posix.send(c.sock.getFd, unsafeAddr data[off], data.len - off, 0)
    if n <= 0: return
    off += n

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

srv.close()
echo "http2 stream teardown ok"
