## Regression for h2spec 6.9.2: changing SETTINGS_INITIAL_WINDOW_SIZE after
## a stream exists must resize that stream's send window and flush any DATA
## the larger window unblocks (RFC 7540 6.9.2).

import std/[unittest, net, httpcore, strutils]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./h2client

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "hello h2")     # 8-byte body

proc bodyLenHandler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, $req.body.len)  # echo how many body bytes arrived

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1)).start(0)

proc addInitialWindow(buf: var string, value: uint32) =
  var payload = ""
  payload.addSetting(setInitialWindowSize, value)
  buf.addFrameHeader(payload.len, ftSettings, 0, 0)
  buf.add payload

proc settingValue(frames: seq[Frame], id: uint16): int =
  ## Value of setting `id` in the server's own (non-ACK) SETTINGS frame, or -1.
  for f in frames:
    if f.typ == uint8(ftSettings) and (f.flags and flagAck) == 0:
      var i = 0
      while i + 6 <= f.payload.len:
        if get16(f.payload, i) == id: return int(get32(f.payload, i + 2))
        i += 6
  -1

proc connWindowGrow(frames: seq[Frame]): int =
  ## Increment of the server's connection-level (stream 0) WINDOW_UPDATE, or -1.
  for f in frames:
    if f.typ == uint8(ftWindowUpdate) and f.streamId == 0 and f.payload.len >= 4:
      return int(get32(f.payload, 0))
  -1

suite "HTTP/2 flow control":
  test "raising INITIAL_WINDOW_SIZE flushes DATA blocked on a zero window":
    var c = newH2TestConn(srv.port)

    # Pin the initial window to 0, then open a stream. The response body is
    # blocked: HEADERS arrive, DATA cannot.
    var open = ""
    open.addInitialWindow(0)
    open.addHeaders(1)                              # :path / , END_STREAM
    c.sendRaw(open)

    var frames = c.readFrames(800)
    check frames.count(ftHeaders) >= 1             # response headers sent
    check frames.count(ftData) == 0                # body withheld (window 0)

    # Grow the window; the previously blocked DATA must now be delivered.
    var grow = ""
    grow.addInitialWindow(100)
    c.sendRaw(grow)

    frames = c.readFrames(1500,
      until = proc(fr: seq[Frame]): bool = fr.count(ftData) >= 1)
    check frames.count(ftData) == 1
    var payload = ""
    var endStream = false
    for fr in frames:
      if fr.typ == uint8(ftData):
        payload = fr.payload
        endStream = (fr.flags and flagEndStream) != 0
    check payload == "hello h2"
    check endStream                                # stream completes
    c.close()

  test "server advertises the configured receive windows (upload throughput)":
    # The HTTP/2 default receive window is only 64 KiB, which throttles uploads
    # to window/round-trip. The server must advertise the configured per-stream
    # window (SETTINGS_INITIAL_WINDOW_SIZE) and grow the connection window, so a
    # large streaming upload keeps the pipe full instead of stalling each cycle.
    var s2 = newVortex(RequestHandler(handler),
      initVortexConfig(numThreads = 1, h2StreamWindow = 512 * 1024,
                       h2ConnWindow = 768 * 1024)).start(0)
    var c2 = newH2TestConn(s2.port)
    let fr = c2.readFrames(500)
    check settingValue(fr, setInitialWindowSize) == 512 * 1024
    check connWindowGrow(fr) == 768 * 1024 - 65535
    c2.close()
    s2.close()

  test "WINDOW_UPDATE is batched, not one per DATA frame":
    # A 200 KiB upload split into twenty 10 KiB DATA frames, with a 256 KiB
    # window (so it fits -- no flow-control violation) and a 128 KiB batch
    # threshold. Un-batched this would emit ~20 stream + ~20 connection
    # WINDOW_UPDATEs; batched it crosses the half-window threshold only ~once
    # each, so the count stays tiny.
    var s3 = newVortex(RequestHandler(bodyLenHandler),
      initVortexConfig(numThreads = 1, h2StreamWindow = 256 * 1024,
                       h2ConnWindow = 256 * 1024)).start(0)
    var c3 = newH2TestConn(s3.port)
    discard c3.readFrames(300)                    # drain the server's hello
    var f = ""
    f.addRequest(1, {":method": "POST", ":scheme": "http", ":path": "/",
                     ":authority": "x"}, endStream = false)
    let chunk = 'x'.repeat(10 * 1024)
    for i in 0 ..< 19: f.addData(1, chunk, endStream = false)
    f.addData(1, chunk, endStream = true)         # 20th frame ends the stream
    c3.sendAndDrain(f)                            # interleave to avoid deadlock
    let fr = c3.readFrames(2000,
      until = proc(frs: seq[Frame]): bool = frs.count(ftHeaders) >= 1)
    var body = ""
    for fx in fr:
      if fx.typ == uint8(ftData): body.add fx.payload
    check body == $(200 * 1024)                   # whole body received intact
    check fr.count(ftWindowUpdate) <= 6           # batched (would be ~40 per-frame)
    c3.close()
    s3.close()

srv.close()
echo "server shut down cleanly"
