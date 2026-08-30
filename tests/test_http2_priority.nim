## RFC 9218 Extensible Prioritization over HTTP/2: the write scheduler must
## serve lower urgency values first, deliver non-incremental streams
## sequentially and incremental streams interleaved, and honour the
## PRIORITY_UPDATE frame and a server-side res.setPriority override.
##
## Each test pins the stream window to 0 so both responses park with their
## bodies buffered, then raises the window so a SINGLE scheduler pass drains
## them -- making the wire order a direct read-out of the scheduler's choices.

import std/[unittest, net, httpcore, strutils]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./h2client

proc handler(req: Request, res: Response) {.gcsafe.} =
  ## `/N` -> a body of N 'x' bytes. `/prio/N` -> N bytes with a server-side
  ## setPriority(urgency 0) override (tests res.setPriority beating the header).
  var p = req.path.strip(chars = {'/'})
  var override = false
  if p.startsWith("prio/"):
    override = true
    p = p["prio/".len .. ^1]
  var n = 0
  try: n = parseInt(p)
  except ValueError: n = 0
  if override: res.setPriority(0, incremental = false)
  res.send(Http200, repeat('x', n))

var srv = newVortex(RequestHandler(handler),
                    initVortexConfig(numThreads = 1)).start(0)

proc addInitialWindow(buf: var string, value: uint32) =
  var payload = ""
  payload.addSetting(setInitialWindowSize, value)
  buf.addFrameHeader(payload.len, ftSettings, 0, 0)
  buf.add payload

proc addReq(buf: var string, sid: uint32, path: string, priority = "") =
  var hs = @[(":method", "GET"), (":path", path),
             (":scheme", "http"), (":authority", "x")]
  if priority.len > 0: hs.add ("priority", priority)
  buf.addRequest(sid, hs)                       # END_HEADERS + END_STREAM

proc addPriorityUpdate(buf: var string, sid: uint32, field: string) =
  ## PRIORITY_UPDATE (type 0x10) is outside the FrameType enum, so write the
  ## 9-byte frame header by hand. Payload = 4-byte prioritized stream id + field.
  var payload = newString(4)
  payload[0] = char((sid shr 24) and 0xff)
  payload[1] = char((sid shr 16) and 0xff)
  payload[2] = char((sid shr 8) and 0xff)
  payload[3] = char(sid and 0xff)
  payload.add field
  buf.add char((payload.len shr 16) and 0xff)
  buf.add char((payload.len shr 8) and 0xff)
  buf.add char(payload.len and 0xff)
  buf.add char(ftPriorityUpdate)                # type 0x10
  buf.add char(0)                               # flags
  buf.add "\0\0\0\0"                             # stream id 0 (connection-level)
  buf.add payload

proc dataOrder(frames: seq[Frame]): seq[uint32] =
  ## Stream ids of the non-empty DATA frames, in wire order.
  for f in frames:
    if f.typ == uint8(ftData) and f.payload.len > 0: result.add f.streamId

proc bothDone(fr: seq[Frame]): bool =
  var ends = 0
  for f in fr:
    if f.typ == uint8(ftData) and (f.flags and flagEndStream) != 0: inc ends
  ends >= 2

suite "HTTP/2 RFC 9218 priority":
  test "server advertises SETTINGS_NO_RFC7540_PRIORITIES":
    var c = newH2TestConn(srv.port)
    let fr = c.readFrames(400)
    var found = false
    for f in fr:
      if f.typ == uint8(ftSettings) and (f.flags and flagAck) == 0:
        var i = 0
        while i + 6 <= f.payload.len:
          if get16(f.payload, i) == setNoRfc7540Priorities:
            found = get32(f.payload, i + 2) == 1
          i += 6
    check found
    c.close()

  test "urgency: u=0 is served before u=7":
    var c = newH2TestConn(srv.port)
    var open = ""
    open.addInitialWindow(0)                     # park both responses
    open.addReq(1, "/16384", "u=7")              # low priority
    open.addReq(3, "/16384", "u=0")              # high priority
    c.sendRaw(open)
    check c.readFrames(500).count(ftData) == 0   # both blocked on window 0

    var grow = ""
    grow.addInitialWindow(1 shl 20)              # one pass drains both
    c.sendRaw(grow)
    let order = dataOrder(c.readFrames(1500, until = bothDone))
    check order == @[3'u32, 1'u32]               # high urgency first
    c.close()

  test "same urgency: incremental interleaves, non-incremental is sequential":
    # Two 24576-byte bodies = two DATA frames each (16384 + 8192).
    block incremental:
      var c = newH2TestConn(srv.port)
      var open = ""
      open.addInitialWindow(0)
      open.addReq(1, "/24576", "u=3, i")
      open.addReq(3, "/24576", "u=3, i")
      c.sendRaw(open)
      discard c.readFrames(400)
      var grow = ""; grow.addInitialWindow(1 shl 20); c.sendRaw(grow)
      let order = dataOrder(c.readFrames(1500, until = bothDone))
      check order.len == 4
      check order[0] != order[1]                 # interleaved (round-robin)
      check order[0] == order[2]
      c.close()
    block nonIncremental:
      var c = newH2TestConn(srv.port)
      var open = ""
      open.addInitialWindow(0)
      open.addReq(1, "/24576", "u=3")            # i defaults to false
      open.addReq(3, "/24576", "u=3")
      c.sendRaw(open)
      discard c.readFrames(400)
      var grow = ""; grow.addInitialWindow(1 shl 20); c.sendRaw(grow)
      let order = dataOrder(c.readFrames(1500, until = bothDone))
      check order.len == 4
      check order[0] == order[1]                 # first stream delivered fully first
      check order[2] == order[3]
      check order[0] != order[2]
      c.close()

  test "PRIORITY_UPDATE frame reprioritizes a stream":
    var c = newH2TestConn(srv.port)
    var open = ""
    open.addInitialWindow(0)
    open.addReq(1, "/16384", "u=1")              # would be higher than stream 3...
    open.addReq(3, "/16384", "u=5")
    open.addPriorityUpdate(1, "u=7")             # ...but demote stream 1 to u=7
    open.addPriorityUpdate(3, "u=0")             # and promote stream 3 to u=0
    c.sendRaw(open)
    discard c.readFrames(400)
    var grow = ""; grow.addInitialWindow(1 shl 20); c.sendRaw(grow)
    let order = dataOrder(c.readFrames(1500, until = bothDone))
    check order == @[3'u32, 1'u32]               # reprioritized order wins
    c.close()

  test "res.setPriority overrides the client's Priority header":
    var c = newH2TestConn(srv.port)
    var open = ""
    open.addInitialWindow(0)
    open.addReq(1, "/16384", "u=7")              # stream 1 stays low...
    open.addReq(3, "/prio/16384", "u=7")         # ...handler forces u=0 on 3, beating it
    c.sendRaw(open)
    discard c.readFrames(400)
    var grow = ""; grow.addInitialWindow(1 shl 20); c.sendRaw(grow)
    let order = dataOrder(c.readFrames(1500, until = bothDone))
    check order == @[3'u32, 1'u32]               # server override wins the tie-break
    c.close()

srv.close()
