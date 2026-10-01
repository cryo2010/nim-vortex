## Frame-level regression suite for the HTTP/2 control-frame budget (#234).
##
## `maxControlFrames` is the cap on overhead frames a peer may push through a
## connection per unit of real work. The audit of #234 found eight ways to
## generate unbounded server work around it: PING ACKs and SETTINGS ACKs that
## returned before the charge, a received GOAWAY, unknown frame types, stream
## and connection WINDOW_UPDATEs, a self-dependent PRIORITY whose RST_STREAM
## reply ran before the charge, DATA on a closed stream, the counter being
## zeroed by every accepted request (which made the cap a per-request ratio),
## and a single SETTINGS frame packed with thousands of INITIAL_WINDOW_SIZE
## entries charged once. Each test below drives one of those floods with a
## deliberately low budget and asserts the connection ends in
## GOAWAY(ENHANCE_YOUR_CALM), or (where the frame is a protocol violation in its
## own right) that the work is bounded immediately and no illegal RST_STREAM is
## emitted for an idle stream id.
##
## The last two tests are the other half of the contract: a client that sends a
## few control frames per request, or returns flow-control credit for response
## bytes it consumed, must never be torn down (regressing that is what #335
## had to repair).

import std/[unittest, net, httpcore]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./h2client

const
  budget = 20
    ## maxControlFrames for this server. Low so a flood of a few dozen frames
    ## settles the question without sending (and reading back) thousands.
  flood = budget * 4
    ## Frames per flood: comfortably past the budget even after the decay an
    ## accepted request grants (max(1, budget div 10) per request).

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

var srv = newVortex(RequestHandler(handler),
                    initVortexConfig(numThreads = 1,
                                     maxControlFrames = budget)).start(0)

proc post(path: string, len: int): seq[(string, string)] =
  ## Request head for a body that is announced but never completed, so the
  ## stream stays open (and un-dispatched) while a flood runs against it.
  @[(":method", "POST"), (":scheme", "http"), (":path", path),
    (":authority", "localhost"), ("content-length", $len)]

# --- frame builders the shared client does not have --------------------------

proc addPingAckFrame(buf: var string) =
  buf.addPingAck("\0\0\0\0\0\0\0\0")

proc addSettingsAck(buf: var string) =
  buf.addFrameHeader(0, ftSettings, flagAck, 0)

proc addUnknownFrame(buf: var string) =
  ## Frame type 0x3f: outside the RFC 9113 range, so the codec must ignore its
  ## payload (RFC 9113 4.1) while still charging the frame.
  buf.add24 0
  buf.add char(0x3f'u8)
  buf.add char(0'u8)
  buf.add32 0'u32

proc addPriorityFrame(buf: var string, sid, dep: uint32, weight = 15'u8) =
  buf.addFrameHeader(5, ftPriority, 0, sid)
  buf.add32 dep
  buf.add char(weight)

proc addPackedSettings(buf: var string, entries: int,
                       value = uint32(defaultInitialWindow)) =
  ## One SETTINGS frame carrying `entries` INITIAL_WINDOW_SIZE settings. Each
  ## entry rewrites every open stream's send window, so the cost is
  ## O(entries x streams) for what used to be a single budget unit.
  var payload = ""
  for _ in 0 ..< entries: payload.addSetting(setInitialWindowSize, value)
  buf.addFrameHeader(payload.len, ftSettings, 0, 0)
  buf.add payload

# --- connection helpers ------------------------------------------------------

proc readUntilGoaway(c: var H2TestConn): seq[Frame] =
  c.readFrames(2000, until = proc(fs: seq[Frame]): bool = fs.goawayError() >= 0)

proc readUntilResponse(c: var H2TestConn, sid: uint32): seq[Frame] =
  ## Read until the response on `sid` arrived. The server tears the stream down
  ## in the same pass that emits the response, so this is the point from which a
  ## following frame on `sid` really is a frame on a closed stream.
  c.readFrames(2000, until = proc(fs: seq[Frame]): bool = fs.hasResponse(sid))

proc floodOf(data: string): seq[Frame] =
  ## Fresh connection, one write, read back until the GOAWAY (or a quiet 2 s).
  var c = newH2TestConn(srv.port)
  c.sendAll(data)
  result = c.readUntilGoaway()
  c.close()

proc floodAfterGet(data: string): seq[Frame] =
  ## As floodOf, but answer a GET on stream 1 first, so stream 1 is a *closed*
  ## (seen, torn down) id by the time the flood runs.
  var c = newH2TestConn(srv.port)
  var head = ""
  head.addHeaders(1)
  c.sendAll(head)
  result = c.readUntilResponse(1)
  doAssert result.hasResponse(1), "the priming GET was not answered"
  c.sendAll(data)
  result.add c.readUntilGoaway()
  c.close()

suite "HTTP/2 control-frame budget (#234)":

  test "PING ACK flood trips ENHANCE_YOUR_CALM":
    # noteControlFrame used to run only when the ACK flag was absent, so an
    # unsolicited PING ACK flood was free.
    var f = ""
    for _ in 0 ..< flood: f.addPingAckFrame()
    let frames = floodOf(f)
    check frames.goawayError() == int(errEnhanceYourCalm)
    check frames.count(ftPing) == 0        # an ACK is never answered

  test "SETTINGS ACK flood trips ENHANCE_YOUR_CALM":
    # Same shape as the PING ACK: we send our SETTINGS once, so every ACK past
    # the first is pure overhead, and the ACK branch returned before the charge.
    var f = ""
    for _ in 0 ..< flood: f.addSettingsAck()
    check floodOf(f).goawayError() == int(errEnhanceYourCalm)

  test "received GOAWAY flood trips ENHANCE_YOUR_CALM":
    # A peer GOAWAY is informational for a server that never pushes; it only set
    # peerGoneAway and was never budgeted.
    var f = ""
    for _ in 0 ..< flood: f.addGoaway(0, errNoError)
    check floodOf(f).goawayError() == int(errEnhanceYourCalm)

  test "unknown frame type flood trips ENHANCE_YOUR_CALM":
    # Ignored per RFC 9113 4.1, but the parse is not free: the early return used
    # to skip the budget entirely.
    var f = ""
    for _ in 0 ..< flood: f.addUnknownFrame()
    check floodOf(f).goawayError() == int(errEnhanceYourCalm)

  test "stream WINDOW_UPDATE flood on an open stream trips ENHANCE_YOUR_CALM":
    # increment=1 against a stream the server owes nothing on: the update
    # unblocks nothing, so it is the cheapest flood there is (13 bytes a frame)
    # and the stream-level branch never charged it. The stream stays open and
    # un-dispatched (announced body never sent), so nothing decays the budget.
    var f = ""
    f.addRequest(1, post("/", 100), endStream = false)
    for _ in 0 ..< flood: f.addWindowUpdate(1, 1)
    let frames = floodOf(f)
    check frames.goawayError() == int(errEnhanceYourCalm)
    check not frames.hasResponse(1)

  test "zero-increment WINDOW_UPDATE flood on a closed stream is bounded":
    # Each one costs a 13-byte RST_STREAM reply, and on an already-closed id the
    # stream error tears nothing down, so the peer could repeat it forever.
    var f = ""
    for _ in 0 ..< flood: f.addWindowUpdate(1, 0)
    let frames = floodAfterGet(f)
    check frames.goawayError() == int(errEnhanceYourCalm)
    check frames.count(ftRstStream) <= budget + 1

  test "self-dependent PRIORITY on an idle stream never RSTs it":
    # RFC 9113 5.1: RST_STREAM on an idle stream id is itself a connection
    # error, so a self-dependency on an id we never opened must answer with
    # GOAWAY(PROTOCOL_ERROR) and nothing else. One frame ends the connection, so
    # the flood behind it is bounded before it starts.
    var f = ""
    for _ in 0 ..< flood: f.addPriorityFrame(99, 99)
    let frames = floodOf(f)
    check frames.goawayError() == int(errProtocol)
    check frames.rstError(99) == -1
    check frames.count(ftRstStream) == 0

  test "self-dependent PRIORITY flood on a used stream trips ENHANCE_YOUR_CALM":
    # On an id we have seen the self-dependency is a stream error (one RST per
    # frame), and streamError ran *before* the charge.
    var f = ""
    for _ in 0 ..< flood: f.addPriorityFrame(1, 1)
    let frames = floodAfterGet(f)
    check frames.goawayError() == int(errEnhanceYourCalm)
    check frames.count(ftRstStream) <= budget + 1

  test "closed-stream DATA flood trips ENHANCE_YOUR_CALM":
    # 9 bytes in, a 13-byte RST_STREAM out, repeatable forever against a peer
    # that never reads: budget it as the overhead it is.
    var f = ""
    for _ in 0 ..< flood: f.addData(1, "x")
    let frames = floodAfterGet(f)
    check frames.goawayError() == int(errEnhanceYourCalm)
    check frames.count(ftRstStream) <= budget + 1

  test "SETTINGS entries are charged individually":
    # One frame, budget*2 INITIAL_WINDOW_SIZE entries: charged per frame this
    # amplified for free (a 16 KiB SETTINGS carries ~2730 of them, each
    # rewriting every open stream's window).
    var f = ""
    f.addPackedSettings(budget * 2)
    check floodOf(f).goawayError() == int(errEnhanceYourCalm)

  test "one request per control-frame burst still trips ENHANCE_YOUR_CALM":
    # The counter used to be zeroed by every accepted HEADERS, which made
    # maxControlFrames a per-request ratio: one minimal GET per N control frames
    # sustained any of the floods above indefinitely. A bounded decay caps the
    # sustained ratio instead, so the interleave must still end in GOAWAY.
    var f = ""
    var sid = 1'u32
    for _ in 0 ..< 8:
      f.addHeaders(sid)
      sid += 2
      for _ in 0 ..< budget div 2: f.addPingAckFrame()
    check floodOf(f).goawayError() == int(errEnhanceYourCalm)

  test "a request with a few control frames is answered":
    # The budget must not fire on the benign ratio it exists to bound.
    var c = newH2TestConn(srv.port)
    var f = ""
    for _ in 0 ..< 3:
      f.addPing()
      f.addSettingsFrame()
    f.addHeaders(1)
    c.sendAll(f)
    let frames = c.readUntilResponse(1)
    check frames.hasResponse(1)
    check frames.goawayError() == -1
    c.close()

  test "a few window updates on an open stream are tolerated":
    # Same point for the stream-level update: a handful while a request body is
    # still arriving is normal client behaviour, not a flood, and the request
    # must still complete.
    var c = newH2TestConn(srv.port)
    var f = ""
    f.addRequest(1, post("/", 2), endStream = false)
    for _ in 0 ..< budget div 4: f.addWindowUpdate(1, 65535)
    f.addData(1, "ok", endStream = true)
    c.sendAll(f)
    let frames = c.readUntilResponse(1)
    check frames.hasResponse(1)
    check frames.goawayError() == -1
    c.close()

srv.close()
echo "http2 control-frame budget ok"
