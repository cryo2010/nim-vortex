## Frame-level regression suite for a REFUSED HTTP/2 stream (#233). Refusing one
## stream must never cost the connection. All four refusal paths in handleHeaders
## -- the PRIORITY self-dependency, the graceful-drain cutoff, the
## maxConcurrentStreams cap, and (sharing the mechanism) a HEADERS on a
## half-closed(remote) stream or one racing the server's own early close --
## answer RST_STREAM, so each one has to finish the header-block bookkeeping
## first:
##
##   * the field block is buffered and HPACK-decoded even though it is discarded
##     (RFC 9113 4.3 and 5.1 both say so). Skipping it desyncs the server's
##     dynamic table from the client's encoder, and every later request on the
##     connection then dies with COMPRESSION_ERROR or silently decodes the wrong
##     name/value;
##   * `contStream` is tracked, so the CONTINUATION the client MUST send for a
##     block that did not set END_HEADERS is not a stray frame that takes the
##     connection down with GOAWAY(PROTOCOL_ERROR);
##   * `lastStreamId` advances, so the DATA / WINDOW_UPDATE / trailer section the
##     client legally pipelined behind the refused HEADERS is not read as a frame
##     on an idle stream (another GOAWAY);
##   * and the refused stream is not created, so it costs no concurrency slot.
##
## The cap is reached deterministically rather than by racing the server:
## SETTINGS_INITIAL_WINDOW_SIZE = 0 parks each /park response body, so those
## streams stay open (and counted) until a later SETTINGS raises the window
## again, which flushes them and frees the slots while that same frame is being
## parsed. Each test then proves the connection is still usable by asking for
## /probe on a fresh stream with the custom header carried as HPACK dynamic-table
## index 62 -- the entry the refused block added. That one request fails in two
## distinguishable ways if the refusal regresses: GOAWAY(COMPRESSION_ERROR) when
## the block was never decoded, or no response at all when the connection went
## down earlier.
##
## The `goingAway` refusal IS reachable from the wire, and the last case here
## drives it. markDrain (and drainSweep) send the final GOAWAY and set
## `goingAway` + `closeAfterFlush`, but they leave the connection `csActive`: the
## close happens inside flushOut once the write completes, and nothing gates
## processInput on `closeAfterFlush` for h2 (h2Input -> h2Feed runs
## unconditionally). So while the write side is stalled -- the client is not
## reading and the socket will not take the rest of the queued output -- a HEADERS
## the client pipelined behind that final GOAWAY is still parsed, with `goingAway`
## set, and must be answered with RST_STREAM(REFUSED_STREAM). That case also pins
## the other half of the rule: the refused id advances `lastStreamId` past the
## cutoff the final GOAWAY announced, so any GOAWAY after it (here, a stray
## CONTINUATION's connection error) must still name the cutoff and not the higher
## id -- RFC 9113 6.8 forbids raising it, because the peer may already have retried
## every stream above the announced value on another connection.

import std/[unittest, net, httpcore, os, strutils]
import vortex/[settings, request, server]
import vortex/http2/[frames, hpack]
import ./h2client

const
  cap = 2                       ## maxConcurrentStreams: small, so two parked
                                ## /park streams fill it exactly
  parkSids = [1'u32, 3'u32]     ## the streams that hold the cap
  refusedSid = 5'u32            ## the stream under test
  probeSid = 7'u32              ## the "is the connection still usable" request
  probeName = "x-refused-probe"
  probeValue = "kept"
  parkBody = "parked"
  padSid = 1'u32                ## the drain case's one real request
  drainRefusedSid = 3'u32       ## the HEADERS it pipelines after the final GOAWAY
  padBytes = 4 * 1024 * 1024    ## response-header bytes queued to stall the write
                                ## side: comfortably more than any socket buffer
                                ## pair will swallow, so the flush stops at EAGAIN

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/park":
    res.send(Http200, parkBody)     # parked by a zero initial window
  of "/pad":
    # A bodiless response (empty body -> END_STREAM on the HEADERS, stream torn
    # down at once) whose response header alone is megabytes. HEADERS and
    # CONTINUATION are NOT flow-controlled and go straight into the connection
    # write buffer, bypassing both the peer's send window and respHighWater, so
    # this leaves the socket stuffed with zero streams open. A response *body*
    # cannot do that: it is metered by the peer's 64 KiB connection window and by
    # respHighWater, and its stream stays active until it drains.
    res.send(Http200, "", [("x-pad", repeat('x', padBytes))])
  of "/probe":
    # Echoes the header the client sent as dynamic-table index 62, so the test
    # sees not just "it decoded" but "it decoded to the right value".
    res.send(Http200, req.header(probeName))
  else:
    res.send(Http200, "ok")

var srv = newVortex(RequestHandler(handler),
                    initVortexConfig(numThreads = 1,
                                     maxConcurrentStreams = cap)).start(0)

const headersDone = flagEndHeaders or flagEndStream

proc reqBlock(path: string, meth = "GET"): string =
  ## A minimal valid request field block, all literals WITHOUT indexing, so it
  ## leaves the server's dynamic table alone.
  result.encodeHeader(":method", meth)
  result.encodeHeader(":scheme", "http")
  result.encodeHeader(":path", path)
  result.encodeHeader(":authority", "localhost")

proc indexingBlock(path: string, meth = "GET"): string =
  ## A request block whose last field is a literal WITH incremental indexing: a
  ## server that decodes it (refused or not) must hold (probeName, probeValue) as
  ## dynamic-table index 62 afterwards.
  result = reqBlock(path, meth)
  result.addIndexedLiteral(probeName, probeValue)

proc probeBlock(): string =
  ## /probe, carrying the custom header as dynamic-table index 62 alone.
  result = reqBlock("/probe")
  result.addDynamicIndex()

proc bodyOf(frames: seq[Frame], sid: uint32): string =
  for f in frames:
    if f.typ == uint8(ftData) and f.streamId == sid: result.add f.payload

proc addCapFill(buf: var string) =
  ## Zero the peer's initial window, then open `cap` /park streams: their
  ## response HEADERS go out but the DATA cannot, so the streams stay in the
  ## table and activeStreams sits at the cap.
  buf.addSettingFrame(setInitialWindowSize, 0)
  for sid in parkSids:
    buf.addRawHeaders(sid, reqBlock("/park"), headersDone)

proc awaitRst(c: var H2TestConn, sid: uint32): seq[Frame] =
  ## Read until the refusal is answered AND the park handlers have run (their
  ## response HEADERS are on the wire), so the cap is genuinely held.
  c.readFrames(2000, until = proc(fs: seq[Frame]): bool =
    fs.rstError(sid) >= 0 and fs.hasResponse(parkSids[^1]))

proc probe(c: var H2TestConn, sid = probeSid): seq[Frame] =
  ## Raise SETTINGS_INITIAL_WINDOW_SIZE, which flushes the parked /park bodies
  ## and tears those streams down while this very frame is parsed (h2Schedule
  ## runs inside handleSettings), so the request that follows in the same write
  ## is under the cap again. Then ask for /probe using dynamic-table index 62.
  var f = ""
  f.addSettingFrame(setInitialWindowSize, 65535)
  f.addRawHeaders(sid, probeBlock(), headersDone)
  c.sendAll(f)
  # rstError is in the predicate too: a probe stream that was itself refused (a
  # regression that leaked a concurrency slot or a stream-table entry) then fails
  # the caller's checks with the RST in hand, instead of burning the read budget.
  c.readFrames(2000, until = proc(fs: seq[Frame]): bool =
    fs.hasResponse(sid) or fs.goawayError() >= 0 or fs.rstError(sid) >= 0)

suite "HTTP/2 refused streams":
  test "a refused HEADERS still updates the HPACK dynamic table (#233)":
    var c = newH2TestConn(srv.port)
    var f = ""
    f.addCapFill()
    f.addRawHeaders(refusedSid, indexingBlock("/"), headersDone)
    c.sendAll(f)
    let fs = c.awaitRst(refusedSid)
    check fs.rstError(refusedSid) == int(errRefusedStream)
    check not fs.hasResponse(refusedSid)   # reset, never dispatched
    check fs.goawayError() == -1
    # The refused block added index 62. Without the decode this request is
    # GOAWAY(COMPRESSION_ERROR) -- an unreadable index -- or decodes to some
    # other field entirely.
    let p = c.probe()
    check p.goawayError() == -1
    check p.hasResponse(probeSid)
    check p.bodyOf(probeSid) == probeValue
    c.close()

  test "a refused HEADERS without END_HEADERS accepts its CONTINUATION (#233)":
    var c = newH2TestConn(srv.port)
    let blk = indexingBlock("/")
    let cut = blk.len div 2
    var f = ""
    f.addCapFill()
    f.addRawHeaders(refusedSid, blk[0 ..< cut], 0'u8)   # no END_HEADERS, no END_STREAM
    f.addContinuation(refusedSid, blk[cut .. ^1])
    c.sendAll(f)
    let fs = c.awaitRst(refusedSid)
    # A refusal that returned before setting contStream makes this mandatory
    # CONTINUATION a stray frame: GOAWAY(PROTOCOL_ERROR) and no RST at all.
    check fs.rstError(refusedSid) == int(errRefusedStream)
    check not fs.hasResponse(refusedSid)   # reset, never dispatched
    check fs.goawayError() == -1
    let p = c.probe()
    check p.goawayError() == -1
    check p.bodyOf(probeSid) == probeValue
    c.close()

  test "DATA and WINDOW_UPDATE pipelined behind a refusal survive (#233)":
    var c = newH2TestConn(srv.port)
    var f = ""
    f.addCapFill()
    f.addRawHeaders(refusedSid, indexingBlock("/", "POST"), flagEndHeaders)
    f.addData(refusedSid, "0123456789", endStream = true)
    f.addWindowUpdate(refusedSid, 4096)
    c.sendAll(f)
    let fs = c.awaitRst(refusedSid)
    # The client could not know the stream would be refused, so these frames are
    # correct behavior. Unless lastStreamId advanced for the refused id they are
    # frames on an idle stream: a connection PROTOCOL_ERROR.
    check fs.rstError(refusedSid) == int(errRefusedStream)
    check not fs.hasResponse(refusedSid)   # reset, never dispatched
    check fs.goawayError() == -1
    let p = c.probe()
    check p.goawayError() == -1
    check p.bodyOf(probeSid) == probeValue
    c.close()

  test "a trailer section pipelined behind a refusal survives (#233)":
    var c = newH2TestConn(srv.port)
    var trailers = ""
    trailers.addIndexedLiteral(probeName, probeValue)
    var f = ""
    f.addCapFill()
    f.addRawHeaders(refusedSid, reqBlock("/", "POST"), flagEndHeaders)
    f.addData(refusedSid, "hi")
    f.addRawHeaders(refusedSid, trailers, headersDone)   # trailers, already reset
    c.sendAll(f)
    let fs = c.awaitRst(refusedSid)
    check fs.rstError(refusedSid) == int(errRefusedStream)
    check not fs.hasResponse(refusedSid)   # reset, never dispatched
    # RFC 9113 5.1: having sent RST_STREAM we must minimally process and discard
    # the frames already in flight, including updating the compression state for
    # a HEADERS among them -- not GOAWAY the connection.
    check fs.goawayError() == -1
    let p = c.probe()
    check p.goawayError() == -1
    check p.bodyOf(probeSid) == probeValue
    c.close()

  test "a self-dependent HEADERS resets only its own stream (#233)":
    var c = newH2TestConn(srv.port)
    var pri = ""
    pri.add32(1'u32)        # stream dependency == this stream's own id
    pri.add '\x0f'          # weight; RFC 9113 deprecates the priority tree
    pri.add indexingBlock("/")
    var f = ""
    f.addRawHeaders(1, pri, flagPriority or headersDone)
    c.sendAll(f)
    let fs = c.readFrames(2000, until = proc(fs: seq[Frame]): bool =
      fs.rstError(1) >= 0 or fs.goawayError() >= 0)
    check fs.rstError(1) == int(errProtocol)   # RFC 7540 5.3.1, a STREAM error
    check not fs.hasResponse(1)                # reset, never dispatched
    check fs.goawayError() == -1
    let p = c.probe()
    check p.goawayError() == -1
    check p.bodyOf(probeSid) == probeValue
    c.close()

  test "refused streams hold no concurrency slot (#233)":
    var c = newH2TestConn(srv.port)
    const refused = [5'u32, 7'u32, 9'u32, 11'u32]
    var f = ""
    f.addCapFill()
    for sid in refused:
      f.addRawHeaders(sid, indexingBlock("/"), headersDone)
    c.sendAll(f)
    let fs = c.awaitRst(refused[^1])
    for sid in refused:
      check fs.rstError(sid) == int(errRefusedStream)
      check not fs.hasResponse(sid)        # reset, never dispatched
    check fs.goawayError() == -1
    # Twice the cap in refusals: if any of them had been counted (or left behind
    # a stream-table entry), the slots freed below would not be enough.
    let p = c.probe(13'u32)
    check p.goawayError() == -1
    check p.bodyOf(13'u32) == probeValue
    c.close()

  test "HEADERS on a half-closed(remote) stream accepts its CONTINUATION (#233)":
    var c = newH2TestConn(srv.port)
    var f = ""
    f.addSettingFrame(setInitialWindowSize, 0)    # park the response: stream 1 stays
    f.addRawHeaders(1, reqBlock("/park"), headersDone)
    c.sendAll(f)
    discard c.readFrames(2000, until = proc(fs: seq[Frame]): bool =
      fs.hasResponse(1))
    # A second HEADERS after END_STREAM is a STREAM error STREAM_CLOSED (#239),
    # which is a refusal too: split across a CONTINUATION it must still be
    # tracked and decoded, or the connection dies on the second fragment.
    var blk = ""
    blk.addIndexedLiteral(probeName, probeValue)
    let cut = blk.len div 2
    var g = ""
    g.addRawHeaders(1, blk[0 ..< cut], 0'u8)
    g.addContinuation(1, blk[cut .. ^1])
    c.sendAll(g)
    let fs = c.readFrames(2000, until = proc(fs: seq[Frame]): bool =
      fs.rstError(1) >= 0 or fs.goawayError() >= 0)
    check fs.rstError(1) == int(errStreamClosed)
    # The discarded block is a bare indexed literal: no :method, no :path. A
    # regression that reset the stream AND dispatched the block would answer it
    # (400, or worse a second response on a stream that already had one).
    check not fs.hasResponse(1)
    check fs.goawayError() == -1
    let p = c.probe()
    check p.goawayError() == -1
    check p.bodyOf(probeSid) == probeValue
    c.close()

  test "a HEADERS after the final GOAWAY is refused, and no GOAWAY raises the cutoff (#233)":
    ## The graceful-drain refusal over the wire, and with it RFC 9113 6.8's
    ## no-raise rule for the last-stream-id. This case must run last: the drain it
    ## starts takes the whole server down.
    ##
    ## The window it needs is the one markDrain leaves open when the write side is
    ## stalled: GOAWAY notice, no active stream left, so the final GOAWAY (which
    ## sets `goingAway` and freezes the cutoff) plus `closeAfterFlush`, then a
    ## flush that stops at EAGAIN. The connection stays `csActive` with the close
    ## owed to a writable socket that will not come while this client does not
    ## read, and h2Feed keeps parsing whatever arrives.
    var c = newH2TestConn(srv.port)
    var f = ""
    f.addRawHeaders(padSid, reqBlock("/pad"), headersDone)
    c.sendAll(f)
    # Read only as far as the response HEADERS frame: that proves the request was
    # served and its stream is already gone, while the remaining megabytes of
    # CONTINUATION stay queued, so the socket stays full.
    discard c.readFrames(2000, until = proc(fs: seq[Frame]): bool =
      fs.hasResponse(padSid))
    srv.requestShutdown()
    # beginDrain closes the listener first and only then calls markDrain on each
    # connection, so a refused connect means the drain is under way (and markDrain
    # for this connection is microseconds behind it, hence the short settle).
    var drainStarted = false
    for i in 0 ..< 200:
      try:
        let s = newSocket(buffered = false)
        s.connect("127.0.0.1", srv.port)
        s.close()
      except OSError:
        drainStarted = true
      if drainStarted: break
      sleep(20)
    check drainStarted
    sleep(100)
    # Pipelined behind the final GOAWAY: a new stream, which `goingAway` refuses,
    # and then a CONTINUATION with no block pending, which is a connection error.
    # The refusal advanced lastStreamId past the announced cutoff, so that GOAWAY
    # is exactly the one that must not name the higher id.
    var g = ""
    g.addRawHeaders(drainRefusedSid, reqBlock("/"), headersDone)
    g.addContinuation(drainRefusedSid, "")
    c.sendAll(g)
    let fs = c.readFrames(4000)          # drains the pad, then EOF on the close
    c.close()
    # The refusal itself: a stream error, not a connection error, and no response.
    check fs.rstError(drainRefusedSid) == int(errRefusedStream)
    check not fs.hasResponse(drainRefusedSid)
    let gs = fs.goaways()
    # `require`, not `check`: the indexing below would otherwise raise instead of
    # reporting. Three GOAWAYs: the drain notice, the cutoff, the connection error.
    require gs.len >= 3
    check fs.goawayLastStreamId() == 0x7fffffff   # RFC 9113 6.8 step 1: notice
    check gs[1].lastId == int(padSid)    # step 2: the real cutoff
    check gs[^1].err == int(errProtocol) # the stray CONTINUATION
    for i in 1 ..< gs.len:
      # Without the frozen cutoff this is gs[^1].lastId == drainRefusedSid: the
      # refused id raised the announced value, and a peer that had already retried
      # stream 3 elsewhere now has it counted as processed here too.
      check gs[i].lastId <= gs[1].lastId

srv.close()
echo "http2 refused streams ok"
