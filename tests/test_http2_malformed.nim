## Frame-level HTTP/2 malformed-header rejection. Regression tests for R4
## (Content-Length: negative or a differing duplicate, RFC 9113 8.1.1) and R10
## (field name/value validation: NUL/CR/LF, RFC 9113 8.2.1). Each sends one
## HEADERS frame and asserts the server answers with RST_STREAM(PROTOCOL_ERROR)
## on the stream, while a well-formed request still succeeds.
##
## The second suite covers the conformance follow-ups of #240 that are visible
## on the wire: frames on a permanently idle even stream id, the field-value and
## Content-Length grammars, the :method and CONNECT pseudo-header rules, the
## connection-specific fields we must never generate on a response, the HPACK
## dynamic-table-size update, and the GOAWAY length check.

import std/[unittest, net, httpcore]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./h2client

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

var srv = newVortex(RequestHandler(handler),
                    initVortexConfig(numThreads = 1)).start(0)

const base = @[(":method", "POST"), (":scheme", "http"), (":path", "/"),
               (":authority", "localhost")]

proc sendReq(headers: openArray[(string, string)]): seq[Frame] =
  var c = newH2TestConn(srv.port)
  var f = ""
  f.addRequest(1, headers, endStream = true)
  c.sendRaw(f)
  result = c.readFrames(1500)
  c.close()

proc sendReqBody(headers: openArray[(string, string)],
                 body: string): seq[Frame] =
  ## A request whose DATA frame carries `body`, so a Content-Length test can
  ## tell "rejected by the grammar" apart from "accepted, then reconciled
  ## against the body": a loose parse of the value would match this body.
  var c = newH2TestConn(srv.port)
  var f = ""
  f.addRequest(1, headers, endStream = false)
  f.addData(1, body, endStream = true)
  c.sendRaw(f)
  result = c.readFrames(1500)
  c.close()

proc sendFrames(data: string): seq[Frame] =
  ## Write raw frame bytes on a fresh connection and collect the reply, for
  ## the cases that are not requests at all.
  var c = newH2TestConn(srv.port)
  c.sendRaw(data)
  result = c.readFrames(1500,
    until = proc(fs: seq[Frame]): bool = fs.goawayError() >= 0)
  c.close()

suite "HTTP/2 malformed header rejection":
  test "negative Content-Length is rejected (R4)":
    check sendReq(base & @[("content-length", "-1")]).rstError(1) ==
      int(errProtocol)

  test "differing duplicate Content-Length is rejected (R4)":
    # The last value (0) matches the empty body, so the body-length
    # reconciliation would NOT catch it -- only the duplicate check does.
    check sendReq(base & @[("content-length", "5"), ("content-length", "0")])
      .rstError(1) == int(errProtocol)

  test "matching duplicate Content-Length is tolerated (R4)":
    # Same value twice is not ambiguous. CL 0 reconciles with the empty body.
    let frames = sendReq(base & @[("content-length", "0"),
                                  ("content-length", "0")])
    check frames.rstError(1) == -1
    check frames.count(ftHeaders) >= 1

  test "CR/LF in a header value is rejected (R10)":
    check sendReq(base & @[("x-bad", "a\r\nb")]).rstError(1) == int(errProtocol)

  test "NUL in a header value is rejected (R10)":
    check sendReq(base & @[("x-bad", "a\x00b")]).rstError(1) == int(errProtocol)

  test "control char in a header name is rejected (R10)":
    check sendReq(base & @[("x\rbad", "v")]).rstError(1) == int(errProtocol)

  test "separator in a header name is rejected (R10)":
    check sendReq(base & @[("x(bad)", "v")]).rstError(1) == int(errProtocol)

  test "an http request without :authority or Host is rejected (RFC 9113 8.3.1)":
    check sendReq(@[(":method", "GET"), (":scheme", "http"), (":path", "/")])
      .rstError(1) == int(errProtocol)

  test "a Host field satisfies the authority requirement":
    let frames = sendReq(@[(":method", "GET"), (":scheme", "http"),
                           (":path", "/"), ("host", "localhost")])
    check frames.rstError(1) == -1
    check frames.count(ftHeaders) >= 1

  test "a well-formed request still succeeds":
    let frames = sendReq(@[(":method", "GET"), (":scheme", "http"),
                           (":path", "/"), (":authority", "localhost")])
    check frames.rstError(1) == -1
    check frames.count(ftHeaders) >= 1

proc hopHandler(req: Request, res: Response) {.gcsafe.} =
  ## h1-portable handler code: sets connection-specific fields an h2 endpoint
  ## MUST NOT generate (RFC 9113 8.2.2), plus one field that must survive.
  res.headers["Connection"] = "close"
  res.headers["Keep-Alive"] = "timeout=5"
  res.headers["Transfer-Encoding"] = "chunked"
  res.headers["Upgrade"] = "h2c"
  res.headers["Proxy-Connection"] = "keep-alive"
  res.headers["X-Kept"] = "yes"
  res.send(Http200, "ok")

const getBase = @[(":method", "GET"), (":scheme", "http"), (":path", "/"),
                  (":authority", "localhost")]

suite "HTTP/2 conformance follow-ups (#240)":
  test "DATA on an even stream id is a connection error (#240.1)":
    # Even ids are server-initiated (push) space the client may never use, so
    # stream 2 is permanently idle: RFC 9113 5.1 makes any frame on it a
    # connection PROTOCOL_ERROR, not a stream reset. Stream 3 runs first in
    # every one of these so the high-water mark is past 2 and only a parity
    # check can catch it (a `> lastStreamId` test alone cannot).
    var f = ""
    f.addRequest(3, getBase, endStream = true)
    f.addData(2, "x")
    check sendFrames(f).goawayError() == int(errProtocol)

  test "WINDOW_UPDATE on an even stream id is a connection error (#240.1)":
    var f = ""
    f.addRequest(3, getBase, endStream = true)
    f.addWindowUpdate(2, 100)
    check sendFrames(f).goawayError() == int(errProtocol)

  test "RST_STREAM on an even stream id is a connection error (#240.1)":
    var f = ""
    f.addRequest(3, getBase, endStream = true)
    f.addRstStream(2, errCancel)
    check sendFrames(f).goawayError() == int(errProtocol)

  test "connection-specific response fields are dropped (#240.3)":
    var s2 = newVortex(RequestHandler(hopHandler),
                       initVortexConfig(numThreads = 1)).start(0)
    var c = newH2TestConn(s2.port)
    var f = ""
    f.addRequest(1, getBase, endStream = true)
    c.sendRaw(f)
    let frames = c.readFrames(1500,
      until = proc(fs: seq[Frame]): bool = fs.hasResponse(1))
    var names: seq[string]
    for (n, _) in decodeHeaders(frames.headerPayload(1)): names.add n
    for banned in ["connection", "keep-alive", "transfer-encoding", "upgrade",
                   "proxy-connection"]:
      check banned notin names
    check "x-kept" in names                  # an ordinary field still rides
    c.close()
    s2.close()

  test "an unknown method is rejected, not routed as GET (#240.4)":
    # `else: HttpGet` used to run the GET handler for PURGE, a method-ACL
    # bypass differential with the h1 parser.
    check sendReq(@[(":method", "PURGE"), (":scheme", "http"), (":path", "/"),
                    (":authority", "localhost")]).rstError(1) == int(errProtocol)

  test "a non-token method value is rejected (#240.4)":
    check sendReq(@[(":method", "GET X"), (":scheme", "http"), (":path", "/"),
                    (":authority", "localhost")]).rstError(1) == int(errProtocol)

  test "a CONNECT carrying :scheme and :path is malformed (#240.5)":
    # RFC 9113 8.5 forbids them on CONNECT; this shape used to classify as an
    # ordinary request and reach the handler.
    check sendReq(@[(":method", "CONNECT"), (":scheme", "http"),
                    (":path", "/"), (":authority", "localhost")])
      .rstError(1) == int(errProtocol)

  test "a '+'-prefixed Content-Length is rejected (#240.6)":
    # RFC 9110 8.6 is 1*DIGIT. parseBiggestInt read "+5" as 5, which matches
    # this 5-byte body, so a 200 here means the grammar check is gone.
    let frames = sendReqBody(base & @[("content-length", "+5")], "hello")
    check frames.rstError(1) == int(errProtocol)

  test "an underscore in Content-Length is rejected (#240.6)":
    # Nim's parseBiggestInt reads "1_0" as 10, which matches this 10-byte body;
    # a re-serializing proxy reads the same field as 1 or rejects it.
    let frames = sendReqBody(base & @[("content-length", "1_0")], "0123456789")
    check frames.rstError(1) == int(errProtocol)

  test "a leading space in a field value is rejected (#240.7)":
    check sendReq(base & @[("x-ws", " v")]).rstError(1) == int(errProtocol)

  test "a trailing HTAB in a field value is rejected (#240.7)":
    check sendReq(base & @[("x-ws", "v\t")]).rstError(1) == int(errProtocol)

  test "lowering SETTINGS_HEADER_TABLE_SIZE is acknowledged in HPACK (#240.8)":
    # RFC 7541 4.2: the encoder must signal the reduced maximum with a
    # dynamic-table-size-update instruction before the next header block, or a
    # strict inflater (nghttp2) fails the block with COMPRESSION_ERROR.
    var c = newH2TestConn(srv.port)
    var f = ""
    f.addSettingFrame(setHeaderTableSize, 0)
    f.addRequest(1, getBase, endStream = true)
    c.sendRaw(f)
    let frames = c.readFrames(1500,
      until = proc(fs: seq[Frame]): bool = fs.hasResponse(1))
    let block1 = frames.headerPayload(1)
    check block1.len > 0
    check uint8(block1[0]) == 0x20'u8        # size update, new maximum 0
    check decodeHeaders(block1).len > 0      # and the block still decodes
    c.close()

  test "a GOAWAY shorter than 8 octets is a FRAME_SIZE_ERROR (#240.10)":
    var f = ""
    f.addFrameHeader(4, ftGoaway, 0, 0)
    f.add "\0\0\0\0"                         # last-stream-id only, no error code
    check sendFrames(f).goawayError() == int(errFrameSize)

srv.close()
echo "http2 malformed headers ok"
