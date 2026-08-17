## Frame-level HTTP/2 malformed-header rejection. Regression tests for R4
## (Content-Length: negative or a differing duplicate, RFC 9113 8.1.1) and R10
## (field name/value validation: NUL/CR/LF, RFC 9113 8.2.1). Each sends one
## HEADERS frame and asserts the server answers with RST_STREAM(PROTOCOL_ERROR)
## on the stream, while a well-formed request still succeeds.

import std/[unittest, net, httpcore]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./h2client

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

var srv = newVortex(RequestHandler(handler),
                    initVortexConfig(numThreads = 1)).start(0)

const base = @[(":method", "POST"), (":scheme", "http"), (":path", "/")]

proc sendReq(headers: openArray[(string, string)]): seq[Frame] =
  var c = newH2TestConn(srv.port)
  var f = ""
  f.addRequest(1, headers, endStream = true)
  c.sendRaw(f)
  result = c.readFrames(1500)
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

  test "a well-formed request still succeeds":
    let frames = sendReq(@[(":method", "GET"), (":scheme", "http"),
                           (":path", "/")])
    check frames.rstError(1) == -1
    check frames.count(ftHeaders) >= 1

srv.close()
echo "http2 malformed headers ok"
