import std/[unittest, httpcore, strutils]
import vortex/http1/parser

proc limits(maxHeaderSize = 16384, maxHeaderCount = 100,
            maxBodySize = 1024 * 1024): ParserLimits =
  ParserLimits(maxHeaderSize: maxHeaderSize, maxHeaderCount: maxHeaderCount,
               maxBodySize: maxBodySize)

proc parseAll(data: string, lim = limits()):
    tuple[res: ParseResult, p: RequestParser, body: string] =
  var p: RequestParser
  p.reset(0)
  var body = ""
  let res = p.parse(data, data.len, lim, body)
  (res, p, body)

proc parseByByte(data: string, lim = limits()):
    tuple[res: ParseResult, p: RequestParser, body: string] =
  ## Feed the buffer one byte at a time to exercise resumability.
  var p: RequestParser
  p.reset(0)
  var body = ""
  for i in 1 .. data.len:
    let res = p.parse(data, i, lim, body)
    if res != prNeedMore:
      return (res, p, body)
  (prNeedMore, p, body)

proc pathOf(p: RequestParser, data: string): string =
  data.substr(int(p.pathStart), int(p.pathStart + p.pathLen) - 1)

proc headerOf(p: RequestParser, data: string, i: int): (string, string) =
  let h = p.headers[i]
  (data.substr(int(h.nameStart), int(h.nameStart + h.nameLen) - 1),
   data.substr(int(h.valStart), int(h.valStart + h.valLen) - 1))

suite "request line":
  test "simple GET":
    let (res, p, _) = parseAll("GET /foo/bar?q=1 HTTP/1.1\r\n\r\n")
    check res == prComplete
    check p.httpMethod == HttpGet
    check p.pathOf("GET /foo/bar?q=1 HTTP/1.1\r\n\r\n") == "/foo/bar?q=1"
    check p.minor == 1
    check p.keepAlive

  test "HTTP/1.0 defaults to close":
    let (res, p, _) = parseAll("GET / HTTP/1.0\r\n\r\n")
    check res == prComplete
    check not p.keepAlive

  test "leading CRLF tolerated":
    let (res, p, _) = parseAll("\r\nGET / HTTP/1.1\r\n\r\n")
    check res == prComplete
    check p.httpMethod == HttpGet

  test "all methods":
    for (m, e) in [("GET", HttpGet), ("HEAD", HttpHead), ("POST", HttpPost),
                   ("PUT", HttpPut), ("DELETE", HttpDelete),
                   ("OPTIONS", HttpOptions), ("PATCH", HttpPatch),
                   ("TRACE", HttpTrace), ("CONNECT", HttpConnect)]:
      let (res, p, _) = parseAll(m & " / HTTP/1.1\r\n\r\n")
      check res == prComplete
      check p.httpMethod == e

  test "unknown method rejected":
    let (res, p, _) = parseAll("BREW / HTTP/1.1\r\n\r\n")
    check res == prError
    check p.errorStatus == Http501

  test "bad version":
    let (res, p, _) = parseAll("GET / HTTP/2.0\r\n\r\n")
    check res == prError
    check p.errorStatus == Http505

  test "garbage rejected":
    let (res, p, _) = parseAll("hello world\r\n\r\n")
    check res == prError
    check p.errorStatus in [Http400, Http501]

  test "bare LF rejected":
    let (res, _, _) = parseAll("GET / HTTP/1.1\n\n")
    check res == prError

suite "headers":
  test "header slices and OWS trimming":
    let data = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Pad:   spaced   \r\n\r\n"
    let (res, p, _) = parseAll(data)
    check res == prComplete
    check p.headers.len == 2
    check p.headerOf(data, 0) == ("Host", "example.com")
    check p.headerOf(data, 1) == ("X-Pad", "spaced")

  test "connection close":
    let (res, p, _) = parseAll("GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
    check res == prComplete
    check not p.keepAlive

  test "1.0 keep-alive":
    let (res, p, _) = parseAll(
      "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
    check res == prComplete
    check p.keepAlive

  test "expect 100-continue":
    let (res, p, _) = parseByByte(
      "POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello")
    check res == prComplete
    check p.expectContinue

  test "space in field name rejected":
    let (res, _, _) = parseAll("GET / HTTP/1.1\r\nBad Header: x\r\n\r\n")
    check res == prError

  test "too many headers":
    var data = "GET / HTTP/1.1\r\n"
    for i in 0 ..< 6: data.add "H" & $i & ": v\r\n"
    data.add "\r\n"
    let (res, p, _) = parseAll(data, limits(maxHeaderCount = 5))
    check res == prError
    check p.errorStatus == Http431

  test "oversized headers":
    var data = "GET / HTTP/1.1\r\nX-Big: " & repeat('a', 300) & "\r\n\r\n"
    let (res, p, _) = parseAll(data, limits(maxHeaderSize = 128))
    check res == prError
    check p.errorStatus == Http431

suite "bodies":
  test "content-length body":
    let data = "POST /e HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world"
    let (res, p, _) = parseAll(data)
    check res == prComplete
    check p.contentLength == 11
    check data.substr(p.bodyStart, p.bodyStart + p.bodyLen - 1) == "hello world"

  test "content-length body split across reads":
    let data = "POST /e HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world"
    let (res, p, _) = parseByByte(data)
    check res == prComplete
    check data.substr(p.bodyStart, p.bodyStart + p.bodyLen - 1) == "hello world"

  test "invalid content-length":
    let (res, p, _) = parseAll("POST / HTTP/1.1\r\nContent-Length: 1x\r\n\r\n")
    check res == prError
    check p.errorStatus == Http400

  test "duplicate content-length":
    let (res, _, _) = parseAll(
      "POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nab")
    check res == prError

  test "content-length plus transfer-encoding rejected":
    let (res, _, _) = parseAll("POST / HTTP/1.1\r\nContent-Length: 2\r\n" &
      "Transfer-Encoding: chunked\r\n\r\n")
    check res == prError

  test "body over limit":
    let (res, p, _) = parseAll(
      "POST / HTTP/1.1\r\nContent-Length: 2000000\r\n\r\n")
    check res == prError
    check p.errorStatus == Http413

  test "unknown transfer-encoding":
    let (res, p, _) = parseAll(
      "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n")
    check res == prError
    check p.errorStatus == Http501

suite "chunked":
  const chunked = "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" &
                  "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n"

  test "chunked body decoded":
    let (res, p, body) = parseAll(chunked)
    check res == prComplete
    check p.chunked
    check body == "hello world"

  test "chunked split across reads":
    let (res, _, body) = parseByByte(chunked)
    check res == prComplete
    check body == "hello world"

  test "chunked with trailers":
    let data = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" &
               "3\r\nabc\r\n0\r\nX-Trailer: v\r\n\r\n"
    let (res, _, body) = parseAll(data)
    check res == prComplete
    check body == "abc"

  test "chunked over limit":
    let data = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" &
               "FFFFF\r\n"
    let (res, p, _) = parseAll(data, limits(maxBodySize = 1024))
    check res == prError
    check p.errorStatus == Http413

  test "bad chunk size":
    let data = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"
    let (res, _, _) = parseAll(data)
    check res == prError

  test "missing chunk CRLF":
    let data = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" &
               "3\r\nabcXX"
    let (res, _, _) = parseAll(data)
    check res == prError

suite "pipelining":
  test "two requests back to back":
    let data = "GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n"
    var p: RequestParser
    p.reset(0)
    var body = ""
    check p.parse(data, data.len, limits(), body) == prComplete
    check p.pathOf(data) == "/a"
    let next = p.pos
    p.reset(next)
    check p.parse(data, data.len, limits(), body) == prComplete
    check p.pathOf(data) == "/b"
