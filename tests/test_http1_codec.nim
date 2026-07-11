import std/[unittest, httpcore, strutils]
import vortex/http1/codec

proc serialize(code: HttpCode, contentType: string, body: string,
               skipBody = false,
               extra: openArray[(string, string)] = []): string =
  ## Serialize one response head+body with fixed Date/Server.
  appendResponse(result, code, "Sun, 06 Jul 2025 12:00:00 GMT", "vortex",
                 contentType, body, extra, keepAlive = true, skipBody = skipBody)

suite "http/1.1 response framing":
  test "200 carries Content-Type, Content-Length and body":
    let r = serialize(Http200, "text/plain", "hi")
    check "Content-Type: text/plain\r\n" in r
    check "Content-Length: 2\r\n" in r
    check r.endsWith("\r\n\r\nhi")

  test "HEAD keeps the Content-Length a GET would send, drops the body":
    let r = serialize(Http200, "text/plain", "hi", skipBody = true)
    check "Content-Length: 2\r\n" in r      # matches the would-be GET
    check "Content-Type: text/plain\r\n" in r
    check r.endsWith("\r\n\r\n")            # no body bytes

  test "304 omits Content-Length and Content-Type (RFC 9110 8.6)":
    # A validator/caching header still passes through; a stray body is
    # dropped so a length-less response can never be mis-framed.
    let r = serialize(Http304, "text/plain", "should-be-dropped",
                      extra = @{"ETag": "\"v1\"", "Cache-Control": "max-age=60"})
    check "Content-Length" notin r
    check "Content-Type" notin r
    check "ETag: \"v1\"\r\n" in r
    check "Cache-Control: max-age=60\r\n" in r
    check r.endsWith("\r\n\r\n")            # no body
    check "should-be-dropped" notin r

  test "204 omits Content-Length and Content-Type":
    let r = serialize(Http204, "text/plain", "")
    check "Content-Length" notin r
    check "Content-Type" notin r
    check r.endsWith("\r\n\r\n")

  test "1xx omits Content-Length and Content-Type":
    let r = serialize(HttpCode(103), "text/plain", "")   # Early Hints
    check "Content-Length" notin r
    check "Content-Type" notin r

  test "empty-body 200 still advertises Content-Length: 0":
    # A genuinely empty representation is different from a bodiless status.
    let r = serialize(Http200, "", "")
    check "Content-Length: 0\r\n" in r
