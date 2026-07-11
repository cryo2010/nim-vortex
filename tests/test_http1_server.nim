import std/[unittest, net, httpcore, strutils, tables]
import std/httpclient except Response
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.url.path
  of "/":
    res.send(Http200, "Hello, World!", "text/plain")
  of "/echo":
    res.send(Http200, req.body, req.header("Content-Type"))
  of "/headers":
    res.send(Http200, req.header("X-Probe"), "text/plain")
  of "/qs":
    var parts: seq[string]
    parts.add "path=" & req.url.path
    for key in ["a", "b", "sp"]:
      if key in req.query:
        parts.add key & "=" & req.query[key]
    res.send(Http200, parts.join("|"), "text/plain")
  of "/boom":
    raise newException(ValueError, "handler exploded")
  else:
    res.send(Http404, "not found", "text/plain")

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 2,
                             headerTimeout = 2, keepAliveTimeout = 2,
                             maxBodySize = 64 * 1024))

let port = srv.port
let base = "http://127.0.0.1:" & $port

suite "http/1.1 integration":
  test "basic GET":
    var client = newHttpClient()
    defer: client.close()
    let resp = client.get(base & "/")
    check resp.code == Http200
    check resp.body == "Hello, World!"
    check resp.headers["content-length"] == "13"
    check resp.headers.hasKey("date")

  test "404":
    var client = newHttpClient()
    defer: client.close()
    check client.get(base & "/nope").code == Http404

  test "POST echo":
    var client = newHttpClient()
    defer: client.close()
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let resp = client.post(base & "/echo", body = """{"a":1}""")
    check resp.code == Http200
    check resp.body == """{"a":1}"""
    check resp.headers["content-type"] == "application/json"

  test "query string parsing (lazy, cached)":
    var client = newHttpClient()
    defer: client.close()
    check client.getContent(base & "/qs?a=1&b=two&sp=hello%20world+x") ==
      "path=/qs|a=1|b=two|sp=hello world x"
    # repeated access + no query at all
    check client.getContent(base & "/qs") == "path=/qs"
    # duplicate keys: last wins
    check client.getContent(base & "/qs?a=first&a=second") ==
      "path=/qs|a=second"
    # root with query still routes (url.path strips it)
    check client.getContent(base & "/?x=1") == "Hello, World!"

  test "request header readable":
    var client = newHttpClient()
    defer: client.close()
    client.headers = newHttpHeaders({"X-Probe": "zap"})
    check client.get(base & "/headers").body == "zap"

  test "keep-alive reuses connection":
    var client = newHttpClient()
    defer: client.close()
    for i in 0 ..< 5:
      check client.get(base & "/").body == "Hello, World!"

  test "HEAD has no body but correct length":
    let resp = rawExchange(port,
      "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check "200" in resp
    check "Content-Length: 13" in resp
    check not resp.endsWith("Hello, World!")

  test "pipelined requests answered in order":
    let resp = rawExchange(port,
      "GET / HTTP/1.1\r\nHost: x\r\n\r\n" &
      "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n" &
      "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check resp.count("HTTP/1.1 200") == 2
    check resp.count("HTTP/1.1 404") == 1
    check resp.find("404") > resp.find("200")

  test "chunked upload":
    let resp = rawExchange(port,
      "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n" &
      "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" &
      "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    check "200" in resp
    check resp.endsWith("hello world")

  test "expect 100-continue":
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", port)
    s.send("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n" &
           "Expect: 100-continue\r\nConnection: close\r\n\r\n")
    const interim = "HTTP/1.1 100 Continue\r\n\r\n"
    check s.recvAvailable(1000) == interim
    s.send("hello")
    let rest = s.recvUntilClose(1000)
    check "200" in rest
    check rest.endsWith("hello")

  test "malformed request gets 400 and close":
    let resp = rawExchange(port, "NOT A REQUEST\r\n\r\n")
    check "HTTP/1.1 4" in resp or "HTTP/1.1 501" in resp
    check "Connection: close" in resp

  test "oversized body gets 413":
    let resp = rawExchange(port,
      "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n")
    check "413" in resp

  test "oversized header delivers 431 before close (lingering close)":
    # The header exceeds the limit while its bytes are still unread; the
    # lingering close drains the peer so the 431 reaches the client
    # instead of being RST-truncated. (No competing load here, so the
    # delivery is deterministic.)
    let resp = rawExchange(port,
      "GET / HTTP/1.1\r\nHost: x\r\nX-Big: " & repeat('a', 20000) & "\r\n\r\n")
    check "431" in resp

  test "handler exception gives 500":
    let resp = rawExchange(port, "GET /boom HTTP/1.1\r\nHost: x\r\n\r\n")
    check "HTTP/1.1 500" in resp

  test "idle connection times out":
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", port)
    check s.waitForClose()

var capSrv = start(RequestHandler(handler),
                   initSettings(port = Port(0), numThreads = 1,
                                maxRequestsPerSocket = 3))

suite "maxRequestsPerSocket":
  test "connection is closed after the request cap":
    # Five pipelined keep-alive requests, but only three are served; the
    # third carries Connection: close and the socket closes after it.
    var req = ""
    for i in 0 ..< 5:
      req.add "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    let resp = rawExchange(capSrv.port, req)
    check resp.count("HTTP/1.1 200") == 3
    check "Connection: close" in resp

  test "requests below the cap keep the connection alive":
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", capSrv.port)
    for i in 0 ..< 2:                 # under the cap of 3
      s.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      check "200" in s.recvAvailable(1000)
    # Connection is still open (not closed by the cap).
    check not s.waitForClose(tries = 2, stepMs = 200)

capSrv.close()
srv.close()
echo "server shut down cleanly"
