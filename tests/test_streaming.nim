## Streaming response bodies over HTTP/1.1: res.sendHead / write / finish.
## Drives a streaming handler over a raw socket and checks the chunked framing,
## body reassembly, keep-alive continuation, and a large (backpressured) body.

import std/[unittest, net, posix, strutils, httpcore, osproc]
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/stream":
    res.sendHead(Http200, "text/plain")
    res.write("Hello, ")
    res.write("streamed ")
    res.write("world!")
    res.finish()
  of "/big":
    # 2 MiB in 4 KiB writes: exceeds the socket buffer, exercising the
    # write()==false backpressure return and the wbuf backlog path.
    res.sendHead(Http200, "application/octet-stream")
    let chunk = repeat('x', 4096)
    for i in 0 ..< 512:
      discard res.write(chunk)
    res.finish()
  of "/trailer":
    res.sendHead(Http200, "text/plain")
    res.write("body")
    res.finish({"X-Checksum": "abc123"})
  of "/pump":
    # A backpressure-honoring producer: write until write() reports the
    # backlog is full, then resume from onDrain. Exercises the deferred
    # streaming + onDrain resume path (4 MiB through a small socket buffer).
    let remaining = new(int)
    remaining[] = 1024
    let chunk = repeat('z', 4096)
    proc pump(res: Response) {.gcsafe.} =
      while remaining[] > 0:
        let ok = res.write(chunk)       # appends even when it returns false
        dec remaining[]
        if not ok:
          res.onDrain(pump)             # backed up: resume when it drains
          return
      res.finish()
    res.sendHead(Http200, "application/octet-stream")
    pump(res)
  else:
    res.send(Http404, "nope", "text/plain")

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1))
let port = srv.port

proc rawGet(path: string, keepAlive = false): string =
  ## Send one request and read until the peer closes (or, for keep-alive,
  ## until the chunked terminator arrives).
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  let conn = if keepAlive: "keep-alive" else: "close"
  s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: " & conn & "\r\n\r\n")
  s.setRecvTimeout(3000)
  var buf = newString(65536)
  while true:
    let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if k <= 0: break
    result.add buf[0 ..< k]
    if keepAlive and result.endsWith("0\r\n\r\n"): break

proc splitHeadBody(resp: string): (string, string) =
  let i = resp.find("\r\n\r\n")
  (resp[0 ..< i], resp[i + 4 .. ^1])

proc dechunk(body: string): string =
  ## Decode a Transfer-Encoding: chunked body (ignoring trailers).
  var pos = 0
  while true:
    let nl = body.find("\r\n", pos)
    if nl < 0: break
    let size = parseHexInt(body[pos ..< nl].strip())
    pos = nl + 2
    if size == 0: break
    result.add body[pos ..< pos + size]
    pos += size + 2                     # skip the chunk data and its CRLF

suite "HTTP/1 streaming responses":
  test "chunked framing and reassembly":
    let resp = rawGet("/stream")
    let (head, body) = splitHeadBody(resp)
    check "HTTP/1.1 200" in head
    check "Transfer-Encoding: chunked" in head
    check "Content-Length:" notin head
    check dechunk(body) == "Hello, streamed world!"

  test "a large body streams intact under backpressure":
    let resp = rawGet("/big")
    let (head, body) = splitHeadBody(resp)
    check "Transfer-Encoding: chunked" in head
    let decoded = dechunk(body)
    check decoded.len == 512 * 4096
    check decoded == repeat('x', 512 * 4096)

  test "backpressure resume via onDrain streams the whole body":
    let resp = rawGet("/pump")
    let (head, body) = splitHeadBody(resp)
    check "Transfer-Encoding: chunked" in head
    check dechunk(body).len == 1024 * 4096

  test "trailers are emitted after the last chunk":
    let resp = rawGet("/trailer")
    check "X-Checksum: abc123" in resp
    let (_, body) = splitHeadBody(resp)
    check dechunk(body) == "body"

  test "keep-alive: two streamed requests on one connection":
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", port)
    s.setRecvTimeout(3000)
    for n in 0 ..< 2:
      s.send("GET /stream HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
      var body: string
      while true:
        var buf = newString(4096)
        let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
        if k <= 0: break
        body.add buf[0 ..< k]
        if body.endsWith("0\r\n\r\n"): break
      let (_, b) = splitHeadBody(body)
      check dechunk(b) == "Hello, streamed world!"

proc h2curl(args: string): (string, int) =
  let (output, rc) = execCmdEx("curl -s --http2-prior-knowledge " & args)
  (output.strip(), rc)

let base = "http://127.0.0.1:" & $port

suite "HTTP/2 streaming responses":
  test "streamed body reassembles over h2 (no chunked framing)":
    let (output, rc) = h2curl("-w '|%{http_version}' " & base & "/stream")
    check rc == 0
    check output == "Hello, streamed world!|2"

  test "a large streamed body is intact over h2":
    let (output, rc) = h2curl("-o /dev/null -w '%{size_download}' " & base & "/big")
    check rc == 0
    check output == $(512 * 4096)

  test "HEAD over a streamed h2 route has no body":
    let (output, rc) = h2curl("-I -w '%{size_download}' " & base & "/stream")
    check rc == 0
    check output.endsWith("0")

srv.close()
echo "server shut down cleanly"
