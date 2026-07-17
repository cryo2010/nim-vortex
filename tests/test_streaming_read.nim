## Pull-based request-body streaming via the asyncdispatch adapter:
## `await req.read()` over a `router.stream` async route, built on the core's
## push `onBody`.

import std/[unittest, net, posix, strutils, httpcore, atomics, os]
import vortex/[settings, request, server, router]
import vortex/adapters/asyncdispatch
import ./helper

var finished: Atomic[int]      # incremented when a streaming handler unwinds

proc hUpload(req: Request, res: Response) {.async.} =
  var total = 0
  while true:
    let chunk = await req.read()
    if chunk.len == 0: break
    total += chunk.len
  res.send(Http200, "got " & $total, "text/plain")

proc hAbortable(req: Request, res: Response) {.async.} =
  var total = 0
  while true:
    let chunk = await req.read()
    if chunk.len == 0: break        # EOF, whether the body completed or the peer left
    total += chunk.len
  finished.atomicInc()             # reached only if the read loop terminated
  res.send(Http200, "got " & $total, "text/plain")

proc hEcho(req: Request, res: Response) {.async.} =
  var body = ""
  while true:
    let chunk = await req.read()
    if chunk.len == 0: break
    body.add chunk
  res.send(Http200, body, "application/octet-stream")

var rt = newRouter()
rt.stream(HttpPost, "/upload", hUpload)
rt.stream(HttpPost, "/echo", hEcho)
rt.stream(HttpPost, "/abortable", hAbortable)

var srv = start(rt.toHandler,
                initSettings(port = Port(0), numThreads = 1,
                             maxBodySize = 8 * 1024 * 1024),
                rt.streamPredicate)
let port = srv.port

proc rawPost(path, body: string): string =
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send("POST " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
         "Content-Length: " & $body.len & "\r\n\r\n")
  var off = 0
  while off < body.len:                  # multiple writes -> multiple onBody
    let n = min(16 * 1024, body.len - off)
    s.send(body[off ..< off + n])
    inc off, n
  s.setRecvTimeout(4000)
  var buf = newString(65536)
  while true:
    let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if k <= 0: break
    result.add buf[0 ..< k]

proc splitBody(resp: string): string =
  let i = resp.find("\r\n\r\n")
  resp[i + 4 .. ^1]

suite "async req.read() request streaming":
  test "await read() reassembles a large upload":
    let body = "r".repeat(256 * 1024)
    check splitBody(rawPost("/upload", body)) == "got " & $body.len

  test "await read() echo returns the exact body":
    let body = "chunky data! ".repeat(6000)   # ~78 KiB
    check splitBody(rawPost("/echo", body)) == body

  test "empty body: read() returns \"\" immediately":
    check splitBody(rawPost("/upload", "")) == "got 0"

  test "small one-read body":
    check splitBody(rawPost("/upload", "hello")) == "got 5"

  test "client disconnect mid-upload unwinds the handler (no leaked reader)":
    # Promise 1000 body bytes, send only a few, then drop the connection. The
    # server must deliver onBody(last=true) on close so await read() returns "",
    # the handler unwinds, and its Future / reader-table entry are released.
    let before = finished.load()
    block:
      let s = newSocket(buffered = false)
      s.connect("127.0.0.1", port)
      s.send("POST /abortable HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
             "Content-Length: 1000\r\n\r\n")
      s.send("partial")                  # far fewer than 1000 bytes
      s.close()                          # disconnect mid-upload
    var advanced = false
    for _ in 0 ..< 200:                  # up to ~2s for the loop to process it
      if finished.load() > before:
        advanced = true
        break
      sleep(10)
    check advanced

srv.close()
echo "server shut down cleanly"
