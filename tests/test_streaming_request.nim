## Streaming request bodies over HTTP/1.1: a `router.stream` route is
## dispatched at headers-complete and consumes the body via `req.onBody`
## instead of it being buffered into `req.body`. Buffered routes on the same
## server must keep working unchanged.

import std/[unittest, net, posix, strutils, httpcore, os, osproc]
import vortex/[settings, request, server, router]
import ./helper

proc hUpload(req: Request, res: Response) {.gcsafe.} =
  ## Streaming: accumulate via onBody, reply with the byte count on the last
  ## chunk. (The accumulator proves incremental delivery reassembles.)
  let acc = new(string)
  req.onBody proc(chunk: openArray[char], last: bool) {.gcsafe.} =
    let base = acc[].len
    acc[].setLen(base + chunk.len)
    for i in 0 ..< chunk.len: acc[][base + i] = chunk[i]
    if last:
      res.send(Http200, "got " & $acc[].len, "text/plain")

proc hEchoStream(req: Request, res: Response) {.gcsafe.} =
  let acc = new(string)
  req.onBody proc(chunk: openArray[char], last: bool) {.gcsafe.} =
    let base = acc[].len
    acc[].setLen(base + chunk.len)
    for i in 0 ..< chunk.len: acc[][base + i] = chunk[i]
    if last:
      res.send(Http200, acc[], "application/octet-stream")

proc hBuffered(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "buffered:" & $req.body.len, "text/plain")

proc hReject(req: Request, res: Response) {.gcsafe.} =
  ## Streaming route that rejects at headers-complete without reading the body,
  ## so no 100 Continue is ever sent (Go's respond-before-read).
  res.send(Http403, "nope", "text/plain")

var rt = newRouter()
rt.stream(HttpPost, "/upload", hUpload)
rt.stream(HttpPost, "/echo", hEchoStream)
rt.stream(HttpPost, "/reject", hReject)
rt.post("/buffered", hBuffered)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1, maxBodySize = 8 * 1024 * 1024), rt.streamPredicate).start(0)
let port = srv.port

proc rawPost(path, body: string): string =
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send("POST " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
         "Content-Length: " & $body.len & "\r\n\r\n")
  # Send the body in chunks so it spans multiple reads on the server (exercises
  # incremental onBody delivery rather than a single buffered read).
  var off = 0
  while off < body.len:
    let n = min(16 * 1024, body.len - off)
    s.send(body[off ..< off + n])
    inc off, n
  s.setRecvTimeout(4000)
  var buf = newString(65536)
  while true:
    let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if k <= 0: break
    result.add buf[0 ..< k]

proc rawPostChunked(path, body: string, chunkSize = 16 * 1024): string =
  ## POST `body` using Transfer-Encoding: chunked, split into wire chunks.
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send("POST " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
         "Transfer-Encoding: chunked\r\n\r\n")
  var off = 0
  while off < body.len:
    let n = min(chunkSize, body.len - off)
    s.send(n.toHex.strip(chars = {'0'}, leading = true, trailing = false)
             .toLowerAscii & "\r\n" & body[off ..< off + n] & "\r\n")
    inc off, n
  s.send("0\r\n\r\n")
  s.setRecvTimeout(4000)
  var buf = newString(65536)
  while true:
    let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if k <= 0: break
    result.add buf[0 ..< k]

proc splitBody(resp: string): string =
  let i = resp.find("\r\n\r\n")
  resp[i + 4 .. ^1]

suite "HTTP/1 streaming request bodies":
  test "onBody reassembles a large streamed upload":
    let body = "x".repeat(256 * 1024)
    let resp = rawPost("/upload", body)
    check "HTTP/1.1 200" in resp
    check splitBody(resp) == "got " & $body.len

  test "streamed echo returns the exact body":
    let body = "The quick brown fox. ".repeat(5000)  # ~105 KiB
    let resp = rawPost("/echo", body)
    check splitBody(resp) == body

  test "small streamed body (arrives in one read)":
    let resp = rawPost("/upload", "hello")
    check splitBody(resp) == "got 5"

  test "empty streamed body":
    let resp = rawPost("/upload", "")
    check splitBody(resp) == "got 0"

  test "buffered routes still work alongside streaming ones":
    let resp = rawPost("/buffered", "12345")
    check splitBody(resp) == "buffered:5"

  test "expect 100-continue: streaming route sends 100 implicitly on read":
    # The handler reads the body (registers onBody), which sends 100 Continue
    # (Go's send-on-read). Only then does the client send the body.
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", port)
    s.setRecvTimeout(2000)
    s.send("POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n" &
           "Expect: 100-continue\r\nConnection: close\r\n\r\n")
    check s.recvAvailable(1000) == "HTTP/1.1 100 Continue\r\n\r\n"
    s.send("hello")
    let rest = s.recvUntilClose(1000)
    check "200" in rest
    check rest.endsWith("got 5")

  test "expect 100-continue: a streaming route that rejects sends no 100":
    # The handler responds before reading, so the client is never prompted for
    # the body: it gets the 403 straight away and no 100 Continue.
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", port)
    s.setRecvTimeout(2000)
    s.send("POST /reject HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n" &
           "Expect: 100-continue\r\nConnection: close\r\n\r\n")
    let resp = s.recvUntilClose(1000)
    check "403" in resp
    check "100 Continue" notin resp

  test "chunked streamed upload reassembles via onBody":
    let body = "y".repeat(200 * 1024)
    let resp = rawPostChunked("/upload", body, chunkSize = 8 * 1024)
    check splitBody(resp) == "got " & $body.len

  test "chunked streamed echo returns the exact body":
    let body = "Lorem ipsum dolor sit amet. ".repeat(4000)  # ~110 KiB
    let resp = rawPostChunked("/echo", body, chunkSize = 4096)
    check splitBody(resp) == body

  test "empty chunked streamed body":
    let resp = rawPostChunked("/upload", "")
    check splitBody(resp) == "got 0"

  test "a multi-megabyte upload streams (bounded rbuf, compaction)":
    let body = "q".repeat(4 * 1024 * 1024)
    let resp = rawPost("/upload", body)
    check splitBody(resp) == "got " & $body.len

  test "keep-alive: two streamed uploads on one connection":
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", port)
    s.setRecvTimeout(4000)
    for n in [111, 222222]:
      s.send("POST /upload HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n" &
             "Content-Length: " & $n & "\r\n\r\n" & "z".repeat(n))
      let want = "got " & $n
      var resp: string
      while want notin resp:
        var buf = newString(8192)
        let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
        if k <= 0: break
        resp.add buf[0 ..< k]
      check want in resp

  test "pipelined: streamed upload then a buffered request":
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", port)
    s.setRecvTimeout(4000)
    # Both requests in one write: the tail (req 2) must survive req 1's
    # compaction and be served.
    s.send("POST /upload HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n" &
           "Content-Length: 5000\r\n\r\n" & "a".repeat(5000) &
           "POST /buffered HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
           "Content-Length: 3\r\n\r\nabc")
    let resp = recvUntilClose(s)
    check "got 5000" in resp
    check "buffered:3" in resp

proc h2curl(args: string): (string, int) =
  let (output, rc) = execCmdEx("curl -s --http2-prior-knowledge " & args)
  (output.strip(), rc)

let base = "http://127.0.0.1:" & $port
let tmpUp = getTempDir() / "vortex_h2up_" & $getCurrentProcessId()
writeFile(tmpUp, "m".repeat(300 * 1024))

suite "HTTP/2 streaming request bodies":
  test "streamed upload over h2 (DATA frames -> onBody)":
    let (output, rc) = h2curl(
      "--data-binary @" & tmpUp & " -w '|%{http_version}' " & base & "/upload")
    check rc == 0
    check output == "got " & $(300 * 1024) & "|2"

  test "streamed echo over h2 returns the exact body":
    let (output, rc) = h2curl("--data-binary @" & tmpUp & " " & base & "/echo")
    check rc == 0
    check output.len == 300 * 1024
    check output == readFile(tmpUp)

  test "empty streamed body over h2":
    let (output, rc) = h2curl("-X POST -w '|%{http_version}' " & base & "/upload")
    check rc == 0
    check output == "got 0|2"

removeFile(tmpUp)
srv.close()
echo "server shut down cleanly"
