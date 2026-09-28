## Pull-based request-body streaming via the asyncdispatch adapter:
## `await req.read()` over a `router.stream` async route, built on the core's
## push `onBody`.

import std/[unittest, net, posix, strutils, httpcore, atomics, os, times]
import vortex/[settings, request, server, routing]
import vortex/asyncdispatch
import ./helper

var finished: Atomic[int]      # incremented when a streaming handler unwinds

proc hUpload(req: Request, res: Response) {.async.} =
  var total = 0
  while true:
    let chunk = await req.read()
    if chunk.len == 0: break
    total += chunk.len
  res.send(Http200, "got " & $total)

proc hAbortable(req: Request, res: Response) {.async.} =
  var total = 0
  while true:
    let chunk = await req.read()
    if chunk.len == 0: break        # EOF, whether the body completed or the peer left
    total += chunk.len
  finished.atomicInc()             # reached only if the read loop terminated
  res.send(Http200, "got " & $total)

proc hEcho(req: Request, res: Response) {.async.} =
  var body = ""
  while true:
    let chunk = await req.read()
    if chunk.len == 0: break
    body.add chunk
  res.send(Http200, body, @[("Content-Type", "application/octet-stream")])

var rt = newRouter()
rt.post("/upload", hUpload, streaming = true)
rt.post("/echo", hEcho, streaming = true)
rt.post("/abortable", hAbortable, streaming = true)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1, maxBodySize = 8 * 1024 * 1024), rt.streamPredicate).start(0)
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

# --- read backpressure for a slow (manualAck) consumer (#271) ----------------

const
  bpBodyLen = 32 * 1024 * 1024   ## far larger than every buffer on the path
  bpStallMs = 700                ## how long the consumer stops pulling chunks
  bpInFlightCap = 8 * 1024 * 1024
    ## Generous ceiling on what the server may take off the wire while the
    ## consumer is parked: the read-ahead high-water, the streaming receive
    ## buffer, and both kernel socket buffers. Without read backpressure the loop
    ## copies the whole body into the reader queue, so all 32 MiB are accepted.

proc hStalled(req: Request, res: Response) {.async.} =
  ## Pull one chunk, stop consuming for a while (a slow sink), then drain. While
  ## it is parked, the delivered-but-unacked bytes must stop the socket read
  ## instead of piling up in the reader queue.
  var total = 0
  total += (await req.read()).len
  await sleepAsync(bpStallMs)
  while true:
    let chunk = await req.read()
    if chunk.len == 0: break
    total += chunk.len
  res.send(Http200, "got " & $total)

proc chunkSize(n: int): string =
  ## n as a chunk-size line value (lowercase hex, no padding).
  var v = n
  while v > 0:
    result = "0123456789abcdef"[v and 15] & result
    v = v shr 4
  if result.len == 0: result = "0"

proc framed(body: string): string =
  ## body as one chunked-transfer stream (64 KiB chunks) plus its terminator.
  const step = 64 * 1024
  var off = 0
  while off < body.len:
    let n = min(step, body.len - off)
    result.add chunkSize(n) & "\r\n" & body[off ..< off + n] & "\r\n"
    off += n
  result.add "0\r\n\r\n"

proc uploadProbe(port: Port, chunked: bool): tuple[stalledAt: int, resp: string] =
  ## Upload bpBodyLen bytes at the parked consumer over a non-blocking socket and
  ## record how much the server had accepted when the write first went unwritable
  ## for 300 ms (-1 = it never stalled, i.e. no backpressure at all).
  let body = "u".repeat(bpBodyLen)
  let payload = if chunked: framed(body) else: body
  let head =
    if chunked: "Transfer-Encoding: chunked\r\n"
    else: "Content-Length: " & $bpBodyLen & "\r\n"
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  var sndbuf = cint(64 * 1024)      # keep our own buffering out of the bound
  discard setsockopt(s.getFd, SOL_SOCKET, SO_SNDBUF, addr sndbuf,
                     SockLen(sizeof(sndbuf)))
  s.send("POST /stalled HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" & head & "\r\n")
  let flags = fcntl(cint(s.getFd), F_GETFL, 0)
  discard fcntl(cint(s.getFd), F_SETFL, flags or O_NONBLOCK)
  var off = 0
  var lastMoved = epochTime()
  let budget = epochTime() + 30.0   # never hang the suite on a wedged upload
  result.stalledAt = -1
  while off < payload.len and epochTime() < budget:
    let n = posix.send(s.getFd, unsafeAddr payload[off],
                       min(64 * 1024, payload.len - off), cint(0))
    if n > 0:
      off += int(n)
      lastMoved = epochTime()
    else:
      if errno != EAGAIN and errno != EWOULDBLOCK and errno != EINTR: break
      if result.stalledAt < 0 and epochTime() - lastMoved > 0.3:
        result.stalledAt = off    # unwritable for 300 ms: the server stopped reading
      sleep(2)
  discard fcntl(cint(s.getFd), F_SETFL, flags)
  result.resp = s.recvUntilClose(5000)

suite "async req.read() backpressure":
  ## A handler that stops pulling must throttle the peer: the loop stops reading
  ## once the delivered-but-unacked bytes hit the read-ahead high-water, leaving
  ## the rest in the kernel, rather than copying the whole upload into the
  ## adapter's reader queue (#271).
  var rtb = newRouter()
  rtb.post("/stalled", hStalled, streaming = true)
  let bcfg = initVortexConfig(numThreads = 1, maxBodySize = 64 * 1024 * 1024)

  test "a parked consumer stalls a Content-Length upload":
    withServer(rtb.toHandler, bcfg, rtb.streamPredicate, bsrv):
      let (stalledAt, resp) = uploadProbe(bsrv.port, chunked = false)
      check stalledAt >= 0                 # the upload really was backpressured
      check stalledAt < bpInFlightCap      # and bounded, not the whole body
      check splitBody(resp) == "got " & $bpBodyLen

  test "a parked consumer stalls a chunked upload":
    withServer(rtb.toHandler, bcfg, rtb.streamPredicate, bsrv):
      let (stalledAt, resp) = uploadProbe(bsrv.port, chunked = true)
      check stalledAt >= 0
      check stalledAt < bpInFlightCap
      check splitBody(resp) == "got " & $bpBodyLen

srv.close()
echo "server shut down cleanly"
