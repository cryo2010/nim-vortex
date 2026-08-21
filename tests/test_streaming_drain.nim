## Awaitable outbound backpressure: a producer streams a large body and yields
## with `await res.drained()` when `res.write` reports the backlog is full. A
## deliberately slow-reading client forces the backpressure, and we assert both
## that the whole body arrives intact and that the producer actually suspended.

import std/[unittest, net, posix, strutils, httpcore, atomics]
from std/os import sleep
import vortex/[settings, request, server, routing]
import vortex/asyncdispatch
import ./helper

var drainCount: Atomic[int]

proc bigStream(req: Request, res: Response) {.async.} =
  res.sendHead(Http200, "application/octet-stream")
  let chunk = repeat('x', 8192)
  for i in 0 ..< 512:                    # 4 MiB
    # Low-level bool form on purpose (this test counts drains); a string arg
    # would resolve to the awaitable `await res.write`, so slice to openArray.
    if not res.write(chunk.toOpenArray(0, chunk.high)):
      drainCount.atomicInc
      await res.drained()                # yield until the socket drains
  res.finish()

var rt = newRouter()
rt.get("/big", bigStream)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let port = srv.port

proc slowGet(path: string): string =
  ## Read the response slowly (small reads with pauses) so the server's write
  ## backlog fills and the producer has to await drained().
  let s = newSocket(buffered = false)
  defer: s.close()
  # Force TCP backpressure deterministically instead of racing timing: a small
  # receive buffer keeps the advertised window tiny, so the server cannot offload
  # the 4 MiB into kernel buffers (regardless of its SO_SNDBUF autotuning or of
  # ASan slowdown). Its app-level outbox then fills past the high water and the
  # producer must await drained(). Must be set before connect.
  var rcvbuf: cint = 16 * 1024
  discard setsockopt(s.getFd, SOL_SOCKET, SO_RCVBUF, addr rcvbuf,
                     SockLen(sizeof(rcvbuf)))
  s.connect("127.0.0.1", port)
  s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
  s.setRecvTimeout(5000)
  var buf = newString(8192)
  var reads = 0
  while true:
    let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if k <= 0: break
    result.add buf[0 ..< k]
    inc reads
    if reads mod 8 == 0: os.sleep(2)     # throttle the consumer
  discard result

proc dechunk(body: string): string =
  var pos = 0
  while true:
    let nl = body.find("\r\n", pos)
    if nl < 0: break
    let size = parseHexInt(body[pos ..< nl].strip())
    pos = nl + 2
    if size == 0: break
    result.add body[pos ..< pos + size]
    pos += size + 2

suite "awaitable outbound backpressure":
  test "await res.drained() streams a large body under a slow reader":
    let resp = slowGet("/big")
    let i = resp.find("\r\n\r\n")
    check "Transfer-Encoding: chunked" in resp[0 ..< i]
    let body = dechunk(resp[i + 4 .. ^1])
    check body.len == 512 * 8192
    check body == repeat('x', 512 * 8192)
    check drainCount.load > 0            # the producer actually suspended

srv.close()
echo "server shut down cleanly"
