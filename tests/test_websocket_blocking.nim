## Per-connection backpressure for ws.blocking: messages from one connection
## must be handled one at a time (the connection is pinned while the worker
## runs), even with several worker threads available. Without pinning the
## rapid burst below would fan out across workers and overlap.

import std/[unittest, net, httpcore, strutils, posix, os, atomics]
import vortex/[settings, request, server]
import ./helper

var concurrent: Atomic[int]      # bodies currently running
var maxConcurrent: Atomic[int]   # high-water mark observed

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.blocking(data):
        let now = concurrent.fetchAdd(1) + 1
        var m = maxConcurrent.load
        while now > m and not maxConcurrent.compareExchange(m, now): discard
        sleep(40)                          # overlap window if run concurrently
        ws.send(msg)                        # echo, in order
        discard concurrent.fetchSub(1)
  else:
    res.send(Http200, "http", "text/plain")

# Several workers so concurrency is possible; a single loop thread owns the
# one test connection.
var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1, workerThreads = 4))
let port = srv.port

proc recvN(s: Socket, n: int): string =
  result = newString(n)
  var got = 0
  while got < n:
    let k = recv(s.getFd, addr result[got], n - got, cint(0))
    if k <= 0: raise newException(IOError, "short read")
    got += k

proc recvText(s: Socket): string =
  let h = recvN(s, 2)
  doAssert (int(uint8(h[0])) and 0x0f) == 0x1        # text frame
  var ln = int(uint8(h[1]) and 0x7f)
  if ln == 126:
    let e = recvN(s, 2); ln = (int(uint8(e[0])) shl 8) or int(uint8(e[1]))
  if ln > 0: recvN(s, ln) else: ""

proc sendText(s: Socket, p: string) =
  var f = "\x81" & char(0x80 or p.len)
  let m = [0x21'u8, 0x43, 0x65, 0x87]
  for x in m: f.add char(x)
  for i in 0 ..< p.len: f.add char(uint8(p[i]) xor m[i and 3])
  s.send(f)

proc openWs(): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.send("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
              "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
              "Sec-WebSocket-Version: 13\r\n\r\n")
  result.setRecvTimeout(5000)
  var hdr = ""
  var one = newString(1)
  while not hdr.endsWith("\r\n\r\n"):
    let k = recv(result.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    hdr.add one[0]
  doAssert "101" in hdr, hdr

suite "websocket ws.blocking backpressure":
  test "messages on one connection are processed one at a time, in order":
    let s = openWs()
    defer: s.close()
    const n = 5
    for i in 0 ..< n:                       # fire the whole burst up front
      s.sendText("m" & $i)
    for i in 0 ..< n:                        # replies come back in send order
      check s.recvText() == "m" & $i
    check maxConcurrent.load == 1           # never overlapped: pinned/serialized

srv.close()
echo "server shut down cleanly"
