import std/[unittest, net, httpcore, base64, strutils, os]
import std/httpclient except Response
import vortex/[settings, request, server]
import vortex/websocket/sha1
import ./helper
import ./wsclient

# --- echo server ------------------------------------------------------------

var bgThread: Thread[WebSocket]

proc bgSend(ws: WebSocket) {.thread.} =
  ## Off-loop sender: exercises the outbox path for cross-thread ws.send.
  sleep(60)
  ws.send("from-thread")

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "spawn":
        createThread(bgThread, bgSend, ws)      # send from a different thread
      elif data == "block":
        ws.blocking(data):                      # run on the worker pool
          sleep(20)                             # pretend to do blocking work
          ws.send("blocked:" & msg)
      else:
        ws.send(data, kind)                     # echo, same kind
    ws.onClose = proc(ws: WebSocket, code: uint16, reason: string) {.gcsafe.} =
      discard
  else:
    res.send(Http200, "not a websocket")

const acceptMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

proc expectedAccept(key: string): string =
  encode(sha1(key & acceptMagic))

withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, maxWsMessageSize = 1024), srv):
  let port = srv.port

  proc open(key = wsTestKey): Socket =
    let (sock, resp) = openWs(port, key = key)
    check "101 Switching Protocols" in resp
    check ("Sec-WebSocket-Accept: " & expectedAccept(key)) in resp
    sock

  suite "websocket server":
    test "handshake completes with the right accept key":
      let s = open()                 # open asserts 101 + accept
      defer: s.close()
      check s != nil

    test "non-upgrade request is served normally":
      var client = newHttpClient()
      defer: client.close()
      check client.getContent("http://127.0.0.1:" & $port & "/") ==
        "not a websocket"

    test "echoes a text message":
      let s = open()
      defer: s.close()
      s.sendFrame(0x1, "hello")
      let f = s.recvFrame()
      check f.op == 0x1
      check f.fin
      check f.payload == "hello"

    test "echoes a binary message":
      let s = open()
      defer: s.close()
      s.sendFrame(0x2, "\x00\x01\x02\xff")
      let f = s.recvFrame()
      check f.op == 0x2
      check f.payload == "\x00\x01\x02\xff"

    test "reassembles a fragmented message":
      let s = open()
      defer: s.close()
      s.sendFrame(0x1, "Hello, ", fin = false)   # text, not final
      s.sendFrame(0x0, "world", fin = true)      # continuation, final
      let f = s.recvFrame()
      check f.op == 0x1
      check f.payload == "Hello, world"

    test "answers a ping with a matching pong":
      let s = open()
      defer: s.close()
      s.sendFrame(0x9, "ping-payload")           # ping
      let f = s.recvFrame()
      check f.op == 0xA                           # pong
      check f.payload == "ping-payload"

    test "control frame interleaved between fragments":
      let s = open()
      defer: s.close()
      s.sendFrame(0x1, "frag1", fin = false)
      s.sendFrame(0x9, "mid")                     # ping mid-message
      check s.recvFrame().op == 0xA               # pong first
      s.sendFrame(0x0, "frag2", fin = true)
      let f = s.recvFrame()
      check f.op == 0x1
      check f.payload == "frag1frag2"

    test "close handshake: server echoes close and drops the connection":
      let s = open()
      defer: s.close()
      # client close with code 1000
      s.sendFrame(0x8, "\x03\xe8")                # 0x03e8 = 1000
      let f = s.recvFrame()
      check f.op == 0x8
      check f.payload.len >= 2
      let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
      check code == 1000
      check s.waitForClose()

    test "a pipelined burst is echoed in order, in one write (#333)":
      # The whole burst arrives in one recv(), so the loop dispatches all of it
      # before the single end-of-batch flush: the echoes leave in ONE send()
      # instead of one per message (which is what a per-send flush cost, plus an
      # armWrite/disarmWrite pair on every EAGAIN). Syscalls aren't observable
      # from here, so the proxy is that the client's first read carries every
      # echo -- with a flush per send the first frame would wake the reader on
      # its own, well before the rest were dispatched.
      let s = open()
      defer: s.close()
      const burstFrames = 8
      var burst = ""
      for i in 0 ..< burstFrames: burst.add buildFrame(0x1, "msg-" & $i)
      s.send(burst)
      let got = recvAvailable(s, 4000)
      let (frames, consumed) = parseFrames(got)
      check consumed == got.len              # no partial frame: one whole write
      check frames.len == burstFrames
      for i in 0 ..< burstFrames:
        check frames[i].op == 0x1
        check frames[i].payload == "msg-" & $i

    test "a close pipelined behind data still flushes the batch (#333)":
      # The close arrives in the same read batch as the data frames, so the
      # handler-side close lands while the flush is held: the echoes, the close
      # echo and the connection close must all still happen.
      let s = open()
      defer: s.close()
      var burst = ""
      for i in 0 ..< 3: burst.add buildFrame(0x1, "b" & $i)
      burst.add buildFrame(0x8, "\x03\xe8")      # 0x03e8 = 1000
      s.send(burst)
      for i in 0 ..< 3:
        let f = s.recvFrame()
        check f.op == 0x1
        check f.payload == "b" & $i
      let f = s.recvFrame()
      check f.op == 0x8
      check s.waitForClose()

    test "ws.blocking runs the body on the worker pool":
      let s = open()
      defer: s.close()
      s.sendFrame(0x1, "block")
      let f = s.recvFrame()
      check f.op == 0x1
      check f.payload == "blocked:block"

    test "send from another thread reaches the client (outbox path)":
      let s = open()
      defer: s.close()
      s.sendFrame(0x1, "spawn")
      let f = s.recvFrame()
      check f.op == 0x1
      check f.payload == "from-thread"
      joinThread(bgThread)

    test "oversized message closes with 1009":
      let s = open()
      defer: s.close()
      # two 600-byte fragments = 1200 > maxWsMessageSize (1024)
      s.sendFrame(0x1, repeat('a', 600), fin = false)
      s.sendFrame(0x0, repeat('a', 600), fin = true)
      let f = s.recvFrame()
      check f.op == 0x8
      let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
      check code == 1009
      check s.waitForClose()

echo "server shut down cleanly"
