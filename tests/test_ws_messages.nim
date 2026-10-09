## ws.messages async iterator sugar (asyncdispatch adapter), driven from a plain
## `{.async.}` handler registered with `router.ws`. Raw frames so the wire is
## checked exactly, over both spellings of the handshake: the HTTP/1.1 GET
## upgrade (RFC 6455) and the HTTP/2 Extended CONNECT (RFC 8441) that `router.ws`
## registers beside it (#400).
##
## Also the refusals: `router.ws` screens both legs, so a request that is not a
## handshake never reaches the handler and is answered 426 (WebSocket intent
## with a missing or unsupported `Sec-WebSocket-Version`, RFC 6455 4.2.2(4)) or
## 400 (no intent at all), and `acceptWebSocket` itself refuses a non-handshake
## with a dead handle instead of writing a 101 over it.

import std/[unittest, net, httpcore, strutils]
import vortex/[settings, request, server, routing]
import vortex/asyncdispatch
import ./helper
import ./h2client
import ./wsclient

proc chat(req: Request, res: Response) {.async.} =
  let ws = req.acceptWebSocket()
  ws.messages(msg):                  # loop over messages until the peer closes
    ws.send("echo: " & msg)

proc boom(req: Request, res: Response) {.async.} =
  let ws = req.acceptWebSocket()
  ws.messages(msg):
    raise newException(ValueError, "kaboom")   # -> WS close 1011, not HTTP 500

proc bare(req: Request, res: Response) {.async.} =
  # A route registered without `ws` gets no screening, so this handler stands in
  # for one that forgot the `isWebSocketUpgrade` check: `acceptWebSocket` must
  # refuse the request itself rather than upgrading it, and must leave the
  # response to the caller.
  let ws = req.acceptWebSocket()
  if ws.isAlive: res.send(Http200, "upgraded")
  else: res.send(Http400, "dead handle")

var r = newRouter()
r.ws("/chat", chat)
r.ws("/boom", boom)
# A hand-registered CONNECT leg: `wsToHandler` is the public wrapper for a route
# the app registers itself (`toHandler` would answer a failure with an HTTP 500
# written into an already upgraded stream).
r.addRoute(HttpConnect, "/manual", wsToHandler(chat))
r.get("/bare", bare)

proc closeCode(f: WsFrame): uint16 =
  (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))

withServer(r.toHandler, initVortexConfig(numThreads = 1), srv):
  let port = srv.port

  suite "websocket ws.messages (plain async handler via router.ws)":
    test "iterates messages and echoes each in order":
      let s = openWs(port, "/chat").sock
      defer: s.close()
      sendText(s, "one")
      check s.recvFrame().payload == "echo: one"
      sendText(s, "two")
      check s.recvFrame().payload == "echo: two"

    test "the loop ends on peer close; the server keeps serving":
      let s1 = openWs(port, "/chat").sock
      sendText(s1, "a")
      check s1.recvFrame().payload == "echo: a"
      s1.close()
      let s2 = openWs(port, "/chat").sock
      defer: s2.close()
      sendText(s2, "b")
      check s2.recvFrame().payload == "echo: b"

    test "an exception in the loop closes the socket with 1011 (not HTTP 500)":
      let s = openWs(port, "/boom").sock
      defer: s.close()
      sendText(s, "trigger")
      let f = s.recvFrame()
      check f.op == 0x8                          # WS close frame, not HTTP bytes
      check f.closeCode == 1011

    test "router.ws also serves the h2 Extended CONNECT leg (RFC 8441)":
      # The h2/h3 handshake is `:method CONNECT` + `:protocol websocket`, so a
      # GET-only registration left an h2 client unrouted (a 405) even though the
      # app had asked for a WebSocket route.
      var c = newH2TestConn(port)
      defer: c.close()
      check c.extendedConnect(1, "/chat") == "200"
      c.sendData(1, buildFrame(0x1, "one"))
      let msgs = parseFrames(c.streamData(1, firstWsFrame))[0]
      check msgs.len >= 1
      check msgs[0].op == 0x1
      check msgs[0].payload == "echo: one"

    test "wsToHandler is exported for a hand-registered CONNECT route":
      var c = newH2TestConn(port)
      defer: c.close()
      check c.extendedConnect(1, "/manual") == "200"
      c.sendData(1, buildFrame(0x1, "by-hand"))
      let msgs = parseFrames(c.streamData(1, firstWsFrame))[0]
      check msgs.len >= 1
      check msgs[0].payload == "echo: by-hand"

    test "an exception over Extended CONNECT closes 1011, not an HTTP 500":
      # The whole point of the wrapper: the stream is already a 200 Extended
      # CONNECT response, so a 500 would be HTTP bytes inside WebSocket framing.
      var c = newH2TestConn(port)
      defer: c.close()
      check c.extendedConnect(1, "/boom") == "200"
      c.sendData(1, buildFrame(0x1, "trigger"))
      let msgs = parseFrames(c.streamData(1, firstWsFrame))[0]
      check msgs.len >= 1
      check msgs[0].op == 0x8                    # WS close frame, not a 500
      check msgs[0].closeCode == 1011

    test "the CONNECT leg joins Allow without disturbing GET/HEAD":
      let resp = rawExchange(port, "POST /chat HTTP/1.1\r\nHost: x\r\n" &
        "Content-Length: 0\r\nConnection: close\r\n\r\n")
      check "405" in resp
      check "Allow: GET, CONNECT, HEAD, OPTIONS" in resp

    test "an HTTP/1.1 proxy-style CONNECT gets a 400, not a bogus upgrade":
      # HTTP/1.1 has a CONNECT of its own (RFC 9110 9.3.6) that matches the same
      # route. It carries no handshake, so it must not reach the handler: that
      # would either switch the connection into WebSocket mode off a request
      # that never asked for one, or park it unanswered forever.
      let resp = rawExchange(port, "CONNECT /chat HTTP/1.1\r\nHost: x\r\n" &
        "Connection: close\r\n\r\n")
      check "400" in resp
      check "101" notin resp
      check "Upgrade: websocket" notin resp

  suite "websocket: a non-handshake never reaches the handler (#400)":
    test "a plain GET on a router.ws route gets a 400, not a bogus 101":
      # The GET leg is matched on method and path, so an ordinary GET to a
      # WebSocket route lands on it. It carries no Upgrade at all, and used to
      # be answered `101 Switching Protocols` with a Sec-WebSocket-Accept
      # computed over an empty key -- and the connection switched into
      # WebSocket mode behind it.
      let resp = rawExchange(port, "GET /chat HTTP/1.1\r\nHost: x\r\n" &
        "Connection: close\r\n\r\n")
      check "400" in resp
      check "101" notin resp
      check "Sec-WebSocket-Accept" notin resp

    test "a HEAD on a router.ws route gets a 400 too":
      # HEAD falls back to the GET slot (routing.nim), so it reaches the same
      # wrapper and must be screened the same way.
      let resp = rawExchange(port, "HEAD /chat HTTP/1.1\r\nHost: x\r\n" &
        "Connection: close\r\n\r\n")
      check "400" in resp
      check "101" notin resp
      check "Sec-WebSocket-Accept" notin resp

    test "acceptWebSocket refuses a non-handshake with a dead handle":
      # The documented contract, on a route that does no screening of its own:
      # the handle comes back dead, no 101 is written, and the response is
      # still the handler's to send.
      let resp = rawExchange(port, "GET /bare HTTP/1.1\r\nHost: x\r\n" &
        "Connection: close\r\n\r\n")
      check "dead handle" in resp
      check "101" notin resp
      check "Sec-WebSocket-Accept" notin resp

    test "an h1 upgrade offering version 8 gets 426 + Sec-WebSocket-Version":
      # RFC 6455 4.2.2(4): a version the server does not support is answered
      # with an error naming the versions it does, so the client can retry.
      let resp = rawExchange(port, "GET /chat HTTP/1.1\r\nHost: x\r\n" &
        "Upgrade: websocket\r\nConnection: Upgrade, close\r\n" &
        "Sec-WebSocket-Key: " & wsTestKey & "\r\n" &
        "Sec-WebSocket-Version: 8\r\n\r\n")
      check "426" in resp
      check "Sec-WebSocket-Version: 13" in resp
      check "101" notin resp

    test "an Extended CONNECT with no version gets 426 + the version header":
      # The h2 codec classifies a ws-connect stream on `:method CONNECT` plus
      # `:protocol websocket` alone (fieldrules.nim), so the version is the
      # guard's business, not the codec's.
      var c = newH2TestConn(port)
      defer: c.close()
      check c.extendedConnect(1, "/chat", version = "") == "426"
      check c.respField(1, "sec-websocket-version") == "13"

    test "an Extended CONNECT offering version 8 gets 426 as well":
      var c = newH2TestConn(port)
      defer: c.close()
      check c.extendedConnect(1, "/chat", version = "8") == "426"
      check c.respField(1, "sec-websocket-version") == "13"

    test "ws beside a hand-registered CONNECT leg raises RouteConflictError":
      # The pre-#400 workaround was to add the CONNECT leg by hand. `ws` now
      # registers it, so keeping both is a duplicate route and fails loudly at
      # startup rather than silently picking one: drop the `addRoute`.
      var dup = newRouter()
      dup.addRoute(HttpConnect, "/chat", wsToHandler(chat))
      expect RouteConflictError:
        dup.ws("/chat", chat)

echo "ws.messages ok"
