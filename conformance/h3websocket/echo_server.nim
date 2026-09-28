## HTTP/3 (RFC 9220) WebSocket echo server under test for the aioquic
## conformance client. It advertises SETTINGS_ENABLE_CONNECT_PROTOCOL, accepts
## an Extended CONNECT WebSocket on a QUIC stream, and echoes each message
## back with the same kind. A "proto?" text message reports the negotiated
## subprotocol so the client can verify negotiation, and a "later" message
## replies from an async continuation (a loop-thread send outside the inbound
## path, which has to drive QUIC egress by itself).

import std/os
import vortex
import vortex/asyncdispatch

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket(["chat", "superchat"])
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "proto?": ws.send(ws.subprotocol)
      elif data == "later":
        # The reply leaves from a timer continuation on the loop thread, long
        # after the packet that carried "later" was processed: nothing else is
        # driving this connection, so the send itself must (#262).
        ws.doAsync:
          await sleepAsync(200)
          ws.send("later")
      else: ws.send(data, kind)               # echo, preserving the kind
  else:
    res.send(Http200, "vortex h3 websocket echo")

when isMainModule:
  # HTTP/3 over QUIC on UDP 4433; a throwaway self-signed cert (the client
  # runs without verification). start() binds before returning, so the
  # "listening" log line is the readiness signal for run.sh.
  var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = "/vortex/cert.pem", keyFile = "/vortex/key.pem", http3 = true, maxWsMessageSize = 4 * 1024 * 1024)).start(4433)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
