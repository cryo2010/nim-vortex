## HTTP/3 (RFC 9220) WebSocket echo server under test for the aioquic
## conformance client. It advertises SETTINGS_ENABLE_CONNECT_PROTOCOL, accepts
## an Extended CONNECT WebSocket on a QUIC stream, and echoes each message
## back with the same kind. A "proto?" text message reports the negotiated
## subprotocol so the client can verify negotiation.

import std/os
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket(["chat", "superchat"])
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "proto?": ws.send(ws.subprotocol)
      else: ws.send(data, kind)               # echo, preserving the kind
  else:
    res.send(Http200, "vortex h3 websocket echo", "text/plain")

when isMainModule:
  # HTTP/3 over QUIC on UDP 4433; a throwaway self-signed cert (the client
  # runs without verification). start() binds before returning, so the
  # "listening" log line is the readiness signal for run.sh.
  var srv = start(RequestHandler(handler),
                  initSettings(port = Port(4433), numThreads = 1,
                               certFile = "/vortex/cert.pem",
                               keyFile = "/vortex/key.pem",
                               http3 = true,
                               maxWsMessageSize = 4 * 1024 * 1024))
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
