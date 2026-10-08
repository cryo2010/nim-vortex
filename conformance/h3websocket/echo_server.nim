## HTTP/3 (RFC 9220) WebSocket echo server under test for the aioquic
## conformance client. It advertises SETTINGS_ENABLE_CONNECT_PROTOCOL, accepts
## an Extended CONNECT WebSocket on a QUIC stream, and echoes each message
## back with the same kind. A "proto?" text message reports the negotiated
## subprotocol so the client can verify negotiation, and a "later" message
## replies from an async continuation (a loop-thread send outside the inbound
## path, which has to drive QUIC egress by itself).
##
## The route is registered with `router.ws`, so the harness covers the router
## path over h3 and not just a bare handler: `ws` registers the Extended CONNECT
## leg itself and screens it, which is what answers the version-less handshake
## the client checks with a 426 (#400).

import std/os
import vortex
import vortex/asyncdispatch

proc handler(req: Request, res: Response) {.async.} =
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
    else: ws.send(data, kind)                 # echo, preserving the kind

when isMainModule:
  var rt = newRouter()
  rt.ws("/", handler)                         # h1 GET upgrade + Extended CONNECT
  # HTTP/3 over QUIC on UDP 4433; a throwaway self-signed cert (the client
  # runs without verification). start() binds before returning, so the
  # "listening" log line is the readiness signal for run.sh.
  var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1, certFile = "/vortex/cert.pem", keyFile = "/vortex/key.pem", http3 = true, maxWsMessageSize = 4 * 1024 * 1024)).start(4433)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
