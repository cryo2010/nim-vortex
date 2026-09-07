## On graceful shutdown, an open HTTP/1.1 WebSocket receives a server-initiated
## close frame with code 1001 (going away).

import std/[unittest, net, os]
import vortex/[settings, request, server]
import ./wsclient

proc handler(req: Request, res: Response) {.gcsafe.} =
  let ws = req.acceptWebSocket()
  ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
    ws.send(data)

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, shutdownGrace = 5)).start(0)
let port = srv.port

suite "graceful shutdown: WebSocket":
  test "an open WebSocket gets a 1001 going-away close":
    let s = openWs(port, timeoutMs = 4000).sock
    sleep(100)                             # ensure the upgrade settled
    requestShutdown()                      # begin graceful drain
    # Read the server's close frame: 0x88 (FIN|close), then len, then 2-byte code.
    let f = s.recvFrame()
    check f.op == 0x08                     # close opcode
    check f.payload.len >= 2
    let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
    check code == 1001
    s.close()
    srv.waitFor()                          # the loop drains and exits

echo "server shut down cleanly"
