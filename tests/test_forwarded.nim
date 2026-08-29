## Forwarded-header resolution (X-Forwarded-Proto/-Host/-For and RFC 7239
## Forwarded): believed only from a peer in settings.trustedProxies, ignored
## otherwise (fail-safe). Raw sockets so arbitrary headers reach the server.

import std/[unittest, net, strutils, httpcore]
import vortex/[settings, request, server, routing]

proc info(req: Request, res: Response) {.gcsafe.} =
  # scheme | host | clientIp | isSecure
  res.send(Http200, req.scheme & "|" & req.host & "|" & req.clientIp &
                    "|" & $req.isSecure)

let rt = newRouter()
rt.get("/i", info)

# Trusts the loopback the test client connects from -> forwarded headers honored.
var trustSrv = newVortex(rt.toHandler,
  initVortexConfig(numThreads = 1, trustedProxies = @["127.0.0.1"])).start(0)
# No trustedProxies -> forwarded headers ignored (default, fail-safe).
var openSrv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)

proc raw(port: Port, extra: string): string =
  let s = newSocket()
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send("GET /i HTTP/1.1\r\nHost: direct.example\r\nConnection: close\r\n" &
         extra & "\r\n")
  var chunk = s.recv(65536, timeout = 2000)
  while chunk.len > 0:
    result.add chunk
    chunk = s.recv(65536, timeout = 2000)

proc body(resp: string): string =
  let i = resp.find("\r\n\r\n")
  if i >= 0: resp[i+4 .. ^1] else: ""

suite "forwarded headers from a trusted proxy":
  test "X-Forwarded-Proto/-Host/-For are honored":
    let b = raw(trustSrv.port,
      "X-Forwarded-Proto: https\r\nX-Forwarded-Host: app.example\r\n" &
      "X-Forwarded-For: 203.0.113.5\r\n").body
    check b == "https|app.example|203.0.113.5|true"

  test "X-Forwarded-For peels trusted hops (rightmost-untrusted wins)":
    # client -> proxy(203.0.113.9) -> us; last hop 127.0.0.1 is trusted, peeled.
    let b = raw(trustSrv.port,
      "X-Forwarded-For: 203.0.113.5, 203.0.113.9, 127.0.0.1\r\n").body
    check b.split("|")[2] == "203.0.113.9"   # first untrusted from the right

  test "RFC 7239 Forwarded is parsed (proto/host/for) and preferred":
    let b = raw(trustSrv.port,
      "Forwarded: for=203.0.113.5;proto=https;host=fwd.example\r\n").body
    check b == "https|fwd.example|203.0.113.5|true"

  test "Forwarded for= with a port yields the bare IP":
    let b = raw(trustSrv.port, "Forwarded: for=\"203.0.113.5:4711\"\r\n").body
    check b.split("|")[2] == "203.0.113.5"

suite "forwarded headers without a trusted-proxy policy (ignored)":
  test "a direct client cannot forge scheme/host/for":
    let b = raw(openSrv.port,
      "X-Forwarded-Proto: https\r\nX-Forwarded-Host: evil.example\r\n" &
      "X-Forwarded-For: 203.0.113.5\r\n").body
    check b == "http|direct.example|127.0.0.1|false"   # connection facts only

trustSrv.close()
openSrv.close()
echo "forwarded ok"
