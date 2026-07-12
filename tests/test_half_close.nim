## A client that half-closes its write side (shutdown(SHUT_WR)) right after
## sending a request -- a legitimate "request done, awaiting response" pattern
## used by some HTTP clients (e.g. the h1spec conformance tool) -- must still
## get its response. Previously the peer FIN surfaced as a kqueue EV_EOF and
## the loop reset the connection before reading the buffered request, so the
## response was lost roughly half the time. The loop is exercised repeatedly
## to catch that race.

import std/[unittest, net, posix, strutils, httpcore]
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1))
let port = srv.port

proc halfCloseGet(): string =
  ## Send a request, half-close the write side, and read the whole response.
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
  discard shutdown(s.getFd, SHUT_WR)          # FIN our write side; keep reading
  s.setRecvTimeout(2000)
  var buf = newString(4096)
  while true:
    let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if k <= 0: break
    result.add buf[0 ..< k]

suite "HTTP/1 half-close":
  test "the response is delivered after a client half-close, repeatedly":
    for i in 0 ..< 30:
      check "HTTP/1.1 200" in halfCloseGet()

srv.close()
echo "server shut down cleanly"
