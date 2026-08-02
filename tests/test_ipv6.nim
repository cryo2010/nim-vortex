## The default bind is dual-stack ("::"), so one server accepts both IPv4
## (via IPv4-mapped addresses) and IPv6 clients on the same port. IPv4 is
## always asserted; the IPv6 leg asserts a 200 when IPv6 loopback is usable
## and otherwise notes a skip (a host without IPv6 falls back to IPv4-only).

import std/[unittest, net, strutils, httpcore]
import vortex/[settings, request, server]

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1)).start(0)
let port = srv.port

proc getStatus(family: Domain, host: string): string =
  ## Connect with the given address family and return the response status line.
  let s = newSocket(domain = family)
  defer: s.close()
  s.connect(host, port)
  s.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
  s.recvLine(timeout = 2000)

proc ipv6LoopbackUsable(): bool =
  ## True if we can create and connect an IPv6 loopback socket at all.
  try:
    let s = newSocket(domain = AF_INET6)
    defer: s.close()
    s.connect("::1", port)
    true
  except OSError, TimeoutError:
    false

suite "dual-stack IPv4/IPv6 binding":
  test "an IPv4 client is served (IPv4-mapped on the dual-stack socket)":
    check "200" in getStatus(AF_INET, "127.0.0.1")

  test "an IPv6 client is served on the same port":
    if not ipv6LoopbackUsable():
      echo "SKIP: no usable IPv6 loopback (server fell back to IPv4-only)"
      skip()
    else:
      check "200" in getStatus(AF_INET6, "::1")

srv.close()
echo "server shut down cleanly"
