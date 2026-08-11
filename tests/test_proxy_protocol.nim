## PROXY protocol (v1 + v2) support: settings.proxyProtocol / trustedProxies.
## A trusted proxy's PROXY header overrides req.remoteAddress with the real
## client IP; an untrusted peer's header is never believed. Raw sockets, so the
## PROXY header can be prepended ahead of the HTTP request.

import std/[unittest, net, httpcore, strutils]
import vortex/[settings, request, server]

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, req.remoteAddress, "text/plain")

# --- raw client: optional PROXY prologue, then a plain GET; return the body,
# or "" if the server dropped the connection without responding. ---
proc rawIp(port: Port, prologue: string): string =
  var s = newSocket()
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send(prologue & "GET /ip HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
  var resp = ""
  var chunk = newString(4096)
  try:
    while true:
      let n = s.recv(chunk, 4096, 2000)
      if n <= 0: break
      resp.add chunk[0 ..< n]
  except TimeoutError:
    discard
  let idx = resp.find("\r\n\r\n")
  if idx < 0: "" else: resp[idx + 4 .. ^1]

# A v2 header: PROXY, AF_INET/STREAM, src 198.51.100.9, then TLS-ish trailing.
proc v2(): string =
  result = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"  # signature
  result.add "\x21"                    # version 2, command PROXY
  result.add "\x11"                    # AF_INET, STREAM
  result.add "\x00\x0C"                # address block length 12
  result.add "\xC6\x33\x64\x09"        # src 198.51.100.9
  result.add "\xC6\x33\x64\x02"        # dst
  result.add "\x30\x39"                # src port
  result.add "\x01\xBB"                # dst port

const v1 = "PROXY TCP4 203.0.113.7 198.51.100.2 12345 443\r\n"

# Server A: optional, trust any direct peer (empty list).
var srvA = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, proxyProtocol = ProxyProtocol.Optional)).start(0)
# Server B: require, loopback trusted.
var srvB = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, proxyProtocol = ProxyProtocol.Require, trustedProxies = @["127.0.0.0/8"])).start(0)
# Server C: require, loopback NOT trusted.
var srvC = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, proxyProtocol = ProxyProtocol.Require, trustedProxies = @["10.0.0.0/8"])).start(0)

suite "PROXY protocol":
  test "v1 header from a trusted peer overrides remoteAddress":
    check rawIp(srvA.port, v1) == "203.0.113.7"

  test "v2 header from a trusted peer overrides remoteAddress":
    check rawIp(srvA.port, v2()) == "198.51.100.9"

  test "optional + no header: falls back to the direct peer":
    check rawIp(srvA.port, "") == "127.0.0.1"

  test "require + trusted peer + header: client IP":
    check rawIp(srvB.port, v1) == "203.0.113.7"

  test "require + no header: connection dropped":
    check rawIp(srvB.port, "") == ""

  test "require + untrusted peer: dropped even with a valid header":
    check rawIp(srvC.port, v1) == ""

srvA.close()
srvB.close()
srvC.close()
echo "proxy protocol ok"
