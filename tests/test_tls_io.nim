## Event-loop TLS I/O regressions: selector interest around a stalled
## handshake, a blocked SSL_write, and an SSL_read that needs the socket
## writable.
##
## These are liveness/CPU bugs rather than protocol ones, so the assertions are
## process CPU time (getrusage over an otherwise idle window: the test's own
## thread sleeps, so whatever is spent belongs to the loop thread) and request
## completion, not response bytes.

import std/[unittest, net, posix, os, strutils, httpcore]
import vortex/[settings, request, server]
import ./helper

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"
  quit 0

if findExe("openssl").len == 0:
  echo "SKIP: need openssl to mint a certificate"
  quit 0

let (cert, key) = makeCertPair("vortex_tlsio_")

# A deliberately fat certificate chain: the leaf repeated until the server's
# first handshake flight is far larger than a socket send buffer, so
# SSL_do_handshake really does hit WANT_WRITE (a ~2 KiB flight always fits in
# the kernel buffer and would never exercise the armed-write path). OpenSSL
# sends the extra chain certificates verbatim; nothing here verifies them.
let fatCert = cert.parentDir / "fatchain.pem"
writeFile(fatCert, repeat(readFile(cert), 3000))

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

# --- helpers ------------------------------------------------------------------

proc secs(tv: Timeval): float =
  float(clong(tv.tv_sec)) + float(tv.tv_usec) / 1e6

proc cpuSeconds(): float =
  ## User + system CPU consumed by this process (all threads) so far.
  var ru: Rusage
  discard getrusage(RUSAGE_SELF, addr ru)
  ru.ru_utime.secs + ru.ru_stime.secs

proc u16(v: int): string =
  char((v shr 8) and 0xff) & char(v and 0xff)

proc clientHello(): string =
  ## A hand-built TLS 1.2 ClientHello: enough for the server to send its whole
  ## flight (ServerHello .. ServerHelloDone) and then wait for a second flight
  ## that this "client" never sends. A real OpenSSL client cannot be stopped
  ## there, which is why the bytes are assembled by hand.
  const host = "localhost"
  var ext = ""
  ext.add u16(0x0000) & u16(host.len + 5) & u16(host.len + 3) & "\x00" &
          u16(host.len) & host                       # server_name
  ext.add u16(0x000a) & u16(4) & u16(2) & "\x00\x17" # supported_groups: secp256r1
  ext.add u16(0x000b) & u16(2) & "\x01\x00"          # ec_point_formats
  ext.add u16(0x000d) & u16(8) & u16(6) &
          "\x04\x01\x08\x04\x05\x01"                 # signature_algorithms
  var hello = "\x03\x03"                             # client_version: TLS 1.2
  hello.add repeat('\x2a', 32)                       # random
  hello.add "\x00"                                   # session_id: empty
  hello.add u16(4) & "\xc0\x2f\xc0\x30"              # ECDHE-RSA-AES128/256-GCM
  hello.add "\x01\x00"                               # compression: null
  hello.add u16(ext.len) & ext
  let hs = "\x01" & char((hello.len shr 16) and 0xff) & u16(hello.len) & hello
  "\x16\x03\x01" & u16(hs.len) & hs

proc drainAll(s: Socket, quietMs = 300): int =
  ## Read until the peer goes quiet for quietMs; returns the byte count.
  s.setRecvTimeout(quietMs)
  var buf = newString(4096)
  while true:
    let n = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if n <= 0: break
    result += int(n)

proc tinyRecvSocket(port: Port, rcvBytes = 1024): Socket =
  ## A connected socket with a deliberately tiny receive buffer, so the peer's
  ## first write blocks long before the whole flight fits.
  result = newSocket(buffered = false)
  var rcv = cint(rcvBytes)
  discard setsockopt(result.getFd, SOL_SOCKET, SO_RCVBUF, addr rcv,
                     SockLen(sizeof(rcv)))
  result.connect("127.0.0.1", port)

# --- #365: driveHandshake must drop write interest on WANT_READ ---------------

suite "TLS handshake selector interest":
  ## A handshake that blocked on a full socket send buffer (WANT_WRITE -> write
  ## interest armed) and then went back to waiting for the peer must stop
  ## watching writability. The selector is level-triggered and every event on a
  ## handshaking connection re-enters driveHandshake, so a writable socket
  ## otherwise spins the loop thread for the whole headerTimeout window (#365).
  test "a handshake stalled after a blocked flight does not spin the loop":
    let cfg = initVortexConfig(numThreads = 1, certFile = fatCert, keyFile = key,
                               headerTimeout = 5)
    withServer(RequestHandler(handler), cfg, srv):
      let s = tinyRecvSocket(srv.port)
      defer: s.close()
      s.send(clientHello())
      # Let the server's flight fill the socket send buffer while nothing reads
      # it: SSL_do_handshake blocks on WANT_WRITE and arms write interest.
      sleep(300)
      # Drain the server's flight: that re-opens our receive window, so the
      # server's socket is writable again while the handshake waits on the
      # client key exchange we will never send.
      # The flight is far larger than any socket buffer, so the server really
      # did block mid-flight; on a platform whose buffers could swallow it whole
      # the assertion below degrades to a no-op rather than flaking.
      check s.drainAll() > 1024 * 1024
      let t0 = cpuSeconds()
      sleep(1000)
      let spent = cpuSeconds() - t0
      # Idle: one 1 s tick. Spinning: a full core (~1.0 s of CPU per second).
      check spent < 0.3
      # The stalled handshake is still reaped by headerTimeout.
      check s.waitForClose(tries = 12, stepMs = 500)

# --- #371: flushOut must not hold write interest on SSL_write WANT_READ ------

const bigLen = 4 * 1024 * 1024

proc bigHandler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, repeat('x', bigLen))

proc sslDrain(s: Socket, want: int): int =
  ## Read up to `want` bytes over TLS; stops at EOF, at a receive timeout (which
  ## std/net surfaces as an SSL "not enough data" error) or at `want`.
  var buf = newString(64 * 1024)
  while result < want:
    var n = 0
    try: n = s.recv(addr buf[0], buf.len)
    except CatchableError: break
    if n <= 0: break
    result += n

suite "TLS write-path stalls":
  ## flushOut arms write interest when the socket cannot take the rest of a
  ## response. While the peer stops reading, the loop must sit on that armed
  ## write without spinning, and the flush must resume the moment the peer
  ## drains. (The SSL_write WANT_READ arm fixed alongside this cannot be driven
  ## from a client: see the commit message for #371.)
  test "a peer that stops reading stalls the flush without spinning the loop":
    let cfg = initVortexConfig(numThreads = 1, certFile = cert, keyFile = key)
    withServer(RequestHandler(bigHandler), cfg, srv):
      let ctx = newContext(verifyMode = CVerifyNone)
      let s = newSocket(buffered = false)
      defer: s.close()
      s.connect("127.0.0.1", srv.port)
      ctx.wrapConnectedSocket(s, handshakeAsClient, "localhost")
      s.send("GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
      sleep(400)                 # the response fills the socket: write armed
      let t0 = cpuSeconds()
      sleep(1000)
      check cpuSeconds() - t0 < 0.3
      # The stalled flush resumes as soon as we read again.
      s.setRecvTimeout(3000)
      check s.sslDrain(bigLen) > 1024 * 1024

# --- #366: decrypted plaintext left inside OpenSSL must still be consumed ----

const
  pinnedSleepMs = 800     ## how long the worker holds the connection pinned
  recLen = 16 * 1024      ## one full TLS record of plaintext
  pinnedHead = "POST /size HTTP/1.1\r\nHost: x\r\nContent-Length: "

proc pinHandler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/slow":
    req.blocking:
      sleep(pinnedSleepMs)             # holds a worker pin on the connection
      res.send(Http200, "slow done")
  of "/size":
    res.send(Http200, "got " & $req.body.len)
  else:
    res.send(Http404)

proc pipelinedRequest(): string =
  ## A complete request of exactly one TLS record, so the server's SSL_read
  ## drains it from the kernel in full and can only return part of it.
  var bodyLen = recLen - pinnedHead.len - len("\r\n\r\n")
  var digits = len($bodyLen)
  bodyLen -= digits
  while len($bodyLen) != digits:       # the length field shrank a digit
    bodyLen -= 1
    digits = len($bodyLen)
  result = pinnedHead & $bodyLen & "\r\n\r\n" & repeat('b', bodyLen)
  doAssert result.len == recLen, $result.len

proc sslText(s: Socket, quietMs = 1500): string =
  ## Read over TLS until the peer goes quiet for quietMs (or closes).
  s.setRecvTimeout(quietMs)
  var buf = newString(recLen)
  while true:
    var n = 0
    try: n = s.recv(addr buf[0], buf.len)
    except CatchableError: break
    if n <= 0: break
    result.add buf[0 ..< n]

suite "TLS plaintext buffered inside OpenSSL":
  ## The recv loop's early exits assume the bytes it did not take are still in
  ## the kernel, held there as TCP backpressure until the next readable event.
  ## Under TLS that is false: a read with a small `wanted` keeps the rest of the
  ## record decrypted inside OpenSSL while the socket goes empty, and a
  ## level-triggered fd never reports readable again. The loop must come back
  ## for those bytes itself (#366).
  test "a pipelined request decrypted behind a pinned worker is still served":
    let cfg = initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                               bodyTimeout = 2)   # fail fast if it stalls
    withServer(RequestHandler(pinHandler), cfg, srv):
      let ctx = newContext(verifyMode = CVerifyNone)
      let s = newSocket(buffered = false)
      defer: s.close()
      s.connect("127.0.0.1", srv.port)
      ctx.wrapConnectedSocket(s, handshakeAsClient, "localhost")
      s.send("GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
      sleep(200)                       # let the worker take its pin
      # One record, larger than the room left in the receive buffer: the recv
      # loop stops at the pin with the tail decrypted inside OpenSSL and the
      # socket drained.
      let req2 = pipelinedRequest()
      s.send(req2)
      let text = s.sslText()
      check text.count("HTTP/1.1 200") == 2
      check "slow done" in text
      check ("got " & $(req2.len - req2.find("\r\n\r\n") - 4)) in text
