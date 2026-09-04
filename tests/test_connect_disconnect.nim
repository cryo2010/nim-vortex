## Connect/disconnect conformance (vs Go/Node graceful behaviors):
##  * an HTTP/2 connection with a half-open stream (client sent HEADERS but no
##    END_STREAM, then went silent) is closed by the read-idle deadline instead
##    of being held forever -- a slowloris hold-open (issue #201).
##  * graceful shutdown sends the RFC 9113 6.8 two-step GOAWAY: an initial
##    GOAWAY(2^31-1) notice, then the final GOAWAY(last-accepted id) (issue #208).

import std/[unittest, net, posix, os, httpcore, times]
import vortex/[settings, request, server, routing]
import vortex/http2/frames
import ./h2client

proc hello(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

proc lastStreamId(f: Frame): uint32 =
  ## GOAWAY payload: 4-byte last-stream-id (high reserved bit masked off).
  if f.payload.len < 4: return 0
  ((uint32(uint8(f.payload[0])) shl 24) or (uint32(uint8(f.payload[1])) shl 16) or
   (uint32(uint8(f.payload[2])) shl 8) or uint32(uint8(f.payload[3]))) and
    0x7fffffff'u32

suite "HTTP/2 half-open stream slowloris timeout (#201)":
  test "a stream opened without END_STREAM, then silence, is closed":
    # bodyTimeout=1s: an open stream still awaiting the client's request bytes
    # must be timed out. keepAliveTimeout is separate and larger, proving the
    # close is the active-stream read deadline, not the idle one.
    let rt = newRouter()
    rt.get("/", hello)
    var srv = newVortex(rt.toHandler,
      initVortexConfig(numThreads = 1, bodyTimeout = 1, keepAliveTimeout = 30)).start(0)
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)                 # drain server SETTINGS
    var f = ""
    f.addRequest(1, [(":method", "POST"), (":path", "/"), (":scheme", "http"),
                     (":authority", "x")], endStream = false)   # body promised, never sent
    c.sendRaw(f)
    # Within ~bodyTimeout the server closes the connection: recv sees EOF (0).
    var tv = Timeval(tv_sec: posix.Time(4), tv_usec: Suseconds(0))
    discard setsockopt(c.sock.getFd, SOL_SOCKET, SO_RCVTIMEO,
                       addr tv, SockLen(sizeof(tv)))
    var buf = newString(4096)
    var closed = false
    let deadline = epochTime() + 3.5
    while epochTime() < deadline:
      let n = recv(c.sock.getFd, addr buf[0], buf.len, cint(0))
      if n == 0: (closed = true; break)       # server closed the connection
      elif n < 0: break
    check closed
    c.close()
    srv.close()

suite "HTTP/2 graceful shutdown two-step GOAWAY (#208)":
  test "shutdown sends GOAWAY(2^31-1) notice then GOAWAY(last id)":
    let rt = newRouter()
    rt.get("/", hello)
    var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    c.sendHeaders(1)                          # GET / (END_STREAM); stream 1 completes
    discard c.readFrames(1000,
      until = proc(fs: seq[Frame]): bool = fs.count(ftHeaders) >= 1)
    srv.requestShutdown()                     # non-blocking: loops enter beginDrain
    let frames = c.readFrames(3000,
      until = proc(fs: seq[Frame]): bool = fs.count(ftGoaway) >= 2)
    var sawNotice, sawFinal = false
    for f in frames:
      if f.typ == uint8(ftGoaway):
        if f.lastStreamId == 0x7fffffff'u32: sawNotice = true
        elif f.lastStreamId == 1'u32: sawFinal = true
    check sawNotice                           # the two-step drain notice
    check sawFinal                            # the real last-accepted cutoff
    c.close()
    srv.close()

echo "connect/disconnect ok"
