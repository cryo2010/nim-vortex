## The QUIC receive buffer must be able to hold what we advertise.
##
## The shim sets `max_udp_payload_size` in its transport parameters, which tells
## the peer "datagrams up to this size are fine". ngReceive's recvfrom buffer was
## 2048 bytes while that advertisement was ngtcp2's 65527 default, so a
## conforming client on a large-MTU path (a 9000-byte VPC MTU, 65536 on loopback)
## was entitled to send a datagram the kernel then truncated: header protection
## and AEAD failed, ngtcp2 dropped the packet, the client retransmitted the same
## oversize datagram, and the connection died on the idle timer with nothing
## logged at either end (#380).
##
## What this suite can and cannot observe. The invariant itself -- the buffer is
## sized from the advertised number, read back out of the C shim rather than
## duplicated in Nim -- is checked white-box, because it is not reachable
## black-box: curl and ngtcp2 probe the path MTU from 1200 bytes and settle
## around 1452, so no stock client sends us 2 KB and a transfer test cannot tell
## a 2048-byte buffer from a 65527-byte one. What is checked on the wire is that
## the larger buffer still serves h3 normally, and that a > 2048-byte datagram
## arriving on the QUIC port (garbage, as a flood would be) is consumed without
## disturbing the connections on it.

import std/[unittest, net, httpcore, os, nativesockets]
import vortex/[settings, request, server]
import ./helper

when not defined(plainHttp):
  import vortex/http3/ngtcp2/backend

  let h3curlBin = requireH3Curl()
  let (certPath, keyPath) = makeCertPair("nh3_recvbuf_")

  proc handler(req: Request, res: Response) {.gcsafe.} =
    res.send(Http200, "payload ok")

  var srv = newVortex(RequestHandler(handler),
    initVortexConfig(numThreads = 1, certFile = certPath, keyFile = keyPath,
                     http3 = true)).start(0)
  let base = "https://localhost:" & $srv.port

  suite "h3 receive buffer vs advertised max_udp_payload_size":
    test "a normal h3 request works (the engine is up)":
      let (body, rc) = h3curl(h3curlBin, base & "/")
      check rc == 0
      check body == "payload ok"

    test "the receive buffer is sized from what the shim advertises":
      # Both numbers come out of the one shim constant: ngMaxRecvUdpPayload
      # calls vq_max_recv_udp_payload (the value written into
      # tp.max_udp_payload_size), and ngRecvBufSize is what ngSetup allocated on
      # the loop thread. Pre-fix this read 2048 vs 65527.
      check ngMaxRecvUdpPayload() == 65527   # the largest a UDP payload can be
      check ngRecvBufSize() == ngMaxRecvUdpPayload()

    test "a datagram larger than the old 2048-byte buffer is absorbed":
      # Not a QUIC packet, so the engine drops it either way; the point is that
      # recvfrom takes a 4 KB datagram in one piece and the loop keeps serving.
      let s = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
      defer: s.close()
      var blast = newString(4096)
      for i in 0 ..< blast.len: blast[i] = char(i and 0xff)
      s.sendTo("127.0.0.1", srv.port, blast)
      sleep(100)
      let (body, rc) = h3curl(h3curlBin, base & "/")
      check rc == 0
      check body == "payload ok"
      # Nothing was truncated: the datagram fits the buffer now. (Only ever
      # non-zero on Linux, where recvfrom honours MSG_TRUNC.)
      check ngTruncatedDrops() == 0'u64

  srv.stop()
  removeDir(certPath.parentDir)
  echo "h3 recv payload ok"
else:
  echo "SKIP: HTTP/3 is not built under -d:plainHttp"
