## QUIC ingress must not starve the loop's TCP connections.
##
## `ngReceive` drained the UDP socket with `while true`, and every datagram is
## decrypted and parsed synchronously (vq_engine_recv -> ngtcp2_conn_read_pkt ->
## nghttp3) before the next `recvfrom`. A UDP source at line rate therefore kept
## the loop thread inside the receive loop, and the HTTP/1.1 and HTTP/2 fds on
## that same thread were not serviced at all: TLS handshakes stalled, responses
## did not flush, deadlines fired. Forging the datagrams is cheap because
## `acceptConn` commits per-connection state before validating the peer address
## (no Retry token yet). The fix is a per-pass datagram budget (`ngRecvBudget`)
## plus "do not wait on the selector while ingress has more", the same rule the
## loop already applies to its `sslReady` queue (#381).
##
## What this suite asserts: with a UDP flood running against the QUIC port, a
## request over TCP on the *same* server and the *same* single loop thread still
## completes inside a bound.
##
## The flood is not random noise. Short garbage is the wrong adversary here: the
## kernel's UDP receive buffer caps the backlog a sender can build, so the drain
## reaches EAGAIN anyway and nothing starves (measured: 12 ms with the budget
## removed). What starves the thread is a datagram that costs us *more* than it
## costs the sender -- a long-header Initial naming an unsupported QUIC version,
## which ngtcp2 answers with a Version Negotiation packet, so each one buys a
## parse plus a sendto. With the budget removed that flood kept the loop inside
## `ngReceive` and curl gave up at its timeout having never been served; with
## the budget it is served while the flood runs.
##
## The bound is therefore generous (5 s) and curl's own timeout is more generous
## still (10 s): the pre-fix failure is "never served", not "served slowly", so
## the assertion does not need to be tight, and letting curl finish keeps a slow
## answer on a loaded runner distinguishable from no answer at all. Measured on
## a 14-core host (13 senders), five runs: 0.46-1.7 s with the budget, and the
## full 10 s curl timeout with it removed. The flood is sized to the host
## (`countProcessors() - 1` senders), because a fixed count oversubscribed a
## 2-vCPU runner and measured its scheduler instead.

import std/[unittest, net, httpcore, os, times, strutils, osproc, atomics]
import vortex/[settings, request, server]
import ./helper

when not defined(plainHttp):
  import vortex/http3/ngtcp2/backend

  let curlBin = requireCurl()
  let (certPath, keyPath) = makeCertPair("nh3_flood_")

  let blasters = max(1, osproc.countProcessors() - 1)
    ## Sender threads. One less than the host has cores, so a thread is always
    ## left for the loop: a fixed 4 oversubscribed a 2-vCPU CI runner and the
    ## suite then measured the runner's scheduler rather than the receive
    ## budget. One is enough to starve an unbounded drain (the datagrams cost
    ## the server more than the sender), so the floor keeps the signal.

  const
    requestBudgetMs = 5_000  ## a TCP request must complete inside this
      ## The pre-fix failure is total, not slow: the loop thread never leaves
      ## `ngReceive` while the flood runs, so it does not recover inside 5 s
      ## either (measured with the budget removed: the full 10 s curl timeout,
      ## never served). With the budget in place the request lands in well under
      ## 2 s even with every core but one blasting, so this bound can be
      ## generous about a loaded runner without losing the signal.
    curlTimeoutSec = 10
      ## Deliberately longer than requestBudgetMs: curl must be allowed to
      ## finish so "served, but slowly" shows up as a latency the check reports,
      ## not as the same exit code as "never served at all".

  proc handler(req: Request, res: Response) {.gcsafe.} =
    res.send(Http200, "tcp alive")

  # One loop thread, so the flooded UDP fd and the TCP connections provably
  # share a thread: with reusePort and N loops the request could land on a loop
  # the flood never reached and the test would prove nothing.
  var srv = newVortex(RequestHandler(handler),
    initVortexConfig(numThreads = 1, certFile = certPath, keyFile = keyPath,
                     http3 = true)).start(0)
  let port = srv.port
  let base = "https://localhost:" & $port

  var stopFlood: Atomic[bool]
  var sent: Atomic[int]

  proc blast(unused: int) {.thread.} =
    let s = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    # A long-header Initial naming a QUIC version we do not support, padded to a
    # realistic 1250 bytes. ngtcp2 answers each one with a Version Negotiation
    # packet, so this is the adversary's *expensive* case: every datagram we take
    # off the socket costs us a parse plus a sendto. That, not raw packet count,
    # is what can make an unbounded drain outrun its own socket.
    var junk = "\xc3" & "\x0a\x0a\x0a\x0a" &
               "\x08" & repeat('\xab', 8) & "\x08" & repeat('\xcd', 8)
    junk.add repeat('\x00', 1250 - junk.len)
    while not stopFlood.load(moRelaxed):
      for _ in 1 .. 64:
        try: s.sendTo("127.0.0.1", port, junk)
        except OSError: discard          # ENOBUFS on a full send buffer: keep going
      sent.atomicInc(64)
    s.close()

  var threads = newSeq[Thread[int]](blasters)

  suite "a UDP flood does not starve the loop's TCP connections":
    test "the per-pass receive budget is in force":
      # The constant is the fix; pin it so an unbounded drain cannot come back
      # unnoticed, and so the comment above cannot drift from the code.
      check ngRecvBudget > 0
      check ngRecvBudget <= 4096

    test "a TCP request completes while the QUIC port is flooded":
      stopFlood.store(false)
      sent.store(0)
      for i in 0 ..< blasters: createThread(threads[i], blast, i)
      sleep(150)                         # let the flood get going first
      let t0 = epochTime()
      let (out1, rc) = execCmdEx(curlBin & " -sk --http1.1 -m " &
                                 $curlTimeoutSec & " " & base & "/")
      let elapsedMs = int((epochTime() - t0) * 1000)
      stopFlood.store(true)
      for i in 0 ..< blasters: joinThread(threads[i])
      echo "  flood sent ", sent.load(moRelaxed), " datagrams from ", blasters,
           " threads; request took ", elapsedMs, " ms"
      check rc == 0
      check out1.strip() == "tcp alive"
      check elapsedMs < requestBudgetMs

    test "h3 itself still works after the flood":
      # The flood must not have left the engine wedged (every datagram was
      # rejected, so no connection state should have accumulated).
      let h3 = findH3Curl()
      if h3.len == 0:
        echo "  SKIP: no HTTP/3-capable curl"
      else:
        let (body, rc) = h3curl(h3, base & "/")
        check rc == 0
        check body == "tcp alive"

  srv.stop()
  removeDir(certPath.parentDir)
  echo "h3 udp flood ok"
else:
  echo "SKIP: HTTP/3 is not built under -d:plainHttp"
