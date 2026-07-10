## Shared plumbing for the perf_* benchmarks: raw-socket helpers, the
## HTTP/1.1 pipelined client loop, load runner, and result reporting.

import std/[os, atomics, strutils, posix, nativesockets, net]

type
  ClientCtx* = tuple
    port: int
    depth: int
    stop: ptr Atomic[bool]
    total: ptr Atomic[int64]

  ClientProc* = proc (ctx: ClientCtx) {.thread, nimcall.}

proc connectLocal*(port: int): SocketHandle =
  result = createNativeSocket(Domain.AF_INET, SockType.SOCK_STREAM,
                              Protocol.IPPROTO_TCP)
  let ai = getAddrInfo("127.0.0.1", net.Port(port), Domain.AF_INET)
  let rc = connect(result, ai.ai_addr, SockLen(ai.ai_addrlen))
  freeAddrInfo(ai)
  if rc < 0:
    result.close()
    return osInvalidSocket
  var one = cint(1)
  discard setsockopt(result, IPPROTO_TCP, TCP_NODELAY,
                     addr one, SockLen(sizeof(one)))

proc findSub*(hay: string, hayLen: int, start: int, needle: string): int =
  ## Naive substring search over hay[start..<hayLen]; -1 if absent.
  if needle.len == 0 or hayLen < needle.len: return -1
  for i in start .. hayLen - needle.len:
    var ok = true
    for j in 0 ..< needle.len:
      if hay[i + j] != needle[j]:
        ok = false
        break
    if ok: return i
  -1

proc contentLengthOf*(buf: string, start, headerEnd: int): int =
  ## Parse Content-Length within one response head; -1 if absent.
  var i = start
  while i < headerEnd:
    var nl = findSub(buf, headerEnd, i, "\r\n")
    if nl < 0: nl = headerEnd
    let colon = findSub(buf, min(nl, headerEnd), i, ":")
    if colon > i:
      let name = buf[i ..< colon].toLowerAscii
      if name == "content-length":
        return parseInt(buf[colon + 1 ..< nl].strip())
    i = nl + 2
  -1

proc h1ClientLoop*(ctx: ClientCtx) {.thread.} =
  ## Keep-alive pipelined HTTP/1.1 load; reconnects when the server
  ## closes the connection so close-happy servers are measured fairly.
  var request = ""
  for i in 0 ..< ctx.depth:
    request.add "GET / HTTP/1.1\r\nHost: bench\r\n\r\n"
  var buf = newString(256 * 1024)
  var count = 0'i64
  var fd = osInvalidSocket
  while not ctx.stop[].load(moRelaxed):
    if fd == osInvalidSocket:
      fd = connectLocal(ctx.port)
      if fd == osInvalidSocket:
        sleep(10)
        continue
    block batch:
      var sent = 0
      while sent < request.len:
        let n = send(fd, unsafeAddr request[sent], request.len - sent, cint(0))
        if n <= 0:
          fd.close()
          fd = osInvalidSocket
          break batch
        sent += n
      var pending = ctx.depth
      var pos = 0
      var have = 0
      while pending > 0:
        let n = recv(fd, addr buf[have], buf.len - have, cint(0))
        if n <= 0:
          fd.close()
          fd = osInvalidSocket
          break batch
        have += n
        while pending > 0:
          let headerEnd = findSub(buf, have, pos, "\r\n\r\n")
          if headerEnd < 0: break
          let bodyLen = contentLengthOf(buf, pos, headerEnd)
          if bodyLen < 0:
            fd.close()
            fd = osInvalidSocket
            break batch
          let respEnd = headerEnd + 4 + bodyLen
          if respEnd > have: break
          pos = respEnd
          dec pending
          inc count
  discard ctx.total[].fetchAdd(count, moRelaxed)
  if fd != osInvalidSocket:
    fd.close()

proc runLoad*(client: ClientProc, port: int,
              conns, seconds, depth: int): float =
  ## Requests per second measured over `seconds`.
  var stop: Atomic[bool]
  var total: Atomic[int64]
  stop.store(false)
  total.store(0)
  var threads = newSeq[Thread[ClientCtx]](conns)
  for i in 0 ..< conns:
    createThread(threads[i], client,
                 (port: port, depth: depth, stop: addr stop,
                  total: addr total))
  sleep(seconds * 1000)
  stop.store(true)
  for t in threads.mitems:
    joinThread(t)
  float(total.load()) / float(seconds)

proc waitReady*(port: int): bool =
  for attempt in 0 ..< 100:
    let fd = connectLocal(port)
    if fd != osInvalidSocket:
      fd.close()
      return true
    sleep(50)
  false

proc report*(results: seq[(string, float)]) =
  var best = 0.0
  for (_, rps) in results:
    best = max(best, rps)
  echo ""
  echo "relative:"
  for (name, rps) in results:
    echo "  ", name.alignLeft(26),
         align(formatFloat(100 * rps / best, ffDecimal, 1), 6), "%"

proc printRow*(name: string, rps: float) =
  echo name.alignLeft(26), align(formatFloat(rps, ffDecimal, 0), 10), " req/s"
