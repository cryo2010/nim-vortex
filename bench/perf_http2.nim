## HTTP/2 throughput benchmark (h2c prior knowledge).
##
## No other Nim server speaks HTTP/2, so this measures vortex
## against itself: HTTP/2 vs HTTP/1.1 protocol overhead on the same
## server, and h2 multi-thread vs single-thread scaling.
##
##   perf_http2                    orchestrator (spawns itself as servers)
##   perf_http2 serve <name> <port>
##
## Build and run:  nimble perf2
## Tunables: -d:benchSeconds=5 -d:benchConns=32 -d:benchStreams=64
##
## The h2 client speaks the real protocol from raw frames: preface +
## SETTINGS, then batches of `benchStreams` concurrent GET streams
## (static-table HPACK: ":method GET, :scheme http, :path /"), counting
## END_STREAM flags and replenishing the connection flow-control window
## every batch. Responses are never HPACK-decoded; framing is enough for
## counting, which keeps the client cheap relative to the server.

import std/[os, osproc, strutils, atomics, posix, nativesockets, net,
            httpcore]
import ../src/vortex
import ../src/vortex/adapters/asyncdispatch as nhsasync
import ../src/vortex/http2/frames
import ./perf_common

const
  benchSeconds {.intdefine.} = 5
  benchConns {.intdefine.} = 32
  benchStreams {.intdefine.} = 64   # concurrent streams per connection
  benchDepth {.intdefine.} = 8      # h1 pipeline depth (comparison row)

proc serveOurs(port: int, threads: int) =
  proc handler(req: vortex.Request, res: vortex.Response) {.gcsafe.} =
    vortex.send(res, Http200, "Hello, World!", "text/plain")
  vortex.run(handler,
    vortex.initSettings(port = net.Port(port), numThreads = threads))

proc serveOursAsync(port: int) =
  ## Suspending async handler via the adapter: h2 streams are
  ## independent, so awaits do not pause the connection (unlike h1).
  proc h(req: vortex.Request, res: vortex.Response): Future[void] {.async.} =
    await sleepAsync(0)
    vortex.send(res, Http200, "Hello, World!", "text/plain")
  vortex.run(toHandler(h),
    vortex.initSettings(port = net.Port(port), numThreads = 0))

# --- HTTP/2 client -----------------------------------------------------------

const
  # ":method GET" (0x82), ":scheme http" (0x86), ":path /" (0x84):
  # a complete GET request from three static-table HPACK indexes.
  reqPayload = "\x82\x86\x84"

proc sendAll(fd: SocketHandle, data: string): bool =
  var sent = 0
  while sent < data.len:
    let n = send(fd, unsafeAddr data[sent], data.len - sent, cint(0))
    if n <= 0: return false
    sent += n
  true

proc h2ClientLoop(ctx: ClientCtx) {.thread.} =
  var count = 0'i64
  var fd = osInvalidSocket
  var buf = newString(1024 * 1024)
  var have = 0
  var pos = 0
  var sid = 1'u32
  var outBuf = ""
  var settingsAcked = false
  while not ctx.stop[].load(moRelaxed):
    if fd == osInvalidSocket:
      fd = connectLocal(ctx.port)
      if fd == osInvalidSocket:
        sleep(10)
        continue
      # Preface + our (empty) SETTINGS.
      outBuf.setLen(0)
      outBuf.add connectionPreface
      outBuf.addFrameHeader(0, ftSettings, 0, 0)
      if not sendAll(fd, outBuf):
        fd.close()
        fd = osInvalidSocket
        continue
      sid = 1
      have = 0
      pos = 0
      settingsAcked = false
    block batch:
      template die() =
        fd.close()
        fd = osInvalidSocket
        break batch
      # One batch of concurrent streams.
      outBuf.setLen(0)
      for i in 0 ..< ctx.depth:
        outBuf.addFrameHeader(reqPayload.len, ftHeaders,
                              flagEndHeaders or flagEndStream, sid)
        outBuf.add reqPayload
        sid += 2
      if sid > 0x7ff00000'u32: die()   # stream ids near exhaustion
      if not sendAll(fd, outBuf): die()
      var pending = ctx.depth
      var dataBytes = 0
      while pending > 0:
        if have == buf.len:
          die()                        # response burst larger than buffer
        let n = recv(fd, addr buf[have], buf.len - have, cint(0))
        if n <= 0: die()
        have += n
        while have - pos >= frameHeaderLen:
          let fh = parseFrameHeader(buf, pos)
          if have - pos < frameHeaderLen + fh.length: break
          if fh.typ <= uint8(high(FrameType)):
            case FrameType(fh.typ)
            of ftHeaders, ftData:
              if FrameType(fh.typ) == ftData:
                dataBytes += fh.length
              if (fh.flags and flagEndStream) != 0:
                dec pending
                inc count
            of ftSettings:
              if (fh.flags and flagAck) == 0 and not settingsAcked:
                settingsAcked = true
                var ack = ""
                ack.addFrameHeader(0, ftSettings, flagAck, 0)
                if not sendAll(fd, ack): die()
            of ftGoaway, ftRstStream:
              die()
            else:
              discard                  # WINDOW_UPDATE, PING, ...
          pos += frameHeaderLen + fh.length
        # Compact consumed bytes.
        if pos > 0:
          if pos >= have:
            have = 0
          else:
            moveMem(addr buf[0], addr buf[pos], have - pos)
            have -= pos
          pos = 0
      # Replenish the connection window for the DATA we consumed.
      if dataBytes > 0:
        outBuf.setLen(0)
        outBuf.addWindowUpdate(0, dataBytes)
        if not sendAll(fd, outBuf): die()
  discard ctx.total[].fetchAdd(count, moRelaxed)
  if fd != osInvalidSocket:
    fd.close()

# --- orchestration -----------------------------------------------------------

proc orchestrate() =
  echo "HTTP/2 (h2c) throughput: ", benchConns, " connections, ",
       benchStreams, " concurrent streams, ", benchSeconds, "s per row; ",
       "h1 row: pipeline depth ", benchDepth
  echo ""
  var results: seq[(string, float)]

  proc bench(label, server: string, port: int, client: ClientProc,
             depth: int) =
    let p = startProcess(getAppFilename(), args = ["serve", server, $port],
                         options = {poParentStreams})
    defer:
      p.kill()
      p.close()
      sleep(300)
    if not waitReady(port):
      echo label, ": failed to start"
      return
    discard runLoad(client, port, benchConns, 1, depth)       # warmup
    let rps = runLoad(client, port, benchConns, benchSeconds, depth)
    results.add (label, rps)
    printRow(label, rps)

  bench("h2", "nhs", 9201, h2ClientLoop, benchStreams)
  bench("h2-1thread", "nhs-1t", 9202, h2ClientLoop, benchStreams)
  bench("h2-async-await", "nhs-async", 9204, h2ClientLoop, benchStreams)
  bench("h1 (same server)", "nhs", 9203, h1ClientLoop, benchDepth)
  report(results)

when isMainModule:
  if paramCount() >= 3 and paramStr(1) == "serve":
    let port = parseInt(paramStr(3))
    case paramStr(2)
    of "nhs": serveOurs(port, 0)
    of "nhs-1t": serveOurs(port, 1)
    of "nhs-async": serveOursAsync(port)
    else: quit "unknown server: " & paramStr(2)
  else:
    orchestrate()
