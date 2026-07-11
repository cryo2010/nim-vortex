## HTTP/1.1 throughput comparison: vortex vs httpbeast,
## std/asynchttpserver, and chronos.
##
## One binary, two modes:
##   perf_http1_1                 orchestrator: spawns each server as a
##                                subprocess of itself, drives the same
##                                in-process load generator against each,
##                                prints a table
##   perf_http1_1 serve <name> <port>   run one server (subprocess mode)
##
## Build and run (deps resolved by the nimble task):
##   nimble perf
## or by hand, with httpbeast and chronos installed:
##   nim c -r -d:danger --threads:on --mm:orc bench/perf_http1_1.nim
##
## Tunables: -d:benchSeconds=5 -d:benchConns=32 -d:benchDepth=8
##
## The load generator opens N keep-alive connections (one thread each),
## sends `depth` pipelined GETs per batch, and counts complete responses
## by parsing Content-Length, so servers with different header sets are
## measured identically. asynchttpserver and chronos are single-threaded
## by design; vortex is also shown pinned to one thread for a
## like-for-like comparison.
##
## The -async row serves through the asyncdispatch adapter with a
## handler that responds without suspending (the adapter tax; the fair
## peer is httpbeast-async, a real {.async.} httpbeast handler, since
## plain httpbeast handlers return nil futures and skip its future
## machinery entirely). The
## -async-await row forces a suspend per request, which on pipelined
## HTTP/1.1 is the worst case: ordering pauses the pipeline at each
## deferred response. See perf_http2 for the same handler on h2, where
## streams are independent and the cost mostly disappears.
##
## The -chronos / -chronos-await rows are the same two handlers through
## the chronos adapter instead of asyncdispatch, so the two adapters can
## be compared directly (the pure `chronos` row below is chronos's own
## HTTP server, a different codebase, for reference).

import std/[os, osproc, strutils, net, httpcore]
import ../src/vortex
import ../src/vortex/adapters/asyncdispatch as nhsasync
import ./perf_common
from ./perf_srv_std import serveHttpbeast, serveHttpbeastAsync,
                           serveAsynchttpserver
from ./perf_srv_chronos import serveChronos
from ./perf_srv_vortex_chronos import serveOursChronos

const
  benchSeconds {.intdefine.} = 5
  benchConns {.intdefine.} = 32
  benchDepth {.intdefine.} = 8

# --- the servers under test -------------------------------------------------

proc serveOurs(port: int, threads: int, minimal = false) =
  proc handler(req: vortex.Request, res: vortex.Response) {.gcsafe.} =
    vortex.send(res, Http200, "Hello, World!", "text/plain")
  proc minHandler(req: vortex.Request, res: vortex.Response) {.gcsafe.} =
    vortex.send(res, Http200, "Hello, World!")
  var cfg = vortex.initSettings(port = net.Port(port),
                                         numThreads = threads)
  if minimal:
    cfg.serverHeader = ""       # diagnostic: byte-parity with httpbeast
    vortex.run(minHandler, cfg)
  else:
    vortex.run(handler, cfg)

proc serveOursAsync(port: int, doAwait: bool) =
  ## Through the asyncdispatch adapter: measures the future/adapter tax
  ## against the plain inline handler (httpbeast handlers are also
  ## Future-based, making that row directly comparable).
  proc immediate(req: vortex.Request, res: vortex.Response): Future[void] {.async.} =
    vortex.send(res, Http200, "Hello, World!", "text/plain")
  proc suspending(req: vortex.Request, res: vortex.Response): Future[void] {.async.} =
    await sleepAsync(0)                  # force a real suspend/resume
    vortex.send(res, Http200, "Hello, World!", "text/plain")
  let handler = if doAwait: toHandler(suspending) else: toHandler(immediate)
  vortex.run(handler,
    vortex.initSettings(port = net.Port(port), numThreads = 0))

# --- orchestration -----------------------------------------------------------

proc orchestrate() =
  let targets = [
    (name: "vortex", port: 9101),
    (name: "vortex-1thread", port: 9102),
    (name: "vortex-minimal", port: 9106),
    (name: "vortex-async", port: 9107),
    (name: "vortex-async-await", port: 9108),
    (name: "vortex-chronos", port: 9110),
    (name: "vortex-chronos-await", port: 9111),
    (name: "httpbeast", port: 9103),
    (name: "httpbeast-async", port: 9109),
    (name: "asynchttpserver", port: 9104),
    (name: "chronos", port: 9105),
  ]
  echo "HTTP/1.1 plaintext throughput: ", benchConns, " connections, ",
       "pipeline depth ", benchDepth, ", ", benchSeconds, "s per server"
  echo ""
  var results: seq[(string, float)]
  for t in targets:
    let p = startProcess(getAppFilename(),
                         args = ["serve", t.name, $t.port],
                         options = {poParentStreams})
    if not waitReady(t.port):
      echo t.name, ": failed to start"
      p.kill()
      p.close()
      continue
    discard runLoad(h1ClientLoop, t.port, benchConns, 1, benchDepth) # warmup
    let rps = runLoad(h1ClientLoop, t.port, benchConns, benchSeconds, benchDepth)
    results.add (t.name, rps)
    printRow(t.name, rps)
    p.kill()
    p.close()
    sleep(300)
  report(results)

when isMainModule:
  if paramCount() >= 3 and paramStr(1) == "serve":
    let port = parseInt(paramStr(3))
    case paramStr(2)
    of "vortex": serveOurs(port, 0)
    of "vortex-1thread": serveOurs(port, 1)
    of "vortex-minimal": serveOurs(port, 0, minimal = true)
    of "vortex-async": serveOursAsync(port, doAwait = false)
    of "vortex-async-await": serveOursAsync(port, doAwait = true)
    of "vortex-chronos": serveOursChronos(port, doAwait = false)
    of "vortex-chronos-await": serveOursChronos(port, doAwait = true)
    of "httpbeast": serveHttpbeast(port)
    of "httpbeast-async": serveHttpbeastAsync(port)
    of "asynchttpserver": serveAsynchttpserver(port)
    of "chronos": serveChronos(port)
    else: quit "unknown server: " & paramStr(2)
  else:
    orchestrate()
