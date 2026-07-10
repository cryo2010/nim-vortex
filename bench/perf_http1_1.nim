## HTTP/1.1 throughput comparison: nim_http_server vs httpbeast,
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
## by design; nim_http_server is also shown pinned to one thread for a
## like-for-like comparison.

import std/[os, osproc, strutils, net, httpcore]
import ../src/nim_http_server
import ./perf_common
from ./perf_srv_std import serveHttpbeast, serveAsynchttpserver
from ./perf_srv_chronos import serveChronos

const
  benchSeconds {.intdefine.} = 5
  benchConns {.intdefine.} = 32
  benchDepth {.intdefine.} = 8

# --- the servers under test -------------------------------------------------

proc serveOurs(port: int, threads: int, minimal = false) =
  proc handler(req: nim_http_server.Request) {.gcsafe.} =
    nim_http_server.respond(req, Http200, "Hello, World!", "text/plain")
  proc minHandler(req: nim_http_server.Request) {.gcsafe.} =
    nim_http_server.respond(req, Http200, "Hello, World!")
  var cfg = nim_http_server.initSettings(port = net.Port(port),
                                         numThreads = threads)
  if minimal:
    cfg.serverHeader = ""       # diagnostic: byte-parity with httpbeast
    nim_http_server.run(minHandler, cfg)
  else:
    nim_http_server.run(handler, cfg)

# --- orchestration -----------------------------------------------------------

proc orchestrate() =
  let targets = [
    (name: "nim_http_server", port: 9101),
    (name: "nim_http_server-1thread", port: 9102),
    (name: "nim_http_server-minimal", port: 9106),
    (name: "httpbeast", port: 9103),
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
    of "nim_http_server": serveOurs(port, 0)
    of "nim_http_server-1thread": serveOurs(port, 1)
    of "nim_http_server-minimal": serveOurs(port, 0, minimal = true)
    of "httpbeast": serveHttpbeast(port)
    of "asynchttpserver": serveAsynchttpserver(port)
    of "chronos": serveChronos(port)
    else: quit "unknown server: " & paramStr(2)
  else:
    orchestrate()
