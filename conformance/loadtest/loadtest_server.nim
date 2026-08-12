## Target server for the k6 load harness (conformance/loadtest/run.sh,
## `nimble loadtest`). TechEmpower-style handlers, the same shape as
## bench/handlers.nim, so k6's numbers line up with the micro-benchmark:
##   /plaintext  -> "Hello, World!"           (tiny, not compressible)
##   /json       -> {"message":"Hello, World!"}
##   /big        -> ~9 KB of text             (compressible; use for the gzip backend)
##
## Two build-time axes, both driven by the Dockerfile from run.sh:
##
## Protocol (BUILD_FLAGS) + runtime env pick the transport:
##   plain build (-d:plainHttp)                       -> h1 (cleartext) on LOADTEST_PORT
##   default build + LOADTEST_TLS=1                    -> h1 + h2 over TLS (ALPN), h3 off
##   + -d:httpGzip --passL:-lz + LOADTEST_COMPRESS=1  -> h2 + gzip response compression
##
## Handler execution model (one -d: flag, set from RUNTIME):
##   sync           plain {.gcsafe.} handler (default; no flag)
##   async          -d:ltAsync         asyncdispatch adapter, no suspend
##   async-await    -d:ltAsyncAwait    asyncdispatch adapter, one await/req
##   chronos        -d:ltChronos       chronos adapter, no suspend
##   chronos-await  -d:ltChronosAwait  chronos adapter, one await/req
## The asyncdispatch and chronos adapters both re-export async/Future/toHandler,
## so only one adapter is imported per build -- a single binary is one runtime.
##
## start() binds before returning, so the "listening" log line is the readiness
## signal run.sh polls for.

import std/[os, strutils]
import vortex

when defined(ltAsync) or defined(ltAsyncAwait):
  import vortex/asyncdispatch
elif defined(ltChronos) or defined(ltChronosAwait):
  import vortex/chronos

const bigBody = "The quick brown fox jumps over the lazy dog. ".repeat(200)  # ~9 KB

template respond(req, res: untyped) =
  ## Shared routing, used by both the sync and the async handler shapes.
  case req.path
  of "/plaintext":
    vortex.send(res, Http200, "Hello, World!")
  of "/json":
    vortex.send(res, Http200, """{"message":"Hello, World!"}""", %*{"Content-Type": "application/json"})
  of "/big":
    vortex.send(res, Http200, bigBody)
  else:
    vortex.send(res, Http404)

when defined(ltAsync) or defined(ltAsyncAwait) or
     defined(ltChronos) or defined(ltChronosAwait):
  proc appHandlerProc(req: vortex.Request,
                      res: vortex.Response): Future[void] {.async.} =
    when defined(ltAsyncAwait):
      await sleepAsync(0)                # asyncdispatch: force a real suspend
    elif defined(ltChronosAwait):
      await sleepAsync(ZeroDuration)     # chronos: force a real suspend
    respond(req, res)
  let appHandler = toHandler(appHandlerProc)
else:
  proc appHandlerProc(req: vortex.Request, res: vortex.Response) {.gcsafe.} =
    respond(req, res)
  let appHandler = RequestHandler(appHandlerProc)

when isMainModule:
  let port = Port(parseInt(getEnv("LOADTEST_PORT", "8080")))
  # numThreads 0 = one loop per core (SO_REUSEPORT), so the server is not the
  # artificial bottleneck. compress only has an effect in an -d:httpGzip build.
  var settings = initVortexConfig(port = port, numThreads = 0,
                              compress = getEnv("LOADTEST_COMPRESS") == "1")
  when not defined(plainHttp):
    if getEnv("LOADTEST_TLS") == "1":
      settings.certFile = "/vortex/cert.pem"
      settings.keyFile = "/vortex/key.pem"
      settings.http3 = false      # k6 is TCP-only (h1/h2); no QUIC listener needed
  let srv = newVortex(appHandler, settings).start()
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
