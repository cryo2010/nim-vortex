## Target server for the k6 stress harness (conformance/stress/run.sh,
## `nimble stress`). TechEmpower-style handlers, the same shape as
## bench/handlers.nim, so k6's numbers line up with the micro-benchmark:
##   /plaintext  -> "Hello, World!"           (tiny, not compressible)
##   /json       -> {"message":"Hello, World!"}
##   /big        -> ~9 KB of text             (compressible; use for the gzip backend)
##
## One source builds every k6-drivable backend: the build flags pick the
## protocol surface and the env vars pick the runtime settings.
##   plain build (-d:plainHttp)                    -> h1 (cleartext) on STRESS_PORT
##   default build + STRESS_TLS=1                   -> h1 + h2 over TLS (ALPN), h3 off
##   + -d:httpGzip --passL:-lz + STRESS_COMPRESS=1 -> h2 + gzip response compression
##
## start() binds before returning, so the "listening" log line is the readiness
## signal run.sh polls for.

import std/[os, strutils]
import vortex

const bigBody = "The quick brown fox jumps over the lazy dog. ".repeat(200)  # ~9 KB

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/plaintext":
    res.send(Http200, "Hello, World!", "text/plain")
  of "/json":
    res.send(Http200, """{"message":"Hello, World!"}""", "application/json")
  of "/big":
    res.send(Http200, bigBody, "text/plain")
  else:
    res.send(Http404)

when isMainModule:
  let port = Port(parseInt(getEnv("STRESS_PORT", "8080")))
  # numThreads 0 = one loop per core (SO_REUSEPORT), so the server is not the
  # artificial bottleneck. compress only has an effect in an -d:httpGzip build.
  var settings = initSettings(port = port, numThreads = 0,
                              compress = getEnv("STRESS_COMPRESS") == "1")
  when not defined(plainHttp):
    if getEnv("STRESS_TLS") == "1":
      settings.certFile = "/vortex/cert.pem"
      settings.keyFile = "/vortex/key.pem"
      settings.http3 = false      # k6 is TCP-only (h1/h2); no QUIC listener needed
  var srv = start(RequestHandler(handler), settings)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
