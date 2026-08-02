## Target HTTP/3 server for the h3load throughput test (conformance/h3load/
## run.sh, `nimble h3load`). h2load, built with HTTP/3 (ngtcp2 + nghttp3),
## drives many concurrent QUIC connections and streams at it; a trivial
## always-200 handler on every core is all that is needed. Built into a Docker
## image by conformance/h3load/Dockerfile.

import std/os
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

when isMainModule:
  # HTTP/3 over QUIC on UDP 4433 with a throwaway self-signed cert (the client
  # runs without verification). numThreads 0 = one event loop per core, each
  # with its own SO_REUSEPORT UDP listener; the kernel hashes each QUIC 4-tuple
  # to one loop, so a connection's packets stay on a single loop. start() binds
  # before returning, so the "listening" log line is the readiness signal for
  # run.sh.
  var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 0, certFile = "/vortex/cert.pem", keyFile = "/vortex/key.pem", http3 = true)).start(4433)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
