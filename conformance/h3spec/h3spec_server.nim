## Minimal HTTP/3 server under test for the h3spec conformance run. h3spec
## drives the QUIC/HTTP/3 error cases (control-stream validation, malformed
## requests, QPACK stream errors), so a trivial always-200 handler is all it
## needs. Built into a Docker image by conformance/h3spec/Dockerfile.

import std/os
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

when isMainModule:
  # HTTP/3 over QUIC on UDP 4433; a throwaway self-signed cert (h3spec runs
  # with --no-validate). start() binds before returning, so the "listening"
  # log line is the readiness signal for run.sh.
  var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = "/vortex/cert.pem", keyFile = "/vortex/key.pem", http3 = true)).start(4433)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
