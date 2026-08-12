## Target server for the testssl.sh TLS scan (conformance/testssl/run.sh,
## `nimble testssl`). testssl.sh probes the TLS handshake -- protocol versions,
## cipher suites, and known vulnerabilities -- so a trivial always-200 handler
## over TLS is all it needs. HTTP/3 is off (TCP-only scan); the cert is the
## throwaway self-signed one baked into the image.

import std/os
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

when isMainModule:
  # start() binds before returning, so the "listening" log line is the
  # readiness signal for run.sh.
  var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = "/vortex/cert.pem", keyFile = "/vortex/key.pem", http3 = false)).start(8443)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
