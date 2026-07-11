## Server under test for the h2spec HTTP/2 conformance run. h2spec drives
## the framing/HPACK/flow-control behavior of the connection itself, so a
## trivial always-200 handler over TLS (HTTP/2 via ALPN) is all it needs.

import std/os
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

when isMainModule:
  # TLS on (ALPN negotiates h2); HTTP/3 off so no UDP/QUIC listener is
  # needed for this TCP-only check. start() binds before returning, so the
  # "listening" log line is a reliable readiness signal for run.sh.
  var srv = start(RequestHandler(handler),
                  initSettings(port = Port(8443), numThreads = 1,
                               certFile = "/vortex/cert.pem",
                               keyFile = "/vortex/key.pem",
                               http3 = false))
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
