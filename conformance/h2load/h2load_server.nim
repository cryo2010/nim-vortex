## Target server for the h2load stress smoke (conformance/h2load/run.sh,
## `nimble h2load`). h2load hammers it with many concurrent HTTP/1.1 and
## HTTP/2 (h2c prior-knowledge) requests; a trivial always-200 handler on all
## cores is all that's needed. Plain HTTP (a -d:plainHttp build, no OpenSSL).

import std/os
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

when isMainModule:
  # numThreads 0 = one loop per core (SO_REUSEPORT). start() binds before
  # returning, so the "listening" log line is the readiness signal for run.sh.
  var srv = start(RequestHandler(handler),
                  initSettings(port = Port(8080), numThreads = 0))
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
