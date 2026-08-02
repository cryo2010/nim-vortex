## Minimal HTTP/1.1 server under test for the h1spec conformance run. h1spec
## drives request-line, header, body, and connection semantics over plain
## TCP, so a trivial always-200 handler is all it needs -- and no TLS, so
## this is a zero-dependency -d:plainHttp build. Built into a Docker image by
## conformance/h1spec/Dockerfile.

import std/os
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

when isMainModule:
  # Plain HTTP/1.1 on 8080. start() binds before returning, so the
  # "listening" log line is the readiness signal for run.sh.
  var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1)).start(8080)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
