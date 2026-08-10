## powpow comparison server (openpeeps/powpow), isolated in its own module.
## powpow is an event-driven Nim networking library with a built-in HTTP/1.1
## server. Its multi-thread mode runs one event loop per worker over
## SO_REUSEPORT listeners -- the same architecture as vortex -- so it is the
## fair all-cores peer; `servePowpow1` is the single-loop variant that lines up
## with `vortex-1thread`.

import std/[net, httpcore]
import powpow

proc powHandler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  res.status(Http200).header("Content-Type", "text/plain").send("Hello, World!")

proc servePowpow*(port: int) =
  ## All-cores multi-thread server (numThreads = 0 -> countProcessors()).
  let server = newMultiThreadHttpServer()
  server.start(powHandler, "127.0.0.1", port)

proc servePowpow1*(port: int) =
  ## Single event-loop server.
  let server = newHttpServer()
  server.start(powHandler, net.Port(port))
