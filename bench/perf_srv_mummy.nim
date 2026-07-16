## mummy comparison server (guzba/mummy), isolated in its own module. mummy is
## a multithreaded, blocking-handler Nim server -- the closest architectural
## peer to vortex's `blocking:` model, so it's a fair throughput comparison for
## a trivial handler. Its handlers run on a worker-thread pool.

import std/net
import mummy

proc serveMummy*(port: int) =
  proc handler(request: Request) {.gcsafe.} =
    var headers: HttpHeaders
    headers["Content-Type"] = "text/plain"
    request.respond(200, headers, "Hello, World!")
  let server = newServer(handler)
  server.serve(Port(port), "127.0.0.1")
