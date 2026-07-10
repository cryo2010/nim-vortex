## asyncdispatch-based comparison servers (httpbeast, std/asynchttpserver),
## isolated in their own module: asyncdispatch and chronos cannot share a
## module scope (both export `async` and `Future`).

import std/[options, httpcore, net, asyncdispatch, asynchttpserver]
import httpbeast

proc serveHttpbeast*(port: int) =
  ## Note: this handler returns a nil Future (not {.async.}, result never
  ## assigned), which httpbeast detects and short-circuits: its future
  ## machinery is skipped entirely. Compare with the inline
  ## nim_http_server rows, not the -async ones.
  proc onRequest(req: httpbeast.Request): Future[void] =
    if req.httpMethod == some(HttpGet):
      req.send("Hello, World!")
  httpbeast.run(onRequest, httpbeast.initSettings(port = Port(port)))

proc serveHttpbeastAsync*(port: int) =
  ## A real {.async.} handler: allocates and completes a future per
  ## request. The fair peer of the nim_http_server-async row.
  proc onRequest(req: httpbeast.Request): Future[void] {.async.} =
    if req.httpMethod == some(HttpGet):
      req.send("Hello, World!")
  httpbeast.run(onRequest, httpbeast.initSettings(port = Port(port)))

proc serveAsynchttpserver*(port: int) =
  var server = newAsyncHttpServer()
  proc cb(req: asynchttpserver.Request) {.async.} =
    await req.respond(Http200, "Hello, World!",
      newHttpHeaders({"Content-Type": "text/plain"}))
  waitFor server.serve(Port(port), cb)
