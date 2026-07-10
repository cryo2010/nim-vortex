## chronos-based comparison server, isolated in its own module:
## asyncdispatch and chronos cannot share a module scope.

import chronos
import chronos/apps/http/httpserver

proc serveChronos*(port: int) =
  proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
    if r.isOk():
      let request = r.get()
      try:
        return await request.respond(Http200, "Hello, World!")
      except CatchableError:
        return defaultResponse()
    else:
      return defaultResponse()
  let server = HttpServerRef.new(
    initTAddress("127.0.0.1", Port(port)), process,
    serverFlags = {HttpServerFlags.Http11Pipeline},
    socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}).get()
  server.start()
  waitFor server.join()
