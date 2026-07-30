## ThreadSanitizer regression for the handler/stream-route closure race.
##
## `start()` copies its handler into every per-core loop thread. If the handler
## is a traced closure (router.toHandler, or a middleware wrapping it), each
## loop thread would incref/decref one shared closure environment concurrently,
## racing its non-atomic ORC refcount -- a rare corruption that surfaced as an
## intermittent SIGSEGV under load. The fix stores the handler as a raw
## (proc, env) pair on the loop (connection.RawClosure), keeping all refcounting
## on the main thread.
##
## Built and run under TSan by `nimble testrace`; TSan aborts (non-zero) on any
## data race, failing the task. -d:plainHttp keeps OpenSSL out of the report.
## Uses the worst case on purpose: a middleware closure wrapping toHandler (a
## closure capturing a closure) and many loop threads, cycled to hammer the
## startup/shutdown refcount windows.

import vortex
import std/os

proc ok(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

proc withGate(inner: RequestHandler): RequestHandler =
  let h = inner
  proc (req: Request, res: Response) {.gcsafe.} =
    if req.header("x-block") == "1": res.send(Http403)
    else: h(req, res)

when isMainModule:
  for i in 0 ..< 50:
    var router = newRouter()
    router.get("/", ok)
    router.stream(HttpPost, "/upload", ok)   # also crosses streamRoute per loop
    var srv = start(withGate(router.toHandler),
                    initSettings(port = Port(0), numThreads = 8, reusePort = true))
    srv.close()                              # concurrent decrefs at shutdown
  echo "thread race regression ok"
