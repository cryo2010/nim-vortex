## Minimal demo server using the asyncdispatch adapter. Run it, then
## poke it from another terminal:
##
##   nim c -r --mm:orc --threads:on demos/minimal.nim
##
##   curl http://localhost:8080/
##   curl http://localhost:8080/hello/you
##   curl -X POST -d 'some data' http://localhost:8080/echo
##   curl http://localhost:8080/slow      # awaits without blocking the loop
##   curl http://localhost:8080/report    # sync work on the worker pool
##   curl -s --http2-prior-knowledge http://localhost:8080/   # HTTP/2
##
## Ctrl-C stops the server.

import std/os
import ../src/vortex
import ../src/vortex/adapters/asyncdispatch

proc hRoot(req: Request, res: Response, params: PathParams) {.async.} =
  res.send(Http200, "Hello, World!\n", "text/plain")

proc hHello(req: Request, res: Response, params: PathParams) {.async.} =
  let name = params.param("name")        # captures are fine in async bodies
  await sleepAsync(10)
  res.send(Http200, "Hello, " & name & "!\n", "text/plain")

proc hEcho(req: Request, res: Response, params: PathParams) {.async.} =
  res.send(Http200, "you sent (" & $req.method & "): " & req.body & "\n",
              "text/plain")

proc hSlow(req: Request, res: Response, params: PathParams) {.async.} =
  await sleepAsync(1000)                 # loop keeps serving other requests
  res.send(Http200, "that took a second\n", "text/plain")

proc hReport(req: Request, res: Response, params: PathParams) {.async.} =
  req.blocking:                          # synchronous escape: worker pool
    sleep(500)                           # stands in for a sync DB/file call
    res.send(Http200, "report built on a worker thread\n", "text/plain")

var router = newRouter()
router.get("/", hRoot)
router.get("/hello/:name", hHello)
router.post("/echo", hEcho)
router.get("/slow", hSlow)
router.get("/report", hReport)

echo "listening on http://localhost:8080  (Ctrl-C to stop)"
run(router.toHandler, initSettings(port = Port(8080)))
