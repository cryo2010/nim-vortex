## Minimal demo server. Run it, then poke it from another terminal:
##
##   nim c -r --mm:orc --threads:on demos/minimal.nim
##
##   curl http://localhost:8080/
##   curl http://localhost:8080/hello/you
##   curl -X POST -d 'some data' http://localhost:8080/echo
##   curl -s --http2-prior-knowledge http://localhost:8080/   # HTTP/2
##
## Ctrl-C stops the server.

import std/os
import ../src/nim_http_server

proc hRoot(req: Request, params: PathParams) {.gcsafe.} =
  req.respond(Http200, "Hello, World!\n", "text/plain")

proc hHello(req: Request, params: PathParams) {.gcsafe.} =
  req.respond(Http200, "Hello, " & params.param("name") & "!\n", "text/plain")

proc hEcho(req: Request, params: PathParams) {.gcsafe.} =
  req.respond(Http200, "you sent (" & $req.method & "): " & req.body & "\n",
              "text/plain")

proc hSlow(req: Request, params: PathParams) {.gcsafe.} =
  req.blocking:                     # runs on the worker pool
    sleep(1000)                     # blocking calls are safe here
    req.respond(Http200, "that took a second\n", "text/plain")

var router = newRouter()
router.get("/", hRoot)
router.get("/hello/:name", hHello)
router.post("/echo", hEcho)
router.get("/slow", hSlow)

echo "listening on http://localhost:8080  (Ctrl-C to stop)"
run(router.toHandler, initSettings(port = Port(8080)))
