## Router features: automatic OPTIONS (Allow header), duplicate-route detection
## (fail hard at registration), and that an explicit OPTIONS handler wins.

import std/[unittest, net, httpcore, strutils]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

proc hRoot(req: Request, res: Response) {.gcsafe.} = res.send(Http200, "root")
proc hCreate(req: Request, res: Response) {.gcsafe.} = res.send(Http201, "made")

var rt = newRouter()
rt.get("/thing", hRoot)
rt.post("/thing", hCreate)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

suite "router: automatic OPTIONS":
  test "OPTIONS on a known path is 204 with Allow listing the methods":
    var c = newHttpClient(); defer: c.close()
    let r = c.request(base & "/thing", HttpOptions)
    check r.code == Http204
    let allow = $r.headers["allow"]       # joined form; [] returns a seq view
    check "GET" in allow
    check "POST" in allow
    check "OPTIONS" in allow
    check "HEAD" in allow                 # HEAD is served wherever GET is

  test "405 on a known path lists OPTIONS in Allow":
    var c = newHttpClient(); defer: c.close()
    let r = c.request(base & "/thing", HttpDelete)
    check r.code == Http405
    check "OPTIONS" in $r.headers["allow"]

  test "OPTIONS on an unknown path is 404":
    var c = newHttpClient(); defer: c.close()
    check c.request(base & "/nope", HttpOptions).code == Http404

srv.close()

suite "router: explicit OPTIONS wins over automatic":
  test "a registered OPTIONS handler is used instead of the auto 204":
    var r2 = newRouter()
    r2.get("/x", hRoot)
    r2.options("/x", proc(req: Request, res: Response) {.gcsafe.} =
      res.send(Http200, "custom-options"))
    var s2 = newVortex(r2.toHandler, initVortexConfig(numThreads = 1)).start(0)
    defer: s2.close()
    var c = newHttpClient(); defer: c.close()
    let r = c.request("http://127.0.0.1:" & $s2.port & "/x", HttpOptions)
    check r.code == Http200
    check r.body == "custom-options"

suite "router: duplicate-route detection":
  test "same method+path registered twice raises RouteConflictError":
    var r3 = newRouter()
    r3.get("/dup", hRoot)
    expect RouteConflictError:
      r3.get("/dup", hRoot)

  test "the same path with different methods is allowed":
    var r4 = newRouter()
    r4.get("/multi", hRoot)
    r4.post("/multi", hCreate)            # must not raise
    check true

  test "a mounted route colliding with a parent route fails hard":
    var child = newRouter()
    child.get("/", hRoot)
    var parent = newRouter()
    parent.get("/users", hRoot)           # collides with child "/" at /users
    expect RouteConflictError:
      parent.use("/users", child)

echo "router features ok"
