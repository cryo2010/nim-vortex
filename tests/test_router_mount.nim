## Router composition: parent.use(prefix, childRouter) mounts a child router's
## routes under a path prefix, carrying over :params and scoping the child's
## own middleware to just its routes.

import std/[unittest, net, tables]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

proc tagChild(next: RequestHandler): RequestHandler =
  let inner = next
  proc(req: Request, res: Response) {.gcsafe.} =
    res.headers["X-Scope"] = "child"      # should ride only mounted routes
    inner(req, res)

proc tagAll(next: RequestHandler): RequestHandler =
  let inner = next
  proc(req: Request, res: Response) {.gcsafe.} =
    res.headers["X-App"] = "yes"          # parent middleware wraps everything
    inner(req, res)

# child router: paths relative to its own root
var users = newRouter()
users.use(tagChild)
users.get("/", proc(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "user list"))
users.get("/:id", proc(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "user " & req.param("id")))

var api = newRouter()
api.get("/ping", proc(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "pong"))

# parent
var root = newRouter()
root.use(tagAll)
root.get("/", proc(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "home"))
root.use("/users", users)     # mount
root.use("/api/v1", api)      # mount under a multi-segment prefix

var srv = newVortex(root.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

suite "router composition (use prefix)":
  test "mounted routes are reachable under the prefix, params carry over":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/users") == "user list"       # child "/" -> /users
    check c.getContent(base & "/users/42") == "user 42"      # child "/:id"
    check c.getContent(base & "/api/v1/ping") == "pong"      # multi-segment prefix

  test "parent's own routes still work":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/") == "home"

  test "child middleware is scoped to the mounted subtree":
    var c = newHttpClient()
    defer: c.close()
    # mounted route: both parent (tagAll) and child (tagChild) middleware ran
    let mounted = c.get(base & "/users/1")
    check mounted.headers["x-app"] == "yes"
    check mounted.headers["x-scope"] == "child"
    # parent's own route: parent middleware only, no child scope leak
    let own = c.get(base & "/")
    check own.headers["x-app"] == "yes"
    check "x-scope" notin own.headers.table

  test "unmatched under a prefix falls through to the parent 404":
    var c = newHttpClient()
    defer: c.close()
    check c.get(base & "/users/1/extra").code == Http404

srv.close()
echo "router mount ok"
