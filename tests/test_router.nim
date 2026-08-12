import std/[unittest, net, httpcore]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

proc hRoot(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "root")

proc hUsers(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "user=" & req.param("id"))

proc hUserPosts(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200,
    "user=" & req.param("id") & " post=" & req.param("post"))

proc hStatic(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "file=" & req.param("*"))

proc hCreate(req: Request, res: Response) {.gcsafe.} =
  res.send(Http201, "created:" & req.body)

proc hSlowUser(req: Request, res: Response) {.gcsafe.} =
  req.blocking:
    # Route params are per-request state, so they survive into
    # capture-free worker bodies (impossible with parameter passing).
    res.send(Http200, "worker user=" & req.param("id"))

var appRouter = newRouter()
appRouter.get("/slow-users/:id", hSlowUser)
appRouter.get("/", hRoot)
appRouter.get("/users/:id", hUsers)
appRouter.get("/users/{id}/posts/{post}", hUserPosts)
appRouter.get("/static/*", hStatic)
appRouter.post("/users", hCreate)

var srv = newVortex(appRouter.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

proc fetch(path: string): (HttpCode, string) =
  var client = newHttpClient()
  defer: client.close()
  let resp = client.get(base & path)
  (resp.code, resp.body)

suite "router":
  test "root":
    check fetch("/") == (Http200, "root")

  test "path param":
    check fetch("/users/42") == (Http200, "user=42")

  test "multiple params":
    check fetch("/users/7/posts/99") == (Http200, "user=7 post=99")

  test "wildcard":
    check fetch("/static/css/site.css") == (Http200, "file=css/site.css")

  test "query string stripped":
    check fetch("/users/5?full=1") == (Http200, "user=5")

  test "404 for unknown path":
    check fetch("/missing")[0] == Http404

  test "405 for wrong method":
    check fetch("/users")[0] == HttpCode(405)   # only POST is routed

  test "405 carries an Allow header":
    var client = newHttpClient()
    defer: client.close()
    let resp = client.get(base & "/users")     # GET on a POST-only resource
    check resp.code == HttpCode(405)
    check resp.headers.hasKey("Allow")
    check "POST" in resp.headers["Allow"]

  test "HEAD falls back to GET":
    var client = newHttpClient()
    defer: client.close()
    let resp = client.request(base & "/users/42", httpMethod = HttpHead)
    check resp.code == Http200                  # no explicit HEAD route
    check resp.body.len == 0                     # HEAD body suppressed

  test "percent-encoded param is decoded":
    check fetch("/users/a%2Fb") == (Http200, "user=a/b")
    check fetch("/users/j%6Fhn") == (Http200, "user=john")

  test "params readable from a blocking: body":
    check fetch("/slow-users/9") == (Http200, "worker user=9")

  test "POST route":
    var client = newHttpClient()
    defer: client.close()
    let resp = client.post(base & "/users", body = "bob")
    check resp.code == Http201
    check resp.body == "created:bob"

srv.close()
echo "server shut down cleanly"
