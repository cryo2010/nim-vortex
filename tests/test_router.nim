import std/[unittest, net, httpcore]
import std/httpclient except Response
import vortex/[settings, request, server, router]

proc hRoot(req: Request, res: Response, params: PathParams) {.gcsafe.} =
  res.send(Http200, "root", "text/plain")

proc hUsers(req: Request, res: Response, params: PathParams) {.gcsafe.} =
  res.send(Http200, "user=" & params.param("id"), "text/plain")

proc hUserPosts(req: Request, res: Response, params: PathParams) {.gcsafe.} =
  res.send(Http200,
    "user=" & params.param("id") & " post=" & params.param("post"),
    "text/plain")

proc hStatic(req: Request, res: Response, params: PathParams) {.gcsafe.} =
  res.send(Http200, "file=" & params.param("*"), "text/plain")

proc hCreate(req: Request, res: Response, params: PathParams) {.gcsafe.} =
  res.send(Http201, "created:" & req.body, "text/plain")

var appRouter = newRouter()
appRouter.get("/", hRoot)
appRouter.get("/users/:id", hUsers)
appRouter.get("/users/{id}/posts/{post}", hUserPosts)
appRouter.get("/static/*", hStatic)
appRouter.post("/users", hCreate)

var srv = start(appRouter.toHandler,
                initSettings(port = Port(0), numThreads = 1))
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

  test "POST route":
    var client = newHttpClient()
    defer: client.close()
    let resp = client.post(base & "/users", body = "bob")
    check resp.code == Http201
    check resp.body == "created:bob"

srv.close()
echo "server shut down cleanly"
