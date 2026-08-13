## newVortex() returns an app (router): register routes, then serve/start.
## start/serve build the server and wire the streaming predicate automatically.

import std/[unittest, net]
import std/httpclient except Response
import vortex

proc hello(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "hi " & req.param("id"))

proc up(req: Request, res: Response) {.gcsafe.} =
  var total = 0
  req.onBody proc(chunk: openArray[char], last: bool) {.gcsafe.} =
    total += chunk.len
    if last: res.send(Http200, $total)     # only fires if dispatched as streaming

var app = newVortex()
app.get("/users/:id", hello)
app.post("/up", up, streaming = true)

let srv = app.start(0, config = initVortexConfig(numThreads = 1))  # non-blocking
let base = "http://127.0.0.1:" & $srv.port

suite "newVortex() app entry":
  test "app.get + start serves, params work":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/users/7") == "hi 7"

  test "streaming route is auto-wired by start (onBody fires)":
    var c = newHttpClient()
    defer: c.close()
    check c.postContent(base & "/up", "hello") == "5"

srv.close()
echo "app entry ok"
