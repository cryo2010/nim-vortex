## req.blocking(a, b, ...): values named in the call are moved into the worker
## and usable by name inside the block (sync form: the block sends the response).

import std/[unittest, net]
import std/httpclient except Response
import vortex

proc one(req: Request, res: Response) {.gcsafe.} =
  let id = req.param("id")
  req.blocking(id):                          # single value moved in
    res.send(Http200, "id=" & id)

proc multi(req: Request, res: Response) {.gcsafe.} =
  let id = req.param("id")
  let n = 3
  let flag = true
  req.blocking(id, n, flag):                  # several values, mixed types
    res.send(Http200, id & "|" & $(n * 2) & "|" & $flag)

proc none(req: Request, res: Response) {.gcsafe.} =
  req.blocking:                               # no values: still runs on a worker
    res.send(Http200, "plain")

var app = newVortex()
app.get("/one/:id", one)
app.get("/multi/:id", multi)
app.get("/none", none)

let srv = app.start(0, config = initVortexConfig(numThreads = 1))
let base = "http://127.0.0.1:" & $srv.port

suite "req.blocking variadic args (sync)":
  test "single value moved in, usable by name":
    var c = newHttpClient(); defer: c.close()
    check c.getContent(base & "/one/42") == "id=42"

  test "several values of mixed types moved in":
    var c = newHttpClient(); defer: c.close()
    check c.getContent(base & "/multi/abc") == "abc|6|true"

  test "no values still dispatches to a worker":
    var c = newHttpClient(); defer: c.close()
    check c.getContent(base & "/none") == "plain"

srv.close()
echo "blocking args ok"
