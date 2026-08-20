## Compile-time guard on the values crossing into req.blocking: value data is
## allowed, a ref/ptr/closure (top-level or nested) is rejected, and a uniquely-
## owned reference may cross when wrapped in isolate(...).

import std/[unittest, net]
import std/httpclient except Response
import vortex

type
  Session = ref object
    id: int
  Cfg = object                 # pure value object
    limit: int
    name: string
  Wrap = object                # value object holding a ref
    s: Session

proc valueH(req: Request, res: Response) {.gcsafe.} =
  let cfg = Cfg(limit: 5, name: "cfg")
  req.blocking(cfg):                       # value object -> copied to the worker
    res.send(Http200, cfg.name & ":" & $cfg.limit)

proc isoH(req: Request, res: Response) {.gcsafe.} =
  var s = isolate(Session(id: 42))         # uniquely-owned ref, proven isolated
  req.blocking(s):                         # allowed; `s` is a Session in the block
    res.send(Http200, "id=" & $s.id)

var app = newVortex()
app.get("/value", valueH)
app.get("/iso", isoH)
let srv = app.start(0, config = initVortexConfig(numThreads = 1))
let base = "http://127.0.0.1:" & $srv.port

suite "req.blocking value guard":
  test "value object crosses and is usable":
    var c = newHttpClient(); defer: c.close()
    check c.getContent(base & "/value") == "cfg:5"

  test "isolate() lets a uniquely-owned ref cross, extracted to the plain type":
    var c = newHttpClient(); defer: c.close()
    check c.getContent(base & "/iso") == "id=42"

  test "a bare ref argument is rejected at compile time":
    check not compiles(
      (proc (req: Request, res: Response) {.gcsafe.} =
        let s = Session(id: 1)
        req.blocking(s):
          res.send(Http200, $s.id)))

  test "a value object with a ref field is rejected at compile time":
    check not compiles(
      (proc (req: Request, res: Response) {.gcsafe.} =
        let w = Wrap(s: Session(id: 1))
        req.blocking(w):
          res.send(Http200, $w.s.id)))

  test "a plain value object still compiles":
    check compiles(
      (proc (req: Request, res: Response) {.gcsafe.} =
        let cfg = Cfg(limit: 1, name: "x")
        req.blocking(cfg):
          res.send(Http200, cfg.name)))

srv.close()
echo "blocking guard ok"
