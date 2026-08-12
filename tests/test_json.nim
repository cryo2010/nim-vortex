## JSON helpers: req.json (lazy-parsed + cached, empty body -> {}, raises on
## malformed) and res.send(json) (stringified, Content-Type application/json).

import std/[unittest, json, tables, strutils, osproc, os, net]
import std/httpclient except Response
import vortex/[settings, request, server, routing]
import ./helper

proc echoJson(req: Request, res: Response) {.gcsafe.} =
  # Repeated req.json access exercises the per-request cache (one parse).
  let name = req.json{"name"}.getStr("")
  let age = req.json{"age"}.getInt(0)
  res.send(Http200, %*{"hello": name, "age": age})

proc emptyOut(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, $req.json)          # empty body -> {}

proc tableOut(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, %{"a": "1", "b": "2"}.toTable)     # % converts a Table

type
  Widget = object
    id: int
    tags: seq[string]
  Level = enum lLow, lHigh

proc objOut(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, Widget(id: 7, tags: @["a", "b"]))  # object -> JSON directly

proc tupleOut(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, (ok: true, count: 3))              # named tuple -> JSON object

proc seqOut(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, @[1, 2, 3])                        # seq -> JSON array

proc enumOut(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, lHigh)                             # enum -> JSON string

proc ctOverride(req: Request, res: Response) {.gcsafe.} =
  # a Content-Type in headers overrides the application/json default
  res.send(Http200, Widget(id: 1, tags: @[]),
           %*{"Content-Type": "application/vnd.api+json"})

var rt = newRouter()
rt.post("/echo", echoJson)
rt.get("/empty", emptyOut)
rt.get("/table", tableOut)
rt.get("/obj", objOut)
rt.get("/tuple", tupleOut)
rt.get("/seq", seqOut)
rt.get("/enum", enumOut)
rt.get("/ct", ctOverride)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

suite "json helpers":
  test "req.json parses body; res.send(json) sets application/json":
    var c = newHttpClient()
    defer: c.close()
    let r = c.post(base & "/echo", $ %*{"name": "ada", "age": 36})
    check r.code == Http200
    check "application/json" in r.headers["content-type"]
    check r.body == """{"hello":"ada","age":36}"""

  test "empty body parses as {}":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/empty") == "{}"

  test "res.send accepts a Table via %":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/table") == """{"a":"1","b":"2"}"""

  test "res.send serializes object/seq/enum, defaulting to application/json":
    var c = newHttpClient()
    defer: c.close()
    let r = c.get(base & "/obj")
    check "application/json" in r.headers["content-type"]
    check r.body == """{"id":7,"tags":["a","b"]}"""
    check c.getContent(base & "/seq") == "[1,2,3]"
    check c.getContent(base & "/enum") == "\"lHigh\""

  test "res.send accepts a named tuple as a JSON object":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/tuple") == """{"ok":true,"count":3}"""

  test "a Content-Type in headers overrides the application/json default":
    var c = newHttpClient()
    defer: c.close()
    check "application/vnd.api+json" in c.get(base & "/ct").headers["content-type"]

  test "malformed body: req.json raises -> 500 (not auto-400)":
    var c = newHttpClient()
    defer: c.close()
    check c.post(base & "/echo", "{not json").code == Http500

  test "req.json + res.send(json) over HTTP/2 (h2c)":
    let (output, rc) = execCmdEx(
      "curl -s --http2-prior-knowledge -w '|%{http_code}|%{http_version}' " &
      "-d '{\"name\":\"grace\",\"age\":45}' " & base & "/echo")
    check rc == 0
    check output.strip() == """{"hello":"grace","age":45}|200|2"""

srv.close()
echo "json helpers ok"
