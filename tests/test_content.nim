## Request-side helpers: req.form (application/x-www-form-urlencoded parsing) and
## content negotiation (req.accepts / acceptsLanguage over Accept headers).

import std/[unittest, net, tables]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

proc hForm(req: Request, res: Response) {.gcsafe.} =
  let f = req.form
  res.send(Http200, f.getOrDefault("name") & "|" & f.getOrDefault("q"))

proc hAccept(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, req.accepts("application/json", "text/html"))

proc hLang(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, req.acceptsLanguage("en-US", "fr"))

var rt = newRouter()
rt.post("/form", hForm)
rt.get("/accept", hAccept)
rt.get("/lang", hLang)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

proc postForm(path, body: string): string =
  var c = newHttpClient(); defer: c.close()
  c.headers = newHttpHeaders({"Content-Type": "application/x-www-form-urlencoded"})
  c.postContent(base & path, body)

proc getWith(path, header, value: string): string =
  var c = newHttpClient(); defer: c.close()
  c.headers = newHttpHeaders({header: value})
  c.getContent(base & path)

suite "req.form (x-www-form-urlencoded)":
  test "fields are decoded, + is a space":
    check postForm("/form", "name=alice&q=hello+world") == "alice|hello world"

  test "percent-encoding is decoded":
    check postForm("/form", "name=a%20b&q=%40") == "a b|@"

  test "a non-form content type yields no fields":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({"Content-Type": "application/json"})
    check c.postContent(base & "/form", "name=alice") == "|"

suite "content negotiation (Accept)":
  test "highest q wins":
    check getWith("/accept", "Accept",
                  "text/html;q=0.8, application/json;q=0.9") == "application/json"

  test "type/* wildcard matches an offered subtype":
    check getWith("/accept", "Accept", "text/*") == "text/html"

  test "*/* falls to server preference (first offered)":
    check getWith("/accept", "Accept", "*/*") == "application/json"

  test "nothing acceptable returns empty":
    check getWith("/accept", "Accept", "image/png") == ""

suite "content negotiation (Accept-Language)":
  test "exact tag is chosen":
    check getWith("/lang", "Accept-Language", "fr, en-US;q=0.5") == "fr"

  test "a range matches a more specific offered tag":
    check getWith("/lang", "Accept-Language", "en") == "en-US"  # en matches en-US

srv.close()
echo "content ok"
