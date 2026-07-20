## Static file serving over HTTP/1.1: raw sockets so status line, headers and
## body are checked exactly.

import std/[unittest, net, os, strutils]
import vortex/[settings, request, server, router, staticfiles]

let dir = getTempDir() / "vortex_static_" & $getCurrentProcessId()
removeDir(dir)
createDir(dir)
createDir(dir / "sub")
writeFile(dir / "hello.txt", "hello static world")   # 18 bytes
writeFile(dir / "app.css", "body{color:red}")
writeFile(dir / "index.html", "<h1>root index</h1>")
writeFile(dir / "sub" / "index.html", "<h1>sub index</h1>")
writeFile(dir / "data.bin", "0123456789")            # 10 bytes
# a secret outside the served root, for the traversal test
writeFile(dir.parentDir / ("vortex_secret_" & $getCurrentProcessId()), "TOPSECRET")

proc oneFile(path: string): RequestHandler =
  proc (req: Request, res: Response) {.gcsafe.} =
    res.serveFile(path)      # res.serveFile: a specific trusted file

let r = newRouter()
let sh = staticHandler(dir)
r.get("/assets", sh)         # /assets and /assets/ -> directory index
r.get("/assets/*", sh)       # /assets/<path>
r.get("/one", oneFile(dir / "hello.txt"))   # res.serveFile
var srv = start(r.toHandler(),
                initSettings(port = Port(0), numThreads = 1, workerThreads = 2))

proc raw(path: string, extra = ""): string =
  let s = newSocket()
  defer: s.close()
  s.connect("127.0.0.1", srv.port)
  s.send("GET " & path & " HTTP/1.1\r\nHost: h\r\nConnection: close\r\n" &
         extra & "\r\n")
  var chunk = s.recv(65536, timeout = 2000)
  while chunk.len > 0:
    result.add chunk
    chunk = s.recv(65536, timeout = 2000)

proc rawHead(path: string): string =
  let s = newSocket()
  defer: s.close()
  s.connect("127.0.0.1", srv.port)
  s.send("HEAD " & path & " HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
  var chunk = s.recv(65536, timeout = 2000)
  while chunk.len > 0:
    result.add chunk
    chunk = s.recv(65536, timeout = 2000)

proc status(resp: string): string =
  resp.splitLines()[0]

proc headerVal(resp, name: string): string =
  for ln in resp.splitLines():
    if ln.len == 0: break
    let c = ln.find(':')
    if c > 0 and cmpIgnoreCase(ln[0..<c].strip, name) == 0:
      return ln[c+1..^1].strip
  ""

proc bodyOf(resp: string): string =
  let i = resp.find("\r\n\r\n")
  if i >= 0: resp[i+4..^1] else: ""

suite "static file serving":
  test "serves a file with the right type, length and body":
    let resp = raw("/assets/hello.txt")
    check "200" in resp.status
    check resp.headerVal("Content-Type") == "text/plain; charset=utf-8"
    check resp.headerVal("Content-Length") == "18"
    check resp.headerVal("Accept-Ranges") == "bytes"
    check resp.headerVal("ETag").len > 0
    check resp.bodyOf == "hello static world"

  test "MIME from extension":
    check raw("/assets/app.css").headerVal("Content-Type") == "text/css; charset=utf-8"

  test "res.serveFile serves a specific file":
    let resp = raw("/one")
    check "200" in resp.status
    check resp.headerVal("Content-Type") == "text/plain; charset=utf-8"
    check resp.bodyOf == "hello static world"

  test "missing file is 404":
    check "404" in raw("/assets/nope.txt").status

  test "directory serves the index":
    check raw("/assets/").bodyOf == "<h1>root index</h1>"
    check raw("/assets/sub/").bodyOf == "<h1>sub index</h1>"

  test "path traversal is refused":
    let resp = raw("/assets/../vortex_secret_" & $getCurrentProcessId())
    check "404" in resp.status
    check "TOPSECRET" notin resp
    # encoded traversal too
    check "404" in raw("/assets/%2e%2e/etc/passwd").status

  test "conditional GET returns 304 for a matching ETag":
    let etag = raw("/assets/hello.txt").headerVal("ETag")
    let resp = raw("/assets/hello.txt", "If-None-Match: " & etag & "\r\n")
    check "304" in resp.status
    check resp.bodyOf.len == 0

  test "byte range returns 206 with the slice":
    let resp = raw("/assets/data.bin", "Range: bytes=2-5\r\n")
    check "206" in resp.status
    check resp.headerVal("Content-Range") == "bytes 2-5/10"
    check resp.headerVal("Content-Length") == "4"
    check resp.bodyOf == "2345"

  test "suffix range (last N bytes)":
    let resp = raw("/assets/data.bin", "Range: bytes=-3\r\n")
    check "206" in resp.status
    check resp.bodyOf == "789"

  test "unsatisfiable range is 416":
    let resp = raw("/assets/data.bin", "Range: bytes=50-60\r\n")
    check "416" in resp.status
    check resp.headerVal("Content-Range") == "bytes */10"

  test "HEAD has the length but no body":
    let resp = rawHead("/assets/hello.txt")
    check "200" in resp.status
    check resp.headerVal("Content-Length") == "18"
    check resp.bodyOf.len == 0

  test "POST to a static path is 405 with Allow":
    let s = newSocket()
    defer: s.close()
    s.connect("127.0.0.1", srv.port)
    s.send("POST /assets/hello.txt HTTP/1.1\r\nHost: h\r\nConnection: close\r\n" &
           "Content-Length: 0\r\n\r\n")
    var resp = ""
    var chunk = s.recv(65536, timeout = 2000)
    while chunk.len > 0:
      resp.add chunk
      chunk = s.recv(65536, timeout = 2000)
    check "405" in resp.status
    check "GET" in resp.headerVal("Allow")

srv.close()
removeDir(dir)
removeFile(dir.parentDir / ("vortex_secret_" & $getCurrentProcessId()))
echo "static files ok"
