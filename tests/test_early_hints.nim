## 103 Early Hints (res.earlyHints / res.informational): a 1xx HEADERS block is
## delivered before the final response, over HTTP/1.1 (raw bytes) and HTTP/2
## (an informational HEADERS frame, no END_STREAM, then the 200).

import std/[unittest, net, strutils, httpcore]
import vortex/[settings, request, server, routing]
import vortex/http2/frames
import ./h2client

proc page(req: Request, res: Response) {.gcsafe.} =
  res.earlyHints(["</app.css>; rel=preload; as=style"])
  res.earlyHints(["<https://cdn.example>; rel=preconnect"])   # a second hint
  res.send(Http200, "PAGE")

let rt = newRouter()
rt.get("/", page)
var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)

suite "103 Early Hints over HTTP/1.1":
  test "the 103 (with Link) precedes the 200, body intact":
    let s = newSocket()
    defer: s.close()
    s.connect("127.0.0.1", srv.port)
    s.send("GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
    var resp: string
    var chunk = s.recv(65536, timeout = 2000)
    while chunk.len > 0:
      resp.add chunk
      chunk = s.recv(65536, timeout = 2000)
    check "103 Early Hints" in resp
    check "Link: </app.css>; rel=preload; as=style" in resp
    check "rel=preconnect" in resp                       # second hint too
    check resp.find("103 Early Hints") < resp.find("200 OK")   # ordering
    check resp.endsWith("PAGE")

suite "103 Early Hints over HTTP/2 (h2c)":
  test "an informational HEADERS frame arrives before the final response":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)                            # drain server SETTINGS
    c.sendHeaders(1)                                     # GET / , END_STREAM
    let frames = c.readFrames(1500,
      until = proc(fr: seq[Frame]): bool =
        var final = 0
        for f in fr:
          if f.typ == uint8(ftHeaders):
            let hs = decodeHeaders(f.payload)
            for (n, v) in hs:
              if n == ":status" and v == "200": inc final
        final >= 1)
    # collect the :status of each HEADERS frame on stream 1, in order
    var statuses: seq[string]
    var sawLink = false
    for f in frames:
      if f.typ == uint8(ftHeaders) and f.streamId == 1:
        for (n, v) in decodeHeaders(f.payload):
          if n == ":status": statuses.add v
          if n == "link" and "app.css" in v: sawLink = true
    check statuses.len >= 2                               # 103(s) then 200
    check statuses[0] == "103"                            # informational first
    check statuses[^1] == "200"                           # final last
    check sawLink                                         # the Link hint carried
    c.close()

srv.close()
echo "early hints ok"
