## Request trailers (req.trailers): the header fields a client may send after a
## chunked/streamed body. Covers HTTP/1.1 (raw chunked framing with a trailer
## section) and HTTP/2 (a trailing HEADERS frame with END_STREAM). The response
## side (res.trailers) is exercised in test_streaming.nim.

import std/[unittest, net, strutils, httpcore]
import vortex/[settings, request, server, routing]
import vortex/http2/frames
import ./h2client

proc echoTrailers(req: Request, res: Response) {.gcsafe.} =
  ## Reflect req.trailers so the client can assert on it:
  ##   <x-checksum value>|<present?>|<count>|<names joined by ,>
  var names: seq[string]
  for (n, _) in req.trailers: names.add n
  res.send(Http200,
    req.trailers["x-checksum"] & "|" &
    $("x-checksum" in req.trailers) & "|" &
    $req.trailers.len & "|" & names.join(","))

let rt = newRouter()
rt.post("/echo", echoTrailers)
var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let port = srv.port

proc bodyOf(resp: string): string =
  let i = resp.find("\r\n\r\n")
  if i < 0: "" else: resp[i + 4 .. ^1]

suite "req.trailers over HTTP/1.1 (chunked)":
  proc chunkedPost(trailerSection: string): string =
    ## POST /echo with a 4-byte "body" chunk, then `trailerSection` (which
    ## already includes the terminating CRLF of each trailer line) plus the
    ## blank line that ends the trailer section.
    let s = newSocket()
    defer: s.close()
    s.connect("127.0.0.1", port)
    s.send("POST /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
           "Transfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n" &
           "4\r\nbody\r\n0\r\n" & trailerSection & "\r\n")
    var chunk = s.recv(65536, timeout = 2000)
    while chunk.len > 0:
      result.add chunk
      chunk = s.recv(65536, timeout = 2000)

  test "a trailer after the last chunk is exposed via req.trailers":
    # h1 preserves the sent field-name case (X-Checksum).
    check bodyOf(chunkedPost("X-Checksum: abc123\r\n")) ==
      "abc123|true|1|X-Checksum"

  test "no trailer section: req.trailers is empty":
    check bodyOf(chunkedPost("")) == "|false|0|"

suite "req.trailers over HTTP/2 (trailing HEADERS)":
  test "a trailer HEADERS frame after DATA reaches req.trailers":
    var c = newH2TestConn(port)
    discard c.readFrames(300)                          # drain server SETTINGS
    var f = ""
    f.addRequest(1, [(":method", "POST"), (":path", "/echo"),
                     (":scheme", "http"), (":authority", "x")],
                 endStream = false)                    # head, body follows
    f.addData(1, "body", endStream = false)            # DATA, trailers follow
    f.addRequest(1, [("x-checksum", "abc123")], endStream = true)  # trailers
    c.sendRaw(f)
    let frames = c.readFrames(1500,
      until = proc(fr: seq[Frame]): bool =
        for x in fr:
          if x.typ == uint8(ftData) and x.streamId == 1 and x.payload.len > 0:
            return true
        false)
    var body: string
    for x in frames:
      if x.typ == uint8(ftData) and x.streamId == 1: body.add x.payload
    check body == "abc123|true|1|x-checksum"           # h2 names are lowercase
    c.close()

  test "a pseudo-header in the trailer section is rejected (RST_STREAM)":
    var c = newH2TestConn(port)
    discard c.readFrames(300)
    var f = ""
    f.addRequest(3, [(":method", "POST"), (":path", "/echo"),
                     (":scheme", "http"), (":authority", "x")],
                 endStream = false)
    f.addData(3, "body", endStream = false)
    f.addRequest(3, [(":method", "GET")], endStream = true)   # illegal in trailers
    c.sendRaw(f)
    let frames = c.readFrames(1000)
    check rstError(frames, 3) != 0                      # stream reset, not 200
    c.close()

srv.close()
echo "trailers ok"
