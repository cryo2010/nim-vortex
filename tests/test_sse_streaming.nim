## Phase-4 streaming API, end to end over HTTP/1.1:
##   - SSE (res.sse / send / comment / close): the actual bytes a streaming
##     response emits, dechunked and checked against the text/event-stream wire
##     format.
##   - Router-free inbound streaming: streamPaths(...) (4a) dispatches an upload
##     handler at headers-complete, which consumes the body with the req.stream
##     sync template (4b) and echoes the byte count.
## Plus pure structural checks on the StreamRoutes predicate.

import std/[unittest, net, strutils, httpcore]
import vortex/[settings, request, server, streaming]
import ./helper

proc pathOnly(req: Request): string =
  ## streaming.nim keeps its own copy private, so the handler needs a local one.
  result = req.path
  let q = result.find('?')
  if q >= 0: result.setLen(q)

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.pathOnly
  of "/events":
    let s = res.sse(retry = 3000)
    discard s.send("hello", event = "greet", id = "1")
    discard s.send("a\nb")                # multi-line data
    discard s.comment("ping")
    s.close()
  of "/upload":
    var total = 0
    req.stream(chunk, last):
      total += chunk.len
      if last: res.send(Http200, "got " & $total)
  else:
    res.send(Http404, "nope")

# streamPaths (router-free) opts /upload into inbound streaming; /events is a
# plain buffered handler that happens to stream its *response*.
var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1), streamRoute = streamPaths("/upload")).start(0)
let port = srv.port

proc splitHeadBody(resp: string): (string, string) =
  let i = resp.find("\r\n\r\n")
  (resp[0 ..< i], resp[i + 4 .. ^1])

proc dechunk(body: string): string =
  var pos = 0
  while true:
    let nl = body.find("\r\n", pos)
    if nl < 0: break
    let size = parseHexInt(body[pos ..< nl].strip())
    pos = nl + 2
    if size == 0: break
    result.add body[pos ..< pos + size]
    pos += size + 2

proc rawGet(path: string): string =
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
  s.setRecvTimeout(3000)
  result = s.recvUntilClose(3000)

proc rawPost(path, body: string): string =
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send("POST " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
         "Content-Length: " & $body.len & "\r\n\r\n" & body)
  s.setRecvTimeout(3000)
  result = s.recvUntilClose(3000)

suite "SSE over HTTP/1.1":
  test "headers advertise event-stream and disable buffering":
    let (head, _) = splitHeadBody(rawGet("/events"))
    check "HTTP/1.1 200" in head
    check "Content-Type: text/event-stream" in head
    check "Cache-Control: no-cache, no-transform" in head
    check "X-Accel-Buffering: no" in head
    check "Transfer-Encoding: chunked" in head

  test "events, multi-line data, and a comment frame per the spec":
    let (_, body) = splitHeadBody(rawGet("/events"))
    check dechunk(body) ==
      "retry: 3000\n\n" &                       # initial retry field
      "id: 1\nevent: greet\ndata: hello\n\n" &  # first event
      "data: a\ndata: b\n\n" &                  # multi-line data
      ": ping\n\n"                              # comment / heartbeat

suite "router-free inbound streaming (streamPaths + req.stream)":
  test "the upload body is streamed to the handler and counted":
    let (head, body) = splitHeadBody(rawPost("/upload", repeat('x', 5000)))
    check "HTTP/1.1 200" in head
    check body == "got 5000"

  test "an empty streamed body still completes":
    let (head, body) = splitHeadBody(rawPost("/upload", ""))
    check "HTTP/1.1 200" in head
    check body == "got 0"

suite "StreamRoutes predicate (structural)":
  test "empty StreamRoutes -> nil predicate (buffered fast path)":
    check newStreamRoutes().predicate == nil

  test "a rule / combinators yield a callable predicate":
    let s = newStreamRoutes()
    s.stream(HttpPost, "/upload")
    check s.predicate != nil
    check streamAll() != nil
    check streamPaths("/a", "/b") != nil
    check streamWhen(proc(req: Request): bool = true) != nil

  test "streamPaths with no paths -> nil (nothing streams)":
    check streamPaths() == nil

echo "sse + streaming ok"
