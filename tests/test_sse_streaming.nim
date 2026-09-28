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

# #268: `alive` and `bufferedAmount` read loop-owned state (the connection
# table, the h2/h3 stream maps, the write buffers), so an off-thread read has to
# report "dead"/"idle" instead of racing the loop thread. The probe runs on a
# plain createThread while the loop thread is parked in joinThread, so the
# handle it reads is genuinely live: only the thread guard makes it answer
# false/0. SseStream is a handle of a pointer plus three ints, so a global copy
# of one carries no GC'd memory across the thread boundary.
var probeSse: SseStream
var probeAlive = true
var probeBuffered = -1

proc probeOffThread(unused: int) {.thread.} =
  probeAlive = probeSse.alive
  probeBuffered = probeSse.bufferedAmount

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
  of "/breaks":
    # #267: every line terminator the wire format knows, including a bare CR.
    let s = res.sse()
    discard s.send("a\r\nb")
    discard s.send("c\rd")
    discard s.send("e\nf")
    discard s.send("g\n")
    s.close()
  of "/withsse":
    # #269: the bare block form, unchanged.
    res.withSse(s):
      discard s.send("plain")
  of "/withsse-opts":
    # #269: res.sse's arguments forwarded through the block form.
    res.withSse(s, headers = [("X-Stream", "report")], retry = 3000):
      discard s.send("opts")
  of "/withsse-retry":
    res.withSse(s, retry = 1500):
      discard s.send("retry")
  of "/probe":
    let s = res.sse()
    probeSse = s
    var thr: Thread[int]
    createThread(thr, probeOffThread, 0)
    joinThread(thr)
    discard s.send("off " & $probeAlive & " " & $probeBuffered)
    discard s.send("on " & $s.alive)
    s.close()
  of "/empty":
    # #266: a payload-free typed event must still dispatch on the client.
    let s = res.sse()
    discard s.send("", event = "ping")
    discard s.send("")
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
withServer(RequestHandler(handler), initVortexConfig(numThreads = 1),
           streamPaths("/upload"), srv):
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
    let s = connectTimeout(port, 3000)
    defer: s.close()
    s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    result = s.recvUntilClose(3000)

  proc rawPost(path, body: string): string =
    let s = connectTimeout(port, 3000)
    defer: s.close()
    s.send("POST " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
           "Content-Length: " & $body.len & "\r\n\r\n" & body)
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

    test "an empty data payload emits two data: fields so the event dispatches":
      # One `data:` field leaves the client's data buffer empty after it strips
      # the trailing LF, and EventSource then discards the event. Two fields
      # leave "\n", which dispatches (#266).
      let (_, body) = splitHeadBody(rawGet("/empty"))
      check dechunk(body) ==
        "event: ping\ndata:\ndata:\n\n" &      # typed, empty payload
        "data:\ndata:\n\n"                     # untyped, empty payload

    test "CRLF, CR and LF in data all split into data: fields":
      # The wire format has no escape for a literal CR, so a CR is a field
      # boundary and the client rebuilds it as an LF: documented, lossy for a
      # byte-exact payload, which is what base64/JSON encoding is for (#267).
      let (_, body) = splitHeadBody(rawGet("/breaks"))
      check dechunk(body) ==
        "data: a\ndata: b\n\n" &     # "a\r\nb": one CRLF break, not two
        "data: c\ndata: d\n\n" &     # "c\rd":   a bare CR breaks the line
        "data: e\ndata: f\n\n" &     # "e\nf":   plain LF
        "data: g\ndata: \n\n"        # "g\n":    trailing break -> empty tail

    test "alive and bufferedAmount are loop-thread guarded":
      # Off-thread: false / 0 without touching loop state. On the loop thread
      # the same live handle still reports alive (#268).
      let (_, body) = splitHeadBody(rawGet("/probe"))
      check dechunk(body) ==
        "data: off false 0\n\n" &
        "data: on true\n\n"

  suite "withSse block form":
    test "the bare form still opens, sends and closes the stream":
      let (head, body) = splitHeadBody(rawGet("/withsse"))
      check "Content-Type: text/event-stream" in head
      check dechunk(body) == "data: plain\n\n"

    test "retry passes through to res.sse":
      let (_, body) = splitHeadBody(rawGet("/withsse-retry"))
      check dechunk(body) == "retry: 1500\n\n" & "data: retry\n\n"

    test "headers and retry both pass through to res.sse":
      let (head, body) = splitHeadBody(rawGet("/withsse-opts"))
      check "X-Stream: report" in head
      check "Cache-Control: no-cache, no-transform" in head   # still applied
      check dechunk(body) == "retry: 3000\n\n" & "data: opts\n\n"

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
