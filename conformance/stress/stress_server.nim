## Target server for the per-workload stress soaks (conformance/stress/run.sh,
## `nimble stressRequests` / `stressWs` / `stressSse` / `stressStreamUpload` /
## `stressStreamDownload`). One server exposes every workload; the client
## (conformance/stress/client/stress_client.py) drives one workload per run and
## verifies it (checksums hard-fail).
##
## Routes:
##   /plaintext /json /big   TechEmpower-style GETs (smoke, shared with loadtest)
##   /echo   GET/POST/PUT     echo the body; req is decompressed and the response
##                            compressed per the build + config (requests workload)
##   /ws                      WebSocket echo (text + binary)
##   /sse                     N events in id order, closing after each batch so the
##                            client must reconnect and resume from Last-Event-ID
##   /upload  (streaming POST) hash the streamed body (constant memory); 200 if it
##                            matches the client's x-sha1 header, else 400
##   /download                stream STREAM_BYTES of a deterministic generator
##                            (byte i = i mod 256); the client re-hashes and checks
##
## Two build-time axes (driven by the Dockerfile from run.sh), same as
## loadtest_server.nim: protocol/codecs via BUILD_FLAGS + LOADTEST_*-style env,
## and the handler runtime via one -d:lt* flag (sync / asyncdispatch / chronos),
## so VORTEX_SERVER sweeps sync|async|chronos under load.

import std/[os, strutils]
import vortex
import nimcrypto/[sha, hash]        # incremental SHA-1 (nimcrypto is a core dep)

when defined(ltAsync) or defined(ltAsyncAwait):
  import vortex/asyncdispatch
elif defined(ltChronos) or defined(ltChronosAwait):
  import vortex/chronos

const asyncMode = defined(ltAsync) or defined(ltAsyncAwait) or
                  defined(ltChronos) or defined(ltChronosAwait)

const
  bigBody = "The quick brown fox jumps over the lazy dog. ".repeat(200)  # ~9 KB
  sseTotal = 100      # total SSE events across reconnects
  sseBatch = 20       # events per connection before the server closes (forces reconnect)
  dlChunk = 64 * 1024 # download chunk size
  downloadFile = "/tmp/vortex_download.bin"    # sync sendFile source (const: gcsafe)

let streamBytes = parseInt(getEnv("STREAM_BYTES", "1073741824"))   # /download size

proc genChunk(start, n: int): string =
  ## `n` bytes of the deterministic generator starting at global index `start`.
  result = newString(n)
  for j in 0 ..< n: result[j] = char((start + j) and 0xff)

# --- shared handler bodies (no await needed; identical sync/async) -----------

template echoBody(req, res: untyped) =
  ## Echo the request body. vortex decompresses the request (decompressRequest)
  ## and compresses the response (compress + Accept-Encoding) transparently.
  case req.method
  of HttpGet:
    case req.path
    of "/plaintext": vortex.send(res, Http200, "Hello, World!")
    of "/json":
      vortex.send(res, Http200, """{"message":"Hello, World!"}""",
                  %*{"Content-Type": "application/json"})
    of "/big": vortex.send(res, Http200, bigBody)
    else: vortex.send(res, Http200, "")
  else:
    vortex.send(res, Http200, req.body)     # POST/PUT echo

template sseBody(req, res: untyped) =
  ## Emit a batch of id-ordered events, then close so the client reconnects and
  ## resumes from Last-Event-ID; repeats until all `sseTotal` are delivered.
  var i = 0
  let last = req.lastEventId
  if last.len > 0:
    try: i = parseInt(last) + 1 except ValueError: i = 0
  let s = res.sse()
  var sent = 0
  while i < sseTotal and sent < sseBatch:
    discard s.send("event " & $i, id = $i)
    inc i; inc sent
  s.close()

# --- runtime-specific handlers -----------------------------------------------

when asyncMode:
  proc hEcho(req: Request, res: Response) {.async.} = echoBody(req, res)
  proc hSse(req: Request, res: Response) {.async.} = sseBody(req, res)

  proc hWs(req: Request, res: Response) {.async.} =
    let ws = req.acceptWebSocket()
    ws.messages(msg):
      ws.send(msg)                          # echo (kind preserved by ws.send)

  proc hUpload(req: Request, res: Response) {.async.} =
    var ctx: sha1
    ctx.init()
    while true:
      let chunk = await req.read()
      if chunk.len == 0: break
      ctx.update(chunk)
    let got = ($ctx.finish()).toLowerAscii
    if got == req.header("x-sha1").toLowerAscii: res.send(Http200, "ok")
    else: res.send(Http400, "mismatch")

  proc hDownload(req: Request, res: Response) {.async.} =
    res.sendHead(Http200, "application/octet-stream")
    var off = 0
    while off < streamBytes:
      let n = min(dlChunk, streamBytes - off)
      await res.write(genChunk(off, n))     # awaitable backpressure
      off += n
    res.finish()

else:
  proc hEcho(req: Request, res: Response) {.gcsafe.} = echoBody(req, res)
  proc hSse(req: Request, res: Response) {.gcsafe.} = sseBody(req, res)

  proc hWs(req: Request, res: Response) {.gcsafe.} =
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.send(data)                         # echo

  proc hUpload(req: Request, res: Response) {.gcsafe.} =
    # onBody runs after the handler frame returns, so the SHA state lives on the
    # heap (a ref the callback captures), not on the handler's stack.
    var box = new(tuple[ctx: sha1])
    box.ctx.init()
    req.onBody proc(chunk: openArray[char], last: bool) {.gcsafe.} =
      if chunk.len > 0: box.ctx.update(chunk)
      if last:
        let got = ($box.ctx.finish()).toLowerAscii
        if got == req.header("x-sha1").toLowerAscii: res.send(Http200, "ok")
        else: res.send(Http400, "mismatch")

  proc hDownload(req: Request, res: Response) {.gcsafe.} =
    res.sendFile(downloadFile)              # backpressure-safe large-body path

when isMainModule:
  when not asyncMode:
    # Pre-generate the deterministic download file once (sync uses sendFile).
    if not fileExists(downloadFile) or getFileSize(downloadFile) != streamBytes:
      let f = open(downloadFile, fmWrite)
      var off = 0
      while off < streamBytes:
        let n = min(dlChunk, streamBytes - off)
        let c = genChunk(off, n)
        discard f.writeBuffer(unsafeAddr c[0], n)
        off += n
      f.close()

  var rt = newRouter()
  rt.get("/plaintext", hEcho)
  rt.get("/json", hEcho)
  rt.get("/big", hEcho)
  rt.get("/echo", hEcho)
  rt.post("/echo", hEcho)
  rt.put("/echo", hEcho)
  rt.get("/ws", hWs)
  rt.get("/sse", hSse)
  rt.post("/upload", hUpload, streaming = true)
  rt.get("/download", hDownload)

  let port = Port(parseInt(getEnv("STRESS_PORT", "8080")))
  var settings = initVortexConfig(port = port, numThreads = 0,
      compress = getEnv("STRESS_COMPRESS") == "1",
      decompressRequest = true,
      maxBodySize = streamBytes + 1024 * 1024)    # allow the upload workload
  when not defined(plainHttp):
    if getEnv("STRESS_TLS") == "1":
      settings.certFile = "/vortex/cert.pem"
      settings.keyFile = "/vortex/key.pem"
      settings.http3 = false
  let srv = newVortex(rt.toHandler, settings, rt.streamPredicate).start()
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
