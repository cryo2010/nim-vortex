## Target server for the per-workload stress soaks (conformance/stress/run.sh,
## `nimble stressRequests` / `stressWs` / `stressSse` / `stressStreamUpload` /
## `stressStreamDownload`). One server exposes every workload; the client
## (conformance/stress/client/stress_client.py) drives one workload per run and
## verifies it (checksums hard-fail).
##
## Routes:
##   /plaintext /json /big   TechEmpower-style GETs (smoke, shared with loadtest)
##   /html /xml /csv /binary  typed GETs with exact deterministic bodies and an
##                            explicit Content-Type (text/html, application/xml,
##                            text/csv, application/octet-stream) -- a cross-language
##                            body + type contract the client asserts
##   /echo   GET/POST/PUT/... echo the body; the non-GET reply reflects the request
##                            Content-Type verbatim (multipart boundary included),
##                            falling back to text/plain; req is decompressed and the
##                            response compressed per the build + config (requests
##                            workload)
##   /ws                      WebSocket echo (text + binary)
##   /sse                     N events in id order, closing after each batch so the
##                            client must reconnect and resume from Last-Event-ID
##   /upload  (streaming POST) hash the streamed body (constant memory); 200 if it
##                            matches the client's x-sha1 header, else 400
##   /download                stream STREAM_BYTES of a deterministic generator
##                            (byte i = i mod 256); the client re-hashes and checks
##   /stats                   "<rss> <heap> <fds>", exactly three fields (the
##                            client and the chaos sidecar both parse it)
##   /drops                   vortex's accept-path drop counters, so a soak can
##                            tell "the server refused the connection, here is
##                            why" from "the network broke" (#388). Also printed
##                            on SIGTERM/SIGINT.
##
## The SIGTERM/SIGINT path at the bottom of the file is for HAND runs: run.sh
## tears a cell's server down with `docker rm -f`, which is a SIGKILL, so no
## handler runs and nothing is printed (that is why run.sh dumps the container's
## last 200 log lines when a cell fails). Run the binary directly and Ctrl-C it
## and you get the tally plus an orderly shutdown.
##
## Two build-time axes (driven by the Dockerfile from run.sh), same as
## loadtest_server.nim: protocol/codecs via BUILD_FLAGS + LOADTEST_*-style env,
## and the handler runtime via one -d:lt* flag (sync / asyncdispatch / chronos),
## so VORTEX_SERVER sweeps sync|async|chronos under load.

import std/[os, strutils, posix, atomics]
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

proc buildDlPattern(): string =
  ## `dlChunk + 256` bytes of the deterministic generator (byte j = j mod 256).
  ## The generator has period 256 and `dlChunk` is a whole number of periods, so
  ## any run of up to `dlChunk` bytes, starting at any global offset, appears in
  ## here as one contiguous slice beginning at `offset mod 256`. That is what
  ## lets genChunk below be a memcpy instead of a per-byte loop.
  result = newString(dlChunk + 256)
  for j in 0 ..< result.len: result[j] = char(j and 0xff)

const dlPattern = buildDlPattern()

proc genChunk(start, n: int): string =
  ## `n` bytes of the deterministic generator starting at global index `start`
  ## (byte i = i mod 256 -- the cross-language contract with the Python client's
  ## gen_chunk, which the client's whole-stream SHA-1 check depends on).
  ##
  ## A slice of the precomputed pattern, not a per-byte loop: the async
  ## /download handler calls this once per 64 KiB chunk for the whole 1 GiB
  ## transfer, and the chaos sidecar hammers /download with aborted and
  ## slow-read connections, so on the event-loop builds this ran 64 Ki
  ## bounds-checked byte stores per chunk on the loop thread -- CPU the loop
  ## needs to accept and serve other connections. (The sync build never paid it:
  ## it serves /download with sendFile from a file generated once at startup.)
  ## `n` must not exceed dlChunk, which is the largest chunk any caller wants.
  doAssert n <= dlChunk, "genChunk: n exceeds the precomputed pattern span"
  let s = start and 0xff
  result = dlPattern[s ..< s + n]

# --- typed GET bodies (cross-language contract with the Python client) --------
# Precomputed once so the hot path does no per-request string building, like
# bigBody above. The formulas are the contract; do not change them casually.

proc buildXmlBody(): string =
  result = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><items>"
  for i in 0 .. 39:
    result &= "<item id=\"" & $i & "\">The quick brown fox jumps over the lazy dog</item>"
  result &= "</items>"

proc buildCsvBody(): string =
  result = "id,name,value\n"
  for i in 0 .. 199:
    result &= $i & ",name-" & $i & "," & $(i * i) & "\n"

const
  htmlBody = "<!doctype html><html><head><title>vortex stress</title></head><body>" &
    "<p>The quick brown fox jumps over the lazy dog.</p>".repeat(30) &
    "</body></html>"
  xmlBody = buildXmlBody()
  csvBody = buildCsvBody()
  binaryBody = genChunk(0, 8192)     # const: gcsafe (hEcho closes over it)

proc rssBytes(): int =
  ## Current resident set size (bytes), from /proc/self/statm (Linux container).
  try:
    let fields = readFile("/proc/self/statm").splitWhitespace()
    if fields.len >= 2: return parseInt(fields[1]) * int(sysconf(SC_PAGESIZE))
  except CatchableError: discard
  0

proc openFds(): int =
  ## Count of open file descriptors, from the /proc/self/fd directory (Linux
  ## container). The chaos sidecar samples this before and after its run to catch
  ## descriptors leaked by connection teardown (sockets, sendFile pins). The
  ## walkDir listing self-counts its own dirfd (a +1 bias), but that bias is a
  ## constant that cancels in the sidecar's baseline-vs-final comparison, so it
  ## needs no correction here. Same defensive style as rssBytes: any failure
  ## (non-Linux, /proc unavailable) yields 0.
  try:
    for _ in walkDir("/proc/self/fd"): inc result
  except CatchableError: result = 0

var terminating: Atomic[bool]
  ## Set by the SIGTERM/SIGINT handler; polled by the main loop (see the bottom
  ## of the file). vortex installs its own signal handlers only in `serve`, not
  ## `start`, so taking these over here does not fight it.

proc onTerm(sig: cint) {.noconv.} =
  terminating.store(true, moRelaxed)

proc dropsText(): string {.gcsafe.} =
  ## The accept-path drop tally as "cap=N tls=N register=N total=N
  ## acceptSuspend=N". Served on /drops and printed on shutdown. `cap`, `tls`
  ## and `register` are each a connection the server accepted and then let go of
  ## on purpose, which at the client is an empty `ConnectError` indistinguishable
  ## from a network fault -- the soak that chased that for an hour is why this is
  ## exposed (#388); `total` is their sum. `acceptSuspend` is printed last
  ## because it is a different kind of number: accept() itself failed on fd
  ## exhaustion and the listener backed off for ~1s, so nothing was accepted and
  ## it is not in `total`.
  ## Deliberately NOT folded into /stats: the client parses that as exactly
  ## three fields.
  let d = acceptDrops()
  "cap=" & $d.cap & " tls=" & $d.tls & " register=" & $d.register &
    " total=" & $d.total & " acceptSuspend=" & $d.acceptSuspend

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
    of "/html":
      vortex.send(res, Http200, htmlBody, %*{"Content-Type": "text/html"})
    of "/xml":
      vortex.send(res, Http200, xmlBody, %*{"Content-Type": "application/xml"})
    of "/csv":
      vortex.send(res, Http200, csvBody, %*{"Content-Type": "text/csv"})
    of "/binary":
      vortex.send(res, Http200, binaryBody,
                  %*{"Content-Type": "application/octet-stream"})
    else: vortex.send(res, Http200, "")
  else:
    # POST/PUT/DELETE/PATCH echo: reflect the request Content-Type verbatim
    # (including any multipart boundary), falling back to text/plain.
    var ct = req.header("content-type")
    if ct.len == 0: ct = "text/plain"
    vortex.send(res, Http200, req.body, %*{"Content-Type": ct})

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

template statsBody(req, res: untyped) =
  ## "<rssBytes> <heapBytes> <openFds>" for the client's periodic report.
  ## getOccupiedMem is the live GC heap of the loop thread that handled this
  ## request; openFds is the process-wide descriptor count the chaos sidecar
  ## watches for leaks (see openFds's bias note).
  vortex.send(res, Http200,
              $rssBytes() & " " & $getOccupiedMem() & " " & $openFds())

template dropsBody(req, res: untyped) =
  ## The accept-path drop counters (see dropsText). Its own route so /stats
  ## keeps its exact three-field contract with the client.
  vortex.send(res, Http200, dropsText())

template whoamiBody(req, res: untyped) =
  ## The remote address as vortex sees it: the PROXY-protocol source when behind
  ## a trusted L4 proxy (HAProxy `send-proxy`), else the direct peer. The proxy
  ## interop suite asserts this to confirm PROXY-header parsing.
  vortex.send(res, Http200, req.remoteAddress)

# --- runtime-specific handlers -----------------------------------------------

when asyncMode:
  proc hEcho(req: Request, res: Response) {.async.} = echoBody(req, res)
  proc hSse(req: Request, res: Response) {.async.} = sseBody(req, res)
  proc hStats(req: Request, res: Response) {.async.} = statsBody(req, res)
  proc hDrops(req: Request, res: Response) {.async.} = dropsBody(req, res)
  proc hWhoami(req: Request, res: Response) {.async.} = whoamiBody(req, res)

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
  proc hStats(req: Request, res: Response) {.gcsafe.} = statsBody(req, res)
  proc hDrops(req: Request, res: Response) {.gcsafe.} = dropsBody(req, res)
  proc hWhoami(req: Request, res: Response) {.gcsafe.} = whoamiBody(req, res)

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
  rt.get("/html", hEcho)                   # typed GETs: exact deterministic bodies
  rt.get("/xml", hEcho)                    # with explicit Content-Type (client asserts
  rt.get("/csv", hEcho)                    # body + type per a cross-language contract)
  rt.get("/binary", hEcho)
  rt.get("/echo", hEcho)
  rt.post("/echo", hEcho)
  rt.put("/echo", hEcho)
  rt.delete("/echo", hEcho)                # every-method coverage (proxy interop);
  rt.patch("/echo", hEcho)                 # HEAD derives from GET, OPTIONS auto-answers
  rt.get("/whoami", hWhoami)               # remote addr (PROXY-protocol assertion)
  rt.get("/ws", hWs)                       # h1/h2 WebSocket (GET Upgrade)
  when asyncMode:
    rt.addRoute(HttpConnect, "/ws", toHandler(hWs))   # h2/h3 Extended CONNECT (RFC 9220)
  else:
    rt.addRoute(HttpConnect, "/ws", hWs)
  rt.get("/sse", hSse)
  rt.get("/stats", hStats)
  rt.get("/drops", hDrops)                 # accept-path drop counters (#388)
  rt.post("/upload", hUpload, streaming = true)
  rt.get("/download", hDownload)

  let port = Port(parseInt(getEnv("STRESS_PORT", "8080")))
  var settings = initVortexConfig(port = port, numThreads = 0,
      compress = getEnv("STRESS_COMPRESS") == "1",
      decompressRequest = true,
      # vortex's 10 s default is a slowloris guard measured from accept, and it
      # counts the TLS handshake and any protocol upgrade. That is right for a
      # deployed server, but these soaks run deliberately oversubscribed (many
      # cells in parallel, host load 20-50), and there a loop thread can be
      # descheduled for longer than that -- measured on a loaded host: a
      # WebSocket upgrade still unserviced 13.9 s after connect, then reset by
      # this very deadline, while every established connection kept echoing tens
      # of thousands of messages a second. That reset is the host's scheduler,
      # not a vortex defect, and failing the cell on it costs an hour of real
      # coverage. Keep it finite (slowloris is still covered, and a genuinely
      # wedged handshake still fails) but well clear of the scheduling noise.
      headerTimeout = parseInt(getEnv("STRESS_HEADER_TIMEOUT", "60")),
      maxBodySize = streamBytes + 1024 * 1024)    # allow the upload workload
  # PROXY protocol (HAProxy send-proxy in front): the proxy interop suite sets
  # STRESS_PROXY_PROTOCOL=require so a missing/invalid header is dropped, proving
  # the header was parsed when /whoami returns the real client IP. An empty
  # trusted list trusts the direct peer (the proxy on the private docker network).
  case getEnv("STRESS_PROXY_PROTOCOL", "off").toLowerAscii
  of "require": settings.proxyProtocol = ProxyProtocol.Require
  of "optional": settings.proxyProtocol = ProxyProtocol.Optional
  else: discard
  let trusted = getEnv("STRESS_TRUSTED_PROXIES", "")
  if trusted.len > 0: settings.trustedProxies = trusted.split(',')
  when not defined(plainHttp):
    if getEnv("STRESS_TLS") == "1":
      settings.certFile = getEnv("STRESS_CERT", "/vortex/cert.pem")
      settings.keyFile = getEnv("STRESS_KEY", "/vortex/key.pem")
      settings.http3 = getEnv("STRESS_HTTP3") == "1"   # QUIC listener for h3 cells
  let srv = newVortex(rt.toHandler, settings, rt.streamPredicate).start()
  echo "listening on ", int(srv.port)
  # Print the accept-path drop tally on the way out, so a cell that ends with
  # `docker stop` leaves the number in the container log even if nothing polled
  # /drops. `docker rm -f` is a SIGKILL and gets nothing, which is why run.sh
  # also dumps the server's logs when a cell fails. The handler only sets a flag
  # (the only async-signal-safe thing to do here); the loop below prints.
  signal(SIGTERM, onTerm)
  signal(SIGINT, onTerm)
  while not terminating.load(moRelaxed): sleep(200)
  # Tally first, teardown second: the print must not be lost if the join below
  # takes the shutdown grace period (or detaches a stuck thread).
  echo "stress_server: accept drops: ", dropsText()
  flushFile(stdout)
  # `close` = requestShutdown + waitFor, i.e. it blocks until the loop threads
  # have drained and been joined. `requestShutdown` alone is non-blocking, so
  # this used to be the last statement of the program: main fell off the end and
  # ran the process's exit while the loop threads were still serving, racing
  # teardown in the one binary whose whole job is to surface crashes.
  srv.close()
  echo "stress_server: stopped"
  flushFile(stdout)
