## asyncdispatch adapter: write handlers with `await` while the core
## stays Future-free. Import this module and either
##
## - register `{.async.}` handlers directly on the router:
##
##   ```nim
##   proc getUser(req: Request, res: Response) {.async.} =
##     let user = await db.getUser(req.param("id"))
##     res.send(Http200, user.toJson)
##   router.get("/users/:id", getUser)
##   ```
##
## - or use the block form inside a plain handler:
##
##   ```nim
##   proc handler(req: Request, res: Response) {.gcsafe.} =
##     req.doAsync:
##       let rows = await db.query(...)
##       res.send(Http200, $rows)
##   ```
##
## (The block form is `doAsync`, not `async`: a template named `async`
## would collide with asyncdispatch's `{.async.}` pragma macro.)
##
## Everything runs on the owning loop thread: each loop thread has its
## own asyncdispatch dispatcher, futures never cross threads, and (unlike
## `blocking:`) the body may capture surrounding locals. `req.blocking:`
## still works inside an async body for synchronous libraries.
##
## Mechanics: the loop calls the registered pump once per iteration to
## run ready callbacks, capping its selector timeout at a few ms while
## async operations are pending (asyncdispatch's own fds cannot wake our
## selector; this bounds completion latency instead). When the future
## finishes, the deferred respond is flushed via LoopCore.kick. An
## uncaught exception in the body responds 500.

import std/[asyncdispatch, httpcore, tables, deques]
import ../connection
import ../request
import ../routing

export asyncdispatch

proc pump(): int {.nimcall, gcsafe.} =
  {.gcsafe.}:
    # Bounded spin: completing one future can resume work that
    # immediately suspends again (pipelined requests, chained awaits);
    # each such link needs another poll pass. Real IO waits are not
    # completed by poll(0) and fall through to the timeout cap below.
    var spins = 0
    while hasPendingOperations() and spins < 8:
      poll(0)                    # run completed futures; never block
      inc spins
    if hasPendingOperations(): 5 else: -1

proc ensurePump*(core: ptr LoopCore) {.inline.} =
  ## Idempotent; called automatically by the entry points below.
  if core.pumpHook == nil:
    core.pumpHook = pump

proc watch(req: Request, fut: Future[void]) =
  ## Attach completion handling: 500 on failure, then flush/resume the
  ## connection (send is a no-op if the body already answered).
  if fut.finished:
    # Completed without suspending (httpbeast's nil-future case): any
    # send already ran inline during dispatch, so skip the callback
    # queue, the pump, and the kick entirely.
    if fut.failed:
      response(req).send(Http500, "500 Internal Server Error", "text/plain")
    return
  ensurePump(req.core)               # pump only once something suspends
  fut.addCallback proc () {.gcsafe.} =
    if fut.failed:
      response(req).send(Http500, "500 Internal Server Error", "text/plain")
    if req.core.kick != nil:
      req.core.kick(req.core.loopPtr, req.fd, req.gen, req.stream)

template doAsync*(req: Request, body: untyped) =
  ## Run `body` asynchronously on the loop thread; it must eventually
  ## call `res.send`. Captures are allowed.
  watch(req, (proc () {.closure, async.} = body)())

proc watchWs(ws: WebSocket, fut: Future[void]) =
  ## Fire-and-forget for a WebSocket: drive the future to completion on the
  ## loop; an uncaught exception closes the socket with 1011 (there is no
  ## HTTP response to answer with a 500).
  if fut.finished:
    if fut.failed and ws.isAlive: ws.close(1011)
    return
  ensurePump(ws.core)
  fut.addCallback proc () {.gcsafe.} =
    if fut.failed and ws.isAlive: ws.close(1011)

template doAsync*(ws: WebSocket, body: untyped) =
  ## Run `body` asynchronously on the loop thread in response to a
  ## WebSocket message: `await` async drivers, then reply with `ws.send`.
  ## Captures are allowed. Fire-and-forget: an uncaught exception closes
  ## the socket with 1011 rather than reaching the peer.
  ##
  ## ```nim
  ## ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
  ##   ws.doAsync:
  ##     let user = await db.getUser(data)
  ##     ws.send(user.toJson)
  ## ```
  watchWs(ws, (proc () {.closure, async.} = body)())

type
  AsyncRequestHandler* =
    proc (req: Request, res: Response): Future[void] {.gcsafe.}

# --- awaitable outbound backpressure (await res.drained) --------------------

proc drained*(res: Response): Future[void] =
  ## Await until a streamed response's write backlog empties, so a producer can
  ## resume after `res.write` reported backpressure (returned false) without the
  ## onDrain callback trampoline:
  ##
  ##   res.sendHead(Http200, "application/octet-stream")
  ##   for chunk in source:
  ##     if not res.write(chunk): await res.drained()
  ##   res.finish()
  result = newFuture[void]("res.drained")
  if res.bufferedAmount == 0:
    complete(result)
    return
  let fut = result
  res.onDrain proc (r: Response) {.gcsafe.} =
    if not fut.finished: complete(fut)

proc write*(res: Response, data: string) {.async.} =
  ## Async streamed write with built-in backpressure: append `data`, and if that
  ## reported backpressure await the drain. The awaitable companion to the sync
  ## `res.write(openArray[char]): bool`; use inside `res.stream`:
  ##
  ##   res.stream(Http200, "text/csv"):
  ##     for row in rows: await res.write(row)
  ##
  ## (Forgetting `await` compiles -- the async transform discards the Future --
  ## but then skips backpressure; the write still happens.)
  if not write(res, data.toOpenArray(0, data.len - 1)):
    await res.drained()

# --- pull-based request-body reading (await req.read) -----------------------
#
# The core delivers the body push-style via req.onBody; this wraps that into an
# awaitable read(). A streaming route (the `stream` registrations below) sets up
# a per-request reader and feeds it from onBody; the handler pulls chunks with
# `await req.read()`, getting "" at end of body.

type
  BodyReader = ref object
    req: Request
    chunks: Deque[string]
    eof: bool
    waiter: Future[string]         ## a read() suspended on an empty queue

var bodyReaders {.threadvar.}: Table[(int32, uint32, uint32), BodyReader]

proc toStr(a: openArray[char]): string =
  result = newString(a.len)
  if a.len > 0: copyMem(addr result[0], unsafeAddr a[0], a.len)

proc take(r: BodyReader): string =
  ## Dequeue a chunk and grant flow-control credit for it (manualAck): the peer
  ## is only allowed to send more once the consumer has pulled this much.
  result = r.chunks.popFirst()
  try: r.req.ackBody(result.len)
  except Exception: discard

proc feed(r: BodyReader, chunk: openArray[char], last: bool) =
  if chunk.len > 0: r.chunks.addLast(toStr(chunk))
  if last: r.eof = true
  if r.waiter != nil and not r.waiter.finished:
    let w = r.waiter
    r.waiter = nil
    if r.chunks.len > 0: w.complete(r.take())
    else: w.complete("")           # eof (a waiter is only set on an empty queue)

proc read*(req: Request): Future[string] =
  ## Await the next request-body chunk in an async streaming handler; resolves
  ## to "" at end of body. Only meaningful on a route registered with the async
  ## `stream` below (or a `streamRoute` predicate); otherwise resolves to "".
  result = newFuture[string]("request.read")
  let r = bodyReaders.getOrDefault((req.fd, req.gen, req.stream))
  if r == nil:
    result.complete("")
  elif r.chunks.len > 0:
    result.complete(r.take())
  elif r.eof:
    result.complete("")
  elif r.waiter != nil and not r.waiter.finished:
    # A read() is already pending: don't overwrite it (that would leak the first
    # future forever). Concurrent reads of one body are unsupported.
    result.fail(newException(ValueError, "concurrent req.read() not supported"))
  else:
    r.waiter = result

proc streamToHandler(inner: AsyncRequestHandler): RequestHandler =
  let h = inner
  proc (req: Request, res: Response) {.gcsafe.} =
    {.gcsafe.}:
      let r = BodyReader(req: req, chunks: initDeque[string]())
      let k = (req.fd, req.gen, req.stream)
      bodyReaders[k] = r
      req.onBody(proc (chunk: openArray[char], last: bool) {.gcsafe.} =
        r.feed(chunk, last), manualAck = true)
      let fut = h(req, res)
      fut.addCallback proc () {.gcsafe.} = bodyReaders.del(k)
      watch(req, fut)

proc stream*(r: Router, meth: HttpMethod, path: string,
             h: AsyncRequestHandler) =
  ## Register an async streaming route: the handler runs at headers-complete
  ## and pulls the body with `await req.read()`. Pass `router.streamPredicate`
  ## to `start` for the loop to dispatch it early.
  r.stream(meth, path, streamToHandler(h))

proc wsToHandler(inner: AsyncRequestHandler): RequestHandler =
  ## Like toHandler, but with WebSocket completion semantics: an unhandled
  ## exception closes the socket with 1011 (not an HTTP 500), and there is no
  ## HTTP resume -- the upgraded connection is owned by the WebSocket.
  let h = inner
  proc (req: Request, res: Response) {.gcsafe.} =
    {.gcsafe.}:
      let fut = h(req, res)
      let target = req
      proc onDone() {.gcsafe.} =
        if fut.failed:
          let ws = WebSocket(core: target.core, fd: target.fd,
                             gen: target.gen, stream: target.stream)
          if ws.isAlive: ws.close(1011)
      if fut.finished: onDone()
      else:
        ensurePump(req.core)
        fut.addCallback onDone

proc ws*(r: Router, path: string, h: AsyncRequestHandler) =
  ## Register an async WebSocket handler (a WS handshake is a GET). Write a
  ## plain `{.async.}` proc that accepts the socket and loops -- e.g. with
  ## `ws.messages` -- and `await` freely; on an unhandled exception the socket
  ## closes with 1011. Prefer this over `get` for WebSocket routes: `get` would
  ## answer a failure with an HTTP 500 written into the WebSocket stream.
  ##
  ##   proc chat(req: Request, res: Response) {.async.} =
  ##     let ws = req.acceptWebSocket()
  ##     ws.messages(msg):
  ##       ws.send(msg)
  ##   router.ws("/chat", chat)
  r.addRoute(HttpGet, path, wsToHandler(h))

proc toHandler*(h: AsyncRequestHandler): RequestHandler =
  ## Adapt an async handler to the core handler type (route parameters
  ## arrive via req.params either way).
  let inner = h
  proc (req: Request, res: Response) {.gcsafe.} =
    {.gcsafe.}:
      watch(req, inner(req, res))

proc route(r: Router, meth: HttpMethod, path: string,
           h: AsyncRequestHandler) =
  r.addRoute(meth, path, toHandler(h))

proc get*(r: Router, path: string, h: AsyncRequestHandler) =
  r.route(HttpGet, path, h)
proc post*(r: Router, path: string, h: AsyncRequestHandler) =
  r.route(HttpPost, path, h)
proc put*(r: Router, path: string, h: AsyncRequestHandler) =
  r.route(HttpPut, path, h)
proc delete*(r: Router, path: string, h: AsyncRequestHandler) =
  r.route(HttpDelete, path, h)
proc patch*(r: Router, path: string, h: AsyncRequestHandler) =
  r.route(HttpPatch, path, h)
proc head*(r: Router, path: string, h: AsyncRequestHandler) =
  r.route(HttpHead, path, h)
proc options*(r: Router, path: string, h: AsyncRequestHandler) =
  r.route(HttpOptions, path, h)

# --- pull-loop sugar + SSE backpressure -------------------------------------

template stream*(req: Request, chunk, body: untyped) =
  ## Consume a streaming request body with a pull loop: `body` runs once with
  ## `chunk: string` rebound each iteration, until end of body. On a clean exit
  ## it auto-acks with an empty `200` **unless the handler already responded
  ## from inside the block** (so a `res.send(Http201, id)` / 4xx *inside* the
  ## loop wins). A response *after* the block is too late -- the 200 already
  ## went out on block exit -- so to reply once you've consumed the whole body,
  ## use the explicit `while (let c = await req.read(); c.len > 0)` loop instead.
  ## If `body` raises, the response is aborted and the exception propagates (a
  ## failed upload becomes a 500, never a 200). Use inside an async body.
  ##
  ##   proc upload(req: Request, res: Response) {.async.} =
  ##     req.stream(chunk):
  ##       await save(chunk)         # -> empty 200 on success
  block:
    let capturedReq = req
    var streamOk = false
    try:
      while true:
        let chunk = await read(capturedReq)
        if chunk.len == 0: break
        body
      streamOk = true
    finally:
      let res = response(capturedReq)
      if streamOk:
        if not res.responded: res.send(Http200)
      else:
        res.abort()

proc drained*(s: SseStream): Future[void] = s.response.drained()
  ## Await until the SSE stream's write backlog empties, so a producer can
  ## resume after `s.send` reported backpressure (returned false).

# --- awaitable WebSocket message reading (await ws.receive / ws.messages) ----
#
# Wraps the core's push ws.onMessage/onClose into an awaitable receive(), so an
# async handler loops over messages instead of nesting them in callbacks. The
# `messages` template is the WebSocket twin of `req.stream`; it owns
# onMessage/onClose while active (don't set them yourself). Setup/teardown live
# in raises-[] helpers (not the awaited receive) so the loop stays effect-clean
# under chronos's strict async effect tracking.

type
  WsMessage* = object
    ## One inbound WebSocket message, or the terminal close (`closed` = true,
    ## carrying the peer's `code`/`reason`).
    data*: string
    kind*: WsKind
    closed*: bool
    code*: uint16
    reason*: string

  WsReader = ref object
    msgs: Deque[(string, WsKind)]
    eof: bool
    code: uint16
    reason: string
    waiter: Future[WsMessage]

var wsReaders {.threadvar.}: Table[(int32, uint32, uint32), WsReader]

proc feedMsg(r: WsReader, data: string, kind: WsKind) =
  if r.waiter != nil and not r.waiter.finished:
    let w = r.waiter; r.waiter = nil
    w.complete(WsMessage(data: data, kind: kind))
  else:
    r.msgs.addLast((data, kind))

proc installWsReader*(ws: WebSocket) {.raises: [].} =
  ## Install ws.onMessage/onClose feeding a per-handle reader, so `receive` can
  ## pull messages. Called by `messages`; call it yourself before a manual
  ## `receive` loop. Idempotent; loop-thread only.
  try:
    let key = (ws.fd, ws.gen, ws.stream)
    if wsReaders.hasKey(key): return
    let r = WsReader(msgs: initDeque[(string, WsKind)]())
    wsReaders[key] = r
    ws.onMessage = proc(s: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      r.feedMsg(data, kind)
    ws.onClose = proc(s: WebSocket, code: uint16, reason: string) {.gcsafe.} =
      r.eof = true; r.code = code; r.reason = reason
      if r.waiter != nil and not r.waiter.finished:
        let w = r.waiter; r.waiter = nil
        w.complete(WsMessage(closed: true, code: code, reason: reason))
        wsReaders.del(key)
  except Exception:
    discard

proc clearWsReader*(ws: WebSocket) {.raises: [].} =
  ## Drop the reader and stop feeding it (run when a `messages` loop ends).
  try:
    wsReaders.del((ws.fd, ws.gen, ws.stream))
    ws.onMessage = nil
    ws.onClose = nil
  except Exception:
    discard

proc receive*(ws: WebSocket): Future[WsMessage] =
  ## Await the next WebSocket message; the result's `closed` is true (carrying
  ## the peer's `code`/`reason`) once the socket closes. The reader must be
  ## installed first (via `messages`, or `installWsReader`). Loop-thread only.
  result = newFuture[WsMessage]("ws.receive")
  let key = (ws.fd, ws.gen, ws.stream)
  let r = wsReaders.getOrDefault(key)
  if r == nil:
    result.complete(WsMessage(closed: true))
  elif r.msgs.len > 0:
    let (d, k) = r.msgs.popFirst()
    result.complete(WsMessage(data: d, kind: k))
  elif r.eof:
    wsReaders.del(key)
    result.complete(WsMessage(closed: true, code: r.code, reason: r.reason))
  elif r.waiter != nil and not r.waiter.finished:
    result.fail(newException(ValueError, "concurrent ws.receive() not supported"))
  else:
    r.waiter = result

template messages*(ws: WebSocket, msg, body: untyped) =
  ## Async loop over incoming WebSocket messages: `body` runs per text/binary
  ## message with `msg: string` in scope, until the peer closes. Sugar over
  ## `await ws.receive()` (the WebSocket twin of `req.stream`); owns
  ## ws.onMessage/onClose. Use in a WS-owned async context (`ws.doAsync:`):
  ##
  ##   proc chat(req: Request, res: Response) {.gcsafe.} =
  ##     let ws = req.acceptWebSocket()
  ##     ws.doAsync:
  ##       ws.messages(msg):
  ##         ws.send(msg)
  block:
    installWsReader(ws)
    try:
      while true:
        let m = await ws.receive()
        if m.closed: break
        let msg {.inject.} = m.data
        body
    finally:
      clearWsReader(ws)

template messages*(ws: WebSocket, msg, kind, body: untyped) =
  ## Two-variable form of `messages`: `msg: string` plus `kind: WsKind`
  ## (`WsKind.Text` / `WsKind.Binary`).
  block:
    installWsReader(ws)
    try:
      while true:
        let m = await ws.receive()
        if m.closed: break
        let msg {.inject.} = m.data
        let kind {.inject.} = m.kind
        body
    finally:
      clearWsReader(ws)
