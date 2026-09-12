# Shared implementation of the async runtime adapters: the entire
# user-facing API (doAsync, AsyncRequestHandler, the router verb
# overloads, streaming reads/writes, WebSocket receive/messages, the
# awaitable `blocking`). Included -- not imported -- by
# adapters/asyncdispatch.nim and adapters/chronos.nim, so every symbol
# below compiles (and exports) as if written in the backend module and
# the two adapters stay byte-compatible in their public API.
#
# Each backend declares, before the include:
# - the runtime import/export itself (Future[T], newFuture, complete,
#   fail, addCallback, the `{.async.}` macro, `await`)
# - `pump` / `teardown` procs (the loop hooks wired by `ensurePump`)
# - `template onCompleted(fut, body)`: run `body` when `fut` completes,
#   absorbing the backend's addCallback callback signature (and, for
#   chronos, the pendingOps bookkeeping that drives its pump)
# - `template runAsyncBody(body)`: an immediately-invoked async closure
#   (the backends need different pragma spellings)

when not declared(onCompleted):
  {.error: "adapterimpl.nim must be included by a backend adapter (vortex/adapters/asyncdispatch or vortex/adapters/chronos), not compiled or imported directly".}

proc ensurePump*(core: ptr LoopCore) {.inline.} =
  ## Idempotent; called automatically by the entry points below.
  if core.hooks.pumpHook == nil:
    core.hooks.pumpHook = pump
    core.hooks.teardownHook = teardown

proc complete(req: Request, failed: bool) {.gcsafe.} =
  ## 500 on failure, then flush/resume the connection (send is a no-op
  ## if the body already answered).
  if failed:
    response(req).send(Http500, "500 Internal Server Error")
  if req.core.hooks.kick != nil:
    req.core.hooks.kick(req.core.loopPtr, req.fd, req.gen, req.stream)

proc watch(req: Request, fut: Future[void]) =
  ## Attach completion handling to a running future: 500 on failure,
  ## then flush/resume the connection.
  if fut.finished:
    # Completed without suspending (httpbeast's nil-future case): any
    # send already ran inline during dispatch, so skip the callback
    # queue, the pump, and the kick entirely.
    if fut.failed:
      response(req).send(Http500, "500 Internal Server Error")
    return
  ensurePump(req.core)               # pump only once something suspends
  let watched = fut
  let target = req
  onCompleted(watched):
    complete(target, watched.failed)

template doAsync*(req: Request, body: untyped) =
  ## Run `body` asynchronously on the loop thread; it must eventually
  ## call `res.send`. Captures are allowed.
  watch(req, runAsyncBody(body))

proc watchWs(ws: WebSocket, fut: Future[void]) =
  ## Fire-and-forget for a WebSocket: drive the future to completion on the
  ## loop; an uncaught exception closes the socket with 1011 (there is no
  ## HTTP response to answer with a 500).
  if fut.finished:
    if fut.failed and ws.isAlive: ws.close(1011)
    return
  ensurePump(ws.core)
  let watched = fut
  let target = ws
  onCompleted(watched):
    if watched.failed and target.isAlive: target.close(1011)

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
  watchWs(ws, runAsyncBody(body))

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

# --- generic single-consumer awaitable reader ------------------------------
# A queue with at most one parked waiter, shared by the request-body reader
# (T = a body chunk string) and the WebSocket message reader (T = WsMessage):
# feed hands an item to a parked take, else enqueues; markEof records the
# terminal value; take drains the queue then returns that eof value, rejecting a
# concurrent second waiter. Every item handed to the consumer passes through
# dequeue, so onConsume (nil unless set) fires exactly once per item -- the body
# reader grants manualAck flow-control credit there.

type
  AwaitableReader[T] = ref object
    queue: Deque[T]
    closed: bool
    eofVal: T                      ## value handed out on/after end of stream
    waiter: Future[T]              ## a take() suspended on an empty queue
    onConsume: proc (item: T) {.gcsafe, raises: [].}

proc dequeue[T](r: AwaitableReader[T]): T =
  result = r.queue.popFirst()
  if r.onConsume != nil: r.onConsume(result)

proc feed[T](r: AwaitableReader[T], item: T) =
  ## Deliver an item: hand it to a parked take (via dequeue, so onConsume fires),
  ## else enqueue it.
  r.queue.addLast item
  if r.waiter != nil and not r.waiter.finished:
    let w = r.waiter
    r.waiter = nil
    w.complete(r.dequeue())

proc markEof[T](r: AwaitableReader[T], eofVal: T) =
  ## End of stream: record the terminal value and hand it to a parked take (a
  ## waiter is only parked on an empty queue, so nothing queued is skipped).
  r.closed = true
  r.eofVal = eofVal
  if r.waiter != nil and not r.waiter.finished:
    let w = r.waiter
    r.waiter = nil
    w.complete(eofVal)

proc drained[T](r: AwaitableReader[T]): bool {.inline.} =
  ## Closed with the queue empty: nothing more will ever be handed out, so the
  ## owner may reap the reader's table entry.
  r.closed and r.queue.len == 0

proc take[T](r: AwaitableReader[T]): Future[T] =
  ## One pull: a queued item, the terminal eof value once drained, or park a
  ## single waiter (a concurrent second reader is rejected -- it would leak the
  ## first future). raises-safe under chronos's strict async effect tracking.
  result = newFuture[T]("AwaitableReader.take")
  if r.queue.len > 0:
    result.complete(r.dequeue())
  elif r.closed:
    result.complete(r.eofVal)
  elif r.waiter != nil and not r.waiter.finished:
    result.fail(newException(ValueError, "concurrent read on one reader is unsupported"))
  else:
    r.waiter = result

# --- pull-based request-body reading (await req.read) -----------------------

var bodyReaders {.threadvar.}: Table[(int32, uint32, uint32), AwaitableReader[string]]

proc toStr(a: openArray[char]): string =
  result = newString(a.len)
  if a.len > 0: copyMem(addr result[0], unsafeAddr a[0], a.len)

proc newBodyReader(req: Request): AwaitableReader[string] =
  ## A body reader whose onConsume grants manualAck flow-control credit for each
  ## consumed chunk: the peer may send more only once the handler has pulled it.
  ## ackBody reaches a loop hook (untyped effect); contain it.
  result = AwaitableReader[string](queue: initDeque[string]())
  let rq = req
  result.onConsume = proc (chunk: string) {.gcsafe, raises: [].} =
    try: rq.ackBody(chunk.len)
    except Exception: discard

proc read*(req: Request): Future[string] =
  ## Await the next request-body chunk in an async streaming handler; resolves
  ## to "" at end of body. Only meaningful on a route registered with the async
  ## `stream` below (or a `streamRoute` predicate); otherwise resolves to "".
  let r = bodyReaders.getOrDefault((req.fd, req.gen, req.stream))
  if r == nil:
    result = newFuture[string]("request.read")
    result.complete("")
  else:
    result = r.take()

proc streamToHandler(inner: AsyncRequestHandler): RequestHandler =
  let h = inner
  proc (req: Request, res: Response) {.gcsafe.} =
    {.gcsafe.}:
      let r = newBodyReader(req)
      let k = (req.fd, req.gen, req.stream)
      bodyReaders[k] = r
      req.onBody(proc (chunk: openArray[char], last: bool) {.gcsafe.} =
        if chunk.len > 0: r.feed(toStr(chunk))
        if last: r.markEof(""), manualAck = true)
      let fut = h(req, res)
      onCompleted(fut):
        bodyReaders.del(k)
      watch(req, fut)

proc wsToHandler(inner: AsyncRequestHandler): RequestHandler =
  ## Like toHandler, but with WebSocket completion semantics: an unhandled
  ## exception closes the socket with 1011 (not an HTTP 500), and there is no
  ## HTTP resume -- the upgraded connection is owned by the WebSocket.
  let h = inner
  proc (req: Request, res: Response) {.gcsafe.} =
    {.gcsafe.}:
      let ws = WebSocket(core: req.core, fd: req.fd,
                         gen: req.gen, stream: req.stream)
      watchWs(ws, h(req, res))

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

proc newVortex*(h: AsyncRequestHandler, config = initVortexConfig(),
                streamRoute: StreamRouteCb = nil): Vortex =
  ## Build a server directly from an async handler (wraps it with `toHandler`),
  ## so `newVortex(handler)` works without the explicit wrap.
  newVortex(toHandler(h), config, streamRoute)

proc route(r: Router, meth: HttpMethod, path: string,
           h: AsyncRequestHandler, streaming: bool) =
  # A streaming route is dispatched at headers-complete and pulls the body with
  # `await req.read()`, so it wraps with streamToHandler; a buffered route uses
  # the plain adapter. Pass `router.streamPredicate` to `start` so the loop
  # dispatches streaming routes early.
  if streaming: r.addRoute(meth, path, streamToHandler(h), streaming = true)
  else: r.addRoute(meth, path, toHandler(h))

proc get*(r: Router, path: string, h: AsyncRequestHandler, streaming = false) =
  r.route(HttpGet, path, h, streaming)
proc post*(r: Router, path: string, h: AsyncRequestHandler, streaming = false) =
  r.route(HttpPost, path, h, streaming)
proc put*(r: Router, path: string, h: AsyncRequestHandler, streaming = false) =
  r.route(HttpPut, path, h, streaming)
proc delete*(r: Router, path: string, h: AsyncRequestHandler, streaming = false) =
  r.route(HttpDelete, path, h, streaming)
proc patch*(r: Router, path: string, h: AsyncRequestHandler, streaming = false) =
  r.route(HttpPatch, path, h, streaming)
proc head*(r: Router, path: string, h: AsyncRequestHandler, streaming = false) =
  r.route(HttpHead, path, h, streaming)
proc options*(r: Router, path: string, h: AsyncRequestHandler, streaming = false) =
  r.route(HttpOptions, path, h, streaming)

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

var wsReaders {.threadvar.}: Table[(int32, uint32, uint32), AwaitableReader[WsMessage]]

proc installWsReader*(ws: WebSocket) {.raises: [].} =
  ## Install ws.onMessage/onClose feeding a per-handle reader, so `receive` can
  ## pull messages. Called by `messages`; call it yourself before a manual
  ## `receive` loop. Idempotent; loop-thread only.
  try:
    let key = (ws.fd, ws.gen, ws.stream)
    if wsReaders.hasKey(key): return
    let r = AwaitableReader[WsMessage](queue: initDeque[WsMessage]())
    wsReaders[key] = r
    ws.onMessage = proc(s: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      r.feed(WsMessage(data: data, kind: kind))
    ws.onClose = proc(s: WebSocket, code: uint16, reason: string) {.gcsafe.} =
      r.markEof(WsMessage(closed: true, code: code, reason: reason))
      # Nothing left to hand out (no parked receive and no queued messages): drop
      # the reader now so its per-handle entry can't leak (R12). A non-empty queue
      # is left for receive() to drain, which reaps the entry once it hits eof.
      if r.drained: wsReaders.del(key)
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
  let key = (ws.fd, ws.gen, ws.stream)
  let r = wsReaders.getOrDefault(key)
  if r == nil:
    result = newFuture[WsMessage]("ws.receive")
    result.complete(WsMessage(closed: true))
  else:
    # Reap the entry once the terminal (closed) message is the thing being handed
    # out -- i.e. the queue was already drained and the reader closed. A pull that
    # merely dequeues the last data message must NOT delete yet: the next receive
    # still owes the closed message (with code/reason).
    let handingOutEof = r.drained
    result = r.take()
    if handingOutEof: wsReaders.del(key)

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

# --- awaitable req.blocking (async) -----------------------------------------
# Overrides the core (sync, terminal) `blocking` for async programs: the block
# runs on the worker pool, its result is moved back, and the returned Future
# completes on the loop. The `vortex/asyncdispatch` and `vortex/chronos`
# facades re-export the core API `except blocking`, so async code sees only
# this awaitable form.

proc blockingRun*[A, R](req: Request,
    body: proc (req: Request, res: Response, args: A): R {.nimcall, gcsafe.},
    args: sink A): Future[R] =
  ## Internal helper behind the async `req.blocking(...)` macro. Runs `body` on
  ## a worker with the moved-in `args`, resolving the Future with its result (or
  ## failing it if the body raised).
  let fut = newFuture[R]("req.blocking")
  let box = BlockingResultBox[A, R](body: body, args: args)
  box.onDone = proc (self: BlockingResultBase) {.gcsafe.} =
    let b = BlockingResultBox[A, R](self)     # downcast; closure captures fut only
    if b.err != nil: fut.fail(b.err)
    else: fut.complete(b.value)
  ensurePump(req.core)
  dispatchBlockingResult(req, box)
  fut

proc blockingRun*[A](req: Request,
    body: proc (req: Request, res: Response, args: A) {.nimcall, gcsafe.},
    args: sink A): Future[void] =
  ## Void overload: the block responds itself (no value flows back). A void
  ## body doesn't infer `R = void` through the generic above, so it binds here.
  let fut = newFuture[void]("req.blocking")
  let box = BlockingResultBox[A, void](body: body, args: args)
  box.onDone = proc (self: BlockingResultBase) {.gcsafe.} =
    let b = BlockingResultBox[A, void](self)
    if b.err != nil: fut.fail(b.err)
    else: fut.complete()
  ensurePump(req.core)
  dispatchBlockingResult(req, box)
  fut

macro blocking*(request: Request, args: varargs[untyped]): untyped =
  ## Run a block on the worker pool and suspend until it finishes, yielding its
  ## result (async form). Values named in the call are **moved** in and usable by
  ## name inside; `req`/`res` are injected. The block's last expression is the
  ## value; the `await` is implicit, so it reads like the sync form:
  ##
  ##   let report = req.blocking(user, cfg):
  ##     buildReport(user, cfg)          # runs on a worker; handler suspends here
  ##   res.send(Http200, report)
  ##
  ## Use inside an async handler. Capturing an unnamed surrounding local is a
  ## compile error (the block is a capture-free nimcall body), so only the named
  ## values cross the thread. Only value data may cross: a ref/ptr/closure (or a
  ## value with one nested) is rejected at compile time; move a uniquely-owned
  ## reference in with `isolate(...)` as a `var` (see the sync `blocking` docs).
  let body = args[^1]
  var names: seq[NimNode]
  for i in 0 ..< args.len - 1: names.add args[i]
  let payload = genSym(nskParam, "payload")
  # prepArg statically rejects ref/ptr/closure args and extracts an isolate(...);
  # prepare into locals first, then build the tuple from them.
  var prelude = newStmtList()
  var tup = nnkTupleConstr.newTree()
  for n in names:
    let a = genSym(nskLet, "barg")
    prelude.add newLetStmt(a, newCall(bindSym"prepArg", n))
    tup.add a
  var inner = newStmtList()
  for i, n in names:
    inner.add newLetStmt(n, nnkBracketExpr.newTree(payload, newLit(i)))
  inner.add body
  # Emit the `await` here: `await req.blocking(x): body` would bind the colon
  # block to `await`, not to `blocking`, so the macro adds it instead.
  result = newCall(ident"await", quote do:
    (block:
      `prelude`
      let moved = `tup`
      blockingRun(`request`, proc (req {.inject.}: Request,
          res {.inject.}: Response, `payload`: typeof(moved)): auto
          {.nimcall, gcsafe.} =
        `inner`, moved)))

template blocking*(socket: WebSocket, message: string, body: untyped) =
  ## Re-provided for async programs (the facade hides the core `blocking`); same
  ## as the core WebSocket `blocking`: run `body` on a worker for one message.
  dispatchWsBlocking(socket, message,
    proc (ws {.inject.}: WebSocket, msg {.inject.}: string)
        {.nimcall, gcsafe.} =
      body)
