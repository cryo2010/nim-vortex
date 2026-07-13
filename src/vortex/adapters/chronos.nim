## chronos adapter: the chronos counterpart to the asyncdispatch
## adapter. Write handlers with `await` over chronos-based drivers
## (chronos-postgres, the chronos HTTP client, ...) while the core stays
## Future-free. Import this module and either
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
## would collide with chronos's `{.async.}` pragma macro.)
##
## Import only one async adapter per program: this module and the
## asyncdispatch adapter both define `AsyncRequestHandler`, `doAsync`,
## and the router overloads over their own (incompatible) `Future`
## type, so importing both is ambiguous. Pick the runtime your drivers
## use.
##
## Everything runs on the owning loop thread: each loop thread has its
## own chronos dispatcher, futures never cross threads, and (unlike
## `blocking:`) the body may capture surrounding locals. `req.blocking:`
## still works inside an async body for synchronous libraries.
##
## Mechanics: the loop calls the registered pump once per iteration to
## drive chronos, capping its selector timeout at a few ms while async
## operations are pending (chronos's own fds cannot wake our selector;
## this bounds completion latency instead). chronos's `poll()` would
## otherwise block until its next timer, so the pump keeps a pending
## callback queued to force a zero-timeout backend poll. When the future
## finishes, the deferred respond is flushed via LoopCore.kick. An
## uncaught exception in the body responds 500.

import pkg/chronos
import std/[httpcore, tables, deques]
import ../connection
import ../request
import ../router

export chronos

# Futures we are still waiting on, per loop thread. chronos futures never
# cross threads, so a plain threadvar (no atomics) is correct and lets
# the pump know when to run and when to keep capping the loop timeout.
var pendingOps {.threadvar.}: int

proc noop(arg: pointer) {.gcsafe, raises: [].} = discard

proc pump(): int {.nimcall, gcsafe.} =
  {.gcsafe.}:
    if pendingOps <= 0: return -1
    # Bounded spin: completing one future can resume work that
    # immediately suspends again (chained awaits); each such link needs
    # another poll pass. chronos derives its backend-poll timeout from
    # the next timer, so queue a callback first: a pending callback
    # forces a zero-timeout poll that runs ready work and checks ready
    # IO without ever blocking the loop.
    var spins = 0
    while pendingOps > 0 and spins < 8:
      callSoon(noop)
      poll()
      inc spins
    if pendingOps > 0: 5 else: -1

proc ensurePump*(core: ptr LoopCore) {.inline.} =
  ## Idempotent; called automatically by the entry points below.
  if core.pumpHook == nil:
    core.pumpHook = pump

proc complete(req: Request, failed: bool) {.gcsafe.} =
  ## 500 on failure, then flush/resume the connection (send is a no-op
  ## if the body already answered).
  if failed:
    response(req).send(Http500, "500 Internal Server Error", "text/plain")
  if req.core.kick != nil:
    req.core.kick(req.core.loopPtr, req.fd, req.gen, req.stream)

proc watch(req: Request, fut: Future[void]) =
  ## Attach completion handling to a running future.
  if fut.finished:
    # Completed without suspending: any send already ran inline during
    # dispatch, so skip the callback queue, the pump, and the kick.
    if fut.failed:
      response(req).send(Http500, "500 Internal Server Error", "text/plain")
    return
  ensurePump(req.core)               # pump only once something suspends
  inc pendingOps
  let watched = fut
  let target = req
  fut.addCallback proc (arg: pointer) {.gcsafe, raises: [].} =
    dec pendingOps
    try:
      complete(target, watched.failed)
    except Exception:
      discard

template doAsync*(req: Request, body: untyped) =
  ## Run `body` asynchronously on the loop thread; it must eventually
  ## call `res.send`. Captures are allowed.
  watch(req, (proc () {.async.} = body)())

proc watchWs(ws: WebSocket, fut: Future[void]) =
  ## Fire-and-forget for a WebSocket: drive the future to completion on the
  ## loop; an uncaught exception closes the socket with 1011 (there is no
  ## HTTP response to answer with a 500).
  if fut.finished:
    if fut.failed and ws.isAlive: ws.close(1011)
    return
  ensurePump(ws.core)
  inc pendingOps
  let watched = fut
  let target = ws
  fut.addCallback proc (arg: pointer) {.gcsafe, raises: [].} =
    dec pendingOps
    try:
      if watched.failed and target.isAlive: target.close(1011)
    except Exception:
      discard

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
  watchWs(ws, (proc () {.async.} = body)())

type
  AsyncRequestHandler* =
    proc (req: Request, res: Response): Future[void] {.gcsafe.}

# --- pull-based request-body reading (await req.read) -----------------------
# Wraps the core's push req.onBody into an awaitable read(); see the
# asyncdispatch adapter for the design.

type
  BodyReader = ref object
    req: Request
    chunks: Deque[string]
    eof: bool
    waiter: Future[string]

var bodyReaders {.threadvar.}: Table[(int32, uint32, uint32), BodyReader]

proc toStr(a: openArray[char]): string =
  result = newString(a.len)
  if a.len > 0: copyMem(addr result[0], unsafeAddr a[0], a.len)

proc take(r: BodyReader): string =
  ## Dequeue a chunk and grant flow-control credit for it (manualAck). ackBody
  ## reaches a loop hook (untyped effect); contain it so read() stays raises-safe
  ## for chronos's strict async effect tracking.
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
    else: w.complete("")

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
  else:
    r.waiter = result

proc streamToHandler(inner: AsyncRequestHandler): RequestHandler =
  let h = inner
  proc (req: Request, res: Response) {.gcsafe.} =
    {.gcsafe.}:
      let rd = BodyReader(req: req, chunks: initDeque[string]())
      let k = (req.fd, req.gen, req.stream)
      bodyReaders[k] = rd
      req.onBody(proc (chunk: openArray[char], last: bool) {.gcsafe.} =
        rd.feed(chunk, last), manualAck = true)
      let fut = h(req, res)
      fut.addCallback proc (arg: pointer) {.gcsafe, raises: [].} =
        bodyReaders.del(k)
      watch(req, fut)

proc stream*(r: Router, meth: HttpMethod, path: string,
             h: AsyncRequestHandler) =
  ## Register an async streaming route: the handler runs at headers-complete
  ## and pulls the body with `await req.read()`. Pass `router.streamPredicate`
  ## to `start` for the loop to dispatch it early.
  r.stream(meth, path, streamToHandler(h))

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
