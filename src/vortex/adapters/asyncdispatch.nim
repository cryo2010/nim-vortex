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
import ../router

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
