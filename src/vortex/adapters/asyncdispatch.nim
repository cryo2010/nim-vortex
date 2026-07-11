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

import std/[asyncdispatch, httpcore]
from std/deques import len          # for the dispatcher's callback queue
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

type
  AsyncRequestHandler* =
    proc (req: Request, res: Response): Future[void] {.gcsafe.}

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
