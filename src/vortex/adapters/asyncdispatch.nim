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
## Import only one async adapter per program: this module and the
## chronos adapter both define `AsyncRequestHandler`, `doAsync`, and
## the router overloads over their own (incompatible) `Future` type, so
## importing both is ambiguous. Pick the runtime your drivers use.
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
## finishes, the deferred respond is flushed via LoopCore.hooks.kick. An
## uncaught exception in the body responds 500.

import std/[asyncdispatch, httpcore, tables, deques, macros, selectors]
import ../connection
import ../request
import ../routing
import ../server
import ../settings

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

proc teardown() {.nimcall, gcsafe.} =
  ## Release this loop thread's asyncdispatch dispatcher on exit. Without it the
  ## dispatcher's epoll fd leaks, and every server restart on a fresh loop thread
  ## leaks another. Drain ready callbacks so completed futures are released, then
  ## close the selector fd and drop the dispatcher; the post-run GC_fullCollect in
  ## runLoopThread (once the Loop is out of scope) collects any remaining cycles.
  {.gcsafe.}:
    var spins = 0
    while hasPendingOperations() and spins < 64:
      poll(0)
      inc spins
    try:
      selectors.close(getIoHandler(getGlobalDispatcher()))
      # Drop the dispatcher so anything it still roots becomes unreachable.
      setGlobalDispatcher(nil)
    except CatchableError, Defect: discard
    GC_fullCollect()

# --- backend primitives for the shared adapter body (adapterimpl.nim) --------

template onCompleted(fut, body: untyped) =
  ## Contract shared with the chronos backend: run `body` when `fut` completes
  ## (asyncdispatch callback signature: a plain nullary closure). Unlike chronos,
  ## this backend does NO pending-op accounting -- the asyncdispatch dispatcher's
  ## hasPendingOperations already tells the pump when to run, so there is no
  ## per-future trackPending/untrackPending to keep. See chronos.nim's onCompleted.
  fut.addCallback proc () {.gcsafe.} =
    body

template runAsyncBody(body: untyped): untyped =
  ## Immediately-invoked async closure; asyncdispatch needs the explicit
  ## `closure` calling convention alongside `{.async.}`.
  (proc () {.closure, async.} = body)()

include ./adapterimpl
