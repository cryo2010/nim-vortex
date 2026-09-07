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
import pkg/chronos/selectors2 as chronosSelectors   # close(Selector) for teardown
import std/[httpcore, tables, deques, macros]
import ../connection
import ../request
import ../routing
import ../server
import ../settings

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

proc teardown() {.nimcall, gcsafe.} =
  ## Release this loop thread's chronos dispatcher on exit. Without it the
  ## dispatcher's epoll fd leaks, and every server restart on a fresh loop thread
  ## leaks another. Drain ready callbacks so completed futures are released, then
  ## close the selector fd and drop the dispatcher; the post-run GC_fullCollect in
  ## runLoopThread (once the Loop is out of scope) collects any remaining cycles.
  {.gcsafe.}:
    var spins = 0
    while pendingOps > 0 and spins < 64:
      callSoon(noop)
      poll()
      inc spins
    try:
      chronosSelectors.close(getIoHandler(getThreadDispatcher()))
      # Drop the dispatcher so anything it still roots becomes unreachable.
      setThreadDispatcher(nil)
    except CatchableError, Defect: discard
    GC_fullCollect()

# --- backend primitives for the shared adapter body (adapterimpl.nim) --------

template onCompleted(fut, body: untyped) =
  ## Run `body` when `fut` completes, absorbing chronos's callback
  ## signature (pointer argument, `raises: []`) and keeping the
  ## pendingOps count that tells the pump when to run.
  inc pendingOps
  fut.addCallback proc (arg: pointer) {.gcsafe, raises: [].} =
    dec pendingOps
    try:
      body
    except Exception:
      discard

template runAsyncBody(body: untyped): untyped =
  ## Immediately-invoked async closure (chronos's `{.async.}` procs are
  ## closures already; no extra pragma needed).
  (proc () {.async.} = body)()

include ./adapterimpl
