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
## callback queued to force a zero-timeout backend poll. The cap is
## dropped again as soon as every outstanding future is parked on a
## wakeup only this loop delivers (an inbound WebSocket message, a
## request-body chunk): chronos has nothing to poll for then, so the loop
## is free to sleep on its own selector. When the future finishes, the
## deferred respond is flushed via LoopCore.hooks.kick. An uncaught
## exception in the body responds 500.

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
# How many of those are parked on a wakeup only the vortex loop can deliver
# (an inbound WebSocket message, a request-body chunk) rather than on anything
# chronos itself drives. See trackParked and the pump's early exit.
var parkedOps {.threadvar.}: int

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
    while spins < 8:
      callSoon(noop)
      poll()
      inc spins
      if pendingOps <= 0: return -1
      # Every future still outstanding is parked on a wakeup that only this
      # loop can deliver, so chronos has nothing of its own left to drive:
      # stop spinning and let the loop block on its selector until that wakeup
      # arrives. Nothing is starved by sleeping here -- the wakeup runs on the
      # loop thread, chronos re-queues the resumed continuation as a callback,
      # and the pump call at the end of THAT same loop iteration polls it.
      #
      # Without this the tally could never reach zero while a long-lived
      # awaited future was open -- and every `ws.messages` / `await req.read()`
      # handler is one -- so a server holding idle WebSocket or streaming
      # connections spun eight chronos polls per loop iteration and pinned the
      # selector wait at 5 ms forever, on every one of its loop threads. That
      # is pure burn: it bought no latency (the wakeups come from our own
      # selector) and cost the headroom a loop thread needs to accept and
      # upgrade new connections on a busy host.
      if parkedOps >= pendingOps: return -1
    5

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

proc trackPending() {.inline.} = inc pendingOps
  ## Count one future as outstanding so the pump keeps running (and keeps capping
  ## the loop timeout) until it completes. Paired with untrackPending.
proc untrackPending() {.inline.} = dec pendingOps
  ## The completion half of trackPending.

proc trackParked() {.inline.} = inc parkedOps
  ## Contract shared with the asyncdispatch backend: one outstanding future has
  ## parked on a wakeup that only the vortex loop delivers, so chronos has
  ## nothing to poll for on its behalf. Once every outstanding future is parked
  ## this way the pump stops spinning and lets the loop sleep (see pump). The
  ## asyncdispatch backend needs no tally -- a bare parked Future registers no
  ## fd, timer or callback, so its hasPendingOperations already reads false.
proc untrackParked() {.inline.} = dec parkedOps
  ## The unpark half of trackParked.

template onCompleted(fut, body: untyped) =
  ## Contract shared with the asyncdispatch backend: run `body` when `fut`
  ## completes (absorbing chronos's callback signature: pointer argument,
  ## `raises: []`). This backend ADDITIONALLY owns the pump's pending-op
  ## accounting -- chronos's own fds cannot wake our selector, so it tracks each
  ## awaited future as outstanding (trackPending) until completion
  ## (untrackPending) to tell the pump when to run. asyncdispatch needs none of
  ## this (its dispatcher's hasPendingOperations already reports pending work), so
  ## its onCompleted only runs body. Callers in adapterimpl rely only on the
  ## "run body on completion" half; this pump-scheduling side is the backend's.
  trackPending()
  fut.addCallback proc (arg: pointer) {.gcsafe, raises: [].} =
    untrackPending()
    try:
      body
    except Exception:
      discard

template runAsyncBody(body: untyped): untyped =
  ## Immediately-invoked async closure (chronos's `{.async.}` procs are
  ## closures already; no extra pragma needed).
  (proc () {.async.} = body)()

include ./adapterimpl
