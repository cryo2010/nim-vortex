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
## run ready callbacks and expired timers, capping its selector timeout at
## the dispatcher's next timer (so a long timer nobody waits on, such as a
## detached heartbeat, costs one wakeup when it is due). The dispatcher's
## own selector fd (its kqueue or epoll fd) is registered with the loop's
## selector, so I/O completing on any socket the dispatcher watches wakes
## the loop like one of its own connections and the pump polls it then:
## a task waiting on the dispatcher's I/O alone runs as soon as that I/O
## is ready, and an idle server sleeps the loop's full wait. When the
## future finishes, the deferred respond is flushed via
## LoopCore.hooks.kick. An uncaught exception in the body responds 500.

import std/[asyncdispatch, httpcore, tables, deques, macros, selectors,
          heapqueue, monotimes, times]
import ../connection
import ../request
import ../routing
import ../server
import ../settings

export asyncdispatch

proc readyNow(d: PDispatcher): bool =
  ## The dispatcher holds work that is runnable now: a queued callback or a
  ## timer that has expired.
  d.callbacks.len > 0 or
    (d.timers.len > 0 and d.timers[0].finishAt <= getMonoTime())

proc nextTimerCap(d: PDispatcher): int =
  ## Milliseconds until the dispatcher's earliest timer is due (rounded up, as
  ## asyncdispatch's own processTimers does, so the loop does not wake a hair
  ## early and pay a second pass for it), clamped to the loop's 1 s idle wait;
  ## -1 with no timer.
  if d.timers.len == 0: return -1
  let left = (d.timers[0].finishAt - getMonoTime()).inMilliseconds + 1
  int(clamp(left, 1'i64, 1000'i64))

# The dispatcher's selector is a kqueue (BSD, macOS) or epoll (Linux) fd, which
# reads ready while it holds pending events, so the loop can watch it (#419).
# Elsewhere std/selectors falls back to select/poll, whose state is no fd.
const nestedSelector = ioselSupportedPlatform and not defined(nuttx)

# The loop's selector found the dispatcher's fd readable this iteration (set by
# ioReadyHook): the pump polls its I/O even with no timer or callback due.
var ioReady {.threadvar.}: bool

proc ioFd(): int {.nimcall, gcsafe.} =
  ## LoopCore.hooks.ioFdHook: this thread's dispatcher selector fd.
  when nestedSelector:
    {.gcsafe.}: getIoHandler(getGlobalDispatcher()).getFd
  else: -1

proc onIoReady() {.nimcall, gcsafe.} =
  ## LoopCore.hooks.ioReadyHook.
  {.gcsafe.}: ioReady = true

proc pump(): int {.nimcall, gcsafe.} =
  ## Drive the dispatcher's ready work, then cap the loop's wait at its next
  ## timer (-1, the loop's full wait, with none).
  ##
  ## Not on hasPendingOperations (#417): that predicate counts every timer the
  ## dispatcher holds, including ones no request waits on -- a detached
  ## heartbeat sleeping 10 s, or the timer of a `withTimeout` whose operation
  ## finished early, which sits in the heap until it expires -- and the pump
  ## used to answer it with a 5 ms cap, so any such timer woke the loop thread
  ## every 5 ms for as long as it lived (0.094 s of loop CPU per 5 s idle after
  ## a `withTimeout(30 s)` that finished early, against 0.0009 s on chronos).
  ## A timer needs a wakeup when it is due, no sooner; the chronos pump's idle
  ## exit already worked that way.
  ##
  ## Registered I/O needs no cap either (#419): the loop watches the
  ## dispatcher's selector fd (ioFdHook), so I/O completing on it wakes the
  ## loop, and ioReady has this pump poll it. A task parked on the dispatcher's
  ## I/O alone, with no timer (a detached task reading its own socket), used to
  ## run only on the 5 ms cap. Without a pollable selector fd
  ## (not nestedSelector) the pump polls registered I/O on every pass under that
  ## 5 ms cap, as before.
  {.gcsafe.}:
    let d = getGlobalDispatcher()
    when nestedSelector:
      let io = ioReady
    else:
      let io = not getIoHandler(d).isEmpty
    ioReady = false
    # Bounded spin: completing one future can resume work that immediately
    # suspends again (pipelined requests, chained awaits, a fired timer whose
    # continuation runs as a callback); each such link needs another poll pass.
    # A poll(0) never blocks, and drains up to 64 ready fds per call; more
    # stay ready on the dispatcher's fd and wake the loop's next pass.
    # The I/O readiness may be stale by now (a handler closed the socket it was
    # for), and poll() raises on a dispatcher with nothing registered.
    let pollIo = io and not getIoHandler(d).isEmpty
    var spins = 0
    while spins < 8 and (readyNow(d) or (pollIo and spins == 0)):
      poll(0)
      inc spins
    if readyNow(d): return 1     # more ready work: come straight back
    result = nextTimerCap(d)
    when not nestedSelector:
      if not getIoHandler(d).isEmpty:
        result = if result < 0: 5 else: min(result, 5)

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

# Futures the adapter watches (handlers, doAsync bodies) that are still
# outstanding, and how many of those are parked on a wakeup only the vortex loop
# delivers, per loop thread. The pump does not need them (it reads the
# dispatcher's own callbacks, timers and fd readiness); a graceful shutdown
# does: it waits for watched work through LoopCore.hooks.pendingHook
# (adapterimpl's watchedPending), not for every timer the dispatcher holds, so
# an app's detached heartbeat timer does not hold a drained loop open.
var pendingOps {.threadvar.}: int
var parkedOps {.threadvar.}: int

proc trackParked() {.inline.} = inc parkedOps
  ## Contract shared with the chronos backend: one outstanding future has parked
  ## on a wakeup that only the vortex loop delivers. The pump needs no tally --
  ## a bare parked Future registers no fd, timer or callback with the
  ## dispatcher, so the pump has nothing to poll for it and the loop may sleep
  ## -- but the shutdown's watchedPending must not wait on such a future
  ## either.
proc untrackParked() {.inline.} = dec parkedOps
  ## The unpark half of trackParked.

template onCompleted(fut, body: untyped) =
  ## Contract shared with the chronos backend: run `body` when `fut` completes
  ## (asyncdispatch callback signature: a plain nullary closure), counting the
  ## future as watched until then (see pendingOps). The pump itself runs on the
  ## dispatcher's own state; see chronos.nim's onCompleted.
  inc pendingOps
  fut.addCallback proc () {.gcsafe.} =
    dec pendingOps
    body

proc completeSoon(fut: Future[void]) =
  ## Contract shared with the chronos backend: complete `fut` on a LATER turn of
  ## the event loop, never inside this call, so a coroutine awaiting it suspends
  ## and the loop serves I/O before it resumes (adapterimpl's `drained()` on an
  ## ended response, #408). Not `callSoon`: asyncdispatch drains its callback
  ## queue until it is empty, including callbacks queued while it runs, so a
  ## producer loop re-arming through callSoon would spin inside one poll()
  ## forever. A zero timer fires on the next poll() (processTimers only pops
  ## timers due when it started), and the vortex pump polls a bounded number of
  ## times per loop iteration.
  sleepAsync(0).addCallback proc () {.gcsafe.} =
    if not fut.finished: complete(fut)

template runAsyncBody(body: untyped): untyped =
  ## Immediately-invoked async closure; asyncdispatch needs the explicit
  ## `closure` calling convention alongside `{.async.}`.
  (proc () {.closure, async.} = body)()

include ./adapterimpl
