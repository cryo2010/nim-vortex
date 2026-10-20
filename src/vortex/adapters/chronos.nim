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
## drive chronos. chronos's `poll()` would otherwise block until its next
## timer, so the pump queues a callback before each poll to force a
## zero-timeout backend poll. The pump caps the loop's selector timeout at
## chronos's next timer, and the dispatcher's own selector fd (its kqueue
## or epoll fd) is registered with the loop's selector, so I/O completing
## on any fd chronos watches wakes the loop like one of its own
## connections and the pump polls chronos then: a future waiting on
## chronos I/O alone, watched or detached, resumes as soon as that I/O is
## ready, and an idle server sleeps the loop's full wait. While every
## outstanding future is parked on a wakeup only this loop delivers (an
## inbound WebSocket message, a request-body chunk), the pump stops
## spinning: chronos has nothing to poll for then. When the future
## finishes, the deferred respond is flushed via LoopCore.hooks.kick. An
## uncaught exception in the body responds 500.

import pkg/chronos
import pkg/chronos/selectors2 as chronosSelectors   # close(Selector) for teardown
import pkg/chronos/config as chronosConfig          # chronosStrictReentrancy
import std/[httpcore, tables, deques, macros, heapqueue]
import ../connection
import ../request
import ../routing
import ../server
import ../settings

export chronos

# Futures we are still waiting on, per loop thread. chronos futures never
# cross threads, so a plain threadvar (no atomics) is correct and lets
# the pump know when to keep spinning chronos (a watched future may resume
# this pass).
var pendingOps {.threadvar.}: int
# How many of those are parked on a wakeup only the vortex loop can deliver
# (an inbound WebSocket message, a request-body chunk) rather than on anything
# chronos itself drives. See trackParked and the pump's early exit.
var parkedOps {.threadvar.}: int

proc noop(arg: pointer) {.gcsafe, raises: [].} = discard

# This loop thread's chronos dispatcher is in use (#422). chronos has no
# "exists" query: getThreadDispatcher() creates one on first use, kqueue/epoll
# fd and all, and the pump's idle check used to call it on every pass. Set where
# vortex first hands chronos work (noteDispatcher: ensurePump, the pending-op
# tally, completeSoon); until then the pump, the loop's fd registration and the
# teardown leave the dispatcher alone. ensurePump runs for every watched handler,
# including one that completed without suspending: it may have detached a task
# onto chronos that nothing else will drive (#412), and whether it did cannot be
# asked without creating the dispatcher, so such a thread gets one too (and its
# teardown releases it).
var dispatcherLive {.threadvar.}: bool

proc noteDispatcher() {.inline.} =
  ## Contract shared with the asyncdispatch backend: vortex is about to hand
  ## the dispatcher work (a watched future, a detached task's completion), so
  ## the pump must drive it from here on.
  dispatcherLive = true

# How many entries an idle chronos dispatcher keeps in its callback queue
# between polls: the one sentinel poll() re-queues, unless strict reentrancy is
# on (`-d:chronosStrictReentrancy`, implied by `-d:chronosPreviewV5`), where
# poll() never adds it. Reading the queue against a hardcoded 1 under strict
# reentrancy took a single queued continuation for an idle queue, so a detached
# task's resumed continuation was never polled. chronos releases from before the
# flag existed always keep the sentinel.
const idleCallbacks =
  when declared(chronosConfig.chronosStrictReentrancy):
    (if chronosConfig.chronosStrictReentrancy: 0 else: 1)
  else: 1

proc unwatchedReady(): bool =
  ## chronos holds work that is runnable now: a queued callback (beyond the
  ## sentinel an idle dispatcher may keep in its queue between polls, see
  ## idleCallbacks) or a timer that has expired. Never creates the dispatcher.
  if not dispatcherLive: return false
  let d = getThreadDispatcher()
  d.callbacks.len > idleCallbacks or
    (d.timers.len > 0 and d.timers[0].finishAt <= Moment.now())

# The dispatcher's selector is a kqueue (BSD, macOS) or epoll (Linux) fd, which
# reads ready while it holds pending events, so the loop can watch it (#419).
# chronos's poll engine has no such fd (its getFd is -1).
const nestedSelector =
  when declared(chronosConfig.chronosEventEngine):
    chronosConfig.chronosEventEngine in ["epoll", "kqueue"]
  else:
    defined(linux) or defined(macosx) or defined(freebsd) or
      defined(netbsd) or defined(openbsd) or defined(dragonfly)

when not nestedSelector:
  import std/importutils                    # ioRegistered: the poll engine's fds
  import std/tables                         # ... and that table's len

# The loop's selector found the dispatcher's fd readable this iteration (set by
# ioReadyHook): the pump polls chronos even with no timer or callback due.
var ioReady {.threadvar.}: bool

proc ioFd(): int {.nimcall, gcsafe.} =
  ## LoopCore.hooks.ioFdHook: this thread's dispatcher selector fd.
  when nestedSelector:
    {.gcsafe.}:
      if not dispatcherLive: return -1   # register it once it exists
      int(getFd(getIoHandler(getThreadDispatcher())))
  else: -1

proc onIoReady() {.nimcall, gcsafe.} =
  ## LoopCore.hooks.ioReadyHook.
  {.gcsafe.}: ioReady = true

proc pollOnce() =
  ## One non-blocking chronos pass. chronos derives its backend-poll timeout
  ## from the next timer, so queue a callback first: a pending callback forces
  ## a zero-timeout poll that runs ready work and checks ready I/O without ever
  ## blocking the loop.
  ioReady = false
  callSoon(noop)
  poll()

proc ioRegistered(): bool =
  ## Without a pollable selector fd (not nestedSelector): the dispatcher watches
  ## at least one fd, so nothing but a bounded wait gets its I/O polled. The
  ## poll engine's selector keeps its fds in a private table and exports no
  ## count, hence the privateAccess; a selector without that table counts as
  ## watching (the bounded wait is the safe side).
  when nestedSelector: false
  else:
    let s = getIoHandler(getThreadDispatcher())
    privateAccess(typeof(s[]))
    when compiles(s.fds.len): s.fds.len > 0
    else:
      # A fallback of `true` would silently pin every loop thread at the 5 ms
      # cap for good, so fail the build instead.
      {.error: "vortex/chronos: the chronos poll engine's selector has no " &
        "private `fds` table (a Table[int32, SelectorKey], checked on chronos " &
        "4.0.4, 4.2.2 and 4.4.0); ioRegistered needs another way to ask " &
        "whether it watches an fd".}

proc idleCap(): int =
  ## The loop's wait once the pump has polled: come straight back (1) while
  ## chronos holds ready work, else its next timer (-1, the loop's full wait,
  ## with none). I/O needs no cap: it wakes the loop through the dispatcher's
  ## fd. Without such an fd (the poll engine) registered I/O caps the wait at
  ## 5 ms instead.
  if not dispatcherLive: return -1
  if unwatchedReady(): return 1
  let d = getThreadDispatcher()
  if d.timers.len == 0:
    result = -1
  else:
    # Rounded up, as asyncdispatch's processTimers does, so the loop does not
    # wake a hair early and pay a second pass for the same timer.
    let left = (d.timers[0].finishAt - Moment.now()).milliseconds + 1
    result = int(clamp(left, 1'i64, 1000'i64))
  when not nestedSelector:
    if ioRegistered():
      result = if result < 0: 5 else: min(result, 5)

proc pumpIdle(): int =
  ## The pump's exit once no watched future needs it: drive the work chronos
  ## holds on its own, then cap the loop's wait at its next timer (-1, the
  ## loop's full wait, with none).
  ##
  ## pendingOps counts only the futures the adapter watches (a handler, a
  ## `doAsync` body), so a task the handler detached with `asyncSpawn` (a
  ## producer that sleeps, then answers with `res.send`) is invisible to it:
  ## once the handler's future completed the pump stopped polling, and the
  ## task never ran again until some unrelated request suspended (#412). Every
  ## chronos sleep and timeout is a timer, so honouring the earliest one drives
  ## such a task at its own pace without spinning, and an idle server with no
  ## timers still sleeps the loop's full wait. The bounded spin covers the
  ## chain a fired timer starts (the timer completes a future, whose
  ## continuation runs as a callback on the next poll). A detached task parked
  ## on chronos I/O alone owns no timer: the loop watches the dispatcher's
  ## selector fd for it (ioFdHook), whose readiness sets ioReady, so the task
  ## runs in the pass its I/O is ready in (#419). Without that fd (chronos's
  ## poll engine) the pump polls on every pass while chronos watches any fd,
  ## under idleCap's 5 ms cap. A thread that has not handed chronos any work
  ## has nothing to drive, and no dispatcher to create (#422).
  if not dispatcherLive: return -1
  when nestedSelector:
    let io = ioReady
  else:
    let io = ioReady or ioRegistered()
  var spins = 0
  while spins < 8 and (unwatchedReady() or (io and spins == 0)):
    pollOnce()
    inc spins
  idleCap()

proc pump(): int {.nimcall, gcsafe.} =
  {.gcsafe.}:
    if pendingOps <= 0: return pumpIdle()
    # Bounded spin: completing one future can resume work that
    # immediately suspends again (chained awaits); each such link needs
    # another poll pass (pollOnce never blocks the loop).
    var spins = 0
    while spins < 8:
      pollOnce()
      inc spins
      if pendingOps <= 0: return pumpIdle()
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
      # upgrade new connections on a busy host. Measured on one loop thread with
      # four idle WebSockets open: 0.0527 s of CPU per 5 s idle with the spin,
      # 0.0004 s without it. That is ~1% of a core per loop thread, paid for as
      # long as any such connection is open and whether or not it carries
      # traffic, so it scales with the countProcessors() loop threads a default
      # server starts -- and the 5 ms cap kept every one of them from sleeping.
      if parkedOps >= pendingOps: return pumpIdle()
    # Watched futures are still waiting on chronos: on a timer (capped below),
    # on I/O (the dispatcher's fd wakes the loop, #419), or on a callback
    # (unwatchedReady: come straight back). Without a pollable selector fd the
    # I/O half keeps the bounded 5 ms cap it always had (idleCap).
    idleCap()

proc releaseDispatcher() =
  ## Close this thread's dispatcher's selector fd and drop the dispatcher, in a
  ## proc of its own so no local ref outlives the drop.
  let d = getThreadDispatcher()
  try: chronosSelectors.close(getIoHandler(d))
  except CatchableError, Defect: discard
  # setThreadDispatcher doAsserts that the dispatcher it replaces has an empty
  # callback queue, and a dispatcher outside strict reentrancy always keeps the
  # sentinel poll() re-queues there (idleCallbacks). So dropping it raised an
  # AssertionDefect, the teardown swallowed it, and the dispatcher stayed rooted
  # in chronos's threadvar, which nothing frees when the thread exits: one
  # ~15 KB dispatcher leaked per loop thread that ever used chronos (#422).
  # Whatever is still queued is work this exiting thread will never run.
  d.callbacks.clear()
  try: setThreadDispatcher(nil)
  except CatchableError, Defect: discard

proc teardown() {.nimcall, gcsafe.} =
  ## Release this loop thread's chronos dispatcher on exit. Without it the
  ## dispatcher's epoll fd leaks, and every server restart on a fresh loop thread
  ## leaks another. Drain ready callbacks so completed futures are released, then
  ## close the selector fd and drop the dispatcher; the post-run GC_fullCollect in
  ## runLoopThread (once the Loop is out of scope) collects any remaining cycles.
  ## A thread that never handed chronos work has no dispatcher to release, and
  ## must not create one just to close it.
  {.gcsafe.}:
    if not dispatcherLive: return
    var spins = 0
    while pendingOps > 0 and spins < 64:
      pollOnce()
      inc spins
    releaseDispatcher()
    dispatcherLive = false
    GC_fullCollect()

# --- backend primitives for the shared adapter body (adapterimpl.nim) --------

proc trackPending() {.inline.} =
  ## Count one future as outstanding so the pump keeps spinning chronos each pass
  ## until it completes. Paired with untrackPending.
  noteDispatcher()
  inc pendingOps
proc untrackPending() {.inline.} = dec pendingOps
  ## The completion half of trackPending.

proc trackParked() {.inline.} = inc parkedOps
  ## Contract shared with the asyncdispatch backend: one outstanding future has
  ## parked on a wakeup that only the vortex loop delivers, so chronos has
  ## nothing to poll for on its behalf. Once every outstanding future is parked
  ## this way the pump stops spinning and lets the loop sleep (see pump). The
  ## asyncdispatch pump needs no tally -- a bare parked Future registers no
  ## fd, timer or callback, so that pump has nothing to poll for it anyway.
proc untrackParked() {.inline.} = dec parkedOps
  ## The unpark half of trackParked.

template onCompleted(fut, body: untyped) =
  ## Contract shared with the asyncdispatch backend: run `body` when `fut`
  ## completes (absorbing chronos's callback signature: pointer argument,
  ## `raises: []`). This backend ADDITIONALLY owns the pump's pending-op
  ## accounting -- it tracks each awaited future as outstanding (trackPending)
  ## until completion (untrackPending), so the pump spins chronos while a
  ## watched future may resume. asyncdispatch keeps the same tally only for the
  ## shutdown's watchedPending (its pump reads the dispatcher's own state).
  ## Callers in adapterimpl rely only on the "run body on completion" half;
  ## this pump-scheduling side is the backend's.
  trackPending()
  fut.addCallback proc (arg: pointer) {.gcsafe, raises: [].} =
    untrackPending()
    try:
      body
    except Exception:
      discard

proc completeSoon(fut: Future[void]) =
  ## Contract shared with the asyncdispatch backend: complete `fut` on a LATER
  ## turn of the event loop, never inside this call, so a coroutine awaiting it
  ## suspends and the loop serves I/O before it resumes (adapterimpl's
  ## `drained()` on an ended response, #408). chronos runs a callback queued
  ## while it is processing callbacks on its next poll, and the vortex pump
  ## polls a bounded number of times per loop iteration.
  noteDispatcher()
  callSoon(proc (arg: pointer) {.gcsafe, raises: [].} =
    if not fut.finished: fut.complete())

template runAsyncBody(body: untyped): untyped =
  ## Immediately-invoked async closure (chronos's `{.async.}` procs are
  ## closures already; no extra pragma needed).
  (proc () {.async.} = body)()

include ./adapterimpl
