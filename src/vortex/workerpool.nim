## Worker pool for `blocking:` handler code. A plain mutex+condvar task
## queue: blocking work is milliseconds-scale, so queue overhead is noise
## here; the zero-overhead requirement applies to the event-loop fast
## path, which never touches this module.
##
## Tasks are plain-data structs (proc pointer + request handle words):
## nothing garbage-collected crosses threads. Closures must not be used
## here: ORC's cycle-collector registry is thread-local, so destroying a
## closure on a foreign thread corrupts it.

import std/[locks, deques, httpcore, atomics]

type
  ReqSnapshot* = object
    ## A plain-data copy of a request, captured on the loop thread at
    ## dispatch and carried into a `blocking:` worker task (IMP2, closing C3).
    ## Every field is a value type -- no GC refs -- so it crosses to the worker
    ## by move, and the worker reads it instead of live loop memory (which would
    ## race the loop's non-atomic ORC refcounts on H2Conn/H3Conn). `present`
    ## marks a task that actually carries one (HTTP blocking bodies do; the
    ## WebSocket/file trampolines don't).
    present*: bool
    httpMethod*: HttpMethod
    target*: string                    ## raw request-target (path + query)
    headers*: seq[(string, string)]    ## all request headers, pseudo-headers kept
    trailers*: seq[(string, string)]   ## request trailers (fields after the body)
    body*: string
    params*: seq[(string, string)]     ## route params captured by the router
    remoteAddr*: string
    secure*: bool
    clientSubject*: string             ## mTLS client-cert subject ("" if none)

  WorkerTask* = object
    ## `fn` is a trampoline (see request.dispatchBlocking) that rebuilds
    ## the Request/WebSocket from the handle words and runs the user's body.
    fn*: proc (user, core: pointer, fd: int32, gen: uint32, stream: uint32,
               data: string) {.nimcall, gcsafe.}
    user*: pointer            ## the user body proc pointer
    core*: pointer            ## ptr LoopCore
    fd*: int32
    gen*: uint32
    stream*: uint32           ## HTTP/2 stream id, 0 for HTTP/1
    data*: string             ## moved-in payload (a WebSocket message); "" for HTTP
    snap*: ReqSnapshot        ## request snapshot for an HTTP blocking body

  # Set by the worker loop to the running task's snapshot, so a blocking
  # trampoline can point its Request at it without changing the trampoline ABI.
  # nil on the loop thread (the inline no-pool path reads live memory instead).

  WorkerPool* = object
    lock: Lock
    cond: Cond
    tasks: Deque[WorkerTask]
    stopping: bool
    maxQueue: int                 ## reject enqueue past this many waiting tasks
                                  ## (0 = unbounded); the load-shedding cap
    alive: ptr Atomic[int]        ## shared live-thread counter (loops + workers);
                                  ## each worker decrements it on exit so a timed
                                  ## shutdown can detect stuck workers (nil = off)
    threads: seq[Thread[ptr WorkerPool]]

var workerSnapshot* {.threadvar.}: ptr ReqSnapshot
  ## The current task's snapshot on a worker thread (see ReqSnapshot).

proc workerLoop(pool: ptr WorkerPool) {.thread.} =
  while true:
    acquire pool.lock
    while pool.tasks.len == 0 and not pool.stopping:
      wait(pool.cond, pool.lock)
    if pool.tasks.len == 0:
      release pool.lock
      break                        # stopping and drained
    var task = pool.tasks.popFirst()
    release pool.lock
    workerSnapshot = addr task.snap   # the trampoline reads this (nil off-pool)
    {.gcsafe.}:
      try:
        task.fn(task.user, task.core, task.fd, task.gen, task.stream,
                move task.data)
      except Exception:
        # Catch Defect too (where catchable, i.e. not --panics:on): a bug in a
        # user blocking body must not take down the worker thread and the whole
        # server. The trampoline already responded and released the pin.
        discard
    workerSnapshot = nil            # don't dangle at a freed task between runs
  # Exited cleanly: mark this worker no longer alive so a timed shutdown knows.
  # A worker still running a never-returning body never reaches here -- which is
  # exactly what lets the timed shutdown detect it and detach instead of hang.
  if pool.alive != nil: discard pool.alive[].fetchSub(1, moAcquireRelease)

proc start*(pool: ptr WorkerPool, n: int, maxQueue = 0,
            alive: ptr Atomic[int] = nil) =
  initLock pool.lock
  initCond pool.cond
  pool.tasks = initDeque[WorkerTask]()
  pool.stopping = false
  pool.maxQueue = maxQueue
  pool.alive = alive
  pool.threads = newSeq[Thread[ptr WorkerPool]](n)
  for i in 0 ..< n:
    createThread(pool.threads[i], workerLoop, pool)

proc enqueue*(pool: ptr WorkerPool, task: WorkerTask) =
  acquire pool.lock
  pool.tasks.addLast task
  # Signal while holding the lock: queue overhead is noise here (blocking work
  # is ms-scale) and it keeps the condvar wakeup race-clean for helgrind.
  signal pool.cond
  release pool.lock

proc tryEnqueue*(pool: ptr WorkerPool, task: sink WorkerTask): bool =
  ## Enqueue unless the pool is closing or its backlog of not-yet-started tasks
  ## is at the configured cap (load shedding): when every worker is busy and the
  ## queue has backed up to maxQueue, reject so the caller can fail fast (503)
  ## instead of queuing unboundedly behind slow/stuck work. Returns false when
  ## rejected. maxQueue = 0 never rejects (unbounded, the default).
  acquire pool.lock
  if pool.stopping or (pool.maxQueue > 0 and pool.tasks.len >= pool.maxQueue):
    release pool.lock
    return false
  pool.tasks.addLast task
  signal pool.cond
  release pool.lock
  true

proc signalStop*(pool: ptr WorkerPool) =
  ## Ask workers to finish the queue and exit, WITHOUT joining. Idle workers wake
  ## and drain; a worker inside a never-returning body stays running. Lets a
  ## timed shutdown wake the pool, then decide (join vs detach) via `alive`.
  acquire pool.lock
  pool.stopping = true
  broadcast pool.cond          # under the lock (see enqueue)
  release pool.lock

proc shutdown*(pool: ptr WorkerPool) =
  ## Finish queued tasks, then stop and join the workers. Only safe to call once
  ## every worker has actually exited (see server.waitFor's timed wait); a worker
  ## stuck in a never-returning body would make joinThread block forever.
  pool.signalStop()
  for t in pool.threads.mitems:
    joinThread t
  # The pool is a manually-managed `ptr WorkerPool` (createShared), so
  # deallocShared frees only the struct, not these seq/deque payloads. Free
  # them here (setLen(0) would keep the buffer), or they leak per pool -- one
  # leak per served-then-closed server instance.
  reset(pool.threads)
  reset(pool.tasks)
  deinitLock pool.lock
  deinitCond pool.cond
