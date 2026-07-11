## Worker pool for `blocking:` handler code. A plain mutex+condvar task
## queue: blocking work is milliseconds-scale, so queue overhead is noise
## here; the zero-overhead requirement applies to the event-loop fast
## path, which never touches this module.
##
## Tasks are plain-data structs (proc pointer + request handle words):
## nothing garbage-collected crosses threads. Closures must not be used
## here: ORC's cycle-collector registry is thread-local, so destroying a
## closure on a foreign thread corrupts it.

import std/[locks, deques]

type
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

  WorkerPool* = object
    lock: Lock
    cond: Cond
    tasks: Deque[WorkerTask]
    stopping: bool
    threads: seq[Thread[ptr WorkerPool]]

proc workerLoop(pool: ptr WorkerPool) {.thread.} =
  while true:
    acquire pool.lock
    while pool.tasks.len == 0 and not pool.stopping:
      wait(pool.cond, pool.lock)
    if pool.tasks.len == 0:
      release pool.lock
      return                       # stopping and drained
    var task = pool.tasks.popFirst()
    release pool.lock
    {.gcsafe.}:
      try:
        task.fn(task.user, task.core, task.fd, task.gen, task.stream,
                move task.data)
      except CatchableError:
        discard                    # trampoline already responded 500

proc start*(pool: ptr WorkerPool, n: int) =
  initLock pool.lock
  initCond pool.cond
  pool.tasks = initDeque[WorkerTask]()
  pool.stopping = false
  pool.threads = newSeq[Thread[ptr WorkerPool]](n)
  for i in 0 ..< n:
    createThread(pool.threads[i], workerLoop, pool)

proc enqueue*(pool: ptr WorkerPool, task: WorkerTask) =
  acquire pool.lock
  pool.tasks.addLast task
  release pool.lock
  signal pool.cond

proc shutdown*(pool: ptr WorkerPool) =
  ## Finish queued tasks, then stop the workers.
  acquire pool.lock
  pool.stopping = true
  release pool.lock
  broadcast pool.cond
  for t in pool.threads.mitems:
    joinThread t
  pool.threads.setLen(0)
  deinitLock pool.lock
  deinitCond pool.cond
