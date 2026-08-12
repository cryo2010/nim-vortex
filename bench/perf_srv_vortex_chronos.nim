## vortex served through the chronos adapter, isolated in its own module:
## the asyncdispatch and chronos adapters both re-export `Future`/`async`/
## `toHandler`, so they cannot share a module scope. The orchestrator in
## perf_http1_1 pulls in only `serveOursChronos` via `from ... import`.

import std/[net, httpcore]
import ../src/vortex
import ../src/vortex/chronos as nhschronos

proc serveOursChronos*(port: int, doAwait: bool) =
  ## Through the chronos adapter: the chronos counterpart to
  ## serveOursAsync, measuring the chronos future/adapter tax. `doAwait`
  ## forces a real suspend/resume per request (worst case on pipelined
  ## HTTP/1.1); otherwise the handler answers without suspending.
  proc immediate(req: vortex.Request, res: vortex.Response): Future[void] {.async.} =
    vortex.send(res, Http200, "Hello, World!")
  proc suspending(req: vortex.Request, res: vortex.Response): Future[void] {.async.} =
    await sleepAsync(ZeroDuration)       # force a real suspend/resume
    vortex.send(res, Http200, "Hello, World!")
  let handler =
    if doAwait: nhschronos.toHandler(suspending)
    else: nhschronos.toHandler(immediate)
  newVortex(handler,
    vortex.initVortexConfig(port = net.Port(port), numThreads = 0)).serve()
