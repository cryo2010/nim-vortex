## Declare which request bodies stream, independent of any router.
##
## Inbound body streaming (dispatch the handler at headers-complete so it can
## `req.onBody(...)` instead of buffering into `req.body`) is decided by a
## predicate the loop consults before the body arrives. The router is one way
## to produce that predicate (`router.streamPredicate`); this module is the
## router-free way. Everything here yields a `StreamRouteCb` for
## `start(handler, settings, streamRoute = ...)`.
##
## A `nil` predicate (an empty `StreamRoutes`) keeps the buffered fast path at
## zero cost, so opting in never taxes routes that don't stream.

import std/[httpcore, strutils]
import ./connection
import ./request

type
  StreamPredicate* = proc(req: Request): bool {.gcsafe.}
    ## A request-level streaming test. The loop core holds the lower-level
    ## handle-word `StreamRouteCb` (connection.nim can't see `Request` without
    ## an import cycle), so predicates written against `Request` are bridged to
    ## it here.

  StreamRoutes* = ref object
    ## An accumulating set of streaming rules: the router-free analog of
    ## `router.stream`, minus the handler. Streaming is a property of the
    ## request, not of whichever proc ends up handling it.
    rules: seq[StreamPredicate]

proc newStreamRoutes*(): StreamRoutes = StreamRoutes()

proc pathOnly(req: Request): string =
  ## The request path with any `?query` stripped.
  result = req.path
  let q = result.find('?')
  if q >= 0: result.setLen(q)

proc stream*(s: StreamRoutes, meth: HttpMethod, path: string) =
  ## Stream the body of `meth path` (exact path, query ignored).
  let m = meth
  let want = path
  s.rules.add(proc(req: Request): bool {.gcsafe.} =
    req.method == m and req.pathOnly == want)

proc streamPath*(s: StreamRoutes, path: string) =
  ## Stream the body of any method for exactly `path` (query ignored).
  let want = path
  s.rules.add(proc(req: Request): bool {.gcsafe.} = req.pathOnly == want)

proc streamWhen*(s: StreamRoutes, pred: StreamPredicate) =
  ## Stream requests for which `pred` returns true (method / path / headers).
  s.rules.add pred

proc predicate*(s: StreamRoutes): StreamRouteCb =
  ## Fold the rules into a single `StreamRouteCb`. Returns nil when there are
  ## no rules, so the server keeps the buffered fast path at zero cost. The
  ## `StreamRoutes` is GC-pinned: it (and its rule closures) are shared
  ## read-only across the loop threads for the process lifetime.
  if s.rules.len == 0: return nil
  GC_ref(s)
  let rules = s.rules
  proc(core: ptr LoopCore, fd: int32, gen: uint32,
       stream: uint32): bool {.gcsafe.} =
    let req = Request(core: core, fd: fd, gen: gen, stream: stream)
    for r in rules:
      if r(req): return true
    false

# --- one-liner combinators for the common cases -----------------------------

proc streamWhen*(pred: StreamPredicate): StreamRouteCb =
  ## Stream requests matching an arbitrary predicate.
  let s = newStreamRoutes()
  s.streamWhen(pred)
  s.predicate

proc streamAll*(): StreamRouteCb =
  ## Stream every request body (a proxy, or a pure upload service).
  let s = newStreamRoutes()
  s.streamWhen(proc(req: Request): bool {.gcsafe.} = true)
  s.predicate

proc streamPaths*(paths: varargs[string]): StreamRouteCb =
  ## Stream any request whose path (query ignored) exactly matches one of
  ## `paths`, for any method.
  let s = newStreamRoutes()
  for p in paths: s.streamPath(p)
  s.predicate
