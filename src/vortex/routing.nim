## Optional path router: a segment tree with exact, `:param`/`{param}`,
## and trailing `*` wildcard matching. Handlers run on the loop threads,
## so the router is built once before `start` and never mutated after.

import std/[strutils, httpcore, uri]
import ./request
import ./connection

proc decodeSegment(s: string): string =
  ## Percent-decode one path segment for matching and param capture (RFC 3986):
  ## `/users/j%6Fhn` matches a literal `john` and `req.param` returns decoded
  ## text. `+` is left as-is (it is form encoding, not path). The trailing `*`
  ## wildcard is captured raw (see match): decoding it would silently turn an
  ## encoded `%2F`/`%2e%2e` into path structure, a traversal footgun the app
  ## must resolve deliberately.
  if '%' notin s: return s          # fast path: nothing to decode
  try: decodeUrl(s, decodePlus = false)
  except CatchableError: s

type
  RouteNode = ref object
    segment: string           ## literal, or param name when isParam
    isParam: bool
    isWild: bool              ## trailing "*": matches the rest
    children: seq[RouteNode]
    handlers: array[HttpMethod, RequestHandler]
    streaming: array[HttpMethod, bool]  ## route registered via `stream`

  Middleware* = proc(next: RequestHandler): RequestHandler {.gcsafe.}
    ## Wraps a handler: run code before/after `next(req, res)`, or skip `next`
    ## to short-circuit (e.g. auth sending 401). Registered with `router.use`.

  Router* = ref object
    root: RouteNode
    notFound*: RequestHandler ## default: plain 404
    middleware: seq[Middleware]

  RouteConflictError* = object of CatchableError
    ## Raised at registration when the same (method, path) is registered twice
    ## (directly or via a sub-router mount). A route table is built once at
    ## startup, so a duplicate is a programming error worth failing hard on
    ## rather than silently letting the last registration win.

proc defaultNotFound(req: Request, res: Response) {.gcsafe.} =
  res.send(Http404, "404 Not Found")

proc newRouter*(): Router =
  Router(root: RouteNode(), notFound: defaultNotFound)

proc addRouteNode(router: Router, path: string): RouteNode =
  var node = router.root
  for rawSeg in path.split('/'):
    if rawSeg.len == 0: continue
    var seg = rawSeg
    var isParam = false
    var isWild = false
    if seg == "*":
      isWild = true
    elif seg[0] == ':':
      isParam = true
      seg = seg.substr(1)
    elif seg.len > 1 and seg[0] == '{' and seg[^1] == '}':
      isParam = true
      seg = seg[1 ..< ^1]
    var next: RouteNode = nil
    for child in node.children:
      if child.isWild == isWild and child.isParam == isParam and
          (isParam or isWild or child.segment == seg):
        next = child
        break
    if next == nil:
      next = RouteNode(segment: seg, isParam: isParam, isWild: isWild)
      node.children.add next
    node = next
    if isWild: break
  node

proc addRoute*(router: Router, meth: HttpMethod, path: string,
               handler: RequestHandler, streaming = false) =
  ## Register `handler` for `meth path`. With `streaming = true` the handler is
  ## dispatched at headers-complete (before the body) so it can `req.onBody(...)`
  ## to consume the body incrementally instead of it being buffered into
  ## `req.body`; only meaningful for body-bearing methods (POST/PUT/PATCH).
  let node = router.addRouteNode(path)
  if node.handlers[meth] != nil:
    raise newException(RouteConflictError,
      "duplicate route: " & $meth & " " & path & " is already registered")
  node.handlers[meth] = handler
  node.streaming[meth] = streaming

proc use*(r: Router, mw: Middleware) =
  ## Register a middleware. Middleware run in registration order (the first
  ## `use`d is outermost, so it runs first on the way in and last on the way
  ## out) and wrap every route, including the 404/405 responses. Call before
  ## `toHandler`; order relative to route registration does not matter. A
  ## middleware that reads `req.body` is only meaningful for buffered routes
  ## (a `stream` route has no body yet when it is dispatched).
  r.middleware.add mw

proc use*(parent: Router, prefix: string, child: Router) =
  ## Mount `child`'s routes under `prefix`: `parent.use("/users", userRouter)`
  ## makes the child's `/:id` reachable at `/users/:id`. Routes are merged into
  ## `parent`'s tree at registration time (no per-request delegation, and the
  ## child's `:param`/`*` carry over). The child's own `use` middleware wraps
  ## just its routes; `parent`'s middleware still wraps everything. This is a
  ## snapshot: fully configure `child` before mounting, and mount before
  ## `toHandler`.
  proc wrap(h: RequestHandler): RequestHandler =
    result = h                                   # no child middleware -> unchanged
    for i in countdown(child.middleware.high, 0):
      result = child.middleware[i](result)
  proc walk(node: RouteNode, path: string) =
    for m in HttpMethod:
      if node.handlers[m] != nil:
        parent.addRoute(m, prefix & path, wrap(node.handlers[m]), node.streaming[m])
    for c in node.children:
      let seg = if c.isWild: "*" elif c.isParam: ":" & c.segment else: c.segment
      walk(c, path & "/" & seg)
  walk(child.root, "")

proc get*(r: Router, path: string, h: RequestHandler, streaming = false) =
  r.addRoute(HttpGet, path, h, streaming)
proc post*(r: Router, path: string, h: RequestHandler, streaming = false) =
  r.addRoute(HttpPost, path, h, streaming)
proc put*(r: Router, path: string, h: RequestHandler, streaming = false) =
  r.addRoute(HttpPut, path, h, streaming)
proc delete*(r: Router, path: string, h: RequestHandler, streaming = false) =
  r.addRoute(HttpDelete, path, h, streaming)
proc patch*(r: Router, path: string, h: RequestHandler, streaming = false) =
  r.addRoute(HttpPatch, path, h, streaming)
proc head*(r: Router, path: string, h: RequestHandler, streaming = false) =
  r.addRoute(HttpHead, path, h, streaming)
proc options*(r: Router, path: string, h: RequestHandler, streaming = false) =
  r.addRoute(HttpOptions, path, h, streaming)

proc match(node: RouteNode, path: string, start: int,
           params: var PathParams): RouteNode =
  ## Recursive segment match: exact children win over params over wildcard.
  var i = start
  while i < path.len and path[i] == '/': inc i
  if i >= path.len:
    return node
  var j = i
  while j < path.len and path[j] != '/': inc j
  let seg = decodeSegment(path.substr(i, j - 1))
  # Exact matches first.
  for child in node.children:
    if not child.isParam and not child.isWild and child.segment == seg:
      let found = match(child, path, j, params)
      if found != nil: return found
  for child in node.children:
    if child.isParam:
      params.add (child.segment, seg)
      let found = match(child, path, j, params)
      if found != nil: return found
      params.setLen(params.len - 1)
  for child in node.children:
    if child.isWild:
      params.add ("*", path.substr(i))   # raw remainder (see decodeSegment)
      return child
  nil

proc route*(router: Router, req: Request, res: Response) {.gcsafe.} =
  ## Look up and invoke the handler for a request; captured route
  ## parameters become req.params.
  var path = req.path
  let q = path.find('?')
  if q >= 0: path.setLen(q)
  var params: PathParams
  let node = router.root.match(path, 0, params)
  if node == nil:
    router.notFound(req, res)
    return
  var h = node.handlers[req.method]
  if h == nil and req.method == HttpHead:
    h = node.handlers[HttpGet]   # HEAD falls back to GET; the codec drops the body
  if h == nil:
    # Path exists but not for this method. Build the Allow header (RFC 9110
    # 10.2.1 / 15.5.6): the methods this resource supports, plus HEAD wherever
    # GET is and OPTIONS (which the router answers automatically).
    var allow: seq[string]
    for m in HttpMethod:
      if node.handlers[m] != nil: allow.add $m
    if allow.len == 0:
      router.notFound(req, res)                 # intermediate node, no handlers
      return
    if node.handlers[HttpGet] != nil and "HEAD" notin allow:
      allow.add "HEAD"                          # HEAD is served wherever GET is
    if "OPTIONS" notin allow:
      allow.add "OPTIONS"                        # answered automatically below
    if req.method == HttpOptions:
      # Automatic OPTIONS: a bodiless 204 advertising the allowed methods. An
      # explicitly registered OPTIONS handler wins (h would be non-nil above).
      res.send(HttpCode(204), "", @{"Allow": allow.join(", ")})
    else:
      res.send(HttpCode(405), "405 Method Not Allowed",
               @{"Allow": allow.join(", ")})
    return
  if params.len > 0:
    req.setParams(move params)
  h(req, res)

proc toHandler*(router: Router): RequestHandler =
  ## Adapt a router into the server's RequestHandler. The router is
  ## GC-pinned: it is shared read-only across loop threads for the
  ## process lifetime. Any middleware registered with `use` is folded around
  ## the route dispatch here (first registered = outermost).
  GC_ref(router)
  let r = router
  var h: RequestHandler = proc (req: Request, res: Response) {.gcsafe.} =
    {.gcsafe.}:
      r.route(req, res)
  for i in countdown(r.middleware.high, 0):
    h = r.middleware[i](h)
  h

proc hasStreamRoutes*(router: Router): bool =
  ## True if any route was registered with `stream`; used to skip installing
  ## the streaming predicate (and its per-request cost) when there are none.
  proc walk(n: RouteNode): bool =
    for m in HttpMethod:
      if n.streaming[m]: return true
    for c in n.children:
      if walk(c): return true
    false
  walk(router.root)

proc streamPredicate*(router: Router): StreamRouteCb =
  ## The `LoopCore.streamRoute` predicate for this router: matches the request
  ## path/method and reports whether that route is streaming. Returns nil if
  ## the router has no streaming routes, so the server keeps the buffered fast
  ## path at zero cost. Pass to `start(handler, settings, streamRoute = ...)`.
  if not router.hasStreamRoutes: return nil
  GC_ref(router)
  let r = router
  proc (core: ptr LoopCore, fd: int32, gen: uint32,
        stream: uint32): bool {.gcsafe.} =
    {.gcsafe.}:
      let req = Request(core: core, fd: fd, gen: gen, stream: stream)
      var path = req.path
      let q = path.find('?')
      if q >= 0: path.setLen(q)
      var params: PathParams
      let node = r.root.match(path, 0, params)
      if node == nil: return false
      node.streaming[req.method]
