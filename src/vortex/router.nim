## Optional path router: a segment tree with exact, `:param`/`{param}`,
## and trailing `*` wildcard matching. Handlers run on the loop threads,
## so the router is built once before `start` and never mutated after.

import std/[strutils, httpcore]
import ./request
import ./connection

type
  RouteNode = ref object
    segment: string           ## literal, or param name when isParam
    isParam: bool
    isWild: bool              ## trailing "*": matches the rest
    children: seq[RouteNode]
    handlers: array[HttpMethod, RequestHandler]
    streaming: array[HttpMethod, bool]  ## route registered via `stream`

  Router* = ref object
    root: RouteNode
    notFound*: RequestHandler ## default: plain 404

proc defaultNotFound(req: Request, res: Response) {.gcsafe.} =
  res.send(Http404, "404 Not Found", "text/plain")

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
               handler: RequestHandler) =
  router.addRouteNode(path).handlers[meth] = handler

proc stream*(router: Router, meth: HttpMethod, path: string,
             handler: RequestHandler) =
  ## Register a streaming route: its handler is dispatched at headers-complete
  ## (before the body) so it can `req.onBody(...)` to consume the body
  ## incrementally instead of it being buffered into `req.body`.
  let node = router.addRouteNode(path)
  node.handlers[meth] = handler
  node.streaming[meth] = true

proc get*(r: Router, path: string, h: RequestHandler) =
  r.addRoute(HttpGet, path, h)
proc post*(r: Router, path: string, h: RequestHandler) =
  r.addRoute(HttpPost, path, h)
proc put*(r: Router, path: string, h: RequestHandler) =
  r.addRoute(HttpPut, path, h)
proc delete*(r: Router, path: string, h: RequestHandler) =
  r.addRoute(HttpDelete, path, h)
proc patch*(r: Router, path: string, h: RequestHandler) =
  r.addRoute(HttpPatch, path, h)
proc head*(r: Router, path: string, h: RequestHandler) =
  r.addRoute(HttpHead, path, h)
proc options*(r: Router, path: string, h: RequestHandler) =
  r.addRoute(HttpOptions, path, h)

proc match(node: RouteNode, path: string, start: int,
           params: var PathParams): RouteNode =
  ## Recursive segment match: exact children win over params over wildcard.
  var i = start
  while i < path.len and path[i] == '/': inc i
  if i >= path.len:
    return node
  var j = i
  while j < path.len and path[j] != '/': inc j
  let seg = path.substr(i, j - 1)
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
      params.add ("*", path.substr(i))
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
  let h = node.handlers[req.method]
  if h == nil:
    # Path exists but not for this method.
    var any = false
    for m in HttpMethod:
      if node.handlers[m] != nil:
        any = true
        break
    if any:
      res.send(HttpCode(405), "405 Method Not Allowed", "text/plain")
    else:
      router.notFound(req, res)
    return
  if params.len > 0:
    req.setParams(move params)
  h(req, res)

proc toHandler*(router: Router): RequestHandler =
  ## Adapt a router into the server's RequestHandler. The router is
  ## GC-pinned: it is shared read-only across loop threads for the
  ## process lifetime.
  GC_ref(router)
  let r = router
  proc (req: Request, res: Response) {.gcsafe.} =
    {.gcsafe.}:
      r.route(req, res)

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
