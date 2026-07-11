## Optional path router: a segment tree with exact, `:param`/`{param}`,
## and trailing `*` wildcard matching. Handlers run on the loop threads,
## so the router is built once before `start` and never mutated after.

import std/[strutils, httpcore]
import ./request

type
  RouteNode = ref object
    segment: string           ## literal, or param name when isParam
    isParam: bool
    isWild: bool              ## trailing "*": matches the rest
    children: seq[RouteNode]
    handlers: array[HttpMethod, RequestHandler]

  Router* = ref object
    root: RouteNode
    notFound*: RequestHandler ## default: plain 404

proc defaultNotFound(req: Request, res: Response) {.gcsafe.} =
  res.send(Http404, "404 Not Found", "text/plain")

proc newRouter*(): Router =
  Router(root: RouteNode(), notFound: defaultNotFound)

proc addRoute*(router: Router, meth: HttpMethod, path: string,
               handler: RequestHandler) =
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
  node.handlers[meth] = handler

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
