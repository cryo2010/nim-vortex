## vortex: a fast HTTP/1.1, HTTP/2, and HTTP/3 server.
##
## ```nim
## import vortex
##
## proc hello(req: Request, res: Response) =
##   res.send(Http200, "Hello, World!")
##
## var app = newVortex()
## app.get("/", hello)
## app.serve(8080)
## ```

import std/httpcore
import std/net
import std/json

import vortex/settings
import vortex/request
import vortex/server
import vortex/routing
import vortex/streaming
import vortex/staticfiles
import vortex/ratelimit

export httpcore
export net.Port
export json                 ## so req.json / res.send(json) are usable without a separate import
export settings
export request except dispatchBlockingData  # internal (staticfiles); use req.blocking
export server
export routing
export streaming
export staticfiles
export ratelimit

# --- App entry point: a router you build up, then serve --------------------
# `newVortex()` returns a `Router`; register routes with get/post/... and
# `serve`/`start` it. The inbound-streaming predicate is wired for you, so
# `streaming = true` routes work without threading `streamRoute` by hand.

proc newVortex*(): Router =
  ## Start an app: a `Router` to register routes on, then `serve` or `start`.
  ##
  ##   var app = newVortex()
  ##   app.get("/", hello)
  ##   app.serve(8080)
  ##
  ## For a single handler with no routing, `newVortex(handler)` also works.
  newRouter()

proc start*(r: Router, port = -1, address = "",
            config = initVortexConfig()): Vortex {.discardable.} =
  ## Bind a server built from the router and return it (non-blocking). The
  ## streaming-route predicate is wired automatically.
  newVortex(r.toHandler, config, r.streamPredicate).start(port, address)

proc serve*(r: Router, port = -1, address = "", config = initVortexConfig()) =
  ## Serve the router forever (see `start` for the non-blocking form).
  newVortex(r.toHandler, config, r.streamPredicate).serve(port, address)
