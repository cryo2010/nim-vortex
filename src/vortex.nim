## vortex: a fast HTTP/1.1 (and, coming, HTTP/2 + HTTP/3) server.
##
## ```nim
## import vortex
##
## proc handler(req: Request, res: Response) =
##   case req.path
##   of "/": res.send(Http200, "Hello, World!", "text/plain")
##   else: res.send(Http404)
##
## run(handler, initSettings(port = Port(8080)))
## ```

import std/httpcore
import std/net

import vortex/settings
import vortex/request
import vortex/server
import vortex/router

export httpcore
export net.Port
export settings
export request
export server
export router
