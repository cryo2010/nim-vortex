## nim_http_server: a fast HTTP/1.1 (and, coming, HTTP/2 + HTTP/3) server.
##
## ```nim
## import nim_http_server
##
## proc handler(req: Request) =
##   case req.path
##   of "/": req.respond(Http200, "Hello, World!", "text/plain")
##   else: req.respond(Http404)
##
## run(handler, initSettings(port = Port(8080)))
## ```

import std/httpcore
import std/net

import nim_http_server/settings
import nim_http_server/request
import nim_http_server/server
import nim_http_server/router

export httpcore
export net.Port
export settings
export request
export server
export router
