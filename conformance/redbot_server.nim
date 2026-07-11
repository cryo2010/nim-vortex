## Server under test for the REDbot conformance check (conformance/run.sh).
##
## REDbot (https://redbot.org, https://github.com/mnot/redbot) lints a
## single HTTP resource: it re-requests the URL under many conditions
## (conditional GET, ranges, compression, connection reuse, HEAD, ...)
## and reports protocol problems. vortex is a low-level server, so
## caching/validators are the application's job; these handlers supply a
## realistic, conformant set so REDbot exercises the interesting paths
## instead of only noting their absence.
##
## Endpoints:
##   /       text/plain, cacheable, with an ETag + Last-Modified and full
##           conditional handling (returns 304 to a matching validator).
##   /json   application/json, cacheable.
##   *       404.

import std/[os, strutils, httpcore]
import ../src/vortex

const
  etag = "\"v1-hello\""
  lastModified = "Sun, 06 Jul 2025 12:00:00 GMT"
  cacheControl = "max-age=60"

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.url.path
  of "/":
    # Honor conditional requests so REDbot can validate the 304 path.
    if req.header("if-none-match") == etag or
       req.header("if-modified-since") == lastModified:
      res.send(Http304, "", "", @{"ETag": etag,
                                   "Last-Modified": lastModified,
                                   "Cache-Control": cacheControl})
    else:
      res.send(Http200, "Hello, World!\n", "text/plain",
               @{"ETag": etag,
                 "Last-Modified": lastModified,
                 "Cache-Control": cacheControl})
  of "/json":
    res.send(Http200, """{"message":"Hello, World!"}""", "application/json",
             @{"Cache-Control": cacheControl})
  else:
    res.send(Http404, "not found\n", "text/plain")

when isMainModule:
  let port = if paramCount() >= 1: Port(parseInt(paramStr(1))) else: Port(8099)
  echo "redbot conformance server on http://127.0.0.1:", int(port), "/"
  run(handler, initSettings(port = port, numThreads = 1))
