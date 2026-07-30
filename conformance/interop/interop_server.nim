## Target server for the cross-client interop test (conformance/interop/run.sh,
## `nimble interop`). Real clients from five ecosystems (Node, Python, Go, Rust,
## Java) hammer it over HTTP/2 + TLS with gzip, exercising every method. Built
## into a Docker image by conformance/interop/Dockerfile with
## `-d:ssl -d:httpGzip` so gzip response compression is available.
##
## Endpoints (all behind the api-key middleware):
##   /echo   - every method; echoes the method + request body, padded so the
##             response is gzip-eligible. Sets X-Echo-Method.
##   /whoami - returns the mTLS client-cert subject ("-" if none).
##
## Env: INTEROP_MTLS=1 requires a client cert (verified against /vortex/ca.pem).

import std/[os, strutils]
import vortex

proc methodToken(m: HttpMethod): string =
  case m
  of HttpGet: "GET"
  of HttpPost: "POST"
  of HttpPut: "PUT"
  of HttpPatch: "PATCH"
  of HttpDelete: "DELETE"
  of HttpHead: "HEAD"
  of HttpOptions: "OPTIONS"
  else: "OTHER"

proc echoHandler(req: Request, res: Response) {.gcsafe.} =
  # Echo the method and any request body, then pad so the response is well over
  # the gzip threshold and highly compressible (proves gzip end-to-end).
  let m = methodToken(req.method)
  var body = "method=" & m & "\n"
  if req.body.len > 0:
    body.add "body=" & req.body & "\n"
  body.add "pad ".repeat(400)          # ~1.6 KiB, very compressible
  res.send(Http200, body, "text/plain", @[("x-echo-method", m)])

proc whoami(req: Request, res: Response) {.gcsafe.} =
  let s = req.clientCertSubject
  res.send(Http200, (if s.len > 0: s else: "-"), "text/plain")

# The router is pinned in a global and dispatched from a top-level proc, so the
# server's handler is a plain proc with a nil closure environment. A capturing
# closure (e.g. `middleware(r.toHandler)`) would have its env copied into every
# per-core loop thread at startup, racing the non-atomic ORC refcount on that
# shared env across threads -- a rare corruption that can later surface as a
# SIGSEGV under load. A nil-env top-level proc sidesteps it, matching the
# proven-stable pattern the other conformance servers use.
var appRouter: Router

proc dispatch(req: Request, res: Response) {.gcsafe.} =
  # api-key gating middleware, then route. `appRouter` is set before start()
  # and GC-pinned, then read-only across threads, so the access is safe.
  if req.header("x-api-key") != "interop":
    res.send(HttpCode(401), "missing or bad x-api-key", "text/plain")
  else:
    {.gcsafe.}: appRouter.route(req, res)

when isMainModule:
  appRouter = newRouter()
  for m in [HttpGet, HttpPost, HttpPut, HttpPatch, HttpDelete, HttpHead,
            HttpOptions]:
    appRouter.addRoute(m, "/echo", echoHandler)   # no auto-OPTIONS: register each
  appRouter.get("/whoami", whoami)
  GC_ref(appRouter)   # pin for the process lifetime; shared read-only by loops

  # Certs are generated once by run.sh and mounted read-only at /certs, shared
  # by every container so they trust a common CA.
  var s = initSettings(port = Port(8443), numThreads = 0,
                       certFile = "/certs/cert.pem", keyFile = "/certs/key.pem",
                       http3 = false,        # this test is h1/h2 over TLS
                       compress = true)      # gzip (needs -d:httpGzip build)
  if getEnv("INTEROP_MTLS") == "1":
    s.verifyClient = cvRequire
    s.clientCaFile = "/certs/ca.pem"

  var srv = start(dispatch, s)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
