## Target web app for the OWASP ZAP baseline scan (conformance/zap/run.sh,
## `nimble zap`). ZAP's baseline is a passive scan: it spiders the site and
## inspects responses for security issues, chief among them missing security
## response headers. So this server does two things the trivial conformance
## servers do not:
##
##   * serves a few cross-linked HTML pages so the spider has a surface to
##     crawl (a single endpoint gives the passive scanner almost nothing), and
##   * sets a hardened set of security headers on *every* response, which is
##     what ZAP checks and what run.sh's rule config promotes to FAIL.
##
## Plain HTTP on 8080 (a -d:plainHttp build, no OpenSSL): the scan runs over a
## private docker network, and ZAP's HTTPS-only rules (e.g. HSTS) are ignored
## in the rule config rather than exercised here. Built by conformance/zap/
## Dockerfile.

import std/os
import vortex

# The response headers ZAP's passive rules look for. Sent on every response so
# no page trips a finding. CSP `default-src 'none'` locks sub-resource loads
# down to nothing (these pages need none), and the frame-ancestors / X-Frame
# pair is the anti-clickjacking control. The Cross-Origin-* trio is the site
# isolation (Spectre) hardening ZAP rule 90004 wants.
const secHeaders = @{
  "Content-Security-Policy":
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; " &
    "form-action 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cache-Control": "no-store"
}

proc page(title, bodyHtml: string): string =
  ## A minimal, self-contained HTML document (no inline scripts or styles, so
  ## it stays within the strict CSP above).
  "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" &
  "<title>" & title & "</title></head><body>" & bodyHtml & "</body></html>"

proc hIndex(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, page("vortex",
    "<h1>vortex</h1><p>OWASP ZAP baseline target.</p><ul>" &
    "<li><a href=\"/about\">About</a></li>" &
    "<li><a href=\"/health\">Health</a></li></ul>"),
    secHeaders & @[("Content-Type", "text/html; charset=utf-8")])

proc hAbout(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, page("about",
    "<h1>About</h1><p>A fast HTTP/1.1, HTTP/2 and HTTP/3 server.</p>" &
    "<p><a href=\"/\">Home</a></p>"),
    secHeaders & @[("Content-Type", "text/html; charset=utf-8")])

proc hHealth(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "{\"status\":\"ok\"}",
           secHeaders & @[("Content-Type", "application/json")])

when isMainModule:
  var router = newRouter()
  router.get("/", hIndex)
  router.get("/about", hAbout)
  router.get("/health", hHealth)
  # start() binds before returning, so the "listening" log line is the
  # readiness signal for run.sh.
  var srv = newVortex(router.toHandler, initVortexConfig(numThreads = 1)).start(8080)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
