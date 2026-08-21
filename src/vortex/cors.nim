## CORS (Cross-Origin Resource Sharing) as a middleware.
##
##   var app = newVortex()
##   app.use(cors(initCorsOptions(origins = @["https://app.example"])))
##
## On a request whose Origin is allowed it adds the `Access-Control-Allow-*`
## response headers; a CORS preflight (an `OPTIONS` carrying
## `Access-Control-Request-Method`) is answered directly with 204 and does not
## reach the route. Non-CORS requests pass through untouched.

import std/[strutils, httpcore]
import ./request
import ./routing

type
  CorsOptions* = object
    origins*: seq[string]        ## allowed origins; `@["*"]` = any. Otherwise an
                                 ## exact-match allowlist (echoed back per request)
    methods*: seq[string]        ## Access-Control-Allow-Methods (preflight)
    headers*: seq[string]        ## Access-Control-Allow-Headers (preflight); empty
                                 ## echoes the client's requested headers
    exposeHeaders*: seq[string]  ## Access-Control-Expose-Headers
    allowCredentials*: bool      ## Access-Control-Allow-Credentials: true
    maxAge*: int                 ## Access-Control-Max-Age seconds; < 0 omits it

proc initCorsOptions*(origins = @["*"],
                      methods = @["GET", "HEAD", "POST", "PUT", "PATCH",
                                  "DELETE", "OPTIONS"],
                      headers: seq[string] = @[],
                      exposeHeaders: seq[string] = @[],
                      allowCredentials = false,
                      maxAge = -1): CorsOptions =
  ## CORS settings. The default is permissive (`origins = @["*"]`, no
  ## credentials); tighten `origins` for a browser app that sends credentials
  ## (a wildcard origin is invalid together with credentials, so with
  ## `allowCredentials = true` the request's Origin is echoed instead).
  CorsOptions(origins: origins, methods: methods, headers: headers,
              exposeHeaders: exposeHeaders, allowCredentials: allowCredentials,
              maxAge: maxAge)

proc isAllowed(opts: CorsOptions, origin: string): bool =
  for o in opts.origins:
    if o == "*" or o == origin: return true
  false

proc cors*(opts = initCorsOptions()): Middleware =
  ## A middleware applying `opts`. Register with `router.use(cors(...))`.
  let opts = opts
  proc (next: RequestHandler): RequestHandler {.gcsafe.} =
    let inner = next
    proc (req: Request, res: Response) {.gcsafe.} =
      let origin = req.origin
      let allowed = origin.len > 0 and opts.isAllowed(origin)
      if allowed:
        # A specific allowlist or credentials must echo the Origin (and Vary on
        # it); only anonymous any-origin may use the literal "*".
        if opts.origins == @["*"] and not opts.allowCredentials:
          res.headers["Access-Control-Allow-Origin"] = "*"
        else:
          res.headers["Access-Control-Allow-Origin"] = origin
          res.headers.add("Vary", "Origin")
        if opts.allowCredentials:
          res.headers["Access-Control-Allow-Credentials"] = "true"
        if opts.exposeHeaders.len > 0:
          res.headers["Access-Control-Expose-Headers"] = opts.exposeHeaders.join(", ")

      # Preflight: an OPTIONS carrying Access-Control-Request-Method. Answer it
      # here (terminal) so it never falls through to a route or the auto-OPTIONS.
      if req.method == HttpOptions and
         req.header("access-control-request-method").len > 0:
        if allowed:
          res.headers["Access-Control-Allow-Methods"] = opts.methods.join(", ")
          let ah = if opts.headers.len > 0: opts.headers.join(", ")
                   else: req.header("access-control-request-headers")
          if ah.len > 0:
            res.headers["Access-Control-Allow-Headers"] = ah
          if opts.maxAge >= 0:
            res.headers["Access-Control-Max-Age"] = $opts.maxAge
          res.send(HttpCode(204), "")
        else:
          res.send(HttpCode(403), "")   # origin not permitted
        return

      inner(req, res)
