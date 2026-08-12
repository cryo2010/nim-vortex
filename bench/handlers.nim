## Benchmark server: TechEmpower-style /plaintext and /json handlers.
## Build: nimble bench   (or: nim c --mm:orc --threads:on -d:danger bench/handlers.nim)
## Pass cert/key paths as arguments to also serve TLS/h2/h3:
##   ./bench/handlers [port] [certFile keyFile]

import std/[os, strutils, httpcore]
import ../src/vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/plaintext":
    res.send(Http200, "Hello, World!")
  of "/json":
    res.send(Http200, """{"message":"Hello, World!"}""", %*{"Content-Type": "application/json"})
  else:
    res.send(Http404)

when isMainModule:
  let port = if paramCount() >= 1: Port(parseInt(paramStr(1))) else: Port(8080)
  var cert, key = ""
  if paramCount() >= 3:
    cert = paramStr(2)
    key = paramStr(3)
  echo "serving on port ", int(port),
       (if cert.len > 0: " (TLS + h2 + h3 enabled)" else: " (cleartext h1 + h2c)")
  newVortex(handler, initVortexConfig(port = port, certFile = cert, keyFile = key)).serve()
