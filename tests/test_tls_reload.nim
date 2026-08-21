## TLS certificate hot-reload: srv.reloadTls swaps the cert presented to new
## HTTPS handshakes without a restart, from explicit paths or by re-reading the
## configured files in place (certbot-style renewal). A bad reload is rejected
## and leaves the running cert untouched.

import std/[unittest, net, httpcore, os, osproc, strutils]
import std/httpclient except Response
import vortex/[settings, request, server]

let dir = getTempDir() / "vortex_tls_reload_" & $getCurrentProcessId()
createDir(dir)
let liveCert = dir / "cert.pem"          # the "live" path (renewed in place)
let liveKey  = dir / "key.pem"
let altCert  = dir / "alt.pem"
let altKey   = dir / "altkey.pem"

proc gen(cert, key, cn: string) =
  let (o, rc) = execCmdEx(
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout " & key &
    " -out " & cert & " -days 2 -subj /CN=" & cn)
  check rc == 0

gen(liveCert, liveKey, "alpha.vortex")

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 2, certFile = liveCert, keyFile = liveKey)).start(0)
let port = $srv.port

proc servedCN(): string =
  ## The CN of the certificate the server currently presents, via s_client.
  let (o, _) = execCmdEx(
    "echo | openssl s_client -connect 127.0.0.1:" & port &
    " -servername localhost 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
  result = o.strip()

proc stillServes(): bool =
  var c = newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))
  defer: c.close()
  try: c.getContent("https://127.0.0.1:" & port & "/") == "ok"
  except CatchableError: false

suite "TLS certificate hot-reload":
  test "serves the initial certificate":
    check "alpha.vortex" in servedCN()

  test "reload with no args re-reads the configured paths (in-place renewal)":
    # Overwrite the configured files in place, as certbot would, then reload.
    gen(liveCert, liveKey, "bravo.vortex")
    check srv.reloadTls()
    check "bravo.vortex" in servedCN()
    check stillServes()

  test "reload from explicit new paths swaps the presented cert":
    gen(altCert, altKey, "charlie.vortex")
    check srv.reloadTls(altCert, altKey)
    check "charlie.vortex" in servedCN()
    check stillServes()

  test "a bad reload is rejected and keeps the running cert":
    check not srv.reloadTls(dir / "nope.pem", dir / "nope.key")
    check "charlie.vortex" in servedCN()      # unchanged
    check stillServes()

  test "reload with a cert/key mismatch is rejected":
    gen(dir / "delta.pem", dir / "deltakey.pem", "delta.vortex")
    check not srv.reloadTls(dir / "delta.pem", liveKey)  # cert + wrong key
    check "charlie.vortex" in servedCN()

srv.close()
removeDir(dir)
echo "tls reload ok"
