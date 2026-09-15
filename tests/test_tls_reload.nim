## TLS certificate hot-reload: srv.reloadTls swaps the cert presented to new
## HTTPS handshakes without a restart, from explicit paths or by re-reading the
## configured files in place (certbot-style renewal). A bad reload is rejected
## and leaves the running cert untouched.

import std/[unittest, net, httpcore, os, osproc, strutils]
import std/httpclient except Response
import vortex/[settings, request, server]
import ./helper

let dir = getTempDir() / "vortex_tls_reload_" & $getCurrentProcessId()
createDir(dir)
let liveCert = dir / "cert.pem"          # the "live" path (renewed in place)
let liveKey  = dir / "key.pem"
let altCert  = dir / "alt.pem"
let altKey   = dir / "altkey.pem"

genCert(liveCert, liveKey, "alpha.vortex")

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

proc servedCNOn(p: string): string =
  ## servedCN, parameterized by port (the OCSP suite uses a second server).
  let (o, _) = execCmdEx(
    "echo | openssl s_client -connect 127.0.0.1:" & p &
    " -servername localhost 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
  result = o.strip()

proc stillServesOn(p: string): bool =
  var c = newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))
  defer: c.close()
  try: c.getContent("https://127.0.0.1:" & p & "/") == "ok"
  except CatchableError: false

suite "TLS certificate hot-reload":
  test "serves the initial certificate":
    check "alpha.vortex" in servedCN()

  test "reload with no args re-reads the configured paths (in-place renewal)":
    # Overwrite the configured files in place, as certbot would, then reload.
    genCert(liveCert, liveKey, "bravo.vortex")
    check srv.reloadTls()
    check "bravo.vortex" in servedCN()
    check stillServes()

  test "reload from explicit new paths swaps the presented cert":
    genCert(altCert, altKey, "charlie.vortex")
    check srv.reloadTls(altCert, altKey)
    check "charlie.vortex" in servedCN()
    check stillServes()

  test "a bad reload is rejected and keeps the running cert":
    check not srv.reloadTls(dir / "nope.pem", dir / "nope.key")
    check "charlie.vortex" in servedCN()      # unchanged
    check stillServes()

  test "reload with a cert/key mismatch is rejected":
    genCert(dir / "delta.pem", dir / "deltakey.pem", "delta.vortex")
    check not srv.reloadTls(dir / "delta.pem", liveKey)  # cert + wrong key
    check "charlie.vortex" in servedCN()

srv.close()
removeDir(dir)

# --- OCSP staple rotation across reload ---------------------------------------
# The staple rotates through the same reloadTls path as the certificate: a new
# ctx carries its own immutable OCSP blob. OpenSSL's server drops a stapled OCSP
# response whose serial does not match the served leaf (confirmed against
# `openssl s_server -status_file`), so each staple is paired with its own cert:
# rotating the staple means rotating cert+staple together, and the client sees
# the response serial equal the served cert's serial. These assert the rotated
# staple is served (serial + "successful"), that a same-cert empty-arg reload
# preserves and re-reads the staple, that a bad explicit ocspFile is rejected
# without breaking serving, and that clearOcsp drops the staple.

let odir = getTempDir() / "vortex_ocsp_reload_" & $getCurrentProcessId()
removeDir(odir); createDir(odir)

proc statusOut(port: string): string =
  ## Full `s_client -status` transcript (lowercased): both the "OCSP Response
  ## Status" line and the response body, where the serial is printed.
  execCmdEx("echo | openssl s_client -status -connect 127.0.0.1:" & port &
    " 2>/dev/null").output.toLowerAscii

suite "OCSP staple rotation across reload":
  # One CA; two distinct-serial certs, each with a matching staple.
  let haveOpenssl = findExe("openssl").len > 0
  var serialA, serialB: string
  if haveOpenssl:
    genOcspCa(odir)
    genSignedCert(odir, "certA", "localhost")
    genSignedCert(odir, "certB", "localhost")
    serialA = mintOcsp(odir, "certA", "respA")   # respA -> certA's serial
    serialB = mintOcsp(odir, "certB", "respB")   # respB -> certB's serial

  if not haveOpenssl or serialA.len == 0 or serialB.len == 0 or
     serialA == serialB:
    test "OCSP rotation (skipped: openssl cannot mint distinct responses)":
      skip()
  else:
    var osrv = newVortex(RequestHandler(handler), initVortexConfig(
      numThreads = 1, certFile = odir / "certA.pem", keyFile = odir / "certA.key",
      ocspFile = odir / "respA.der")).start(0)
    let oport = $osrv.port

    test "initial staple A is served":
      let o = statusOut(oport)
      check "ocsp response status: successful" in o
      check serialA.toLowerAscii in o

    test "reloadTls(cert+ocspFile) rotates cert and staple to B":
      check osrv.reloadTls(odir / "certB.pem", odir / "certB.key",
                           ocspFile = odir / "respB.der")
      let o = statusOut(oport)
      check serialB.toLowerAscii in o
      check serialA.toLowerAscii notin o          # A no longer stapled
      check "cn=localhost" in servedCNOn(oport).toLowerAscii  # serving cert B
      check stillServesOn(oport)

    test "cert-only reload preserves the current staple (B)":
      # No ocsp args and the stored path is respB.der (unchanged on disk), so
      # the re-read yields B again: a cert renewal keeps the staple.
      check osrv.reloadTls()
      let o = statusOut(oport)
      check serialB.toLowerAscii in o

    test "empty-arg reload re-reads the stored ocspFile in place":
      # Re-mint respB.der in place (a fresh signing of the same cert, so a new
      # response body for the same serial); a bare reload must re-read the file,
      # proving the staple comes from disk each time, not a startup-frozen copy.
      let reminted = mintOcsp(odir, "certB", "respB")
      check reminted == serialB
      check osrv.reloadTls()
      let o = statusOut(oport)
      check "ocsp response status: successful" in o
      check serialB.toLowerAscii in o

    test "a bad explicit ocspFile rejects the reload, staple unaffected":
      check not osrv.reloadTls(ocspFile = odir / "nope.der")
      let o = statusOut(oport)
      check "ocsp response status: successful" in o   # still stapling B's bytes
      check serialB.toLowerAscii in o
      check stillServesOn(oport)

    test "clearOcsp drops the staple, server still serves":
      check osrv.reloadTls(clearOcsp = true)
      let o = statusOut(oport)
      check "ocsp response status: successful" notin o
      check stillServesOn(oport)

    osrv.close()

removeDir(odir)
echo "tls reload ok"
