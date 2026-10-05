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

suite "a rejected reload records why":
  # reloadTlsConfig used to catch the exception carrying the only diagnostic
  # that existed and return a bare false, and reloadTls passed that on with
  # nothing written anywhere, so an operator whose certbot deploy hook failed
  # had no way to learn whether the cert was unreadable, the key mismatched,
  # the OCSP file was missing or the cipher string was rejected (#378).
  test "a missing cert file leaves the path or the OpenSSL reason":
    check not srv.reloadTls(dir / "nope.pem", dir / "nope.key")
    let reason = srv.lastTlsReloadError
    check reason.len > 0
    check "unknown TLS error" notin reason
    check ("nope.pem" in reason or "No such file" in reason or
           "no such file" in reason.toLowerAscii)

  test "a cert/key mismatch names the mismatch":
    check not srv.reloadTls(dir / "delta.pem", liveKey)
    check "mismatch" in srv.lastTlsReloadError

  test "contradictory OCSP arguments are named":
    check not srv.reloadTls(clearOcsp = true, ocspResponse = "x")
    check "clearOcsp" in srv.lastTlsReloadError

  test "an unreadable explicit ocspFile names the path":
    check not srv.reloadTls(ocspFile = dir / "nostaple.der")
    check "nostaple.der" in srv.lastTlsReloadError

  test "a successful reload clears the reason":
    check srv.reloadTls(altCert, altKey)
    check srv.lastTlsReloadError == ""
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

# --- SNI across a certificate reload -----------------------------------------
# reloadTlsConfig rebuilds the default ctx, so every callback the initial build
# installed on the old one has to be installed on the replacement. It used to
# re-register only ALPN, which dropped the servername callback: from the first
# reload onwards every configured SNI host was served the *default* certificate
# and failed the handshake on a name mismatch, until the process restarted
# (#355). Both paths now go through one helper so they cannot drift again.

let sdir = getTempDir() / "vortex_tls_reload_sni_" & $getCurrentProcessId()
removeDir(sdir); createDir(sdir)
genCert(sdir / "def.pem", sdir / "def.key", "default.vortex")
genCert(sdir / "host.pem", sdir / "host.key", "alt.vortex")

# http3 = false keeps the assertions about the TCP listener: the h3 engine
# reloads asynchronously on its own loop tick, and test_tls_reload_h3.nim is
# where that path is covered.
var ssrv = newVortex(RequestHandler(handler), initVortexConfig(
  numThreads = 1, certFile = sdir / "def.pem", keyFile = sdir / "def.key",
  http3 = false,
  sni = @[SniCertEntry(host: "alt.vortex", certFile: sdir / "host.pem",
                       keyFile: sdir / "host.key")])).start(0)
let sport = $ssrv.port

proc sniSubject(servername: string): string =
  let (o, _) = execCmdEx(
    "echo | openssl s_client -connect 127.0.0.1:" & sport &
    " -servername " & servername &
    " 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
  result = o.strip()

suite "SNI across a certificate reload":
  test "the per-host certificate is served before any reload":
    check "alt.vortex" in sniSubject("alt.vortex")
    check "default.vortex" in sniSubject("other.vortex")

  test "the servername callback survives a reload":
    check ssrv.reloadTls()
    check "alt.vortex" in sniSubject("alt.vortex")        # not the default cert
    check "default.vortex" in sniSubject("other.vortex")
    check stillServesOn(sport)

  test "and survives a second one (the helper is used on every rebuild)":
    genCert(sdir / "def.pem", sdir / "def.key", "default2.vortex")
    check ssrv.reloadTls()
    check "default2.vortex" in sniSubject("other.vortex")  # default rotated
    check "alt.vortex" in sniSubject("alt.vortex")          # SNI still routed

suite "per-host SNI certificates rotate on reload":
  # Before #356 the per-host ctxs were built once and never rebuilt, so every
  # SNI host served the certificate it loaded at startup for the lifetime of
  # the process and eventually served an expired one, with no API to rotate it
  # short of a restart.
  test "a bare reloadTls re-reads the per-host certificate files":
    # The certbot pattern: the per-host files are renewed in place and the
    # deploy hook calls reloadTls() with no arguments.
    genCert(sdir / "host.pem", sdir / "host.key", "alt2.vortex")
    check ssrv.reloadTls()
    check "alt2.vortex" in sniSubject("alt.vortex")   # the renewed per-host cert
    check "default2.vortex" in sniSubject("other.vortex")   # default untouched
    check stillServesOn(sport)

  test "reloadTls(sni = ...) installs new in-memory per-host material":
    genCert(sdir / "mem.pem", sdir / "mem.key", "alt3.vortex")
    check ssrv.reloadTls(sni = @[SniCertEntry(host: "alt.vortex",
      certPem: readFile(sdir / "mem.pem"), keyPem: readFile(sdir / "mem.key"))])
    check "alt3.vortex" in sniSubject("alt.vortex")
    check "default2.vortex" in sniSubject("other.vortex")
    check stillServesOn(sport)

  test "the sni override can add a host":
    genCert(sdir / "extra.pem", sdir / "extra.key", "extra.vortex")
    check ssrv.reloadTls(sni = @[
      SniCertEntry(host: "alt.vortex", certPem: readFile(sdir / "mem.pem"),
                   keyPem: readFile(sdir / "mem.key")),
      SniCertEntry(host: "extra.vortex", certFile: sdir / "extra.pem",
                   keyFile: sdir / "extra.key")])
    check "alt3.vortex" in sniSubject("alt.vortex")
    check "extra.vortex" in sniSubject("extra.vortex")
    check "default2.vortex" in sniSubject("other.vortex")

  test "a bad per-host certificate rejects the whole reload":
    # All-or-nothing with the default ctx: the default must not rotate either,
    # or the server would be left half-rotated with no way to tell.
    genCert(sdir / "def.pem", sdir / "def.key", "default3.vortex")
    writeFile(sdir / "bad.pem", "-----BEGIN CERTIFICATE-----\nnot a cert\n")
    check not ssrv.reloadTls(sni = @[
      SniCertEntry(host: "alt.vortex", certFile: sdir / "bad.pem",
                   keyFile: sdir / "extra.key")])
    check "alt3.vortex" in sniSubject("alt.vortex")          # per-host unchanged
    check "extra.vortex" in sniSubject("extra.vortex")       # and the other host
    check "default2.vortex" in sniSubject("other.vortex")    # default unchanged
    check stillServesOn(sport)
    check "alt.vortex" in ssrv.lastTlsReloadError            # names the host

  test "a per-host file that disappears rejects a bare reload too":
    removeFile(sdir / "extra.pem")
    check not ssrv.reloadTls()
    check "default2.vortex" in sniSubject("other.vortex")    # default unchanged
    check "alt3.vortex" in sniSubject("alt.vortex")
    check stillServesOn(sport)

  test "a good reload after the rejection still works":
    # The rejected attempt persisted nothing, so the stored material is the one
    # that worked and a corrected reload rotates from it.
    genCert(sdir / "extra.pem", sdir / "extra.key", "extra2.vortex")
    check ssrv.reloadTls()
    check "default3.vortex" in sniSubject("other.vortex")    # now it rotates
    check "extra2.vortex" in sniSubject("extra.vortex")

ssrv.close()
removeDir(sdir)
echo "tls reload ok"
