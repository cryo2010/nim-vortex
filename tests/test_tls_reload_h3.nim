## HTTP/3 (QUIC) certificate hot-reload. The cross-thread reload signal
## (CertReload) is pure and always tested. The full-server reload (a running h3
## server surviving a TCP+h3 cert swap) needs ngtcp2/nghttp3, which a TLS build
## links, so it runs whenever this suite is built (i.e. not -d:plainHttp).
##
## The certificate actually *presented* over h3 is read back with an
## HTTP/3-capable curl where one is installed (findH3Curl); the rest of the
## suite runs without it, checking that the server keeps serving and that the
## TCP side presents the new certificate.

import std/[unittest, os, osproc, net, httpcore, strutils]
import std/httpclient except Response
import vortex/[settings, request, server]
import vortex/transport/tls
import ./helper

let h3curlBin = findH3Curl()   # "" when no HTTP/3-capable curl is installed

proc h3Subject(port: Port): string =
  ## The certificate subject an HTTP/3 handshake is served, per curl -v.
  if h3curlBin.len == 0: return ""
  let (output, _) = execCmdEx(
    h3curlBin & " -sv -k -m 10 -o /dev/null --http3-only https://127.0.0.1:" &
    $port & "/ 2>&1")
  for line in output.splitLines:
    let l = line.strip(chars = {' ', '*', '\t'})
    if l.startsWith("subject:"): return l
  ""

let dir = getTempDir() / "vortex_h3reload_" & $getCurrentProcessId()
createDir(dir)
let certA = dir / "a.pem"
let keyA = dir / "akey.pem"
genCert(certA, keyA, "alpha.vortex")

suite "QUIC cert reload signaling":
  test "request/pending carries paths and advances the generation":
    let r = createShared(CertReload)
    initCertReload(r)
    defer:
      deinitCertReload(r)
      deallocShared(r)
    var seen = 0
    var cf, kf: string
    check pendingCertReload(r, seen, cf, kf) == 0        # nothing pending yet
    requestCertReload(r, "/x/cert.pem", "/x/key.pem")
    let g1 = pendingCertReload(r, seen, cf, kf)
    check g1 == 1
    check cf == "/x/cert.pem" and kf == "/x/key.pem"
    seen = g1                                            # caller advances on act
    check pendingCertReload(r, seen, cf, kf) == seen      # consumed, no change
    requestCertReload(r, "", "")                         # empty => configured
    check pendingCertReload(r, seen, cf, kf) == 2
    check cf == "" and kf == ""

suite "http3 server survives a certificate reload":
  test "TCP cert swaps and the server keeps serving with h3 enabled":
    var srv = newVortex(RequestHandler(proc(req: Request, res: Response) {.gcsafe.} =
                      res.send(Http200, "ok")), initVortexConfig(numThreads = 2, certFile = certA, keyFile = keyA, http3 = true)).start(0)
    defer: srv.close()
    let port = $srv.port
    proc served(): bool =
      var c = newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))
      defer: c.close()
      try: c.getContent("https://127.0.0.1:" & port & "/") == "ok"
      except CatchableError: false
    proc cn(): string =
      let (o, _) = execCmdEx("echo | openssl s_client -connect 127.0.0.1:" &
        port & " 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")
      o
    check served()
    check "alpha.vortex" in cn()
    let certC = dir / "c.pem"
    let keyC = dir / "ckey.pem"
    genCert(certC, keyC, "charlie.vortex")
    check srv.reloadTls(certC, keyC)      # TCP + signals h3 loops
    sleep(1500)                           # let the loop ticks apply the h3 swap
    check "charlie.vortex" in cn()         # TCP presents the new cert
    check served()                         # and the server is still up
    if h3curlBin.len > 0:
      check "charlie.vortex" in h3Subject(srv.port)

suite "a bare reloadTls() rotates the h3 certificate too (#353)":
  ## The certbot pattern: renew in place, then srv.reloadTls() with no
  ## arguments. Nothing resolved the configured paths on the QUIC side (the loop
  ## called readFile("")), so HTTP/1.1 and HTTP/2 picked up the new certificate
  ## and HTTP/3 kept serving the one loaded at startup until it expired -- a
  ## protocol-specific outage 90 days after deployment.
  test "overwriting the configured files and reloading rotates both transports":
    let certR = dir / "r.pem"
    let keyR = dir / "rkey.pem"
    genCert(certR, keyR, "renew-before.vortex")
    var srv = newVortex(RequestHandler(proc(req: Request, res: Response) {.gcsafe.} =
                      res.send(Http200, "ok")),
                      initVortexConfig(numThreads = 2, certFile = certR,
                                       keyFile = keyR, http3 = true)).start(0)
    defer: srv.close()
    proc tcpSubject(): string =
      execCmdEx("echo | openssl s_client -connect 127.0.0.1:" & $srv.port &
                " 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")[0]
    check "renew-before.vortex" in tcpSubject()
    if h3curlBin.len > 0:
      check "renew-before.vortex" in h3Subject(srv.port)
    genCert(certR, keyR, "renew-after.vortex")   # certbot, in place
    check srv.reloadTls()                        # no arguments at all
    sleep(1500)                                  # let every loop tick apply it
    check "renew-after.vortex" in tcpSubject()
    if h3curlBin.len > 0:
      check "renew-after.vortex" in h3Subject(srv.port)

  test "a server configured from certPem keeps serving across a bare reload":
    # No files to re-read, so the rebuild is a no-op for the material. It must
    # still report success rather than failing the renewal hook.
    let certP = dir / "p.pem"
    let keyP = dir / "pkey.pem"
    genCert(certP, keyP, "inmem.vortex")
    var srv = newVortex(RequestHandler(proc(req: Request, res: Response) {.gcsafe.} =
                      res.send(Http200, "ok")),
                      initVortexConfig(numThreads = 2,
                                       certPem = readFile(certP),
                                       keyPem = readFile(keyP),
                                       http3 = true)).start(0)
    defer: srv.close()
    check srv.reloadTls()
    sleep(1500)
    var c = newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))
    defer: c.close()
    check c.getContent("https://127.0.0.1:" & $srv.port & "/") == "ok"
    if h3curlBin.len > 0:
      check "inmem.vortex" in h3Subject(srv.port)

removeDir(dir)
echo "h3 cert reload ok"
