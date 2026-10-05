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

proc h3HostSubject(port: Port, host: string): string =
  ## The same, for a request that sends `host` as its SNI name (resolved back to
  ## loopback), so the per-host certificate selection is what is being read.
  if h3curlBin.len == 0: return ""
  let (output, _) = execCmdEx(
    h3curlBin & " -sv -k -m 10 -o /dev/null --http3-only --resolve " & host &
    ":" & $port & ":127.0.0.1 https://" & host & ":" & $port & "/ 2>&1")
  for line in output.splitLines:
    let l = line.strip(chars = {' ', '*', '\t'})
    if l.startsWith("subject:"): return l
  ""

proc tcpHostSubject(port: Port, host: string): string =
  execCmdEx("echo | openssl s_client -connect 127.0.0.1:" & $port &
            " -servername " & host &
            " 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")[0]

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

  test "the replacement per-host set rides the same signal":
    # The sni override used to stop at the TCP listener: the loops were told the
    # cert/key paths alone, so a host added through reloadTls(sni = ...) was
    # served the default certificate over h3 (#356). The set now travels as a
    # serialised blob published with the generation.
    let r = createShared(CertReload)
    initCertReload(r)
    defer:
      deinitCertReload(r)
      deallocShared(r)
    var seen = 0
    var cf, kf: string
    var sni: seq[SniCert]
    requestCertReload(r, "", "", @[
      SniCert(host: "a.example.com", material: TlsMaterial(
        certFile: "/x/a.pem", keyFile: "/x/a.key")),
      SniCert(host: "b.example.com", material: TlsMaterial(
        certPem: "PEM-BYTES", keyPem: "KEY-BYTES", keyPassword: "pw"))])
    let g1 = pendingCertReload(r, seen, cf, kf, sni)
    check g1 == 1
    check sni.len == 2
    check sni[0].host == "a.example.com"
    check sni[0].material.certFile == "/x/a.pem"
    check sni[0].material.keyFile == "/x/a.key"
    check sni[1].host == "b.example.com"
    check sni[1].material.certPem == "PEM-BYTES"
    check sni[1].material.keyPem == "KEY-BYTES"
    check sni[1].material.keyPassword == "pw"
    seen = g1
    # The next request replaces it, and an empty set decodes to @[], which every
    # consumer reads as "keep the configured per-host material".
    requestCertReload(r, "/x/c.pem", "/x/c.key")
    check pendingCertReload(r, seen, cf, kf, sni) == 2
    check cf == "/x/c.pem" and sni.len == 0

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


suite "reloadTls(sni = ...) rotates the h3 per-host set too (#356)":
  ## The override replaced the TCP listener's per-host material and nothing
  ## else: the h3 loops were signalled with the cert/key paths alone and
  ## rebuilt their host contexts from the material they were configured with.
  ## A host added here was therefore served the DEFAULT certificate over h3 and
  ## every client that followed Alt-Svc failed on a name mismatch (the #374 bug
  ## again, for any host configured after startup), while a host removed here
  ## kept being served its old certificate over h3 for the life of the process.
  test "a host added by the override is served over h3, the old one is not":
    let certS = dir / "s.pem"
    let keyS = dir / "skey.pem"
    genCert(certS, keyS, "default.vortex")
    genCert(dir / "one.pem", dir / "one.key", "one.vortex")
    genCert(dir / "two.pem", dir / "two.key", "two.vortex")
    var srv = newVortex(RequestHandler(proc(req: Request, res: Response) {.gcsafe.} =
                      res.send(Http200, "ok")),
                      initVortexConfig(numThreads = 2, certFile = certS,
                                       keyFile = keyS, http3 = true,
                                       sni = @[SniCertEntry(
                                         host: "one.example.com",
                                         certFile: dir / "one.pem",
                                         keyFile: dir / "one.key")])).start(0)
    defer: srv.close()
    check "one.vortex" in tcpHostSubject(srv.port, "one.example.com")
    if h3curlBin.len > 0:
      check "one.vortex" in h3HostSubject(srv.port, "one.example.com")
      check "default.vortex" in h3HostSubject(srv.port, "two.example.com")
    # Replace the set: one.example.com goes away and two.example.com arrives
    # with material that only ever exists in memory, which is the case a file
    # re-read on the h3 side could never have covered.
    check srv.reloadTls(sni = @[SniCertEntry(
      host: "two.example.com", certPem: readFile(dir / "two.pem"),
      keyPem: readFile(dir / "two.key"))])
    sleep(1500)                                  # let every loop tick apply it
    check "two.vortex" in tcpHostSubject(srv.port, "two.example.com")
    check "default.vortex" in tcpHostSubject(srv.port, "one.example.com")
    if h3curlBin.len > 0:
      check "two.vortex" in h3HostSubject(srv.port, "two.example.com")
      # The dropped host falls back to the default certificate on h3 as well,
      # instead of being served its retired certificate indefinitely.
      check "default.vortex" in h3HostSubject(srv.port, "one.example.com")
      check "default.vortex" in h3Subject(srv.port)
    else:
      echo "    (h3 assertions skipped: no HTTP/3-capable curl)"

removeDir(dir)
echo "h3 cert reload ok"
