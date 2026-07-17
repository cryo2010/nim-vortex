## HTTP/3 (QUIC) certificate hot-reload. The cross-thread reload signal
## (CertReload) is pure and always tested. The in-place ctx update
## (reloadQuicCert) and a full http3 server surviving a reload need OpenSSL's
## QUIC server API, so they're skipped when it isn't available on the host.
##
## The actual cert *presented* over h3 is verified by CI's curl-h3 suite (which
## exercises the per-loop QUIC ctx); locally there is no h3 client that reports
## the peer certificate.

import std/[unittest, os, osproc, net, httpcore, strutils]
import std/httpclient except Response
import vortex/[settings, request, server]
import vortex/transport/tls
import vortex/transport/quic

let dir = getTempDir() / "vortex_h3reload_" & $getCurrentProcessId()
createDir(dir)
proc gen(cert, key, cn: string) =
  let (o, rc) = execCmdEx(
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout " & key &
    " -out " & cert & " -days 2 -subj /CN=" & cn)
  doAssert rc == 0, "cert gen failed: " & o

let certA = dir / "a.pem"
let keyA = dir / "akey.pem"
gen(certA, keyA, "alpha.vortex")

# Detect QUIC support once.
var quicOk = false
try:
  let c = newQuicConfig(certA, keyA)
  quicOk = c != nil
  if c != nil: freeTlsConfig(c)
except CatchableError:
  quicOk = false

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

suite "reloadQuicCert (in-place update)":
  test "accepts a valid cert, rejects missing and mismatched":
    if not quicOk:
      skip()
    else:
      let cfg = newQuicConfig(certA, keyA)
      check cfg != nil
      if cfg != nil:
        defer: freeTlsConfig(cfg)
        # ctxCertSubject reads the cert actually installed on the QUIC ctx, so
        # these assertions prove the in-place reload reached the ctx (new h3
        # connections read that ctx at accept, the same way the TCP suite proves
        # end to end via s_client).
        check "alpha.vortex" in ctxCertSubject(cfg)      # initial cert
        let certB = dir / "b.pem"
        let keyB = dir / "bkey.pem"
        gen(certB, keyB, "bravo.vortex")
        check reloadQuicCert(cfg, certB, keyB)           # valid swap
        check "bravo.vortex" in ctxCertSubject(cfg)      # ctx now holds it
        check not reloadQuicCert(cfg, dir / "nope.pem", dir / "nope.key")
        check "bravo.vortex" in ctxCertSubject(cfg)      # unchanged on failure
        check not reloadQuicCert(cfg, certA, keyB)       # cert/key mismatch
        check reloadQuicCert(cfg, "", "")                # re-read current paths

suite "http3 server survives a certificate reload":
  test "TCP cert swaps and the server keeps serving with h3 enabled":
    if not quicOk:
      skip()
    else:
      var srv = start(RequestHandler(proc(req: Request, res: Response) {.gcsafe.} =
                        res.send(Http200, "ok", "text/plain")),
                      initSettings(port = Port(0), numThreads = 2,
                                   certFile = certA, keyFile = keyA,
                                   http3 = true))
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
      gen(certC, keyC, "charlie.vortex")
      check srv.reloadTls(certC, keyC)      # TCP + signals h3 loops
      sleep(1500)                           # let the loop ticks apply the h3 swap
      check "charlie.vortex" in cn()         # TCP presents the new cert
      check served()                         # and the server is still up

removeDir(dir)
echo "h3 cert reload ok (quic=", quicOk, ")"
