## tlsCipherList and tlsCipherSuites are preference ORDERS, not allow-sets
## (#375).
##
## SSL_CTX_set_options was never called with SSL_OP_SERVER_PREFERENCE (the
## OpenSSL >= 3.5 name for the bit also spelled SSL_OP_CIPHER_SERVER_PREFERENCE),
## so OpenSSL walked the *client's* list and took the first entry the server also
## allowed. An operator who wrote "AES256:AES128" to prefer AES-256 got AES-128
## on every connection from every client whose own list happened to start there:
## the ordering was accepted, applied, and silently inverted.
##
## Two things ride along with that option and are pinned here too.
##
## On OpenSSL >= 3.5 the same bit is documented as "when choosing a cipher,
## signature, (TLS 1.2) curve or (TLS 1.3) group, use the server's preferences",
## so group, curve and signature-algorithm selection follow the server's order as
## well. That is deliberate (the server decides) and free: the group list is
## OpenSSL's default unless an embedder configures one, and OpenSSL still uses a
## group the client sent a key share for, so no extra HelloRetryRequest appears.
##
## And when the operator configured *neither* list, the order being enforced is
## only OpenSSL's built-in one, so SSL_OP_PRIORITIZE_CHACHA is set: a client
## whose own first choice is ChaCha20-Poly1305 (the "no AES hardware" signal a
## phone sends) still gets it. Writing either list withholds that courtesy,
## because then the order IS a policy statement.
##
## These are real handshakes driven by `openssl s_client`, which offers the
## ciphers in the order given on its command line, so each case pits a server
## order against the opposite client order. Reverting the SSL_OP_SERVER_PREFERENCE
## line in buildTlsCtx fails every ordering check; reverting the
## SSL_OP_PRIORITIZE_CHACHA line fails the unconfigured-list ones.

import std/[unittest, os, osproc, strutils, httpcore, net, exitprocs]
import vortex/[settings, request, server]
import vortex/transport/tls as tlstransport
import ./helper

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"
  quit 0

let opensslBin = findExe("openssl")
if opensslBin.len == 0:
  echo "SKIP: need openssl"
  quit 0

# LibreSSL's s_client has -cipher but no -ciphersuites, so the TLS 1.3 half of
# this needs a real OpenSSL 1.1.1+ client. A stock macOS /usr/bin/openssl is
# LibreSSL; CI runs an Arch container whose CLI is OpenSSL 3.6, so nothing skips
# there.
let hasCiphersuitesFlag =
  "ciphersuites" in execCmdEx(opensslBin & " s_client -help 2>&1")[0]

# ... and LibreSSL's s_client labels the connection "TLSv1/SSLv3" in the
# "New, <proto>, Cipher is <name>" summary for every TLS 1.x version, where
# OpenSSL prints "TLSv1.2". Probe which CLI this is once, rather than letting the
# TLS 1.2 protocol assertions fail hard on a developer's Mac while the cipher
# assertions they guard pass. The assertion itself is kept: it is what pins
# maxTlsVersion = V12, and under either CLI it rules out a 1.3 handshake, which
# both spell "TLSv1.3".
let isLibreSsl =
  "libressl" in execCmdEx(opensslBin & " version 2>&1")[0].toLowerAscii

proc isTls12(proto: string): bool =
  proto == "TLSv1.2" or (isLibreSsl and proto == "TLSv1/SSLv3")

let (cert, key) = makeCertPair("vortex_cipherorder_")
let dir = cert.parentDir
# The fixture directory holds unencrypted private keys, so remove it on every
# exit path. A bare removeDir at the end of the module is skipped whenever an
# exception escapes a suite body (a failing `check` does not escape, but a raise
# from a server start or a context build does) and on an early `quit`; an exit
# proc covers both. Nim does not allow `defer` at module level.
addExitProc(proc() = removeDir(dir))

const
  # Two TLS 1.2 suites an RSA certificate can serve, and three TLS 1.3 suites.
  aes256 = "ECDHE-RSA-AES256-GCM-SHA384"
  aes128 = "ECDHE-RSA-AES128-GCM-SHA256"
  # RFC 7540 Appendix A blacklists this one (ECDHE, but CBC + HMAC, not AEAD):
  # an h2 client that sees it closes the connection with INADEQUATE_SECURITY.
  cbcSha = "ECDHE-RSA-AES128-SHA"
  # ... and this one, which is AEAD but has no forward secrecy (static RSA).
  staticAead = "AES256-GCM-SHA384"
  suite256 = "TLS_AES_256_GCM_SHA384"
  suite128 = "TLS_AES_128_GCM_SHA256"
  suiteChaCha = "TLS_CHACHA20_POLY1305_SHA256"

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

proc negotiated(port: Port, args: string): tuple[proto, cipher: string] =
  ## Drive one handshake and report the protocol and cipher s_client reports.
  ## A failed handshake shows up as a cipher of "(NONE)" (or "0000", in the
  ## SSL-Session block that only a TLS 1.2 connection prints here: under TLS 1.3
  ## the session arrives post-handshake, after `echo |` has closed stdin, so the
  ## "New, <proto>, Cipher is <name>" summary is the line both versions share).
  ##
  ## Bounded at 15 s. A handshake that wedges must fail the caller's check with a
  ## readable reason, not hang the suite (and with it CI) forever, so the client
  ## is killed at the deadline and the reason is reported in place of the cipher.
  ## Output goes to a file rather than a pipe, so a child killed mid-write cannot
  ## deadlock us on a full pipe buffer first.
  let outFile = dir / "sclient.out"
  let cmd = "echo | " & opensslBin & " s_client -connect 127.0.0.1:" & $port &
    " " & args & " >" & outFile & " 2>/dev/null"
  let p = startProcess("/bin/sh", args = ["-c", cmd], options = {})
  var waitedMs = 0
  const deadlineMs = 15_000
  while p.peekExitCode == -1 and waitedMs < deadlineMs:
    sleep 25
    waitedMs += 25
  let timedOut = p.peekExitCode == -1
  if timedOut:
    p.kill()
    discard p.waitForExit()
  p.close()
  let text = try: readFile(outFile) except CatchableError: ""
  removeFile(outFile)
  if timedOut:
    return ("timeout", "s_client did not finish within 15 s: " & args)
  for line in text.splitLines:
    let s = line.strip()
    const mark = ", Cipher is "
    if mark in s and result.cipher.len == 0:
      let parts = s.split(mark)
      result.proto = parts[0].rsplit(',', 1)[^1].strip()
      result.cipher = parts[1].strip()

template withServer(cfgExpr: VortexConfig, body: untyped) =
  var srv {.inject.} = newVortex(RequestHandler(handler), cfgExpr).start(0)
  try:
    body
  finally:
    srv.close()

proc buildRefused(reason: var string, cipherList = "", cipherSuites = "",
                  enableH2 = true, minProtoVersion: clong = 0): bool =
  ## Build a TLS context the way server start-up does and report whether it was
  ## refused, with the reason in `reason`.
  reason = ""
  try:
    let cfg = tlstransport.newTlsConfig(cert, key, enableH2 = enableH2,
                                        minProtoVersion = minProtoVersion,
                                        cipherList = cipherList,
                                        cipherSuites = cipherSuites)
    tlstransport.freeTlsConfig(cfg)
    false
  except CatchableError as e:
    reason = e.msg
    true

suite "TLS 1.2 cipher order is the server's (#375)":
  test "the server's first choice wins over the client's":
    # http3 = false goes with the TLS 1.2 ceiling: QUIC cannot negotiate below
    # 1.3, so the pair is refused rather than half-applied (#359).
    withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                http3 = false,
                                maxTlsVersion = TlsVersion.V12,
                                tlsCipherList = aes256 & ":" & aes128)):
      let r = negotiated(srv.port, "-tls1_2 -cipher '" & aes128 & ":" & aes256 & "'")
      check isTls12(r.proto)
      check r.cipher == aes256          # pre-fix: aes128, the client's order

  test "... and that is the server's order, not a fixed strength ranking":
    # The same client preference against the opposite server list: whatever the
    # operator wrote first is what is served.
    withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                http3 = false,
                                maxTlsVersion = TlsVersion.V12,
                                tlsCipherList = aes128 & ":" & aes256)):
      let r = negotiated(srv.port, "-tls1_2 -cipher '" & aes256 & ":" & aes128 & "'")
      check isTls12(r.proto)
      check r.cipher == aes128

  test "the list is still an allow-set: a client offering only the second gets it":
    # Server preference reorders the overlap, it does not narrow it. A client
    # that cannot do the preferred suite still connects on the other one.
    withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                http3 = false,
                                maxTlsVersion = TlsVersion.V12,
                                tlsCipherList = aes256 & ":" & aes128)):
      let r = negotiated(srv.port, "-tls1_2 -cipher '" & aes128 & "'")
      check r.cipher == aes128

suite "TLS 1.3 ciphersuite order is the server's (#375)":
  ## OpenSSL runs TLS 1.3 ciphersuite selection through the same preference pick
  ## as TLS 1.2, so one option covers tlsCipherSuites too.
  test "the server's first choice wins over the client's":
    if not hasCiphersuitesFlag:
      skip()   # LibreSSL s_client: no -ciphersuites
    else:
      withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                  minTlsVersion = TlsVersion.V13,
                                  tlsCipherSuites = suite256 & ":" & suiteChaCha)):
        let r = negotiated(srv.port,
          "-tls1_3 -ciphersuites '" & suiteChaCha & ":" & suite256 & "'")
        check r.proto == "TLSv1.3"
        check r.cipher == suite256      # pre-fix: ChaCha20, the client's order

  test "... and it follows the configured order when reversed":
    if not hasCiphersuitesFlag:
      skip()
    else:
      withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                  minTlsVersion = TlsVersion.V13,
                                  tlsCipherSuites = suiteChaCha & ":" & suite256)):
        let r = negotiated(srv.port,
          "-tls1_3 -ciphersuites '" & suite256 & ":" & suiteChaCha & "'")
        check r.proto == "TLSv1.3"
        check r.cipher == suiteChaCha

suite "an unconfigured list keeps the ChaCha courtesy (#375)":
  ## With neither tlsCipherList nor tlsCipherSuites set, the operator configured
  ## nothing, yet the order now being imposed is OpenSSL's own: AES-256-GCM,
  ## ChaCha20, AES-128-GCM. A client that offers ChaCha20-Poly1305 first is
  ## telling us it has no AES hardware, and moving it onto software AES on
  ## nobody's authority is both slower for it and more side-channel exposed.
  ## SSL_OP_PRIORITIZE_CHACHA keeps the server's order for everyone else and
  ## hands that client ChaCha, which is what Go's crypto/tls and the
  ## BoringSSL-based servers do by default.
  test "a ChaCha-first client gets ChaCha when no list is configured":
    if not hasCiphersuitesFlag:
      skip()
    else:
      withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                  minTlsVersion = TlsVersion.V13)):
        let r = negotiated(srv.port,
          "-tls1_3 -ciphersuites '" & suiteChaCha & ":" & suite256 & "'")
        check r.proto == "TLSv1.3"
        # Without SSL_OP_PRIORITIZE_CHACHA: TLS_AES_256_GCM_SHA384, OpenSSL's
        # default order forced onto a client that asked for the opposite.
        check r.cipher == suiteChaCha

  test "an AES-first client still gets the server's default order":
    # The courtesy is not a surrender: a client that leads with AES-128 does not
    # get AES-128, it gets the server's first choice, AES-256-GCM.
    if not hasCiphersuitesFlag:
      skip()
    else:
      withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                  minTlsVersion = TlsVersion.V13)):
        let r = negotiated(srv.port,
          "-tls1_3 -ciphersuites '" & suite128 & ":" & suite256 & "'")
        check r.proto == "TLSv1.3"
        check r.cipher == suite256

  test "a configured list withholds it, and either list is enough":
    # Once the operator wrote an order it is a policy statement, so a
    # ChaCha-first client must not be able to reorder it. tlsCipherSuites alone
    # withholds the courtesy for TLS 1.2 as well: one context, one policy.
    let plain = tlstransport.newTlsConfig(cert, key, enableH2 = true)
    defer: tlstransport.freeTlsConfig(plain)
    check tlstransport.ctxPrefersServerOrder(plain)
    check tlstransport.ctxPrioritizesChaCha(plain)

    let byList = tlstransport.newTlsConfig(cert, key, enableH2 = true,
                                           cipherList = aes256 & ":" & aes128)
    defer: tlstransport.freeTlsConfig(byList)
    check tlstransport.ctxPrefersServerOrder(byList)
    check not tlstransport.ctxPrioritizesChaCha(byList)

    let bySuites = tlstransport.newTlsConfig(cert, key, enableH2 = true,
                                             cipherSuites = suite256)
    defer: tlstransport.freeTlsConfig(bySuites)
    check tlstransport.ctxPrefersServerOrder(bySuites)
    check not tlstransport.ctxPrioritizesChaCha(bySuites)

suite "tlsCipherList is screened for HTTP/2 (#375)":
  ## New footgun from enforcing the order. RFC 7540 Appendix A blacklists every
  ## TLS 1.2 suite that is not an ephemeral-key AEAD one, and an h2 client that
  ## sees a blacklisted suite closes the connection with INADEQUATE_SECURITY
  ## (browsers show a protocol error). Before, a CBC-first tlsCipherList was
  ## quietly rescued by every real client's own AEAD-first order; now the server
  ## imposes it. Vortex used to check only that OpenSSL parsed the string, so the
  ## operator got a server that negotiates h2 on a cipher no browser accepts.
  test "a CBC-first list is refused at construction, with what to do about it":
    var reason: string
    check buildRefused(reason, cipherList = cbcSha & ":" & aes256)
    check "tlsCipherList must lead with an ECDHE/DHE AEAD suite" in reason
    check cbcSha in reason
    check "RFC 7540 Appendix A" in reason
    check "move an AEAD suite first or disable HTTP/2" in reason

  test "an AEAD-first list that also contains CBC suites is accepted":
    # The screen looks at the suite that will actually be chosen, not at the
    # whole list: a CBC entry further down is reached only by a client that
    # cannot do AEAD, and such a client is not an h2 client either.
    var reason: string
    check not buildRefused(reason, cipherList = aes256 & ":" & cbcSha & ":" & aes128)
    check reason == ""

  test "a non-ephemeral AEAD suite is refused too (no forward secrecy)":
    # RFC 7540 Appendix A keeps static-RSA AEAD suites on the blacklist as well,
    # so "is it AEAD" is not the whole test: the key exchange must be ECDHE/DHE.
    var reason: string
    check buildRefused(reason, cipherList = staticAead & ":" & aes256)
    check staticAead in reason

  test "it reaches the real server config path, not only the context builder":
    # What an operator actually trips over: initVortexConfig + newVortex.
    var raised = ""
    try:
      let srv = newVortex(RequestHandler(handler),
        initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                         http3 = false, maxTlsVersion = TlsVersion.V12,
                         tlsCipherList = cbcSha & ":" & aes256)).start(0)
      srv.close()
    except CatchableError as e:
      raised = e.msg
    check "RFC 7540 Appendix A" in raised

  test "no HTTP/2 on the context, no screen":
    # The suites are forbidden for h2 only. An HTTP/1.1-only listener may serve
    # one, so a context that does not advertise h2 is left alone.
    var reason: string
    check not buildRefused(reason, cipherList = cbcSha, enableH2 = false)

  test "a TLS 1.3-only version range skips the screen":
    # tlsCipherList cannot be reached at all then, so a stale value left in the
    # config must not refuse to start.
    var reason: string
    check not buildRefused(reason, cipherList = cbcSha,
                           minProtoVersion = tlstransport.TLS1_3_VERSION)

suite "per-host (SNI) contexts and the preference (#375)":
  test "the default context's copy governs an SNI connection too":
    ## What this proves: a connection the servername callback switched to a
    ## per-host certificate is still ordered by the server. It does NOT prove the
    ## per-host context's own option bit did it. SSL_set_SSL_CTX does not re-read
    ## options: a connection carries the option word SSL_new copied from the
    ## context it was created on, which is always the default one. This case
    ## would therefore pass even with buildSniCtxs' option missing, so the bit on
    ## the per-host contexts is asserted directly in the next test.
    genCert(dir / "api.pem", dir / "api.key", "api.example.com")
    withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                http3 = false,
                                maxTlsVersion = TlsVersion.V12,
                                tlsCipherList = aes256 & ":" & aes128,
                                sni = @[SniCertEntry(host: "api.example.com",
                                                     certFile: dir / "api.pem",
                                                     keyFile: dir / "api.key")])):
      let r = negotiated(srv.port, "-tls1_2 -servername api.example.com -cipher '" &
                                   aes128 & ":" & aes256 & "'")
      check r.cipher == aes256

  test "every per-host context carries the bit anyway":
    ## Defence in depth: inert at runtime today, for the reason above, and kept
    ## so a refactor that creates the SSL from the host context (rather than
    ## switching an existing one) cannot silently drop the policy.
    genCert(dir / "api.pem", dir / "api.key", "api.example.com")
    genCert(dir / "web.pem", dir / "web.key", "web.example.com")
    let cfg = tlstransport.newTlsConfig(cert, key, enableH2 = true,
      cipherList = aes256 & ":" & aes128,
      sni = @[
        SniCert(host: "api.example.com",
                material: TlsMaterial(certFile: dir / "api.pem",
                                      keyFile: dir / "api.key")),
        SniCert(host: "web.example.com",
                material: TlsMaterial(certFile: dir / "web.pem",
                                      keyFile: dir / "web.key"))])
    defer: tlstransport.freeTlsConfig(cfg)
    check tlstransport.sniCtxCount(cfg) == 2
    for i in 0 ..< 2:
      check tlstransport.sniCtxPrefersServerOrder(cfg, i)

  test "a per-host context is screened for HTTP/2 as well":
    # buildSniCtxs goes through buildTlsCtx with the same cipher list, so a
    # blacklisted lead is refused there too, named by host.
    genCert(dir / "api.pem", dir / "api.key", "api.example.com")
    var raised = ""
    try:
      let cfg = tlstransport.newTlsConfig(cert, key, enableH2 = true,
        cipherList = cbcSha & ":" & aes256,
        sni = @[SniCert(host: "api.example.com",
                        material: TlsMaterial(certFile: dir / "api.pem",
                                              keyFile: dir / "api.key"))])
      tlstransport.freeTlsConfig(cfg)
    except CatchableError as e:
      raised = e.msg
    check "RFC 7540 Appendix A" in raised
