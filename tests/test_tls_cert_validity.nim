## Certificate validity (notBefore/notAfter) is checked when material is
## installed, on both transports and at both startup and hot reload (#379).
##
## Nothing checked it before: an expired certificate loaded cleanly, so a
## renewal hook racing a certbot symlink swap, or a script pointing at
## `archive/` instead of `live/`, got `reloadTls() == true` and reported
## success while every new connection failed at the client with
## certificate_expired. The policy is a hard failure with no clock-skew
## allowance: startup refuses to come up and a reload keeps the running
## certificate.
##
## The dated fixtures need `openssl req -x509 -not_before/-not_after`
## (OpenSSL 3.5+); the suite skips cleanly without it.

import std/[unittest, os, osproc, net, httpcore, strutils, base64]
import std/httpclient except Response
import vortex/[settings, request, server]
import ./helper

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"
  quit 0

let dir = getTempDir() / "vortex_certvalid_" & $getCurrentProcessId()
removeDir(dir); createDir(dir)

proc mintDated(cert, key, cn, notBefore, notAfter: string): bool =
  ## A self-signed cert whose validity window is stated explicitly. False when
  ## the installed openssl does not take -not_before/-not_after.
  execCmdEx("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & key &
            " -out " & cert & " -subj /CN=" & cn &
            " -not_before " & notBefore & " -not_after " & notAfter)[1] == 0

let expiredCert = dir / "expired.pem"
let expiredKey = dir / "expired.key"
let futureCert = dir / "future.pem"
let futureKey = dir / "future.key"
let haveDated =
  mintDated(expiredCert, expiredKey, "expired.vortex",
            "20200101000000Z", "20200102000000Z") and
  mintDated(futureCert, futureKey, "future.vortex",
            "20400101000000Z", "20400102000000Z")

let goodCert = dir / "good.pem"
let goodKey = dir / "good.key"
genCert(goodCert, goodKey, "good.vortex")

let h3curlBin = findH3Curl()   # "" when no HTTP/3-capable curl is installed

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

proc startupError(cert, key: string, http3 = false): string =
  ## The message starting a server on this material raises, or "" if it came up.
  try:
    var srv = newVortex(RequestHandler(handler),
                        initVortexConfig(certFile = cert, keyFile = key,
                                         http3 = http3)).start(0)
    srv.close()
    ""
  except CatchableError as e:
    e.msg

# --- a validity time that cannot be parsed at all ----------------------------
# X509_cmp_current_time answers <0 for past, >0 for future and 0 ONLY on
# failure: an exact equality is reported as -1, so 0 means an ASN.1 time it
# could not read. The check used to compare `< 0` and `> 0` and so treated that
# 0 as "inside the window", installing a certificate on the strength of a
# comparison that never happened. OpenSSL loads such a certificate without
# complaint (its own x509 command prints `notAfter=Bad time value` for it), so
# this is reachable, not theoretical.

let badTimeCert = dir / "badtime.pem"
let badTimeKey = dir / "badtime.key"

proc mintUnparsableNotAfter(cert, key: string): bool =
  ## A certificate whose notAfter is a well-formed UTCTime string that is not a
  ## real time (month 13). Rewritten straight into the DER, keeping the field's
  ## length, so nothing else has to be re-encoded and the key still matches; the
  ## signature no longer does, which is irrelevant to a self-signed leaf being
  ## loaded as server material.
  genCert(cert, key, "badtime.vortex")
  var b64 = ""
  for line in readFile(cert).splitLines:
    if not line.startsWith("-----"): b64.add line.strip()
  var der = decode(b64)
  var at = -1                          # the second UTCTime is notAfter
  var seen = 0
  for i in 0 ..< der.len - 15:
    if der[i] == '\x17' and der[i + 1] == '\x0D' and der[i + 14] == 'Z':
      var digits = true
      for j in i + 2 ..< i + 14:
        if der[j] notin {'0' .. '9'}: digits = false
      if digits:
        inc seen
        if seen == 2: at = i + 2
  if at < 0: return false
  der[at .. at + 12] = "251399000000Z"
  let body = encode(der)
  var pem = "-----BEGIN CERTIFICATE-----\n"
  var i = 0
  while i < body.len:
    pem.add body[i ..< min(i + 64, body.len)] & "\n"
    i += 64
  pem.add "-----END CERTIFICATE-----\n"
  writeFile(cert, pem)
  true

suite "a validity time that cannot be parsed is refused (#379)":
  test "startup refuses a certificate whose notAfter will not parse":
    check mintUnparsableNotAfter(badTimeCert, badTimeKey)
    check "certificate validity time could not be parsed" in
          startupError(badTimeCert, badTimeKey)

  test "a reload with one is rejected and keeps the running certificate":
    var srv = newVortex(RequestHandler(handler),
                        initVortexConfig(numThreads = 1, certFile = goodCert,
                                         keyFile = goodKey)).start(0)
    defer: srv.close()
    check not srv.reloadTls(badTimeCert, badTimeKey)
    check "certificate validity time could not be parsed" in
          srv.lastTlsReloadError
    var c = newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))
    defer: c.close()
    check c.getContent("https://127.0.0.1:" & $srv.port & "/") == "ok"

if not haveDated:
  echo "SKIP: openssl does not support -not_before/-not_after"
  removeDir(dir)
  quit 0

suite "an invalid validity window is refused at startup (#379)":
  test "an expired certificate names its notAfter":
    let msg = startupError(expiredCert, expiredKey)
    check "certificate expired at" in msg
    check "2020" in msg

  test "a not-yet-valid certificate names its notBefore":
    let msg = startupError(futureCert, futureKey)
    check "certificate not valid until" in msg
    check "2040" in msg

  test "the same refusal applies with HTTP/3 enabled":
    # Both transports load the material through buildTlsCtx before a QUIC
    # engine exists, so the server never comes up with an expired certificate
    # on either of them. The QUIC context builder refuses it as well (pinned
    # white-box in tests/test_h3_tls_ctx.nim).
    check "certificate expired at" in startupError(expiredCert, expiredKey,
                                                   http3 = true)

  test "a certificate inside its window still starts":
    check startupError(goodCert, goodKey) == ""
    check startupError(goodCert, goodKey, http3 = true) == ""

suite "an invalid validity window is refused on reload (#379)":
  test "reloadTls keeps the running certificate on both transports":
    var srv = newVortex(RequestHandler(handler),
                        initVortexConfig(numThreads = 2, certFile = goodCert,
                                         keyFile = goodKey,
                                         http3 = true)).start(0)
    defer: srv.close()
    let port = $srv.port
    proc tcpSubject(): string =
      execCmdEx("echo | openssl s_client -connect 127.0.0.1:" & port &
                " 2>/dev/null | openssl x509 -noout -subject 2>/dev/null")[0]
    proc h3Subject(): string =
      if h3curlBin.len == 0: return ""
      let (output, _) = execCmdEx(
        h3curlBin & " -sv -k -m 10 -o /dev/null --http3-only https://127.0.0.1:" &
        port & "/ 2>&1")
      for line in output.splitLines:
        let l = line.strip(chars = {' ', '*', '\t'})
        if l.startsWith("subject:"): return l
      ""
    proc served(): bool =
      var c = newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))
      defer: c.close()
      try: c.getContent("https://127.0.0.1:" & port & "/") == "ok"
      except CatchableError: false

    check "good.vortex" in tcpSubject()
    if h3curlBin.len > 0:
      check "good.vortex" in h3Subject()

    check not srv.reloadTls(expiredCert, expiredKey)
    check not srv.reloadTls(futureCert, futureKey)
    sleep(1000)                       # a signalled loop would have applied it
    check served()
    check "good.vortex" in tcpSubject()
    if h3curlBin.len > 0:
      check "good.vortex" in h3Subject()

    # ... and a renewal that is actually valid still goes through.
    let nextCert = dir / "next.pem"
    let nextKey = dir / "next.key"
    genCert(nextCert, nextKey, "next.vortex")
    check srv.reloadTls(nextCert, nextKey)
    sleep(1500)
    check "next.vortex" in tcpSubject()
    if h3curlBin.len > 0:
      check "next.vortex" in h3Subject()

removeDir(dir)
echo "cert validity ok"
