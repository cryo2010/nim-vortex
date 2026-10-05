## tlsCipherList and tlsCipherSuites are preference ORDERS, not allow-sets
## (#375).
##
## SSL_CTX_set_options was never called with SSL_OP_CIPHER_SERVER_PREFERENCE, so
## OpenSSL walked the *client's* list and took the first entry the server also
## allowed. An operator who wrote "AES256:AES128" to prefer AES-256 got AES-128
## on every connection from every client whose own list happened to start there:
## the ordering was accepted, applied, and silently inverted.
##
## These are real handshakes driven by `openssl s_client`, which offers the
## ciphers in the order given on its command line, so each case pits a server
## order against the opposite client order. Reverting the
## SSL_OP_CIPHER_SERVER_PREFERENCE line in buildTlsCtx fails all four "server's
## order wins" checks.

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]
import ./helper

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"
  quit 0

let opensslBin = findExe("openssl")
if opensslBin.len == 0:
  echo "SKIP: need openssl"
  quit 0

# LibreSSL's s_client has -cipher but no -ciphersuites, so the TLS 1.3 half of
# this needs a real OpenSSL 1.1.1+ client.
let hasCiphersuitesFlag =
  "ciphersuites" in execCmdEx(opensslBin & " s_client -help 2>&1")[0]

let (cert, key) = makeCertPair("vortex_cipherorder_")

const
  # Two TLS 1.2 suites an RSA certificate can serve, and two TLS 1.3 suites.
  aes256 = "ECDHE-RSA-AES256-GCM-SHA384"
  aes128 = "ECDHE-RSA-AES128-GCM-SHA256"
  suite256 = "TLS_AES_256_GCM_SHA384"
  suiteChaCha = "TLS_CHACHA20_POLY1305_SHA256"

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

proc negotiated(port: Port, args: string): tuple[proto, cipher: string] =
  ## Drive one handshake and report the protocol and cipher s_client reports.
  ## A failed handshake shows up as a cipher of "(NONE)" (or "0000", in the
  ## SSL-Session block that only a TLS 1.2 connection prints here: under TLS 1.3
  ## the session arrives post-handshake, after `echo |` has closed stdin, so the
  ## "New, <proto>, Cipher is <name>" summary is the line both versions share).
  let cmd = "echo | " & opensslBin & " s_client -connect 127.0.0.1:" & $port &
    " " & args & " 2>/dev/null"
  let text = execCmdEx(cmd)[0]
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

suite "TLS 1.2 cipher order is the server's (#375)":
  test "the server's first choice wins over the client's":
    # http3 = false goes with the TLS 1.2 ceiling: QUIC cannot negotiate below
    # 1.3, so the pair is refused rather than half-applied (#359).
    withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                http3 = false,
                                maxTlsVersion = TlsVersion.V12,
                                tlsCipherList = aes256 & ":" & aes128)):
      let r = negotiated(srv.port, "-tls1_2 -cipher '" & aes128 & ":" & aes256 & "'")
      check r.proto == "TLSv1.2"
      check r.cipher == aes256          # pre-fix: aes128, the client's order

  test "... and that is the server's order, not a fixed strength ranking":
    # The same client preference against the opposite server list: whatever the
    # operator wrote first is what is served.
    withServer(initVortexConfig(numThreads = 1, certFile = cert, keyFile = key,
                                http3 = false,
                                maxTlsVersion = TlsVersion.V12,
                                tlsCipherList = aes128 & ":" & aes256)):
      let r = negotiated(srv.port, "-tls1_2 -cipher '" & aes256 & ":" & aes128 & "'")
      check r.proto == "TLSv1.2"
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

suite "per-host (SNI) contexts share the preference (#375)":
  test "a per-host certificate's context orders ciphers the same way":
    # Every SNI context is built by buildTlsCtx, so one that drifted would serve
    # a different cipher policy than the default certificate on the same port.
    let dir = cert.parentDir
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

removeDir(cert.parentDir)
