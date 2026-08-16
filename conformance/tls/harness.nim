## Per-configuration TLS smoke harness (CI). `TLS_CONFIG` selects one TLS
## configuration; the harness mints the material that config needs (openssl),
## starts a real HTTPS server (`newVortex(...).start(0)`), makes a request, and
## asserts it works. One config per process: `fail()` -> exit 1, success ->
## `echo "tls ok: <config>"` -> exit 0. Driven by conformance/tls/run.sh and the
## `tls` CI job (one step per config). These are TCP/OpenSSL config checks
## (`http3 = false`); h3 cert/key material is covered by tests/test_tls_h3_material.
##
## Recipes mirror the existing suites (test_tls.nim, test_tls_advanced.nim,
## test_tls_polish.nim, test_tls_reload.nim) so behaviour stays consistent.

import std/[os, osproc, strutils, net, httpcore, times]
import vortex/[settings, request, server]

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"; quit 0

let cfg = getEnv("TLS_CONFIG")
if cfg.len == 0:
  stderr.writeLine "set TLS_CONFIG (e.g. TLS_CONFIG=certFile)"; quit 2

let curlBin = findExe("curl")
let opensslBin = findExe("openssl")
if curlBin.len == 0 or opensslBin.len == 0:
  stderr.writeLine "FAIL: need curl and openssl on PATH"; quit 1

let dir = getTempDir() / "vortex_tlscfg_" & $getCurrentProcessId()
removeDir(dir); createDir(dir)

proc fail(msg: string) =
  stderr.writeLine "TLS FAIL [" & cfg & "]: " & msg
  quit 1

proc ok() =
  echo "tls ok: " & cfg
  quit 0

proc sh(cmd: string) =
  let (o, rc) = execCmdEx(cmd)
  if rc != 0: fail("command failed (rc=" & $rc & "): " & cmd & "\n" & o)

# --- request handler --------------------------------------------------------
proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.path == "/whoami":                  # mTLS client subject, or "-" if none
    let s = req.clientCertSubject
    res.send(Http200, if s.len > 0: s else: "-")
  else:
    res.send(Http200, "ok")

# --- material generators (verbatim from the existing suites) -----------------
proc genCert(cert, key, cn: string) =
  sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & key & " -out " &
     cert & " -days 2 -subj /CN=" & cn)

proc genMtls() =
  ## A client CA and a client cert (CN=test-client) signed by it.
  sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir & "/ca.key -out " &
     dir & "/ca.pem -days 2 -subj /CN=TestCA")
  sh("openssl req -newkey rsa:2048 -nodes -keyout " & dir & "/client.key -out " &
     dir & "/client.csr -subj /CN=test-client")
  sh("openssl x509 -req -in " & dir & "/client.csr -CA " & dir & "/ca.pem -CAkey " &
     dir & "/ca.key -CAcreateserial -out " & dir & "/client.pem -days 2")

proc buildOcsp() =
  ## CA + server cert + a signed OCSP response (resp.der). The index.txt expiry
  ## is formatted in Nim (std/times) so no python3 dependency is needed.
  sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir & "/ca.key -out " &
     dir & "/ca.pem -days 2 -subj /CN=OCSP-CA")
  sh("openssl req -newkey rsa:2048 -nodes -keyout " & dir & "/srv.key -out " &
     dir & "/srv.csr -subj /CN=localhost")
  sh("openssl x509 -req -in " & dir & "/srv.csr -CA " & dir & "/ca.pem -CAkey " &
     dir & "/ca.key -CAcreateserial -out " & dir & "/srv.pem -days 2")
  let serialOut = execCmdEx("openssl x509 -in " & dir &
                            "/srv.pem -noout -serial")[0].strip()
  let serial = serialOut.split('=', 1)[1]
  let expiry = (now().utc + 2.years).format("yyMMddHHmmss") & "Z"
  writeFile(dir / "index.txt",
            "V\t" & expiry & "\t\t" & serial & "\tunknown\t/CN=localhost\n")
  sh("openssl ocsp -issuer " & dir & "/ca.pem -cert " & dir &
     "/srv.pem -reqout " & dir & "/req.der -no_nonce")
  sh("openssl ocsp -index " & dir & "/index.txt -CA " & dir & "/ca.pem -rsigner " &
     dir & "/ca.pem -rkey " & dir & "/ca.key -reqin " & dir & "/req.der -respout " &
     dir & "/resp.der -ndays 1 -no_nonce")
  if not fileExists(dir / "resp.der") or getFileSize(dir / "resp.der") == 0:
    fail("OCSP response was not generated")

# --- clients ----------------------------------------------------------------
proc curlGet(port: Port, args = "", path = "/"): (string, int) =
  let (o, rc) = execCmdEx(curlBin & " -sk --http1.1 -m 5 " & args &
                          " https://127.0.0.1:" & $port & path)
  (o.strip(), rc)

proc sClientSubject(port: Port, servername: string): string =
  ## Subject of the cert the server presents for this SNI name.
  execCmdEx("echo | " & opensslBin & " s_client -connect 127.0.0.1:" & $port &
    " -servername " & servername & " 2>/dev/null | " & opensslBin &
    " x509 -noout -subject")[0].strip()

proc handshakeOk(port: Port, flag: string): bool =
  ## openssl s_client exits 0 on a completed handshake, non-zero on a
  ## version/handshake rejection.
  execCmdEx("echo | " & opensslBin & " s_client -connect 127.0.0.1:" & $port &
    " " & flag & " >/dev/null 2>&1")[1] == 0

# --- one config per invocation ----------------------------------------------
case cfg
of "certFile":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem")).start(0)
  let (o, rc) = curlGet(srv.port)
  if rc != 0 or o != "ok": fail("GET failed rc=" & $rc & " body=" & o)
  ok()

of "certPem":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certPem = readFile(dir / "cert.pem"),
    keyPem = readFile(dir / "key.pem"))).start(0)
  let (o, rc) = curlGet(srv.port)
  if rc != 0 or o != "ok": fail("GET failed rc=" & $rc & " body=" & o)
  ok()

of "pkcs12File":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  sh("openssl pkcs12 -export -out " & dir & "/bundle.p12 -inkey " & dir &
     "/key.pem -in " & dir & "/cert.pem -passout pass:p12pass")
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, pkcs12File = dir / "bundle.p12", keyPassword = "p12pass")).start(0)
  let (o, rc) = curlGet(srv.port)
  if rc != 0 or o != "ok": fail("GET failed rc=" & $rc & " body=" & o)
  ok()

of "verifyClient":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  genMtls()
  # Require: no client cert -> refused; valid client cert -> accepted + subject.
  var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
    verifyClient = ClientVerify.Require, clientCaFile = dir / "ca.pem")).start(0)
  let (_, rc0) = curlGet(srv.port)
  if rc0 == 0: fail("Require accepted a connection with no client cert")
  let (o1, rc1) = curlGet(srv.port, "--cert " & dir & "/client.pem --key " & dir &
                          "/client.key", "/whoami")
  if rc1 != 0 or "test-client" notin o1: fail("Require + client cert failed rc=" &
    $rc1 & " body=" & o1)
  srv.close()
  # Optional: no client cert still connects, subject empty.
  let srv2 = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
    verifyClient = ClientVerify.Optional, clientCaFile = dir / "ca.pem")).start(0)
  let (o2, rc2) = curlGet(srv2.port, "", "/whoami")
  if rc2 != 0 or o2 != "-": fail("Optional no-cert failed rc=" & $rc2 & " body=" & o2)
  ok()

of "clientCaFile":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  genMtls()
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
    verifyClient = ClientVerify.Require, clientCaFile = dir / "ca.pem")).start(0)
  let (o, rc) = curlGet(srv.port, "--cert " & dir & "/client.pem --key " & dir &
                        "/client.key", "/whoami")
  if rc != 0 or "test-client" notin o: fail("file-CA mTLS failed rc=" & $rc &
    " body=" & o)
  ok()

of "clientCaPem":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  genMtls()
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
    verifyClient = ClientVerify.Require, clientCaPem = readFile(dir / "ca.pem"))).start(0)
  let (o, rc) = curlGet(srv.port, "--cert " & dir & "/client.pem --key " & dir &
                        "/client.key", "/whoami")
  if rc != 0 or "test-client" notin o: fail("in-memory-CA mTLS failed rc=" & $rc &
    " body=" & o)
  ok()

of "sni":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")   # default
  genCert(dir / "alt.pem", dir / "altkey.pem", "alt.example")
  sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
     "/wildkey.pem -out " & dir & "/wild.pem -days 2 -subj '/CN=*.example.com'")
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
    sni = @[SniCertEntry(host: "alt.example", certFile: dir / "alt.pem",
                         keyFile: dir / "altkey.pem"),
            SniCertEntry(host: "*.example.com", certFile: dir / "wild.pem",
                         keyFile: dir / "wildkey.pem")])).start(0)
  if "alt.example" notin sClientSubject(srv.port, "alt.example"):
    fail("exact SNI did not select alt cert")
  if "*.example.com" notin sClientSubject(srv.port, "foo.example.com"):
    fail("wildcard SNI did not select wildcard cert")
  if "localhost" notin sClientSubject(srv.port, "example.com"):
    fail("bare domain did not fall back to the default cert")
  ok()

of "minTlsVersion":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
    minTlsVersion = TlsVersion.V13)).start(0)
  if not handshakeOk(srv.port, "-tls1_3"): fail("V13 refused TLS 1.3")
  if handshakeOk(srv.port, "-tls1_2"): fail("V13 accepted TLS 1.2")
  ok()

of "maxTlsVersion":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
    maxTlsVersion = TlsVersion.V12)).start(0)
  if not handshakeOk(srv.port, "-tls1_2"): fail("cap-1.2 refused TLS 1.2")
  if handshakeOk(srv.port, "-tls1_3"): fail("cap-1.2 accepted TLS 1.3")
  ok()

of "ocspFile":
  buildOcsp()
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "srv.pem", keyFile = dir / "srv.key",
    ocspFile = dir / "resp.der")).start(0)
  let (o, _) = execCmdEx("echo | " & opensslBin & " s_client -status -connect " &
    "127.0.0.1:" & $srv.port & " 2>/dev/null | grep -iE 'OCSP Response Status'")
  if "successful" notin o.toLowerAscii: fail("no stapled OCSP response: " & o)
  ok()

of "ocspResponse":
  buildOcsp()
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "srv.pem", keyFile = dir / "srv.key",
    ocspResponse = readFile(dir / "resp.der"))).start(0)
  let (o, _) = execCmdEx("echo | " & opensslBin & " s_client -status -connect " &
    "127.0.0.1:" & $srv.port & " 2>/dev/null | grep -iE 'OCSP Response Status'")
  if "successful" notin o.toLowerAscii: fail("no stapled OCSP response: " & o)
  ok()

of "tlsCipherSuites":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
    tlsCipherSuites = "TLS_AES_128_GCM_SHA256")).start(0)
  let (o, rc) = execCmdEx("echo | " & opensslBin & " s_client -connect " &
    "127.0.0.1:" & $srv.port & " -tls1_3 2>&1")
  if rc != 0 or "TLS_AES_128_GCM_SHA256" notin o or "TLS_AES_256_GCM_SHA384" in o:
    fail("restricted 1.3 suite not honored: " & o)
  srv.close()
  var raised = false
  try:
    let bad = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
      http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
      tlsCipherSuites = "NOT_A_REAL_CIPHER")).start(0)
    bad.close()
  except CatchableError: raised = true
  if not raised: fail("invalid cipher suite was not rejected at startup")
  ok()

of "tlsCipherList":
  genCert(dir / "cert.pem", dir / "key.pem", "localhost")
  let srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
    maxTlsVersion = TlsVersion.V12,
    tlsCipherList = "ECDHE-RSA-AES128-GCM-SHA256")).start(0)
  let (o, rc) = execCmdEx("echo | " & opensslBin & " s_client -connect " &
    "127.0.0.1:" & $srv.port & " -tls1_2 2>&1")
  if rc != 0 or "ECDHE-RSA-AES128-GCM-SHA256" notin o:
    fail("restricted 1.2 cipher not negotiated: " & o)
  srv.close()
  var raised = false
  try:
    let bad = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
      http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem",
      tlsCipherList = "NOT_A_REAL_CIPHER")).start(0)
    bad.close()
  except CatchableError: raised = true
  if not raised: fail("invalid cipher list was not rejected at startup")
  ok()

of "hotReload":
  genCert(dir / "cert.pem", dir / "key.pem", "alpha.vortex")
  var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1,
    http3 = false, certFile = dir / "cert.pem", keyFile = dir / "key.pem")).start(0)
  if "alpha.vortex" notin sClientSubject(srv.port, "localhost"):
    fail("initial cert is not alpha")
  genCert(dir / "bravo.pem", dir / "bravokey.pem", "bravo.vortex")
  if not srv.reloadTls(dir / "bravo.pem", dir / "bravokey.pem"):
    fail("reloadTls returned false")
  if "bravo.vortex" notin sClientSubject(srv.port, "localhost"):
    fail("cert did not swap to bravo after reload")
  let (o, rc) = curlGet(srv.port)
  if rc != 0 or o != "ok": fail("not serving after reload rc=" & $rc & " body=" & o)
  ok()

else:
  fail("unknown TLS_CONFIG: " & cfg)
