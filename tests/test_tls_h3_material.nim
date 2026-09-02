## TLS key/cert material matrix, exercised over BOTH HTTP/1.1 and HTTP/3.
##
## Regression guard for the h3 QUIC engine loading its TLS material. The engine
## (ngtcp2 + nghttp3, ossl crypto backend) builds its own SSL_CTX per loop
## thread, separate from the TCP path, and used to load only cert_file/key_file
## with no passphrase callback and no in-memory PEM support. That meant:
##   * an encrypted key prompted for a passphrase on the tty (hanging) and, when
##     stdin was EOF (CI), silently failed -> h3 was disabled, not reported; and
##   * in-memory PEM (certPem/keyPem) never reached h3 at all.
## The HTTP/1.1 tests did not notice (they do not require h3), so the breakage
## was invisible. Here every case asserts h3 actually serves, so a regression in
## the QUIC TLS material plumbing fails the suite even in a headless CI run.

import std/[unittest, net, httpcore, osproc, strutils, os]
import vortex/[settings, request, server, connection]

proc findH3Curl(): string =
  ## Any curl advertising HTTP3 (system, then Homebrew). "" if none.
  var cands: seq[string]
  let sys = findExe("curl")
  if sys.len > 0: cands.add sys
  cands.add "/opt/homebrew/opt/curl/bin/curl"
  for exe in cands:
    if fileExists(exe):
      let (ver, rc) = execCmdEx(exe & " --version")
      if rc == 0 and "HTTP3" in ver.toUpperAscii: return exe
  ""

let h3curlBin = findH3Curl()
let plainCurl = findExe("curl")
if plainCurl.len == 0:
  echo "SKIP: no curl found"
  quit 0

# --- generate cert + an unencrypted and an encrypted copy of the key ----------
const pass = "s3cr3t-pass"
let dir = getTempDir() / "nhs_h3_mat_" & $getCurrentProcessId()
createDir(dir)
let certPath = dir / "cert.pem"
let keyPath = dir / "key.pem"          # unencrypted
let encKeyPath = dir / "enc.pem"       # same key, AES-256 encrypted
let p12Path = dir / "bundle.p12"       # cert + key as a PKCS#12 bundle
check execCmdEx("openssl req -x509 -newkey rsa:2048 -nodes -keyout " &
  keyPath & " -out " & certPath & " -days 2 -subj /CN=localhost")[1] == 0
check execCmdEx("openssl rsa -in " & keyPath & " -aes256 -out " & encKeyPath &
  " -passout pass:" & pass)[1] == 0
check execCmdEx("openssl pkcs12 -export -inkey " & keyPath & " -in " & certPath &
  " -out " & p12Path & " -passout pass:" & pass)[1] == 0

let certData = readFile(certPath)
let keyData = readFile(keyPath)
let encKeyData = readFile(encKeyPath)
let p12Data = readFile(p12Path)

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "hello tls")

proc curlGet(bin, proto, base: string): (string, int) =
  ## GET base/ with the given curl protocol flag; returns (body, rc).
  let (o, rc) = execCmdEx(bin & " -sk " & proto & " -m 10 " & base & "/")
  (o.strip(), rc)

proc checkServes(cfg: VortexConfig) =
  ## Start a server with `cfg` and assert it serves "hello tls" over HTTP/1.1
  ## and (when an h3 curl is available) HTTP/3. The h3 request is the one that
  ## proves the QUIC engine loaded the key material.
  var srv = newVortex(RequestHandler(handler), cfg).start(0)
  let base = "https://localhost:" & $srv.port
  try:
    let (h1, rc1) = curlGet(plainCurl, "--http1.1", base)
    check rc1 == 0
    check h1 == "hello tls"
    if h3curlBin.len > 0:
      let (h3, rc3) = curlGet(h3curlBin, "--http3-only", base)
      check rc3 == 0
      check h3 == "hello tls"
  finally:
    srv.stop()

suite "TLS material over HTTP/1.1 + HTTP/3":
  test "unencrypted key from files":
    checkServes(initVortexConfig(numThreads = 1, certFile = certPath,
      keyFile = keyPath))

  test "encrypted key from a file + keyPassword":
    checkServes(initVortexConfig(numThreads = 1, certFile = certPath,
      keyFile = encKeyPath, keyPassword = pass))

  test "unencrypted key from in-memory PEM":
    checkServes(initVortexConfig(numThreads = 1, certPem = certData,
      keyPem = keyData))

  test "encrypted key from in-memory PEM + keyPassword":
    checkServes(initVortexConfig(numThreads = 1, certPem = certData,
      keyPem = encKeyData, keyPassword = pass))

  # A PKCS#12-only config used to reach the QUIC engine with empty PEM fields, so
  # h3 was advertised via Alt-Svc yet every handshake failed (the p12 bundle was
  # never forwarded to the ossl SSL_CTX). Assert h3 actually serves from a .p12.
  test "PKCS#12 bundle from a file + keyPassword":
    checkServes(initVortexConfig(numThreads = 1, pkcs12File = p12Path,
      keyPassword = pass))

  test "PKCS#12 bundle from in-memory bytes + keyPassword":
    checkServes(initVortexConfig(numThreads = 1, pkcs12 = p12Data,
      keyPassword = pass))

echo "tls h3 material ok"
