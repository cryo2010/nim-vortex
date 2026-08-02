## In-memory cert/key (certPem/keyPem) and passphrase-protected keys
## (keyPassword), over TLS via curl.

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"
  quit 0
let curlBin = findExe("curl")
if curlBin.len == 0:
  echo "SKIP: no curl"
  quit 0

let dir = getTempDir() / "vortex_tlskey_" & $getCurrentProcessId()
removeDir(dir); createDir(dir)
let cert = dir / "cert.pem"
let key = dir / "key.pem"          # unencrypted
let enckey = dir / "enc.pem"       # same key, AES-encrypted with a passphrase
const pass = "s3cr3t-pass"

doAssert execCmdEx("openssl req -x509 -newkey rsa:2048 -nodes -keyout " &
  key & " -out " & cert & " -days 2 -subj /CN=localhost")[1] == 0
doAssert execCmdEx("openssl rsa -in " & key & " -aes256 -out " & enckey &
  " -passout pass:" & pass)[1] == 0

let certData = readFile(cert)
let keyData = readFile(key)
let encKeyData = readFile(enckey)

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

proc get(port: Port): (string, int) =
  # -k: self-signed; --http1.1 keeps it simple.
  let (o, rc) = execCmdEx(curlBin & " -sk --http1.1 -m 5 https://127.0.0.1:" &
                          $port & "/")
  (o.strip(), rc)

suite "TLS key options":
  test "in-memory cert + key (certPem/keyPem)":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certPem = certData, keyPem = keyData)).start(0)
    defer: srv.close()
    let (o, rc) = get(srv.port)
    check rc == 0
    check o == "ok"

  test "passphrase-protected key from a file (keyFile + keyPassword)":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = cert, keyFile = enckey, keyPassword = pass)).start(0)
    defer: srv.close()
    let (o, rc) = get(srv.port)
    check rc == 0
    check o == "ok"

  test "in-memory encrypted key + passphrase (keyPem + keyPassword)":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certPem = certData, keyPem = encKeyData, keyPassword = pass)).start(0)
    defer: srv.close()
    let (o, rc) = get(srv.port)
    check rc == 0
    check o == "ok"

  test "wrong passphrase fails to start":
    expect CatchableError:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = cert, keyFile = enckey, keyPassword = "wrong")).start(0)
      srv.close()

  test "cert without key is rejected":
    expect CatchableError:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certPem = certData)).start(0)   # no key material
      srv.close()

removeDir(dir)
echo "tls key options ok"
