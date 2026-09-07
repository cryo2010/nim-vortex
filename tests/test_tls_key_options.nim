## In-memory cert/key (certPem/keyPem) and passphrase-protected keys
## (keyPassword), over TLS via curl.

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]
import ./helper

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"
  quit 0
let curlBin = requireCurl()

let (cert, key) = makeCertPair("vortex_tlskey_")   # key.pem is unencrypted
let dir = cert.parentDir
let enckey = dir / "enc.pem"       # same key, AES-encrypted with a passphrase
const pass = "s3cr3t-pass"

check execCmdEx("openssl rsa -in " & key & " -aes256 -out " & enckey &
  " -passout pass:" & pass)[1] == 0

let certData = readFile(cert)
let keyData = readFile(key)
let encKeyData = readFile(enckey)

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

proc get(port: Port): (string, int) =
  # -k: self-signed; --http1.1 keeps it simple. The first connect can race
  # the TLS listener coming up right after start(0), so retry briefly.
  for attempt in 1 .. 3:
    let (o, rc) = execCmdEx(curlBin & " -sk --http1.1 -m 5 https://127.0.0.1:" &
                            $port & "/")
    result = (o.strip(), rc)
    if rc == 0 and result[0].len > 0: return
    sleep(150)

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
