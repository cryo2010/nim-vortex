## In-memory cert/key (certPem/keyPem) and passphrase-protected keys
## (keyPassword), over TLS via curl.

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]
import vortex/transport/tls as tlstransport
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

  test "a key failure reports the OpenSSL reason, not 'unknown TLS error'":
    # loadKeyMem used to clear the error queue before the caller read it, so
    # every key failure -- wrong passphrase, truncated PEM, wrong algorithm --
    # surfaced as "cannot load TLS certificate/key: unknown TLS error" and read
    # like a library fault rather than a configuration one (#377). Both key
    # paths (file and in-memory PEM) go through loadKeyMem, so check both.
    var fileMsg, memMsg, truncMsg: string
    try:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(
        numThreads = 1, certFile = cert, keyFile = enckey,
        keyPassword = "wrong")).start(0)
      srv.close()
    except CatchableError as e:
      fileMsg = e.msg
    try:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(
        numThreads = 1, certPem = certData, keyPem = encKeyData,
        keyPassword = "wrong")).start(0)
      srv.close()
    except CatchableError as e:
      memMsg = e.msg
    # A truncated (not encrypted) key: a different reason reaches the message.
    try:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(
        numThreads = 1, certPem = certData,
        keyPem = keyData[0 ..< keyData.len div 2])).start(0)
      srv.close()
    except CatchableError as e:
      truncMsg = e.msg
    check "unknown TLS error" notin fileMsg
    check "bad decrypt" in fileMsg
    check "unknown TLS error" notin memMsg
    check "bad decrypt" in memMsg
    check "unknown TLS error" notin truncMsg
    check truncMsg.len > 0

  test "a cert failure after a key failure is not reported with the key's reason":
    # lastErrorMsg drains the queue it read from, so one failed load cannot
    # lend its reason to the next one on the same thread.
    var second: string
    try:
      let cfg = tlstransport.newTlsConfig(cert, enckey, keyPassword = "wrong")
      tlstransport.freeTlsConfig(cfg)
    except CatchableError:
      discard
    try:
      let cfg = tlstransport.newTlsConfig(dir / "missing.pem", key)
      tlstransport.freeTlsConfig(cfg)
    except CatchableError as e:
      second = e.msg
    check second.len > 0
    check "bad decrypt" notin second

  test "cert without key is rejected":
    expect CatchableError:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certPem = certData)).start(0)   # no key material
      srv.close()

removeDir(dir)
echo "tls key options ok"
