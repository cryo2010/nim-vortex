## PEM material integrity: a certificate chain or CA bundle that does not parse
## in full must be rejected, not silently truncated at the point of damage.
## `PEM_read_bio_X509` returns nil for every failure, so the loaders read the
## OpenSSL error queue to tell a clean end-of-data from real corruption.

import std/[unittest, os, osproc, strutils, httpcore, net, nativesockets]
import vortex/[settings, request, server]
import vortex/http3/ngtcp2/backend as h3backend

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"
  quit 0
let opensslBin = findExe("openssl")
let curlBin = findExe("curl")
if opensslBin.len == 0 or curlBin.len == 0:
  echo "SKIP: need openssl and curl"
  quit 0

let dir = getTempDir() / "vortex_tlsmat_" & $getCurrentProcessId()
removeDir(dir); createDir(dir)

proc must(cmd: string) =
  let (o, rc) = execCmdEx(cmd)
  doAssert rc == 0, cmd & "\n" & o

# A two-level chain: ChainCA -> leaf (CN=localhost). Serving leaf + ChainCA puts
# two certificates in the Certificate message.
must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
     "/ca.key -out " & dir & "/ca.pem -days 2 -subj /CN=ChainCA")
must("openssl req -newkey rsa:2048 -nodes -keyout " & dir &
     "/leaf.key -out " & dir & "/leaf.csr -subj /CN=localhost")
must("openssl x509 -req -in " & dir & "/leaf.csr -CA " & dir & "/ca.pem -CAkey " &
     dir & "/ca.key -CAcreateserial -out " & dir & "/leaf.pem -days 2")

let leafPem = readFile(dir / "leaf.pem")
let leafKeyFile = dir / "leaf.key"
let leafKey = readFile(leafKeyFile)
let caPem = readFile(dir / "ca.pem")

proc mangle(pem: string): string =
  ## Replace a base64 body line of a PEM block with invalid base64, which
  ## PEM_read_bio_X509 reports as PEM_R_BAD_BASE64_DECODE (100) rather than the
  ## benign PEM_R_NO_START_LINE (108) a clean end of data leaves behind.
  var lines = pem.strip.splitLines()
  doAssert lines.len > 4
  let mid = lines.len div 2
  lines[mid] = repeat('!', lines[mid].len)
  lines.join("\n") & "\n"

# Two client CAs and a client certificate issued by the *last* one, so a bundle
# that stops at the first CA cannot verify it.
must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
     "/caA.key -out " & dir & "/caA.pem -days 2 -subj /CN=BundleCA-A")
must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
     "/caB.key -out " & dir & "/caB.pem -days 2 -subj /CN=BundleCA-B")
must("openssl req -newkey rsa:2048 -nodes -keyout " & dir &
     "/client.key -out " & dir & "/client.csr -subj /CN=bundle-client")
must("openssl x509 -req -in " & dir & "/client.csr -CA " & dir & "/caB.pem -CAkey " &
     dir & "/caB.key -CAcreateserial -out " & dir & "/client.pem -days 2")

let caBundle = readFile(dir / "caA.pem") & readFile(dir / "caB.pem")

proc truncateLast(pem: string): string =
  ## Drop the tail of the last PEM block (a bundle written non-atomically, or
  ## cut mid-certificate by a partial write).
  let lines = pem.strip.splitLines()
  lines[0 ..< lines.len - 3].join("\n") & "\n"

let goodChain = leafPem & caPem
let corruptChain = leafPem & mangle(caPem) & caPem   # damage between valid blocks
let goodChainFile = dir / "good-chain.pem"
let badChainFile = dir / "bad-chain.pem"
writeFile(goodChainFile, goodChain)
writeFile(badChainFile, corruptChain)

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.path == "/whoami":
    let sub = req.clientCertSubject
    res.send(Http200, if sub.len > 0: sub else: "-")
  else:
    res.send(Http200, "ok")

proc servedCerts(port: Port): int =
  ## How many certificates the server puts in its Certificate message.
  let cmd = "echo | " & opensslBin & " s_client -showcerts -connect 127.0.0.1:" &
            $port & " 2>/dev/null"
  execCmdEx(cmd)[0].count("BEGIN CERTIFICATE")

suite "certificate chain integrity":
  test "a clean leaf + intermediate chain serves both certificates":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(
      numThreads = 1, certPem = goodChain, keyPem = leafKey)).start(0)
    defer: srv.close()
    check servedCerts(srv.port) == 2

  test "a corrupt block after the leaf is rejected at startup":
    expect CatchableError:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(
        numThreads = 1, certPem = corruptChain, keyPem = leafKey)).start(0)
      srv.close()

  test "reloadTls rejects a corrupt chain and keeps the running one":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(
      numThreads = 1, certFile = goodChainFile, keyFile = leafKeyFile)).start(0)
    defer: srv.close()
    check servedCerts(srv.port) == 2
    check not srv.reloadTls(certFile = badChainFile, keyFile = leafKeyFile)
    check servedCerts(srv.port) == 2                  # old chain still served
    check srv.reloadTls(certFile = goodChainFile, keyFile = leafKeyFile)

suite "client CA bundle integrity":
  test "a clean multi-CA bundle verifies a client from the last CA":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(
      numThreads = 1, certFile = dir / "leaf.pem", keyFile = leafKeyFile,
      verifyClient = ClientVerify.Require, clientCaPem = caBundle)).start(0)
    defer: srv.close()
    let (o, rc) = execCmdEx(curlBin & " -sk --http1.1 -m 5 --cert " & dir &
      "/client.pem --key " & dir & "/client.key https://127.0.0.1:" &
      $srv.port & "/whoami")
    check rc == 0
    check "bundle-client" in o

  test "a truncated CA bundle is rejected at startup":
    expect CatchableError:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(
        numThreads = 1, certFile = dir / "leaf.pem", keyFile = leafKeyFile,
        verifyClient = ClientVerify.Require,
        clientCaPem = truncateLast(caBundle))).start(0)
      srv.close()

  test "a CA bundle with a mangled block is rejected at startup":
    expect CatchableError:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(
        numThreads = 1, certFile = dir / "leaf.pem", keyFile = leafKeyFile,
        verifyClient = ClientVerify.Require,
        clientCaPem = readFile(dir / "caA.pem") &
                      mangle(readFile(dir / "caB.pem")))).start(0)
      srv.close()

suite "h3 shim certificate chain integrity":
  # The QUIC engine builds its own SSL_CTX from the same PEM bytes (the C++
  # loadCertChain), so drive vq_engine_new directly: through a Vortex the TCP
  # context is built first and rejects the material before h3 ever sees it.
  test "the QUIC engine rejects a corrupt chain and accepts a clean one":
    let fd = createNativeSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    doAssert fd != osInvalidSocket
    defer: close(fd)
    check not h3backend.ngSetup(nil, cint(fd), "", "", 65536, 16, 16384,
                                certPem = corruptChain, keyPem = leafKey)
    check h3backend.ngSetup(nil, cint(fd), "", "", 65536, 16, 16384,
                            certPem = goodChain, keyPem = leafKey)
    h3backend.ngEngineFree()

removeDir(dir)
echo "tls material integrity ok"
