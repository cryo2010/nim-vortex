## mTLS must be enforced on HTTP/3, not only on the TCP listener (#351).
## The QUIC engine never called SSL_CTX_set_verify, so a server configured with
## `verifyClient = ClientVerify.Require` advertised h3 via Alt-Svc and then
## completed the QUIC handshake with a client that presented no certificate at
## all. `req.clientCertSubject` was also always "" over h3, so an application
## could not even compensate with its own check.

import std/[unittest, net, httpcore, os, osproc, strutils]
import vortex/[settings, request, server]
import ./helper

let h3curlBin = requireH3Curl()

let (certFile, keyFile) = makeCertPair("nhs_h3_mtls_")
let dir = certFile.parentDir

# A client CA and a client cert signed by it (the helper's OCSP CA fixtures are
# a plain CA + signing pair, reused here as the mTLS trust anchor).
genOcspCa(dir)
genSignedCert(dir, "client", "h3-client")
let caFile = dir / "ca.pem"
let clientCert = dir / "client.pem"
let clientKey = dir / "client.key"

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/who": res.send(Http200, req.clientCertSubject)
  else: res.send(Http200, "mtls")

withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, workerThreads = 2,
                            certFile = certFile, keyFile = keyFile,
                            verifyClient = ClientVerify.Require,
                            clientCaFile = caFile), srv):
  let base = "https://localhost:" & $srv.port
  let clientArgs = " --cert " & clientCert & " --key " & clientKey & " "

  suite "mTLS over HTTP/3 (#351)":
    test "h3 without a client certificate is refused":
      # The handshake must fail, so curl reports an error and no response body.
      let (output, rc) = helper.h3curl(h3curlBin, base & "/")
      check rc != 0
      check "mtls" notin output

    test "h3 with a valid client certificate is served":
      let (output, rc) = helper.h3curl(
        h3curlBin, clientArgs & "-w '|%{http_version}' " & base & "/")
      check rc == 0
      check output == "mtls|3"

    test "req.clientCertSubject reports the client cert over h3":
      let (output, rc) = helper.h3curl(h3curlBin, clientArgs & base & "/who")
      check rc == 0
      check "h3-client" in output

    test "the TCP listener enforces the same policy":
      let (_, rcNoCert) = execCmdEx(
        h3curlBin & " -sk -m 10 -o /dev/null --http2 " & base & "/")
      check rcNoCert != 0
      let (output, rc) = execCmdEx(
        h3curlBin & " -sk -m 10 --http2 " & clientArgs & base & "/who")
      check rc == 0
      check "h3-client" in output

withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, workerThreads = 2,
                            certFile = certFile, keyFile = keyFile,
                            verifyClient = ClientVerify.Require,
                            clientCaPem = readFile(caFile)), mem):
  let base = "https://localhost:" & $mem.port

  suite "mTLS over HTTP/3 with an in-memory client CA (#351)":
    # The in-memory bundle goes through the shim's own PEM loader rather than
    # SSL_CTX_load_verify_locations, so it needs its own coverage.
    test "h3 without a client certificate is refused":
      let (_, rc) = helper.h3curl(h3curlBin, base & "/")
      check rc != 0

    test "h3 with a valid client certificate is served":
      let (output, rc) = helper.h3curl(
        h3curlBin, " --cert " & clientCert & " --key " & clientKey & " " &
        base & "/who")
      check rc == 0
      check "h3-client" in output

withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, workerThreads = 2,
                            certFile = certFile, keyFile = keyFile,
                            verifyClient = ClientVerify.Optional,
                            clientCaFile = caFile), opt):
  let base = "https://localhost:" & $opt.port

  suite "mTLS Optional over HTTP/3 (#351)":
    test "no client certificate still connects, subject empty":
      let (output, rc) = helper.h3curl(h3curlBin, base & "/who")
      check rc == 0
      check output == ""

    test "a presented certificate is verified and reported":
      let (output, rc) = helper.h3curl(
        h3curlBin, " --cert " & clientCert & " --key " & clientKey & " " &
        base & "/who")
      check rc == 0
      check "h3-client" in output

removeDir(dir)
echo "server shut down cleanly"
