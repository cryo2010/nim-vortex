## The operator's TLS 1.3 policy must be in force on HTTP/3, not just on the
## TCP listener (#359). The QUIC engine used to hardcode TLS 1.3 and negotiate
## OpenSSL's default suites, so `tlsCipherSuites` was silently ignored by every
## h3 connection while it held on HTTP/1.1 and HTTP/2.

import std/[unittest, net, httpcore, os, osproc, strutils]
import vortex/[settings, request, server]
import ./helper

let h3curlBin = requireH3Curl()

let (certFile, keyFile) = makeCertPair("nhs_h3_policy_")
let certDir = certFile.parentDir

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "policy")

# A single TLS 1.3 suite that is NOT OpenSSL's first choice (its default order
# prefers TLS_AES_256_GCM_SHA384), so the negotiated suite proves the
# restriction was applied rather than coinciding with the default.
const onlySuite = "TLS_CHACHA20_POLY1305_SHA256"

withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, workerThreads = 2,
                            certFile = certFile, keyFile = keyFile,
                            tlsCipherSuites = onlySuite), srv):
  let base = "https://localhost:" & $srv.port

  suite "TLS 1.3 cipher-suite policy over HTTP/3 (#359)":
    test "h3 negotiates the single configured suite":
      # -v reports the negotiated suite for the QUIC handshake too; execCmdEx
      # folds stderr into the output.
      let (output, rc) = execCmdEx(
        h3curlBin & " -sv -k --http3-only -m 10 -o /dev/null " & base & "/")
      check rc == 0
      check "HTTP/3" in output        # the QUIC handshake, not the TCP one
      check onlySuite in output
      check "TLS_AES_256_GCM_SHA384" notin output

    test "the same policy still applies to the TCP listener":
      # Same curl binary as the h3 case: a curl linked against LibreSSL names
      # the suite differently (AEAD-CHACHA20-POLY1305-SHA256).
      let (output, rc) = execCmdEx(
        h3curlBin & " -sv -k -m 10 -o /dev/null " & base & "/")
      check rc == 0
      check onlySuite in output
      check "HTTP/2" in output        # the TCP listener, not QUIC

    test "h3 still serves requests under the restriction":
      let (output, rc) = helper.h3curl(h3curlBin, "-w '|%{http_version}' " &
                                       base & "/")
      check rc == 0
      check output == "policy|3"

suite "HTTP/3 cannot honor a TLS 1.2 ceiling (#359)":
  test "maxTlsVersion = V12 with http3 is rejected at config time":
    # QUIC mandates TLS 1.3, so serving h3 would apply the ceiling on TCP and
    # silently ignore it on QUIC. The operator has to pick one.
    var raised = false
    try:
      discard newVortex(RequestHandler(handler),
                        initVortexConfig(certFile = certFile, keyFile = keyFile,
                                         maxTlsVersion = TlsVersion.V12)).start(0)
    except CatchableError as e:
      raised = true
      check "HTTP/3" in e.msg
    check raised

  test "the same ceiling is fine with http3 disabled":
    var s = newVortex(RequestHandler(handler),
                      initVortexConfig(numThreads = 1, workerThreads = 2,
                                       certFile = certFile, keyFile = keyFile,
                                       http3 = false,
                                       maxTlsVersion = TlsVersion.V12)).start(0)
    let (output, rc) = execCmdEx(
      h3curlBin & " -s -k -m 10 https://localhost:" & $s.port & "/")
    check rc == 0
    check output.strip() == "policy"
    s.close()

removeDir(certDir)
echo "server shut down cleanly"
