## Per-host certificates (SNI) must be served over HTTP/3 too (#374). The QUIC
## engine had one SSL_CTX and one certificate per loop and no servername
## callback at all, so a browser that followed the server's own Alt-Svc
## advertisement for an SNI host was handed the *default* certificate and
## aborted with a name mismatch, while the identical request over TCP got the
## right certificate.

import std/[unittest, net, httpcore, os, osproc, strutils]
import vortex/[settings, request, server]
import ./helper

let h3curlBin = requireH3Curl()

let (certFile, keyFile) = makeCertPair("nhs_h3_sni_")
let dir = certFile.parentDir
genCert(dir / "api.pem", dir / "api.key", "api.example.com")
genCert(dir / "wild.pem", dir / "wild.key", "*.wild.example.com")

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "sni")

proc servedSubject(port: Port, host: string, h3: bool): string =
  ## The certificate subject curl reports for a request to `host`, resolved back
  ## to loopback. -v prints "*  subject: CN=..." for the connection's peer cert.
  let proto = if h3: " --http3-only" else: " --http2"
  let (output, _) = execCmdEx(
    h3curlBin & " -sv -k -m 10 -o /dev/null" & proto & " --resolve " & host &
    ":" & $port & ":127.0.0.1 https://" & host & ":" & $port & "/ 2>&1")
  for line in output.splitLines:
    let l = line.strip(chars = {' ', '*', '\t'})
    if l.startsWith("subject:"): return l
  ""

withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, workerThreads = 2,
                            certFile = certFile, keyFile = keyFile,
                            sni = @[
                              SniCertEntry(host: "api.example.com",
                                           certFile: dir / "api.pem",
                                           keyFile: dir / "api.key"),
                              SniCertEntry(host: "*.wild.example.com",
                                           certFile: dir / "wild.pem",
                                           keyFile: dir / "wild.key")]), srv):

  suite "SNI over HTTP/3 (#374)":
    test "an h3 request for the SNI host gets that host's certificate":
      check "api.example.com" in servedSubject(srv.port, "api.example.com", true)

    test "a wildcard SNI host matches one label over h3":
      check "wild.example.com" in
        servedSubject(srv.port, "foo.wild.example.com", true)

    test "a wildcard matches exactly one label, not the bare domain":
      check "localhost" in servedSubject(srv.port, "wild.example.com", true)
      check "localhost" in
        servedSubject(srv.port, "a.b.wild.example.com", true)

    test "the default host still gets the default certificate over h3":
      check "localhost" in servedSubject(srv.port, "localhost", true)

    test "an unmatched host falls back to the default certificate over h3":
      check "localhost" in servedSubject(srv.port, "other.example.org", true)

    test "the TCP listener selects the same certificates":
      check "api.example.com" in servedSubject(srv.port, "api.example.com", false)
      check "localhost" in servedSubject(srv.port, "localhost", false)

    test "h3 still serves the request after switching context":
      let (output, rc) = execCmdEx(
        h3curlBin & " -sk -m 10 --http3-only --resolve api.example.com:" &
        $srv.port & ":127.0.0.1 -w '|%{http_version}' https://api.example.com:" &
        $srv.port & "/")
      check rc == 0
      check output.strip() == "sni|3"

    test "a cert reload rebuilds the per-host certificates too":
      # reloadTls rotates the h3 certificate in place on every loop. The
      # per-host contexts are rebuilt from the material they were configured
      # with, so per-host certificate files replaced by the same renewal (the
      # certbot pattern: reloadTls names the default pair only) are picked up
      # instead of leaving those hosts on the old material.
      genCert(dir / "cert.pem", dir / "key.pem", "localhost")
      genCert(dir / "api.pem", dir / "api.key", "api-rotated.example.com")
      check srv.reloadTls(certFile, keyFile)
      sleep(1500)          # let the loop ticks apply the h3 swap
      check "api-rotated.example.com" in
        servedSubject(srv.port, "api.example.com", true)
      check "localhost" in servedSubject(srv.port, "localhost", true)

removeDir(dir)
echo "server shut down cleanly"
