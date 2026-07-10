import std/[unittest, net, httpcore, osproc, strutils, os]
import vortex/[settings, request, server]

# HTTP/3 needs an h3-capable curl (Homebrew's links libnghttp3/ngtcp2).
const h3curlBin = "/opt/homebrew/opt/curl/bin/curl"
if not fileExists(h3curlBin):
  echo "SKIP: no HTTP/3-capable curl at ", h3curlBin
  quit 0

let certDir = getTempDir() / "nhs_h3_certs_" & $getCurrentProcessId()
createDir(certDir)
let certFile = certDir / "cert.pem"
let keyFile = certDir / "key.pem"
doAssert execCmdEx("openssl req -x509 -newkey rsa:2048 -nodes -keyout " &
  keyFile & " -out " & certFile & " -days 2 -subj /CN=localhost")[1] == 0

const bigBody = "0123456789abcdef".repeat(8 * 1024)   # 128 KiB

proc handler(req: Request) {.gcsafe.} =
  case req.path
  of "/":
    req.respond(Http200, "hello h3", "text/plain")
  of "/echo":
    req.respond(Http200, req.body, req.header("Content-Type"),
                headers = [("X-Proto", $req.httpVersion)])
  of "/big":
    req.respond(Http200, bigBody, "application/octet-stream")
  of "/slow":
    req.blocking:
      sleep(100)
      req.respond(Http200, "slow h3 done", "text/plain")
  else:
    req.respond(Http404, "nope", "text/plain")

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1,
                             workerThreads = 2, certFile = certFile,
                             keyFile = keyFile,
                             maxBodySize = 1024 * 1024))
let base = "https://localhost:" & $srv.port

proc h3curl(args: string): (string, int) =
  let (output, rc) = execCmdEx(h3curlBin & " -sk --http3-only -m 10 " & args)
  (output.strip(), rc)

suite "HTTP/3 (QUIC, via curl)":
  test "GET":
    let (output, rc) = h3curl("-w '|%{http_version}' " & base & "/")
    check rc == 0
    check output == "hello h3|3"

  test "POST echo":
    let (output, rc) = h3curl(
      "-H 'Content-Type: text/plain' -d 'payload h3' " &
      "-w '|%{http_version}' " & base & "/echo")
    check rc == 0
    check output == "payload h3|3"

  test "404":
    let (output, rc) = h3curl("-o /dev/null -w '%{http_code}' " & base & "/x")
    check rc == 0
    check output == "404"

  test "HEAD has no body":
    let (output, rc) = h3curl("-I -w '%{size_download}' " & base & "/")
    check rc == 0
    check "HTTP/3 200" in output
    check output.endsWith("0")

  test "large response":
    let (output, rc) = h3curl("-o /dev/null -w '%{size_download}' " & base & "/big")
    check rc == 0
    check output == $bigBody.len

  test "blocking route over h3 (worker respond path)":
    let (output, rc) = h3curl(base & "/slow")
    check rc == 0
    check output == "slow h3 done"

  test "several sequential requests":
    for i in 0 ..< 3:
      check h3curl(base & "/")[0] == "hello h3"

  test "alt-svc advertised on h1/h2":
    let (output, rc) = execCmdEx(
      "curl -skI -m 5 " & base & "/")
    check rc == 0
    check ("h3=\":" & $srv.port & "\"") in output

srv.close()
removeDir(certDir)
echo "server shut down cleanly"
