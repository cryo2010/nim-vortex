import std/[unittest, net, httpcore, os, osproc, strutils]
import std/httpclient except Response
import vortex/[settings, request, server]
import ./helper

let certDir = getTempDir() / "nhs_test_certs_" & $getCurrentProcessId()
createDir(certDir)
let certFile = certDir / "cert.pem"
let keyFile = certDir / "key.pem"
let (genOut, genRc) = execCmdEx(
  "openssl req -x509 -newkey rsa:2048 -nodes -keyout " & keyFile &
  " -out " & certFile & " -days 2 -subj /CN=localhost")
doAssert genRc == 0, "cert generation failed: " & genOut

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/":
    res.send(Http200, "hello over TLS", "text/plain")
  of "/echo":
    res.send(Http200, req.body, req.header("Content-Type"))
  else:
    res.send(Http404)

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 2,
                             certFile = certFile, keyFile = keyFile))
let base = "https://localhost:" & $srv.port

proc tlsClient(): HttpClient =
  newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))

suite "TLS":
  test "basic HTTPS GET":
    var client = tlsClient()
    defer: client.close()
    let resp = client.get(base & "/")
    check resp.code == Http200
    check resp.body == "hello over TLS"

  test "HTTPS POST echo":
    var client = tlsClient()
    defer: client.close()
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    check client.post(base & "/echo", body = """{"tls":true}""").body ==
      """{"tls":true}"""

  test "HTTPS keep-alive":
    var client = tlsClient()
    defer: client.close()
    for i in 0 ..< 5:
      check client.getContent(base & "/") == "hello over TLS"

  test "plaintext client against TLS port fails cleanly":
    # Send plain HTTP to the TLS listener; server must not crash and the
    # connection must close (handshake failure).
    let resp = rawExchange(srv.port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                           timeoutMs = 1500)
    check "hello over TLS" notin resp
    # And the server is still alive afterwards:
    var client = tlsClient()
    defer: client.close()
    check client.getContent(base & "/") == "hello over TLS"

  test "curl smoke with ALPN":
    let (output, rc) = execCmdEx(
      "curl -sk -w '|%{http_code}' https://localhost:" & $srv.port & "/")
    check rc == 0
    check output.strip() == "hello over TLS|200"

srv.close()
removeDir(certDir)
echo "server shut down cleanly"
