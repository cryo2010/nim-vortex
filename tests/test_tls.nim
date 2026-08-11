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

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 2, certFile = certFile, keyFile = keyFile)).start(0)
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

# --- minimum TLS version -----------------------------------------------------

proc handshakeOk(port: Port, tlsFlag: string): bool =
  ## openssl s_client exits 0 on a completed handshake, non-zero on a
  ## version/handshake rejection. (System curl here is LibreSSL and is
  ## unreliable for --tlsv1.3, so drive OpenSSL directly.)
  execCmdEx("echo | openssl s_client -connect localhost:" & $port & " " &
            tlsFlag & " >/dev/null 2>&1")[1] == 0

var srv12 = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, http3 = false, certFile = certFile, keyFile = keyFile)).start(0)
                               # default minTlsVersion = TlsVersion.V12
var srv13 = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, http3 = false, certFile = certFile, keyFile = keyFile, minTlsVersion = TlsVersion.V13)).start(0)

suite "minimum TLS version":
  test "default (TlsVersion.V12) accepts TLS 1.2":
    check handshakeOk(srv12.port, "-tls1_2")

  test "default (TlsVersion.V12) accepts TLS 1.3":
    check handshakeOk(srv12.port, "-tls1_3")

  test "TlsVersion.V13 rejects TLS 1.2":
    check not handshakeOk(srv13.port, "-tls1_2")

  test "TlsVersion.V13 accepts TLS 1.3":
    check handshakeOk(srv13.port, "-tls1_3")

var srvCipher = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, http3 = false, certFile = certFile, keyFile = keyFile, tlsCipherSuites = "TLS_AES_128_GCM_SHA256")).start(0)

suite "TLS cipher configuration":
  test "restricted TLS 1.3 cipher suite is honored":
    let (output, rc) = execCmdEx(
      "echo | openssl s_client -connect localhost:" & $srvCipher.port &
      " -tls1_3 2>&1")
    check rc == 0
    check "TLS_AES_128_GCM_SHA256" in output      # the only suite we allowed
    check "TLS_AES_256_GCM_SHA384" notin output   # the default, now excluded

  test "an invalid cipher suite is rejected at startup":
    expect CatchableError:
      var bad = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, http3 = false, certFile = certFile, keyFile = keyFile, tlsCipherSuites = "NOT_A_REAL_CIPHER")).start(0)
      bad.close()

srvCipher.close()
srv12.close()
srv13.close()
srv.close()
removeDir(certDir)
echo "server shut down cleanly"
