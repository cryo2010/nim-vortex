## PKCS#12 (.pfx), mTLS (client-cert verification), and SNI (per-host certs).

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"
  quit 0
let curlBin = findExe("curl")
let opensslBin = findExe("openssl")
if curlBin.len == 0 or opensslBin.len == 0:
  echo "SKIP: need curl and openssl"
  quit 0

let dir = getTempDir() / "vortex_tlsadv_" & $getCurrentProcessId()
removeDir(dir); createDir(dir)
proc sh(cmd: string) = doAssert execCmdEx(cmd)[1] == 0, cmd

# server cert (CN=localhost), a PKCS#12 bundle of it, and an alt cert for SNI
sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir & "/key.pem -out " &
   dir & "/cert.pem -days 2 -subj /CN=localhost")
sh("openssl pkcs12 -export -out " & dir & "/bundle.p12 -inkey " & dir &
   "/key.pem -in " & dir & "/cert.pem -passout pass:p12pass")
sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir & "/altkey.pem -out " &
   dir & "/alt.pem -days 2 -subj /CN=alt.example")
# a client CA and a client cert signed by it (mTLS)
sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir & "/ca.key -out " &
   dir & "/ca.pem -days 2 -subj /CN=TestCA")
sh("openssl req -newkey rsa:2048 -nodes -keyout " & dir & "/client.key -out " &
   dir & "/client.csr -subj /CN=test-client")
sh("openssl x509 -req -in " & dir & "/client.csr -CA " & dir & "/ca.pem -CAkey " &
   dir & "/ca.key -CAcreateserial -out " & dir & "/client.pem -days 2")

let cert = dir / "cert.pem"
let key = dir / "key.pem"

proc handler(req: Request, res: Response) {.gcsafe.} =
  # /whoami reports the mTLS client subject (or "-" if none)
  if req.path == "/whoami":
    let s = req.clientCertSubject
    res.send(Http200, if s.len > 0: s else: "-", "text/plain")
  else:
    res.send(Http200, "ok", "text/plain")

proc curlGet(port: Port, args = ""): (string, int) =
  let (o, rc) = execCmdEx(curlBin & " -sk --http1.1 -m 5 " & args &
                          " https://127.0.0.1:" & $port & "/")
  (o.strip(), rc)

suite "PKCS#12":
  test "cert+key from a .p12 file":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, pkcs12File = dir / "bundle.p12", keyPassword = "p12pass")).start(0)
    defer: srv.close()
    let (o, rc) = curlGet(srv.port)
    check rc == 0 and o == "ok"

  test "cert+key from in-memory .p12 bytes":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, pkcs12 = readFile(dir / "bundle.p12"), keyPassword = "p12pass")).start(0)
    defer: srv.close()
    let (o, rc) = curlGet(srv.port)
    check rc == 0 and o == "ok"

suite "mTLS":
  test "require: connection without a client cert is refused":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = cert, keyFile = key, verifyClient = cvRequire, clientCaFile = dir / "ca.pem")).start(0)
    defer: srv.close()
    let (_, rc) = curlGet(srv.port)                 # no client cert
    check rc != 0                                    # TLS handshake rejected

  test "require: valid client cert is accepted and its subject exposed":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = cert, keyFile = key, verifyClient = cvRequire, clientCaFile = dir / "ca.pem")).start(0)
    defer: srv.close()
    let (o, rc) = execCmdEx(curlBin & " -sk --http1.1 -m 5 --cert " & dir &
      "/client.pem --key " & dir & "/client.key https://127.0.0.1:" &
      $srv.port & "/whoami")
    check rc == 0
    check "test-client" in o

  test "optional: no client cert still connects, subject empty":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = cert, keyFile = key, verifyClient = cvOptional, clientCaFile = dir / "ca.pem")).start(0)
    defer: srv.close()
    let (o, rc) = execCmdEx(curlBin & " -sk --http1.1 -m 5 https://127.0.0.1:" &
      $srv.port & "/whoami")
    check rc == 0
    check o.strip() == "-"

suite "SNI":
  test "servername selects the matching per-host certificate":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = cert, keyFile = key, # default CN=localhost
                                 sni = @[SniCertEntry(host: "alt.example",
                                         certFile: dir / "alt.pem",
                                         keyFile: dir / "altkey.pem")])).start(0)
    defer: srv.close()
    proc servedSubject(servername: string): string =
      let cmd = "echo | " & opensslBin & " s_client -connect 127.0.0.1:" &
        $srv.port & " -servername " & servername &
        " 2>/dev/null | " & opensslBin & " x509 -noout -subject"
      execCmdEx(cmd)[0].strip()
    check "alt.example" in servedSubject("alt.example")   # SNI hit -> alt cert
    check "localhost" in servedSubject("localhost")       # default cert

removeDir(dir)
echo "tls advanced ok"
