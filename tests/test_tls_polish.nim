## Wildcard SNI, max TLS version, and OCSP stapling.

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]

when defined(plainHttp):
  echo "SKIP: -d:plainHttp has no TLS"
  quit 0
let opensslBin = findExe("openssl")
if opensslBin.len == 0:
  echo "SKIP: need openssl"
  quit 0

let dir = getTempDir() / "vortex_tlspol_" & $getCurrentProcessId()
removeDir(dir); createDir(dir)
proc sh(cmd: string): int = execCmdEx(cmd)[1]
proc must(cmd: string) = doAssert sh(cmd) == 0, cmd

# default cert (CN=localhost) and a wildcard cert (CN=*.example.com)
must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir & "/key.pem -out " &
     dir & "/cert.pem -days 2 -subj /CN=localhost")
must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
     "/wildkey.pem -out " & dir & "/wild.pem -days 2 -subj '/CN=*.example.com'")
let cert = dir / "cert.pem"
let key = dir / "key.pem"

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok", "text/plain")

proc servedSubject(port: Port, servername: string): string =
  let cmd = "echo | " & opensslBin & " s_client -connect 127.0.0.1:" & $port &
    " -servername " & servername & " 2>/dev/null | " & opensslBin &
    " x509 -noout -subject"
  execCmdEx(cmd)[0].strip()

proc negotiatedProto(port: Port): string =
  let cmd = "echo | " & opensslBin & " s_client -connect 127.0.0.1:" & $port &
    " 2>/dev/null | grep -iE 'Protocol *:'"
  execCmdEx(cmd)[0].strip()

proc tls13Establishes(port: Port): bool =
  # s_client -tls1_3 prints the *requested* protocol even on failure, so judge
  # by whether a cipher was actually negotiated.
  let cmd = "echo | " & opensslBin & " s_client -connect 127.0.0.1:" & $port &
    " -tls1_3 2>&1"
  let (o, rc) = execCmdEx(cmd)
  rc == 0 and "cipher is " in o.toLowerAscii and "(none)" notin o.toLowerAscii

suite "wildcard SNI":
  test "*.example.com matches one label; not the bare domain":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = cert, keyFile = key, sni = @[SniCertEntry(host: "*.example.com",
                                         certFile: dir / "wild.pem",
                                         keyFile: dir / "wildkey.pem")])).start(0)
    defer: srv.close()
    check "*.example.com" in servedSubject(srv.port, "foo.example.com")  # wildcard hit
    check "localhost" in servedSubject(srv.port, "example.com")          # bare -> default
    check "localhost" in servedSubject(srv.port, "other.org")            # no match -> default

suite "max TLS version":
  test "cap at 1.2 negotiates 1.2, refuses 1.3":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = cert, keyFile = key, maxTlsVersion = tlsMax12)).start(0)
    defer: srv.close()
    check "TLSv1.2" in negotiatedProto(srv.port)
    check not tls13Establishes(srv.port)                          # 1.3 refused

  test "min 1.3 > max 1.2 is rejected at start":
    expect CatchableError:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = cert, keyFile = key, minTlsVersion = tlsV13, maxTlsVersion = tlsMax12)).start(0)
      srv.close()

# --- OCSP stapling: generate a real response, or skip if the toolchain differs
proc buildOcsp(): bool =
  if sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
        "/ca.key -out " & dir & "/ca.pem -days 2 -subj /CN=OCSP-CA") != 0: return false
  if sh("openssl req -newkey rsa:2048 -nodes -keyout " & dir & "/srv.key -out " &
        dir & "/srv.csr -subj /CN=localhost") != 0: return false
  if sh("openssl x509 -req -in " & dir & "/srv.csr -CA " & dir & "/ca.pem -CAkey " &
        dir & "/ca.key -CAcreateserial -out " & dir & "/srv.pem -days 2") != 0: return false
  # index.txt from the cert's serial + expiry (via python for the date format)
  let py = "import subprocess,datetime; " &
    "g=lambda a: subprocess.check_output(['openssl','x509','-in','" & dir &
    "/srv.pem','-noout',a]).decode().strip().split('=',1)[1]; " &
    "s=g('-serial'); e=' '.join(g('-enddate').split()); " &
    "d=datetime.datetime.strptime(e,'%b %d %H:%M:%S %Y %Z'); " &
    "open('" & dir & "/index.txt','w').write('V\\t'+d.strftime('%y%m%d%H%M%SZ')+" &
    "'\\t\\t'+s+'\\tunknown\\t/CN=localhost\\n')"
  if sh("python3 -c \"" & py & "\"") != 0: return false
  if sh("openssl ocsp -issuer " & dir & "/ca.pem -cert " & dir &
        "/srv.pem -reqout " & dir & "/req.der -no_nonce") != 0: return false
  sh("openssl ocsp -index " & dir & "/index.txt -CA " & dir & "/ca.pem -rsigner " &
     dir & "/ca.pem -rkey " & dir & "/ca.key -reqin " & dir & "/req.der -respout " &
     dir & "/resp.der -ndays 1 -no_nonce") == 0 and
    fileExists(dir / "resp.der") and getFileSize(dir / "resp.der") > 0

suite "OCSP stapling":
  test "a client status request gets the stapled response":
    if not buildOcsp():
      echo "  SKIP: could not build an OCSP response with this openssl"
      skip()
    else:
      var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, certFile = dir / "srv.pem", keyFile = dir / "srv.key", ocspFile = dir / "resp.der")).start(0)
      defer: srv.close()
      let cmd = "echo | " & opensslBin & " s_client -status -connect 127.0.0.1:" &
        $srv.port & " 2>/dev/null | grep -iE 'OCSP Response Status'"
      let (o, _) = execCmdEx(cmd)
      check "successful" in o.toLowerAscii

removeDir(dir)
echo "tls polish ok"
