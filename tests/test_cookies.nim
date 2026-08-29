## Cookies end-to-end: the client's Cookie request header reaches the handler
## and parses (req.cookies["name"]), and Set-Cookie response headers reach the
## client. Exercised over HTTP/1.1, HTTP/2 (h2c) and HTTP/3 (gated), because the
## cookie *logic* is transport-agnostic but the header *transport* is not: h2
## (HPACK) and h3 (QPACK) may split a client's cookies across several `cookie`
## fields that the server must recombine (RFC 7540 8.1.2.5 / RFC 9114 4.2.1).

import std/[unittest, net, osproc, strutils, os, tables, times, options]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

suite "Set-Cookie attribute building (pure)":
  test "Expires renders an RFC 7231 IMF-fixdate":
    let (_, v) = setCookie("a", "b", expires = some(fromUnix(1700000000)))
    check "Expires=Tue, 14 Nov 2023 22:13:20 GMT" in v
  test "__Host- prefix forces Secure + Path=/ and drops Domain":
    let (_, v) = setCookie("sid", "x", path = "/app", domain = "example.com",
                           secure = false, prefix = cpHost)
    check v.startsWith("__Host-sid=x")
    check "; Path=/;" in (v & ";")          # Path is exactly "/"
    check "Domain=" notin v
    check "; Secure" in v
  test "__Secure- prefix forces Secure but keeps Path/Domain":
    let (_, v) = setCookie("sid", "x", path = "/app", secure = false,
                           prefix = cpSecure)
    check v.startsWith("__Secure-sid=x")
    check "; Path=/app" in v
    check "; Secure" in v
  test "Partitioned (CHIPS) attribute is emitted":
    let (_, v) = setCookie("a", "b", partitioned = true)
    check "; Partitioned" in v
  test "signed cookie carries Expires + Partitioned":
    let (_, v) = setSignedCookie("s", "v", "secret", partitioned = true,
                                 expires = some(fromUnix(1700000000)))
    check "; Partitioned" in v
    check "Expires=Tue, 14 Nov 2023 22:13:20 GMT" in v

proc echoCookies(req: Request, res: Response) {.gcsafe.} =
  # first-match wins on duplicate names; theme absent -> ""
  res.send(Http200, req.cookies["sid"] & "|" & req.cookies["theme"])

proc allSids(req: Request, res: Response) {.gcsafe.} =
  # every value of the "sid" cookie, in client order (for shadow detection)
  var vals: seq[string]
  for v in req.cookies.all("sid"): vals.add v
  res.send(Http200, vals.join(","))

proc setCookies(req: Request, res: Response) {.gcsafe.} =
  let (k, v) = setCookie("sid", "abc", maxAge = 3600)       # full attributes
  res.headers.add(k, v)
  res.headers.add("Set-Cookie", "theme=dark; Path=/")       # second, raw
  res.send(Http200, "ok")

var rt = newRouter()
rt.get("/echo", echoCookies)
rt.get("/all", allSids)
rt.get("/set", setCookies)
let handler = rt.toHandler

# --- HTTP/1.1 + HTTP/2 (h2c): one plaintext server --------------------------
var srv = newVortex(handler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

proc h2curl(args: string): (string, int) =
  let (output, rc) = execCmdEx("curl -s --http2-prior-knowledge " & args)
  (output.strip(), rc)

suite "cookies over HTTP/1.1":
  test "client Cookie header reaches the handler and parses":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({"Cookie": "sid=abc; theme=dark"})
    check c.getContent(base & "/echo") == "abc|dark"

  test "absent cookie is empty":
    var c = newHttpClient(); defer: c.close()
    check c.getContent(base & "/echo") == "|"

  test "duplicate cookie name: first wins (RFC 6265 5.4 most-specific first)":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({"Cookie": "sid=first; sid=second"})
    check c.getContent(base & "/echo") == "first|"

  test "all() yields every value of a duplicated cookie, in order":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({"Cookie": "sid=first; sid=second"})
    check c.getContent(base & "/all") == "first,second"

  test "a matched pair of surrounding double quotes is stripped":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({"Cookie": "sid=\"abc\"; theme=dark"})
    check c.getContent(base & "/echo") == "abc|dark"

  test "interior and unbalanced quotes are left as-is":
    var c = newHttpClient(); defer: c.close()
    # sid has an interior quote (no leading quote), theme is unbalanced
    c.headers = newHttpHeaders({"Cookie": "sid=a\"b; theme=\"dark"})
    check c.getContent(base & "/echo") == "a\"b|\"dark"

  test "server Set-Cookie reaches the client (duplicates preserved)":
    var c = newHttpClient(); defer: c.close()
    let r = c.get(base & "/set")
    check r.headers.table["set-cookie"].len == 2
    let joined = r.headers.table["set-cookie"].join(" ")
    check "sid=abc" in joined
    check "Max-Age=3600" in joined
    check "HttpOnly" in joined
    check "theme=dark" in joined

suite "cookies over HTTP/2 (h2c, via curl)":
  test "split cookie fields are recombined for the handler":
    # two separate Cookie headers -> h2 may send two `cookie` fields; the
    # handler must see both (req.cookies scans all of them).
    let (output, rc) = h2curl(
      "-H 'Cookie: sid=abc' -H 'Cookie: theme=dark' " & base & "/echo")
    check rc == 0
    check output == "abc|dark"

  test "Set-Cookie is delivered over h2":
    let (output, rc) = h2curl("-D - -o /dev/null " & base & "/set")
    check rc == 0
    check "set-cookie:" in output.toLowerAscii

srv.close()

# --- HTTP/3 (QUIC): gated on an HTTP/3-capable curl -------------------------
proc findH3Curl(): string =
  var cands: seq[string]
  let sys = findExe("curl")
  if sys.len > 0: cands.add sys
  cands.add "/opt/homebrew/opt/curl/bin/curl"
  for exe in cands:
    if fileExists(exe):
      let (ver, rc) = execCmdEx(exe & " --version")
      if rc == 0 and "HTTP3" in ver.toUpperAscii: return exe
  ""

let h3curlBin = findH3Curl()
if h3curlBin.len == 0:
  echo "SKIP: no HTTP/3-capable curl found"
  echo "cookies ok"
  quit 0

let certDir = getTempDir() / "nhs_cookie_certs_" & $getCurrentProcessId()
createDir(certDir)
let certFile = certDir / "cert.pem"
let keyFile = certDir / "key.pem"
check execCmdEx("openssl req -x509 -newkey rsa:2048 -nodes -keyout " &
  keyFile & " -out " & certFile & " -days 2 -subj /CN=localhost")[1] == 0

var srvH3 = newVortex(handler, initVortexConfig(
  numThreads = 1, workerThreads = 2, certFile = certFile, keyFile = keyFile)).start(0)
let baseH3 = "https://localhost:" & $srvH3.port

proc h3curl(args: string): (string, int) =
  let (output, rc) = execCmdEx(h3curlBin & " -sk --http3-only -m 10 " & args)
  (output.strip(), rc)

suite "cookies over HTTP/3 (QUIC, via curl)":
  test "split cookie fields are recombined for the handler":
    let (output, rc) = h3curl(
      "-H 'Cookie: sid=abc' -H 'Cookie: theme=dark' " & baseH3 & "/echo")
    check rc == 0
    check output == "abc|dark"

  test "Set-Cookie is delivered over h3":
    let (output, rc) = h3curl("-D - -o /dev/null " & baseH3 & "/set")
    check rc == 0
    check "set-cookie:" in output.toLowerAscii

srvH3.close()
removeDir(certDir)
echo "cookies ok"
