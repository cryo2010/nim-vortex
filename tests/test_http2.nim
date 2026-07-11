import std/[unittest, net, httpcore, osproc, strutils, os, tables]
import vortex/[settings, request, server]

const bigBody = "0123456789abcdef".repeat(16 * 1024)   # 256 KiB

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.url.path
  of "/":
    res.send(Http200, "hello h2", "text/plain")
  of "/qs":
    res.send(Http200, req.url.path & "|" & req.query["k"], "text/plain")
  of "/echo":
    res.send(Http200, req.body, req.header("Content-Type"),
                headers = [("X-Proto", $req.httpVersion)])
  of "/big":
    res.send(Http200, bigBody, "application/octet-stream")
  of "/slow":
    req.blocking:
      sleep(100)
      res.send(Http200, "slow h2 done", "text/plain")
  of "/nm":
    res.send(Http304, "", "text/plain", headers = [("etag", "\"v1\"")])
  else:
    res.send(Http404, "nope", "text/plain")

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 2,
                             workerThreads = 2,
                             maxBodySize = 1024 * 1024))
let base = "http://127.0.0.1:" & $srv.port

proc h2curl(args: string): (string, int) =
  let (output, rc) = execCmdEx("curl -s --http2-prior-knowledge " & args)
  (output.strip(), rc)

suite "HTTP/2 (h2c prior knowledge, via curl)":
  test "GET":
    let (output, rc) = h2curl("-w '|%{http_version}' " & base & "/")
    check rc == 0
    check output == "hello h2|2"

  test "POST echo with headers":
    let (output, rc) = h2curl(
      "-H 'Content-Type: text/plain' -d 'payload h2' " &
      "-w '|%{http_version}|%{content_type}' " & base & "/echo")
    check rc == 0
    check output == "payload h2|2|text/plain"

  test "query string over h2":
    let (output, rc) = h2curl("'" & base & "/qs?k=v%20w'")
    check rc == 0
    check output == "/qs|v w"

  test "404":
    let (output, rc) = h2curl("-o /dev/null -w '%{http_code}' " & base & "/nope")
    check rc == 0
    check output == "404"

  test "HEAD has no body":
    let (output, rc) = h2curl("-I -w '%{size_download}' " & base & "/")
    check rc == 0
    check "HTTP/2 200" in output
    check output.endsWith("0")

  test "large response exercises flow control":
    let (output, rc) = h2curl("-o /dev/null -w '%{size_download}' " & base & "/big")
    check rc == 0
    check output == $bigBody.len

  test "blocking route over h2 (worker respond path)":
    let (output, rc) = h2curl(base & "/slow")
    check rc == 0
    check output == "slow h2 done"

  test "multiplexed requests on one connection":
    # curl reuses one connection for multiple URLs with --parallel.
    var (output, rc) = execCmdEx(
      "curl -s --http2-prior-knowledge --parallel " &
      base & "/ " & base & "/slow " & base & "/echo")
    output = output.strip()
    check rc == 0
    check "hello h2" in output
    check "slow h2 done" in output

  test "304 omits content-length/content-type but keeps validator":
    let (output, rc) = h2curl("-D - -o /dev/null " & base & "/nm")
    check rc == 0
    check "HTTP/2 304" in output
    check "content-length" notin output.toLowerAscii
    check "content-type" notin output.toLowerAscii
    check "etag: \"v1\"" in output.toLowerAscii

  test "HTTP/1.1 still served on the same port":
    var (output, rc) = execCmdEx(
      "curl -s --http1.1 -w '|%{http_version}' " & base & "/")
    output = output.strip()
    check rc == 0
    check output == "hello h2|1.1"

srv.close()
echo "server shut down cleanly"
