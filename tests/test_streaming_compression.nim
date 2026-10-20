## Streaming response compression: res.sendHead/write/finish (and thus SSE and
## large-file streaming) compressed with gzip/brotli, negotiated from
## Accept-Encoding. Run via `nimble teststreamcomp`; skips under a build without
## a compression flag. curl fetches (h1 chunked and h2c) and the gzip/brotli
## CLIs decode, so we verify the framing and a byte-exact round-trip.
##
## The static-file cases (#413) serve a `.txt` through `staticHandler`, whose
## first read runs on the worker pool: a large file streams (the worker hands
## the first chunk back and the loop negotiates the head), a small one is
## buffered and sent from the worker itself, which used to answer 500 because
## negotiation read Accept-Encoding through the loop-only connection table.

# The test body after the compile-time skip below is intentionally unreachable
# when the flags are absent (the SKIP path quits).
{.warning[UnreachableCode]: off.}

when not defined(httpGzip) and not defined(httpBrotli):
  echo "SKIP: streaming compression needs -d:httpGzip and/or -d:httpBrotli"
  quit 0

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server, routing, staticfiles]
import ./helper

let curlBin = requireCurl()

const chunkText = "The quick brown fox jumps over the lazy dog.\n"
const nChunks = 200
let expected = chunkText.repeat(nChunks)

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/stream":
    # A chunked/streamed body (no Content-Length) emitted over many writes.
    res.sendHead(Http200, "text/plain")
    for _ in 0 ..< nChunks:
      discard res.write(chunkText)
    res.finish()
  of "/fixed":
    # A declared length (file-serving shape): negotiated compression drops it,
    # so a GET is chunked and a HEAD takes the no-length path (#410).
    res.sendHead(Http200, "text/plain",
                 contentLength = chunkText.len * nChunks)
    for _ in 0 ..< nChunks:
      discard res.write(chunkText)
    res.finish()
  else:
    res.send(Http404)

let tmp = getTempDir() / "vortex_streamcomp_" & $getCurrentProcessId()
createDir(tmp)
let assetDir = tmp / "assets"
createDir(assetDir)
let smallText = chunkText.repeat(100)              # ~4.5 KiB: buffered on the worker
let largeText = chunkText.repeat(16 * 1024)        # ~720 KiB: above the stream threshold
writeFile(assetDir / "small.txt", smallText)
writeFile(assetDir / "large.txt", largeText)

let r = newRouter()
r.get("/assets/*", staticHandler(assetDir))
r.get("/stream", RequestHandler(handler))
r.get("/fixed", RequestHandler(handler))
var srv = newVortex(r.toHandler(),
  initVortexConfig(numThreads = 1, workerThreads = 2, compress = true)).start(0)
let base = "http://127.0.0.1:" & $srv.port

proc decoderCmd(enc: string): string =
  case enc
  of "gzip": "gunzip -c "
  of "br":   "brotli -d -c "
  else:      ""

proc fetch(h2: bool, enc: string, path = "/stream"): (string, string) =
  ## Returns (lowercased response headers, decoded body). Raw compressed body is
  ## written to a file (curl does not decode without --compressed) and decoded
  ## with the encoding's CLI.
  let bodyf = tmp / "body.bin"
  let proto = if h2: " --http2-prior-knowledge" else: ""
  let (hdrs, rc) = execCmdEx(curlBin & " -s" & proto & " -H 'Accept-Encoding: " &
    enc & "' -D - -o " & bodyf & " " & base & path)
  check rc == 0
  let outf = tmp / "plain.out"
  check execCmdEx(decoderCmd(enc) & bodyf & " > " & outf)[1] == 0
  (hdrs.toLowerAscii, readFile(outf))

var encodings: seq[string]
when defined(httpBrotli):
  if findExe("brotli").len > 0: encodings.add "br"
when defined(httpGzip):
  encodings.add "gzip"

suite "streaming response compression":
  for enc in encodings:
    test "HTTP/1.1 chunked, " & enc:
      let (hdrs, body) = fetch(false, enc)
      check ("content-encoding: " & enc) in hdrs
      check "transfer-encoding: chunked" in hdrs      # no Content-Length
      check body == expected                          # byte-exact round-trip

    test "HTTP/2 (h2c), " & enc:
      let (hdrs, body) = fetch(true, enc)
      check ("content-encoding: " & enc) in hdrs
      check body == expected

suite "static .txt served from the worker pool (#413)":
  for enc in encodings:
    for h2 in [false, true]:
      let proto = if h2: "HTTP/2 (h2c)" else: "HTTP/1.1"
      test proto & " buffered small.txt, " & enc:
        let (hdrs, body) = fetch(h2, enc, "/assets/small.txt")
        check hdrs.startsWith(if h2: "http/2 200" else: "http/1.1 200")
        check ("content-encoding: " & enc) in hdrs
        check body == smallText

      test proto & " streamed large.txt, " & enc:
        let (hdrs, body) = fetch(h2, enc, "/assets/large.txt")
        check hdrs.startsWith(if h2: "http/2 200" else: "http/1.1 200")
        check ("content-encoding: " & enc) in hdrs
        check body == largeText

when defined(httpGzip):
  suite "HEAD on a compressed streamed route (#410)":
    for path in ["/stream", "/fixed"]:
      test "HTTP/1.1 HEAD " & path & " carries the GET's gzip head, no body":
        # The head a GET gets: chunked, content-encoding + vary, and no
        # Content-Length (it used to be Content-Length: 0 and identity).
        let s = connectTimeout(srv.port, 3000)
        defer: s.close()
        s.send("HEAD " & path & " HTTP/1.1\r\nHost: x\r\n" &
               "Accept-Encoding: gzip\r\n\r\n")
        let head = s.recvAvailable(3000)
        let lower = head.toLowerAscii
        check head.startsWith("HTTP/1.1 200")
        check head.endsWith("\r\n\r\n")              # no body
        check "content-encoding: gzip" in lower
        check "vary: accept-encoding" in lower
        check "transfer-encoding: chunked" in lower
        check "content-length" notin lower
        # Keep-alive survives: the next request is answered in full.
        s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\n\r\n")
        let r = s.readHttpResponse()
        check r.ok and r.body == expected

srv.close()
removeDir(tmp)
echo "streaming compression ok"
