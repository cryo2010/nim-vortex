## Zstandard response compression (Content-Encoding: zstd), buffered and
## streamed, plus Accept-Encoding negotiation among br/zstd/gzip. Built with all
## three encoders so the tie-break is exercised. Run via `nimble testzstd`;
## skips under a build without -d:httpZstd. curl fetches; the gzip/brotli/zstd
## CLIs decode, verifying framing and a byte-exact round-trip.

when not defined(httpZstd):
  echo "SKIP: zstd compression needs -d:httpZstd"
  quit 0

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]

let curlBin = findExe("curl")
if curlBin.len == 0:
  echo "SKIP: no curl"
  quit 0

const bufText = "the quick brown fox. ".repeat(300)     # ~6 KB buffered body
const chunkText = "streamed zstd chunk. ".repeat(20)
const nChunks = 200
let streamExpected = chunkText.repeat(nChunks)

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/buf":
    res.send(Http200, bufText, "text/plain")
  of "/stream":
    res.sendHead(Http200, "text/plain")
    for _ in 0 ..< nChunks: discard res.write(chunkText)
    res.finish()
  else:
    res.send(Http404)

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1, compress = true))
let base = "http://127.0.0.1:" & $srv.port
let tmp = getTempDir() / "vortex_zstd_" & $getCurrentProcessId()
createDir(tmp)

proc decoderCmd(enc: string): string =
  case enc
  of "zstd": "zstd -d -c "
  of "gzip": "gunzip -c "
  of "br":   "brotli -d -c "
  else:      "cat "

proc fetch(path: string, h2: bool, accept: string): (string, string) =
  ## Returns (lowercased headers, decoded body), decoding by the response's
  ## actual Content-Encoding.
  let bodyf = tmp / "body.bin"
  let proto = if h2: " --http2-prior-knowledge" else: ""
  let (hdrs, rc) = execCmdEx(curlBin & " -s" & proto & " -H 'Accept-Encoding: " &
    accept & "' -D - -o " & bodyf & " " & base & path)
  doAssert rc == 0
  let low = hdrs.toLowerAscii
  var enc = ""
  for ln in low.splitLines:
    let c = ln.find(':')
    if c > 0 and ln[0 ..< c].strip == "content-encoding": enc = ln[c+1 .. ^1].strip
  let outf = tmp / "plain.out"
  doAssert execCmdEx(decoderCmd(enc) & bodyf & " > " & outf)[1] == 0, "decode " & enc
  (low, readFile(outf))

suite "zstd response compression":
  test "buffered response, Accept-Encoding: zstd":
    let (hdrs, body) = fetch("/buf", false, "zstd")
    check "content-encoding: zstd" in hdrs
    check body == bufText

  test "streamed response (h1 chunked), zstd":
    let (hdrs, body) = fetch("/stream", false, "zstd")
    check "content-encoding: zstd" in hdrs
    check "transfer-encoding: chunked" in hdrs
    check body == streamExpected

  test "streamed response (h2c), zstd":
    let (hdrs, body) = fetch("/stream", true, "zstd")
    check "content-encoding: zstd" in hdrs
    check body == streamExpected

  test "negotiation: zstd chosen over gzip":
    let (hdrs, body) = fetch("/buf", false, "gzip, zstd")
    check "content-encoding: zstd" in hdrs
    check body == bufText

  test "negotiation: br preferred over zstd on a tie":
    let (hdrs, _) = fetch("/buf", false, "gzip, zstd, br")
    check "content-encoding: br" in hdrs

  test "negotiation: q-value can pick zstd over br":
    let (hdrs, _) = fetch("/buf", false, "br;q=0.5, zstd;q=1.0")
    check "content-encoding: zstd" in hdrs

srv.close()
removeDir(tmp)
echo "zstd compression ok"
