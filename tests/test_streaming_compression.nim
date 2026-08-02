## Streaming response compression: res.sendHead/write/finish (and thus SSE and
## large-file streaming) compressed with gzip/brotli, negotiated from
## Accept-Encoding. Run via `nimble teststreamcomp`; skips under a build without
## a compression flag. curl fetches (h1 chunked and h2c) and the gzip/brotli
## CLIs decode, so we verify the framing and a byte-exact round-trip.

# The test body after the compile-time skip below is intentionally unreachable
# when the flags are absent (the SKIP path quits).
{.warning[UnreachableCode]: off.}

when not defined(httpGzip) and not defined(httpBrotli):
  echo "SKIP: streaming compression needs -d:httpGzip and/or -d:httpBrotli"
  quit 0

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]

let curlBin = findExe("curl")
if curlBin.len == 0:
  echo "SKIP: no curl"
  quit 0

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
  else:
    res.send(Http404)

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, compress = true)).start(0)
let base = "http://127.0.0.1:" & $srv.port
let tmp = getTempDir() / "vortex_streamcomp_" & $getCurrentProcessId()
createDir(tmp)

proc decoderCmd(enc: string): string =
  case enc
  of "gzip": "gunzip -c "
  of "br":   "brotli -d -c "
  else:      ""

proc fetch(h2: bool, enc: string): (string, string) =
  ## Returns (lowercased response headers, decoded body). Raw compressed body is
  ## written to a file (curl does not decode without --compressed) and decoded
  ## with the encoding's CLI.
  let bodyf = tmp / "body.bin"
  let proto = if h2: " --http2-prior-knowledge" else: ""
  let (hdrs, rc) = execCmdEx(curlBin & " -s" & proto & " -H 'Accept-Encoding: " &
    enc & "' -D - -o " & bodyf & " " & base & "/stream")
  doAssert rc == 0, "curl failed"
  let outf = tmp / "plain.out"
  doAssert execCmdEx(decoderCmd(enc) & bodyf & " > " & outf)[1] == 0, enc & " decode failed"
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

srv.close()
removeDir(tmp)
echo "streaming compression ok"
