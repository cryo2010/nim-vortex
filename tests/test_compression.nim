## gzip response compression (settings.compress, -d:httpGzip). Run via
## `nimble testgzip`; under the default build it skips (the feature is compiled
## out). curl handles the gzip round-trip.

when not defined(httpGzip):
  echo "SKIP: gzip response compression needs -d:httpGzip"
  quit 0

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]

let curlBin = findExe("curl")
if curlBin.len == 0:
  echo "SKIP: no curl"
  quit 0

const bigText = "The quick brown fox jumps over the lazy dog. ".repeat(120)  # ~5 KiB

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/big":   res.send(Http200, bigText, "text/plain")
  of "/small": res.send(Http200, "tiny", "text/plain")
  of "/png":   res.send(Http200, bigText, "image/png")   # not compressible
  else:        res.send(Http404)

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1, compress = true))
let base = "http://127.0.0.1:" & $srv.port
let tmp = getTempDir() / "vortex_gzip_" & $getCurrentProcessId()
createDir(tmp)

proc fetch(path, acceptEnc: string): (string, string) =
  ## Returns (headers, decompressed-or-raw body). Body written to a file and,
  ## if gzip, gunzipped; headers captured with -D.
  let bodyf = tmp / "body.bin"
  let (hdrs, rc) = execCmdEx(curlBin & " -s -H 'Accept-Encoding: " & acceptEnc &
    "' -D - -o " & bodyf & " " & base & path)
  doAssert rc == 0
  let ce = block:
    var v = ""
    for ln in hdrs.splitLines:
      let c = ln.find(':')
      if c > 0 and cmpIgnoreCase(ln[0..<c].strip, "content-encoding") == 0:
        v = ln[c+1..^1].strip
    v
  let body =
    if ce == "gzip":
      # Decompress to a file and read it back byte-exactly (capturing gunzip's
      # stdout through a pipe is not byte-faithful).
      let outf = tmp / "plain.out"
      doAssert execCmdEx("gunzip -c " & bodyf & " > " & outf)[1] == 0
      readFile(outf)
    else: readFile(bodyf)
  (hdrs.toLowerAscii, body)

suite "gzip response compression":
  test "compressible body with Accept-Encoding: gzip is gzipped and round-trips":
    let (hdrs, body) = fetch("/big", "gzip")
    check "content-encoding: gzip" in hdrs
    check "vary: accept-encoding" in hdrs
    check body == bigText                    # gunzip matches the original

  test "no Accept-Encoding: gzip -> identity":
    let (hdrs, body) = fetch("/big", "identity")
    check "content-encoding: gzip" notin hdrs
    check body == bigText

  test "small bodies are not compressed":
    let (hdrs, _) = fetch("/small", "gzip")
    check "content-encoding: gzip" notin hdrs

  test "non-compressible content-type is not compressed":
    let (hdrs, _) = fetch("/png", "gzip")
    check "content-encoding: gzip" notin hdrs

srv.close()
removeDir(tmp)
echo "gzip compression ok"
