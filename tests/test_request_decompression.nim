## Inbound request-body decompression (settings.decompressRequest): a gzip/br/zstd
## request body is transparently decoded into req.body, bounded by maxBodySize
## so a decompression bomb is rejected with 413 (corrupt -> 400). Run via
## `nimble testreqdecomp`; skips under a build without a compression flag.

# The test body after the compile-time skip below is intentionally unreachable
# when the flags are absent (the SKIP path quits).
{.warning[UnreachableCode]: off.}

when not defined(httpGzip) and not defined(httpBrotli) and not defined(httpZstd):
  echo "SKIP: request decompression needs -d:httpGzip, -d:httpBrotli and/or -d:httpZstd"
  quit 0

import std/[unittest, os, osproc, strutils, httpcore, net]
import vortex/[settings, request, server]
when defined(httpGzip): import vortex/gzip
when defined(httpBrotli): import vortex/brotli
when defined(httpZstd): import vortex/zstd

let curlBin = findExe("curl")
if curlBin.len == 0:
  echo "SKIP: no curl"
  quit 0

const maxBody = 1_000_000
proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.path == "/echo": res.send(Http200, req.body)
  else: res.send(Http404)

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, decompressRequest = true, maxBodySize = maxBody)).start(0)
let base = "http://127.0.0.1:" & $srv.port
let tmp = getTempDir() / "vortex_reqdecomp_" & $getCurrentProcessId()
createDir(tmp)

proc post(h2: bool, enc, file: string): (int, string) =
  ## POST the file as the body with Content-Encoding: enc; return (status, body).
  let bodyf = tmp / "resp.bin"
  let proto = if h2: " --http2-prior-knowledge" else: ""
  let (outp, rc) = execCmdEx(curlBin & " -s" & proto & " -o " & bodyf &
    " -w '%{http_code}' --data-binary @" & file &
    " -H 'Content-Encoding: " & enc & "' -H 'Content-Type: text/plain' " &
    base & "/echo")
  check rc == 0
  (parseInt(outp.strip), readFile(bodyf))

let expected = "the quick brown fox. ".repeat(300)   # ~6 KB, well under the cap
let bomb = "A".repeat(5_000_000)                      # decodes to 5 MB > cap

# Write compressed request bodies with vortex's own encoders.
var encs: seq[string]
when defined(httpGzip):
  writeFile(tmp / "ok.gzip", gzip(expected))
  writeFile(tmp / "bomb.gzip", gzip(bomb))
  encs.add "gzip"
when defined(httpBrotli):
  writeFile(tmp / "ok.br", brotli(expected))
  writeFile(tmp / "bomb.br", brotli(bomb))
  encs.add "br"
when defined(httpZstd):
  writeFile(tmp / "ok.zstd", zstd(expected))
  writeFile(tmp / "bomb.zstd", zstd(bomb))
  encs.add "zstd"

suite "request-body decompression":
  for enc in encs:
    test "HTTP/1.1 " & enc & " body is decoded into req.body":
      let (status, body) = post(false, enc, tmp / ("ok." & enc))
      check status == 200
      check body == expected                      # server echoed the decoded body

    test "HTTP/2 (h2c) " & enc & " body is decoded":
      let (status, body) = post(true, enc, tmp / ("ok." & enc))
      check status == 200
      check body == expected

    test "decompression bomb over the cap -> 413 (" & enc & ")":
      let (status, _) = post(false, enc, tmp / ("bomb." & enc))
      check status == 413

  test "corrupt gzip body -> 400":
    when defined(httpGzip):
      writeFile(tmp / "bad.gzip", "this is not a gzip stream at all")
      let (status, _) = post(false, "gzip", tmp / "bad.gzip")
      check status == 400

  test "corrupt zstd body -> 400":
    when defined(httpZstd):
      writeFile(tmp / "bad.zstd", "this is not a zstd stream at all")
      let (status, _) = post(false, "zstd", tmp / "bad.zstd")
      check status == 400

srv.close()
removeDir(tmp)
echo "request decompression ok"
