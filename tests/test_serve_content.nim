## conditional.nim (preconditions + range parsing) as pure units, and
## request.serveContent end-to-end: conditional GET (304), write preconditions
## (412), single + multiple byte ranges (206 / multipart/byteranges), and 416.

import std/[unittest, net, strutils, tables, times, options, osproc]
import std/httpclient except Response
import vortex/[settings, request, server, routing]
import vortex/conditional

suite "conditional (pure)":
  test "etagIn: weak comparison matches W/ on either side; strong does not":
    check etagIn("\"a\", \"b\"", "\"b\"", strong = false)
    check etagIn("W/\"b\"", "\"b\"", strong = false)     # weak cmp ignores W/
    check not etagIn("W/\"b\"", "\"b\"", strong = true)  # strong: weak excluded
    check etagIn("*", "\"anything\"", strong = true)

  test "evalPreconditions precedence (RFC 9110 13.2.2)":
    let lm = some(fromUnix(1000))
    # If-Match miss -> 412
    check evalPreconditions("\"x\"", "", "", "", "\"y\"", lm, true) == pcFailed
    # If-None-Match hit on GET -> 304, on non-GET -> 412
    check evalPreconditions("", "\"y\"", "", "", "\"y\"", lm, true) == pcNotModified
    check evalPreconditions("", "\"y\"", "", "", "\"y\"", lm, false) == pcFailed
    # If-Unmodified-Since in the past (resource newer) -> 412
    check evalPreconditions("", "", "", httpDate(fromUnix(500)), "", lm, true) == pcFailed
    # nothing blocks -> proceed
    check evalPreconditions("", "", "", "", "\"y\"", lm, true) == pcProceed

  test "parseRanges: single, multiple, suffix, unsatisfiable, whole":
    check parseRanges("bytes=0-3", 16) == (true, @[(0'i64, 3'i64)])
    check parseRanges("bytes=0-3,8-11", 16) == (true, @[(0'i64, 3'i64), (8'i64, 11'i64)])
    check parseRanges("bytes=-4", 16) == (true, @[(12'i64, 15'i64)])   # last 4
    check parseRanges("bytes=100-200", 16) == (false, newSeq[ByteRange]())  # 416
    check parseRanges("bytes=0-15", 16) == (true, newSeq[ByteRange]())  # whole -> 200

const bodyStr = "0123456789ABCDEF"          # 16 bytes
const etag = "\"v1\""
const lmUnix = 1700000000                   # Tue, 14 Nov 2023 22:13:20 GMT

proc content(req: Request, res: Response) {.gcsafe.} =
  req.serveContent(res, bodyStr, "application/x-test",
                   etag = etag, lastModified = some(fromUnix(lmUnix)),
                   cacheControl = "max-age=60")

var rt = newRouter()
rt.get("/c", content)
var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

proc req(headers: seq[(string, string)] = @[]): auto =
  var c = newHttpClient(maxRedirects = 0)
  if headers.len > 0: c.headers = newHttpHeaders(headers)
  let r = c.get(base & "/c")
  c.close()
  r

suite "serveContent end-to-end":
  test "plain GET: 200 with validators, Accept-Ranges, single Content-Type":
    let r = req()
    check r.status.startsWith("200")
    check r.body == bodyStr
    check r.headers["etag"] == etag
    # httpclient splits comma-bearing header values; rejoin the IMF-fixdate.
    check "GMT" in r.headers.table["last-modified"].join(", ")
    check r.headers["accept-ranges"] == "bytes"
    check r.headers["cache-control"] == "max-age=60"
    check r.headers.table["content-type"].len == 1          # no duplicate
    check r.headers["content-type"] == "application/x-test"

  test "If-None-Match hit -> 304, no body":
    let r = req(@[("If-None-Match", etag)])
    check r.status.startsWith("304")
    check r.body.len == 0

  test "If-Match miss -> 412":
    check req(@[("If-Match", "\"other\"")]).status.startsWith("412")

  test "If-Unmodified-Since before mtime -> 412":
    check req(@[("If-Unmodified-Since", httpDate(fromUnix(1000)))]).status.startsWith("412")

  test "single Range -> 206 with the slice + Content-Range":
    let r = req(@[("Range", "bytes=0-3")])
    check r.status.startsWith("206")
    check r.body == "0123"
    check r.headers["content-range"] == "bytes 0-3/16"

  test "multiple Range -> 206 multipart/byteranges with both parts":
    # curl sends the multi-range header verbatim (Nim's httpclient splits the
    # comma into two Range fields, so the server would see only the first).
    let (output, rc) = execCmdEx("curl -s -i -H 'Range: bytes=0-3,8-11' " & base & "/c")
    check rc == 0
    check "206" in output
    check "multipart/byteranges" in output.toLowerAscii
    check "bytes 0-3/16" in output
    check "bytes 8-11/16" in output
    check "0123" in output
    check "89AB" in output

  test "unsatisfiable Range -> 416 with Content-Range */size":
    let r = req(@[("Range", "bytes=100-200")])
    check r.status.startsWith("416")
    check r.headers["content-range"] == "bytes */16"

  test "If-Range with a stale validator ignores Range -> full 200":
    let r = req(@[("Range", "bytes=0-3"), ("If-Range", "\"stale\"")])
    check r.status.startsWith("200")
    check r.body == bodyStr

srv.close()
echo "serveContent ok"
