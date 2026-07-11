## Pure/fast security tests: request smuggling, integer overflow, and the
## HPACK decompression bomb. No server; parser and decoder are exercised
## directly. Tests assert the *secure* behavior throughout, so the bomb
## test is expected to fail until the decoder gains an output-size cap.

import std/[unittest, httpcore, strutils]
import vortex/http1/parser
import vortex/http2/hpack

proc limits(maxHeaderSize = 16384, maxHeaderCount = 100,
            maxBodySize = 1024 * 1024): ParserLimits =
  ParserLimits(maxHeaderSize: maxHeaderSize, maxHeaderCount: maxHeaderCount,
               maxBodySize: maxBodySize)

proc parseAll(data: string, lim = limits()): (ParseResult, HttpCode) =
  var p: RequestParser
  p.reset(0)
  var body = ""
  let res = p.parse(data, data.len, lim, body)
  (res, p.errorStatus)

suite "request smuggling should be rejected":
  test "Content-Length with Transfer-Encoding should be rejected":
    let (res, _) = parseAll(
      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n" &
      "Transfer-Encoding: chunked\r\n\r\n")
    check res == prError

  test "Transfer-Encoding then Content-Length should be rejected":
    let (res, _) = parseAll(
      "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n" &
      "Content-Length: 5\r\n\r\n")
    check res == prError

  test "duplicate Content-Length should be rejected":
    let (res, _) = parseAll(
      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
    check res == prError

  test "bare LF line ending should be rejected":
    let (res, _) = parseAll("GET / HTTP/1.1\nHost: x\n\n")
    check res == prError

  test "non-chunked Transfer-Encoding should be rejected":
    let (res, status) = parseAll(
      "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n")
    check res == prError
    check status == Http501

  test "space in field name should be rejected":
    let (res, _) = parseAll("GET / HTTP/1.1\r\nHost: x\r\nBad Header: x\r\n\r\n")
    check res == prError

  test "obs-fold continuation line should be rejected":
    let (res, _) = parseAll(
      "GET / HTTP/1.1\r\nHost: x\r\nX-A: value\r\n folded: c\r\n\r\n")
    check res == prError

  test "chunk extensions should be tolerated":
    let (res, _) = parseAll(
      "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" &
      "5;name=value\r\nhello\r\n0\r\n\r\n")
    check res == prComplete

suite "integer overflow should not wrap":
  test "oversized Content-Length should give 413 not wraparound":
    let (res, status) = parseAll(
      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999\r\n\r\n")
    check res == prError
    check status == Http413

  test "oversized chunk size should give 413 not wraparound":
    let (res, status) = parseAll(
      "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" &
      "FFFFFFFFFFFFFFFF\r\n")
    check res == prError
    check status == Http413

  test "non-numeric Content-Length should be rejected":
    let (res, _) = parseAll("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1e9\r\n\r\n")
    check res == prError

proc encodeInt7(buf: var string, value: int, firstByte: uint8) =
  ## HPACK integer with a 7-bit prefix, for building raw string lengths.
  encodeInt(buf, value, 7, firstByte)

proc hpackBomb(entryValueLen, refCount: int): string =
  ## A block that adds one large entry to the dynamic table, then floods
  ## 1-byte indexed references to it. Compact on the wire, huge decoded.
  result = ""
  # Literal with incremental indexing, new name (0x40): name "x", big value.
  result.add char(0x40)
  encodeInt7(result, 1, 0x00)          # name length 1
  result.add "x"
  encodeInt7(result, entryValueLen, 0x00)
  result.add repeat('a', entryValueLen)
  # Indexed references to dynamic entry 62 (0x80 | 62 = 0xBE).
  for i in 0 ..< refCount:
    result.add char(0xBE)

suite "HPACK decompression bomb should be rejected":
  test "block expanding far beyond the header list limit should raise":
    # Entry ~3 KB, 60 refs => ~180 KB decoded from a ~3 KB block.
    let bomb = hpackBomb(entryValueLen = 3000, refCount = 60)
    var d = initHpackDecoder()
    var headers: seq[(string, string)]
    expect HpackError:
      d.decodeHeaderBlock(bomb, 0, bomb.len, headers)

  test "a normal small block should still decode":
    let bomb = hpackBomb(entryValueLen = 20, refCount = 3)
    var d = initHpackDecoder()
    var headers: seq[(string, string)]
    d.decodeHeaderBlock(bomb, 0, bomb.len, headers)
    check headers.len == 4          # the literal + 3 references
