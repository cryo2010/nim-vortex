## QPACK (RFC 9204) in capacity-0 mode: we advertise
## QPACK_MAX_TABLE_CAPACITY = 0, so peers cannot reference a dynamic
## table and only static-table and literal representations occur. This is
## fully spec-compliant and sidesteps the encoder/decoder-stream
## machinery; dynamic QPACK is a post-1.0 optimization.
##
## Integer, string, and Huffman primitives are shared with HPACK.

import ./qpack_tables
import ../http2/hpack

type
  QpackError* = object of CatchableError

proc decodeFieldSection*(buf: openArray[char], start, endPos: int,
                         headers: var seq[(string, string)]) =
  ## Decode a complete encoded field section (one HEADERS frame payload).
  var pos = start
  try:
    # Prefix: Required Insert Count (8-bit) + S/Delta Base (7-bit).
    let ric = decodeInt(buf, pos, endPos, 8)
    if ric != 0:
      raise newException(QpackError, "dynamic table use with capacity 0")
    discard decodeInt(buf, pos, endPos, 7)   # base: irrelevant at RIC 0
    while pos < endPos:
      let b = uint8(buf[pos])
      if (b and 0x80) != 0:
        # Indexed field line (1TXXXXXX); T must be 1 (static).
        if (b and 0x40) == 0:
          raise newException(QpackError, "dynamic index with capacity 0")
        let idx = decodeInt(buf, pos, endPos, 6)
        if idx > high(qpackStaticTable):
          raise newException(QpackError, "static index out of range")
        headers.add (qpackStaticTable[idx][0], qpackStaticTable[idx][1])
      elif (b and 0xc0) == 0x40:
        # Literal with name reference (01NTXXXX); T must be 1.
        if (b and 0x10) == 0:
          raise newException(QpackError, "dynamic name ref with capacity 0")
        let idx = decodeInt(buf, pos, endPos, 4)
        if idx > high(qpackStaticTable):
          raise newException(QpackError, "static index out of range")
        var value: string
        decodeStr(buf, pos, endPos, 7, value)
        headers.add (qpackStaticTable[idx][0], value)
      elif (b and 0xe0) == 0x20:
        # Literal with literal name (001NHXXX): 3-bit name length prefix.
        var name, value: string
        decodeStr(buf, pos, endPos, 3, name)
        decodeStr(buf, pos, endPos, 7, value)
        headers.add (name, value)
      else:
        # 0001xxxx / 0000xxxx: post-base forms (dynamic table only).
        raise newException(QpackError, "post-base ref with capacity 0")
  except HpackError as e:
    raise newException(QpackError, e.msg)

# --- encoding ---------------------------------------------------------------

proc addPrefix*(buf: var string) =
  ## Field section prefix for static-only encoding: RIC=0, base=0.
  buf.add '\0'
  buf.add '\0'

proc encodeRawStr(buf: var string, s: string, prefixBits: int,
                  firstByte: uint8) =
  encodeInt(buf, s.len, prefixBits, firstByte)   # H bit left 0: raw
  buf.add s

proc qpackStaticIndexOf(name: string): int =
  for i in 0 .. high(qpackStaticTable):
    if qpackStaticTable[i][0] == name: return i
  -1

proc encodeStatus*(buf: var string, status: int) =
  let idx =
    case status
    of 103: 24
    of 200: 25
    of 304: 26
    of 404: 27
    of 503: 28
    of 100: 63
    of 204: 64
    of 206: 65
    of 302: 66
    of 400: 67
    of 403: 68
    of 421: 69
    of 425: 70
    of 500: 71
    else: -1
  if idx >= 0:
    encodeInt(buf, idx, 6, 0xc0)                 # indexed, static
  else:
    encodeInt(buf, 24, 4, 0x50)                  # literal, name = :status
    encodeRawStr(buf, $status, 7, 0x00)

proc encodeHeader*(buf: var string, name, value: string) =
  ## Literal representations only; name must already be lowercase.
  let idx = qpackStaticIndexOf(name)
  if idx >= 0:
    encodeInt(buf, idx, 4, 0x50)                 # literal w/ static name ref
  else:
    encodeRawStr(buf, name, 3, 0x20)             # literal name
  encodeRawStr(buf, value, 7, 0x00)
