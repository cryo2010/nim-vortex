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

  QpackDynTable* = object
    ## QPACK decoder dynamic table (RFC 9204 3.2): a FIFO of inserted entries,
    ## the oldest evicted to stay within `capacity` bytes. Entries have stable
    ## absolute indices; `dropped` is how many have been evicted, so absolute
    ## index i lives at `entries[i - dropped]` while `has(i)` holds.
    entries: seq[(string, string)]
    dropped: int                 ## count evicted (absolute index of entries[0])
    size: int                    ## current byte size
    capacity*: int               ## max byte size (Set Dynamic Table Capacity)

proc entrySize(name, value: string): int {.inline.} =
  name.len + value.len + 32      ## RFC 9204 3.2.1

proc insertCount*(t: QpackDynTable): int {.inline.} =
  ## Total insertions ever (the absolute index the next insert will get).
  t.dropped + t.entries.len

proc has*(t: QpackDynTable, absIdx: int): bool {.inline.} =
  absIdx >= t.dropped and absIdx < t.insertCount

proc get*(t: QpackDynTable, absIdx: int): (string, string) {.inline.} =
  t.entries[absIdx - t.dropped]

proc evictOne(t: var QpackDynTable) =
  t.size -= entrySize(t.entries[0][0], t.entries[0][1])
  t.entries.delete(0)
  inc t.dropped

proc setCapacity*(t: var QpackDynTable, cap: int) =
  ## Set the table capacity, evicting the oldest entries to fit (RFC 9204 4.3.1).
  t.capacity = cap
  while t.size > t.capacity and t.entries.len > 0:
    t.evictOne()

proc insert*(t: var QpackDynTable, name, value: string): bool {.discardable.} =
  ## Insert an entry, evicting oldest to make room. Returns false (no insert)
  ## if it cannot fit even in an empty table.
  let sz = entrySize(name, value)
  while t.size + sz > t.capacity and t.entries.len > 0:
    t.evictOne()
  if t.size + sz > t.capacity:
    return false
  t.entries.add (name, value)
  t.size += sz
  true

proc decodeEncoderInstructions*(t: var QpackDynTable, buf: openArray[char],
                                maxCapacity: int): int =
  ## Apply as many complete QPACK encoder-stream instructions (RFC 9204 4.3) as
  ## `buf` holds and return the number of bytes consumed; a trailing partial
  ## instruction is left for the next call. Raises QpackError on a protocol
  ## violation (bad index, capacity over the advertised maximum).
  var pos = 0
  while pos < buf.len:
    let start = pos
    let b = uint8(buf[pos])
    try:
      if (b and 0x80) != 0:
        # Insert with Name Reference (4.3.2): 1 T index(6) + value.
        let isStatic = (b and 0x40) != 0
        let idx = decodeInt(buf, pos, buf.len, 6)
        var name: string
        if isStatic:
          if idx > high(qpackStaticTable):
            raise newException(QpackError, "static name index out of range")
          name = qpackStaticTable[idx][0]
        else:
          let abs = t.insertCount - 1 - idx        # relative to insert count
          if not t.has(abs):
            raise newException(QpackError, "dynamic name index out of range")
          name = t.get(abs)[0]
        var value: string
        decodeStr(buf, pos, buf.len, 7, value)
        discard t.insert(name, value)
      elif (b and 0xc0) == 0x40:
        # Insert with Literal Name (4.3.3): 01 H name(5) + value.
        var name, value: string
        decodeStr(buf, pos, buf.len, 5, name)
        decodeStr(buf, pos, buf.len, 7, value)
        discard t.insert(name, value)
      elif (b and 0xe0) == 0x20:
        # Set Dynamic Table Capacity (4.3.1): 001 capacity(5).
        let cap = decodeInt(buf, pos, buf.len, 5)
        if cap > maxCapacity:
          raise newException(QpackError, "capacity exceeds the maximum")
        t.setCapacity(cap)
      else:
        # Duplicate (4.3.4): 000 index(5).
        let idx = decodeInt(buf, pos, buf.len, 5)
        let abs = t.insertCount - 1 - idx
        if not t.has(abs):
          raise newException(QpackError, "duplicate index out of range")
        let (n, v) = t.get(abs)
        discard t.insert(n, v)
    except HpackError:
      return start          # incomplete instruction: leave it buffered
    result = pos

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
