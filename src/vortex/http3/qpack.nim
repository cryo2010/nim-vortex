## QPACK (RFC 9204) in capacity-0 mode: we advertise
## QPACK_MAX_TABLE_CAPACITY = 0, so peers cannot reference a dynamic
## table and only static-table and literal representations occur. This is
## fully spec-compliant and sidesteps the encoder/decoder-stream
## machinery; dynamic QPACK is a post-1.0 optimization.
##
## Integer, string, and Huffman primitives are shared with HPACK.

import std/strutils
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
    except HpackError as e:
      if e.msg.startsWith("truncated"):
        return start        # incomplete instruction: leave it buffered
      raise newException(QpackError, e.msg)   # malformed (overflow / too large)
    result = pos

proc decodeRequiredInsertCount(enc, totalInserts, maxEntries: int): int =
  ## Reconstruct the absolute Required Insert Count from its wrapped encoding
  ## (RFC 9204 4.5.1.1). `enc` is the value from the 8-bit prefix.
  if enc == 0: return 0
  let fullRange = 2 * maxEntries
  if enc > fullRange:
    raise newException(QpackError, "required insert count out of range")
  let maxValue = totalInserts + maxEntries
  let maxWrapped = (maxValue div fullRange) * fullRange
  result = maxWrapped + enc - 1
  if result > maxValue:
    if result <= fullRange:
      raise newException(QpackError, "required insert count out of range")
    result -= fullRange
  if result == 0:
    raise newException(QpackError, "required insert count of zero encoded")

proc decodeFieldSection*(buf: openArray[char], start, endPos: int,
                         headers: var seq[(string, string)],
                         dyn: QpackDynTable = QpackDynTable()): int
                        {.discardable.} =
  ## Decode a complete encoded field section (one HEADERS frame payload) against
  ## `dyn` (an empty table = capacity-0 mode, where any dynamic reference is out
  ## of range and errors). Returns the Required Insert Count (0 if the dynamic
  ## table was not referenced), for the caller's Section Acknowledgment.
  var pos = start
  try:
    let maxEntries = dyn.capacity div 32
    let ric = decodeRequiredInsertCount(decodeInt(buf, pos, endPos, 8),
                                        dyn.insertCount, maxEntries)
    if ric > dyn.insertCount:                # blocked reference (not supported)
      raise newException(QpackError, "required insert count exceeds inserts")
    if pos >= endPos:                        # Sign/Delta Base byte is required
      raise newException(QpackError, "truncated field section prefix")
    let sign = (uint8(buf[pos]) and 0x80) != 0
    let deltaBase = decodeInt(buf, pos, endPos, 7)
    let base = if sign: ric - deltaBase - 1 else: ric + deltaBase
    result = ric
    while pos < endPos:
      let b = uint8(buf[pos])
      if (b and 0x80) != 0:
        # Indexed field line: 1 T index(6).
        let isStatic = (b and 0x40) != 0
        let idx = decodeInt(buf, pos, endPos, 6)
        if isStatic:
          if idx > high(qpackStaticTable):
            raise newException(QpackError, "static index out of range")
          headers.add qpackStaticTable[idx]
        else:
          let abs = base - 1 - idx
          if abs < 0 or not dyn.has(abs):
            raise newException(QpackError, "dynamic index out of range")
          headers.add dyn.get(abs)
      elif (b and 0x40) != 0:
        # Literal with name reference: 01 N T index(4).
        let isStatic = (b and 0x10) != 0
        let idx = decodeInt(buf, pos, endPos, 4)
        var name: string
        if isStatic:
          if idx > high(qpackStaticTable):
            raise newException(QpackError, "static index out of range")
          name = qpackStaticTable[idx][0]
        else:
          let abs = base - 1 - idx
          if abs < 0 or not dyn.has(abs):
            raise newException(QpackError, "dynamic name index out of range")
          name = dyn.get(abs)[0]
        var value: string
        decodeStr(buf, pos, endPos, 7, value)
        headers.add (name, value)
      elif (b and 0x20) != 0:
        # Literal with literal name: 001 N H nameLen(3).
        var name, value: string
        decodeStr(buf, pos, endPos, 3, name)
        decodeStr(buf, pos, endPos, 7, value)
        headers.add (name, value)
      elif (b and 0x10) != 0:
        # Indexed field line with post-base index: 0001 index(4).
        let idx = decodeInt(buf, pos, endPos, 4)
        let abs = base + idx
        if not dyn.has(abs):
          raise newException(QpackError, "post-base index out of range")
        headers.add dyn.get(abs)
      else:
        # Literal with post-base name reference: 0000 N index(3).
        let idx = decodeInt(buf, pos, endPos, 3)
        let abs = base + idx
        if not dyn.has(abs):
          raise newException(QpackError, "post-base name index out of range")
        var value: string
        decodeStr(buf, pos, endPos, 7, value)
        headers.add (dyn.get(abs)[0], value)
  except HpackError as e:
    raise newException(QpackError, e.msg)

# --- decoder-stream instructions (RFC 9204 4.4) -----------------------------

proc encodeInsertCountIncrement*(buf: var string, n: int) =
  ## 00 increment(6): acknowledge `n` dynamic-table insertions.
  encodeInt(buf, n, 6, 0x00)

proc encodeSectionAck*(buf: var string, streamId: int) =
  ## 1 stream-id(7): acknowledge a field section that used the dynamic table.
  encodeInt(buf, streamId, 7, 0x80)

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

# --- dynamic-table encoder (response header compression) --------------------
#
# A conservative encoder: it inserts repeated response header fields into a
# dynamic table but only *references* entries the peer's decoder has already
# acknowledged (`known`). So it never produces a blocking reference (peer
# BLOCKED_STREAMS is irrelevant) and never needs to evict -- it just stops
# inserting once the table is full. That trades some compression for simplicity
# and safety (a bad reference would break the peer's decoder for the connection).

proc qpackStaticFullIndex(name, value: string): int =
  ## Static index of a full (name, value) match, else -1.
  for i in 0 .. high(qpackStaticTable):
    if qpackStaticTable[i][0] == name and qpackStaticTable[i][1] == value:
      return i
  -1

proc fits(t: QpackDynTable, name, value: string): bool {.inline.} =
  t.size + entrySize(name, value) <= t.capacity   # would insert without evicting

proc findAcked(t: QpackDynTable, name, value: string, known: int): int =
  ## Absolute index of an acknowledged (abs < known) (name,value) entry, else
  ## -1. The encoder never evicts, so dropped == 0 and abs == the position.
  for i in 0 ..< t.entries.len:
    let abs = t.dropped + i
    if abs >= known: break
    if t.entries[i][0] == name and t.entries[i][1] == value: return abs
  -1

proc encodeRequiredInsertCount(ric, maxEntries: int): int {.inline.} =
  if ric == 0: 0 else: (ric mod (2 * maxEntries)) + 1

type
  QpackEncoder* = object
    table: QpackDynTable
    known: int              ## acknowledged insertions (Insert Count Increment)
    insts: string           ## pending encoder-stream instructions

proc setCapacity*(e: var QpackEncoder, cap: int) =
  ## Set the dynamic table capacity and queue the encoder-stream instruction.
  if cap == e.table.capacity: return
  e.table.setCapacity(cap)
  encodeInt(e.insts, cap, 5, 0x20)               # Set Dynamic Table Capacity

proc ackInsertions*(e: var QpackEncoder, n: int) =
  ## The peer acknowledged `n` more insertions (Insert Count Increment).
  e.known = min(e.known + n, e.table.insertCount)

proc takeInstructions*(e: var QpackEncoder): string =
  ## Move out the queued encoder-stream instructions. The field section is sent
  ## too, but references only acknowledged entries, so cross-stream ordering is
  ## safe.
  result = move(e.insts)

proc applyDecoderInstructions*(e: var QpackEncoder, buf: openArray[char]): int =
  ## Process the peer's decoder-stream instructions (RFC 9204 4.4): apply Insert
  ## Count Increment (acknowledging our insertions) and skip Section
  ## Acknowledgment and Stream Cancellation (we never evict, so they need no
  ## tracking). Returns bytes consumed; a partial trailing instruction is left.
  ## Raises QpackError on a protocol violation (Insert Count Increment of 0).
  var pos = 0
  while pos < buf.len:
    let start = pos
    let b = uint8(buf[pos])
    try:
      if (b and 0x80) != 0:
        discard decodeInt(buf, pos, buf.len, 7)      # Section Acknowledgment
      elif (b and 0x40) != 0:
        discard decodeInt(buf, pos, buf.len, 6)      # Stream Cancellation
      else:
        let inc = decodeInt(buf, pos, buf.len, 6)    # Insert Count Increment
        if inc == 0:
          raise newException(QpackError, "insert count increment of zero")
        e.ackInsertions(inc)
    except HpackError as ex:
      if ex.msg.startsWith("truncated"): return start
      raise newException(QpackError, ex.msg)
    result = pos

proc cacheable(name: string): bool {.inline.} =
  name != "date" and name != "content-length"   # values vary every response

proc encodeSection*(e: var QpackEncoder, status: int,
                    hdrs: openArray[(string, string)]): string =
  ## Encode a response field section (`:status` first, then hdrs). Names must
  ## already be lowercase.
  type Kind = enum kStaticIdx, kDynIdx, kStaticNameLit, kLiteral
  var reps: seq[tuple[kind: Kind, a: int, name, value: string]]
  var ric = 0
  # Pass 1: decide each representation, insert new cacheable entries, find RIC.
  for (name, value) in hdrs:
    let sFull = qpackStaticFullIndex(name, value)
    if sFull >= 0:
      reps.add (kStaticIdx, sFull, "", "")
      continue
    if e.table.capacity > 0:
      let dAbs = e.table.findAcked(name, value, e.known)
      if dAbs >= 0:
        reps.add (kDynIdx, dAbs, "", "")
        if dAbs + 1 > ric: ric = dAbs + 1
        continue
      if cacheable(name) and e.table.fits(name, value):
        let sName = qpackStaticIndexOf(name)
        if sName >= 0:
          encodeInt(e.insts, sName, 6, 0xc0)     # Insert w/ Name Ref (static)
        else:
          encodeRawStr(e.insts, name, 5, 0x40)   # Insert w/ Literal Name
        encodeRawStr(e.insts, value, 7, 0x00)
        discard e.table.insert(name, value)
    let sName2 = qpackStaticIndexOf(name)
    if sName2 >= 0: reps.add (kStaticNameLit, sName2, "", value)
    else: reps.add (kLiteral, 0, name, value)
  # Pass 2: prefix (RIC + base=RIC), :status, then the representations.
  let maxEntries = if e.table.capacity > 0: e.table.capacity div 32 else: 0
  encodeInt(result, encodeRequiredInsertCount(ric, maxEntries), 8, 0x00)
  result.add '\0'                                # base = RIC: sign 0, delta 0
  encodeStatus(result, status)
  for r in reps:
    case r.kind
    of kStaticIdx: encodeInt(result, r.a, 6, 0xc0)
    of kDynIdx: encodeInt(result, ric - 1 - r.a, 6, 0x80)   # indexed dynamic
    of kStaticNameLit:
      encodeInt(result, r.a, 4, 0x50)
      encodeRawStr(result, r.value, 7, 0x00)
    of kLiteral:
      encodeRawStr(result, r.name, 3, 0x20)
      encodeRawStr(result, r.value, 7, 0x00)
