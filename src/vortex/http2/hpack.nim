## HPACK (RFC 7541). Decoder is complete: static + dynamic tables and
## Huffman-coded strings (clients Huffman-encode by default). The encoder
## uses only the static table and raw literals: spec-legal, interoperable,
## and keeps response serialization allocation-light; dynamic-table
## encoding is a post-1.0 optimization.

import ./hpack_tables

type
  HpackError* = object of CatchableError

  DynEntry = object
    name, value: string

  HpackDecoder* = object
    entries: seq[DynEntry]    ## newest first; bounded by maxSize/32
    size: int                 ## RFC size: sum(name+value+32)
    maxSize*: int             ## current limit (after size-update instr.)
    settingsMax*: int         ## cap we advertised via SETTINGS
    maxDecoded*: int          ## cap on total decoded field-list size (bomb guard)

proc initHpackDecoder*(settingsMax = 4096, maxDecoded = 64 * 1024): HpackDecoder =
  HpackDecoder(maxSize: settingsMax, settingsMax: settingsMax,
               maxDecoded: maxDecoded)

# --- Huffman decode tree, built at compile time --------------------------

type HuffNode = object
  sym: int16                  ## -1 for internal nodes
  zero, one: int16            ## child indices, -1 absent

const huffTree = block:
  var nodes = @[HuffNode(sym: -1, zero: -1, one: -1)]
  for sym in 0 .. 256:
    let (code, bits) = huffmanCodes[sym]
    var cur = 0
    for i in countdown(int(bits) - 1, 0):
      let bit = (code shr i) and 1
      var next = if bit == 0: int(nodes[cur].zero) else: int(nodes[cur].one)
      if next < 0:
        nodes.add HuffNode(sym: -1, zero: -1, one: -1)
        next = nodes.len - 1
        if bit == 0: nodes[cur].zero = int16(next)
        else: nodes[cur].one = int16(next)
      cur = next
    nodes[cur].sym = int16(sym)
  nodes

proc huffmanDecode(input: openArray[char], start, len: int,
                   output: var string) =
  var node = 0
  var padOnes = true          # unfinished path must be all 1s (EOS prefix)
  var depth = 0
  for i in start ..< start + len:
    let b = uint8(input[i])
    for bitPos in countdown(7, 0):
      let bit = (b shr bitPos) and 1
      node = if bit == 0: int(huffTree[node].zero) else: int(huffTree[node].one)
      if node < 0:
        raise newException(HpackError, "invalid huffman code")
      if bit == 0: padOnes = false
      inc depth
      if huffTree[node].sym >= 0:
        if huffTree[node].sym == 256:
          raise newException(HpackError, "EOS in huffman string")
        output.add char(huffTree[node].sym)
        node = 0
        padOnes = true
        depth = 0
  if depth > 7 or not padOnes:
    raise newException(HpackError, "bad huffman padding")

# --- primitive decoders ---------------------------------------------------

proc decodeInt*(buf: openArray[char], pos: var int, endPos: int,
                prefixBits: int): int =
  if pos >= endPos:
    raise newException(HpackError, "truncated integer")
  let mask = (1 shl prefixBits) - 1
  result = int(uint8(buf[pos])) and mask
  inc pos
  if result < mask:
    return
  var shift = 0
  while true:
    if pos >= endPos:
      raise newException(HpackError, "truncated integer")
    if shift > 28:
      raise newException(HpackError, "integer overflow")
    let b = uint8(buf[pos])
    inc pos
    result += (int(b) and 0x7f) shl shift
    if result < 0 or result > 1 shl 24:
      raise newException(HpackError, "integer too large")
    if (b and 0x80) == 0:
      break
    shift += 7

proc decodeStr*(buf: openArray[char], pos: var int, endPos: int,
                prefixBits: int, output: var string) =
  ## Length-prefixed string with the Huffman bit just above the length
  ## prefix. HPACK always uses prefixBits=7; QPACK varies (shared here).
  if pos >= endPos:
    raise newException(HpackError, "truncated string")
  let huffman = (uint8(buf[pos]) and uint8(1 shl prefixBits)) != 0
  let len = decodeInt(buf, pos, endPos, prefixBits)
  if pos + len > endPos:
    raise newException(HpackError, "truncated string data")
  if huffman:
    huffmanDecode(buf, pos, len, output)
  else:
    for i in pos ..< pos + len:
      output.add buf[i]
  pos += len

proc decodeString(buf: openArray[char], pos: var int, endPos: int,
                  output: var string) =
  decodeStr(buf, pos, endPos, 7, output)

# --- dynamic table --------------------------------------------------------

proc evict(d: var HpackDecoder) =
  while d.size > d.maxSize and d.entries.len > 0:
    let last = d.entries.pop()
    d.size -= last.name.len + last.value.len + 32

proc addEntry(d: var HpackDecoder, name, value: string) =
  let esz = name.len + value.len + 32
  d.size += esz
  d.entries.insert(DynEntry(name: name, value: value), 0)
  d.evict()

proc lookup(d: HpackDecoder, idx: int): (string, string) =
  if idx >= 1 and idx <= 61:
    (hpackStaticTable[idx][0], hpackStaticTable[idx][1])
  elif idx >= 62 and idx - 62 < d.entries.len:
    (d.entries[idx - 62].name, d.entries[idx - 62].value)
  else:
    raise newException(HpackError, "invalid table index " & $idx)

# --- header block decoding ------------------------------------------------

proc decodeHeaderBlock*(d: var HpackDecoder, buf: openArray[char],
                        start, endPos: int,
                        headers: var seq[(string, string)]) =
  ## Decode a complete header block (caller assembles CONTINUATIONs first).
  var pos = start
  var seenHeader = false
  var decoded = 0                # accumulated field-list size (bomb guard)
  template accrue(n, v: string) =
    decoded += n.len + v.len + 32
    if d.maxDecoded > 0 and decoded > d.maxDecoded:
      raise newException(HpackError, "decoded header list too large")
  while pos < endPos:
    let b = uint8(buf[pos])
    if (b and 0x80) != 0:
      # Indexed header field.
      let idx = decodeInt(buf, pos, endPos, 7)
      if idx == 0: raise newException(HpackError, "index 0")
      let (n, v) = d.lookup(idx)
      accrue(n, v)
      headers.add (n, v)
      seenHeader = true
    elif (b and 0xc0) == 0x40:
      # Literal with incremental indexing.
      let nameIdx = decodeInt(buf, pos, endPos, 6)
      var name, value: string
      if nameIdx == 0:
        decodeString(buf, pos, endPos, name)
      else:
        name = d.lookup(nameIdx)[0]
      decodeString(buf, pos, endPos, value)
      accrue(name, value)
      d.addEntry(name, value)
      headers.add (name, value)
      seenHeader = true
    elif (b and 0xe0) == 0x20:
      # Dynamic table size update; must precede header fields.
      if seenHeader:
        raise newException(HpackError, "size update after header field")
      let newMax = decodeInt(buf, pos, endPos, 5)
      if newMax > d.settingsMax:
        raise newException(HpackError, "table size above SETTINGS limit")
      d.maxSize = newMax
      d.evict()
    else:
      # Literal without indexing (0000) or never-indexed (0001).
      let nameIdx = decodeInt(buf, pos, endPos, 4)
      var name, value: string
      if nameIdx == 0:
        decodeString(buf, pos, endPos, name)
      else:
        name = d.lookup(nameIdx)[0]
      decodeString(buf, pos, endPos, value)
      accrue(name, value)
      headers.add (name, value)
      seenHeader = true

# --- encoding (static table + raw literals only) --------------------------

proc encodeInt*(buf: var string, value, prefixBits: int, firstByte: uint8) =
  let mask = (1 shl prefixBits) - 1
  if value < mask:
    buf.add char(firstByte or uint8(value))
  else:
    buf.add char(firstByte or uint8(mask))
    var v = value - mask
    while v >= 128:
      buf.add char(uint8(v and 0x7f) or 0x80)
      v = v shr 7
    buf.add char(uint8(v))

proc encodeRawString(buf: var string, s: string) =
  encodeInt(buf, s.len, 7, 0x00)      # H=0: raw
  buf.add s

proc staticIndexOf(name: string): int =
  ## First static entry with this (lowercase) name, 0 if none.
  for i in 1 .. 61:
    if hpackStaticTable[i][0] == name: return i
  0

proc encodeStatus*(buf: var string, status: int) =
  ## :status via full static index when possible.
  let idx =
    case status
    of 200: 8
    of 204: 9
    of 206: 10
    of 304: 11
    of 400: 12
    of 404: 13
    of 500: 14
    else: 0
  if idx > 0:
    encodeInt(buf, idx, 7, 0x80)      # indexed representation
  else:
    encodeInt(buf, 8, 4, 0x00)        # literal w/o indexing, name = :status
    encodeRawString(buf, $status)

proc encodeHeader*(buf: var string, name, value: string) =
  ## Literal without indexing; name must already be lowercase.
  let idx = staticIndexOf(name)
  if idx > 0:
    encodeInt(buf, idx, 4, 0x00)
  else:
    encodeInt(buf, 0, 4, 0x00)
    encodeRawString(buf, name)
  encodeRawString(buf, value)
