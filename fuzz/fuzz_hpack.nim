## Fuzz the HPACK decoder: arbitrary header blocks must either decode or
## raise HpackError, never crash. Decodes several blocks against one
## decoder so dynamic-table state (insertion, eviction, size updates)
## carries across inputs the way it does on a real connection.

import ../src/vortex/http2/hpack
import ./fuzzcommon

proc testOne(data: openArray[char]) =
  var d = initHpackDecoder()
  # Split the input into up to a handful of blocks on 0x00 boundaries so
  # the fuzzer can build up dynamic-table state across "frames".
  var start = 0
  var blocks = 0
  var buf = newString(data.len)
  for i in 0 ..< data.len: buf[i] = data[i]
  for i in 0 ..< buf.len:
    if buf[i] == '\0' and blocks < 8:
      var headers: seq[(string, string)]
      try:
        d.decodeHeaderBlock(buf, start, i, headers)
      except HpackError:
        discard
      start = i + 1
      inc blocks
  var headers: seq[(string, string)]
  try:
    d.decodeHeaderBlock(buf, start, buf.len, headers)
  except HpackError:
    discard

fuzzMain(testOne)
