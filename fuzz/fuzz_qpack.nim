## Fuzz the QPACK decoder (capacity-0 mode): an encoded field section of
## arbitrary bytes must either decode or raise QpackError, never crash.
## decodeFieldSection is stateless (no dynamic table), so each input is a
## single independent field section.

import ../src/vortex/http3/qpack
import ./fuzzcommon

proc testOne(data: openArray[char]) =
  var buf = newString(data.len)
  for i in 0 ..< data.len: buf[i] = data[i]
  var headers: seq[(string, string)]
  try:
    decodeFieldSection(buf, 0, buf.len, headers)
  except QpackError:
    discard

fuzzMain(testOne)
