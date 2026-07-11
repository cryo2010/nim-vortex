## Fuzz the HTTP/1.1 request parser: arbitrary bytes must never crash it,
## only ever yielding prComplete / prNeedMore / prError. Exercises both a
## whole-buffer parse and a split feed (resumability).

import ../src/vortex/http1/parser
import ./fuzzcommon

const limits = ParserLimits(maxHeaderSize: 16384, maxHeaderCount: 100,
                            maxBodySize: 1024 * 1024)

proc parseWhole(data: openArray[char]) =
  var p: RequestParser
  p.reset(0)
  var body = ""
  discard p.parse(data, data.len, limits, body)

proc parseSplit(data: openArray[char]) =
  ## Feed the buffer incrementally: the first byte picks a split point,
  ## catching resumability bugs the whole-buffer path would miss.
  if data.len < 2: return
  let cut = 1 + (int(data[0]) mod (data.len - 1))
  var buf = newString(data.len - 1)
  for i in 1 ..< data.len: buf[i - 1] = data[i]
  var p: RequestParser
  p.reset(0)
  var body = ""
  if p.parse(buf, cut - 1, limits, body) == prNeedMore:
    discard p.parse(buf, buf.len, limits, body)

proc testOne(data: openArray[char]) =
  parseWhole(data)
  parseSplit(data)

fuzzMain(testOne)
