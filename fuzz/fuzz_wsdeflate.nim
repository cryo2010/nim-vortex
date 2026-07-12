## Fuzz the permessage-deflate inflate path: arbitrary bytes fed as a
## "compressed" WebSocket message must return dsOk/dsTooBig/dsError, never
## crash or run away (the maxOut cap is the bomb guard). Built with
## -d:wsDeflate --passL:-lz (see fuzz/run.sh).

import ../src/vortex/websocket/deflate
import ./fuzzcommon

proc testOne(data: openArray[char]) =
  var inf = initInflator(false)
  if inf.inited:
    discard inf.decompress(data, 1 shl 20)   # bounded; must not crash/hang
    inf.close()

fuzzMain(testOne)
