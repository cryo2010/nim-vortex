## Shared system-zlib FFI bindings: the `ZStream` control struct, the
## deflate/inflate entry points and the generic return-code / flush-mode
## constants. Both the gzip response codec (`vortex/gzip`) and the WebSocket
## permessage-deflate codec (`vortex/websocket/deflate`) build on these; keeping
## the struct layout and imports in one place means a field-order or size slip
## can't diverge between the two consumers (a silent memory-corruption bug).
##
## This module is only pulled in when a consumer that needs zlib is compiled
## (`-d:httpGzip` or `-d:wsDeflate`), and it carries the `-lz` link directive so
## importing it is enough to link zlib. Window-bits / trailer details that differ
## per use (gzip header vs raw deflate) stay with each consumer.

{.passL: "-lz".}

type
  ZStream* {.bycopy.} = object
    nextIn*: ptr uint8
    availIn*: cuint
    totalIn*: culong
    nextOut*: ptr uint8
    availOut*: cuint
    totalOut*: culong
    msg*: cstring
    state*: pointer
    zalloc*: pointer
    zfree*: pointer
    opaque*: pointer
    dataType*: cint
    adler*: culong
    reserved*: culong

const
  # Return codes.
  zOk* = cint(0)
  zStreamEnd* = cint(1)
  zNeedDict* = cint(2)
  zStreamError* = cint(-2)
  zDataError* = cint(-3)
  zMemError* = cint(-4)
  zBufError* = cint(-5)
  # Flush modes.
  zNoFlush* = cint(0)
  zSyncFlush* = cint(2)
  zFinish* = cint(4)
  # Init parameters.
  zDeflated* = cint(8)
  zDefaultStrategy* = cint(0)
  zDefaultCompression* = cint(-1)
  zMemLevel* = cint(8)

proc zlibVersion*(): cstring {.importc, cdecl.}
proc deflateInit2*(strm: ptr ZStream, level, meth, windowBits, memLevel,
                   strategy: cint, version: cstring,
                   streamSize: cint): cint {.importc: "deflateInit2_", cdecl.}
proc deflate*(strm: ptr ZStream, flush: cint): cint {.importc, cdecl.}
proc deflateReset*(strm: ptr ZStream): cint {.importc, cdecl.}
proc deflateEnd*(strm: ptr ZStream): cint {.importc, cdecl.}
proc inflateInit2*(strm: ptr ZStream, windowBits: cint, version: cstring,
                   streamSize: cint): cint {.importc: "inflateInit2_", cdecl.}
proc inflate*(strm: ptr ZStream, flush: cint): cint {.importc, cdecl.}
proc inflateReset*(strm: ptr ZStream): cint {.importc, cdecl.}
proc inflateEnd*(strm: ptr ZStream): cint {.importc, cdecl.}
