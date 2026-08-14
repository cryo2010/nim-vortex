## permessage-deflate (RFC 7692) DEFLATE codec, backed by system zlib.
##
## Compiled only under `-d:wsDeflate` (link with `--passL:-lz`); without the
## flag the WebSocket layer never imports this and no zlib is linked, so the
## default and `-d:plainHttp` builds pull in no compression library.
##
## Raw deflate/inflate is used (negative windowBits: no zlib header/trailer),
## which is what RFC 7692 requires and also sidesteps zlib's gzip-header
## code path. Decompression is bounded (see `decompress`) so a compression
## bomb cannot exhaust memory.

when not defined(wsDeflate):
  {.error: "websocket/deflate requires -d:wsDeflate".}

{.passL: "-lz".}

type
  ZStream {.bycopy.} = object
    nextIn: ptr uint8
    availIn: cuint
    totalIn: culong
    nextOut: ptr uint8
    availOut: cuint
    totalOut: culong
    msg: cstring
    state: pointer
    zalloc: pointer
    zfree: pointer
    opaque: pointer
    dataType: cint
    adler: culong
    reserved: culong

const
  zNoFlush = cint(0)
  zSyncFlush = cint(2)
  zStreamEnd = cint(1)
  zStreamError = cint(-2)
  zDataError = cint(-3)
  zMemError = cint(-4)
  zNeedDict = cint(2)
  zDeflated = cint(8)
  zDefaultStrategy = cint(0)
  zDefaultCompression = cint(-1)
  zMemLevel = cint(8)
  # RFC 7692 7.2.1/7.2.2: the sync-flush trailer stripped/appended per message.
  deflateTail = "\x00\x00\xff\xff"

proc zlibVersion(): cstring {.importc, cdecl.}
proc deflateInit2(strm: ptr ZStream, level, meth, windowBits, memLevel,
                  strategy: cint, version: cstring,
                  streamSize: cint): cint {.importc: "deflateInit2_", cdecl.}
proc deflate(strm: ptr ZStream, flush: cint): cint {.importc, cdecl.}
proc deflateReset(strm: ptr ZStream): cint {.importc, cdecl.}
proc deflateEnd(strm: ptr ZStream): cint {.importc, cdecl.}
proc inflateInit2(strm: ptr ZStream, windowBits: cint, version: cstring,
                  streamSize: cint): cint {.importc: "inflateInit2_", cdecl.}
proc inflate(strm: ptr ZStream, flush: cint): cint {.importc, cdecl.}
proc inflateReset(strm: ptr ZStream): cint {.importc, cdecl.}
proc inflateEnd(strm: ptr ZStream): cint {.importc, cdecl.}

type
  Deflator* = object
    strm: ZStream
    noContextTakeover: bool
    inited*: bool

  Inflator* = object
    strm: ZStream
    noContextTakeover: bool
    inited*: bool

  DecompressStatus* = enum
    dsOk, dsTooBig, dsError

proc clampWindow(bits: int): cint =
  ## zlib accepts 9..15 for raw deflate (8 behaves as 9).
  cint(max(9, min(15, bits)))

proc initDeflator*(windowBits: int, noContextTakeover: bool): Deflator =
  result.noContextTakeover = noContextTakeover
  let rc = deflateInit2(addr result.strm, zDefaultCompression, zDeflated,
                         -clampWindow(windowBits), zMemLevel, zDefaultStrategy,
                         zlibVersion(), cint(sizeof(ZStream)))
  result.inited = rc == 0

proc initInflator*(noContextTakeover: bool): Inflator =
  ## Always uses the max window (15) so it can decode any client window.
  result.noContextTakeover = noContextTakeover
  let rc = inflateInit2(addr result.strm, -15, zlibVersion(),
                         cint(sizeof(ZStream)))
  result.inited = rc == 0

proc close*(d: var Deflator) =
  if d.inited:
    discard deflateEnd(addr d.strm)
    d.inited = false

proc close*(inf: var Inflator) =
  if inf.inited:
    discard inflateEnd(addr inf.strm)
    inf.inited = false

proc compress*(d: var Deflator, data: openArray[char]): string =
  ## Deflate one message: sync-flush, then strip the 4-byte tail. `data`
  ## must be non-empty (callers send empty messages uncompressed).
  d.strm.nextIn = cast[ptr uint8](unsafeAddr data[0])
  d.strm.availIn = cuint(data.len)
  var outbuf = newString(max(64, data.len div 2 + 16))
  var total = 0
  while true:
    if total == outbuf.len:
      outbuf.setLen(outbuf.len * 2)
    d.strm.nextOut = cast[ptr uint8](addr outbuf[total])
    d.strm.availOut = cuint(outbuf.len - total)
    discard deflate(addr d.strm, zSyncFlush)
    total = outbuf.len - int(d.strm.availOut)
    if d.strm.availOut != 0:
      break                      # flush complete, all input consumed
  outbuf.setLen(total)
  # Strip the trailing 00 00 FF FF the sync flush emits (RFC 7692 7.2.1).
  if outbuf.len >= 4:
    outbuf.setLen(outbuf.len - 4)
  if d.noContextTakeover:
    discard deflateReset(addr d.strm)
  outbuf

proc decompress*(inf: var Inflator, data: openArray[char],
                 maxOut: int): tuple[status: DecompressStatus, data: string] =
  ## Inflate one message: append the 4-byte tail, then inflate into a buffer
  ## bounded by `maxOut`. Aborting at the cap is the decompression-bomb guard.
  var input = newStringOfCap(data.len + 4)
  for c in data: input.add c
  input.add deflateTail
  inf.strm.nextIn = cast[ptr uint8](addr input[0])
  inf.strm.availIn = cuint(input.len)
  var outbuf = newString(min(maxOut + 1, max(256, data.len * 4)))
  var total = 0
  var status = dsOk
  while true:
    if total == outbuf.len:
      if outbuf.len > maxOut:
        status = dsTooBig
        break
      outbuf.setLen(min(outbuf.len * 2, maxOut + 1))
    inf.strm.nextOut = cast[ptr uint8](addr outbuf[total])
    inf.strm.availOut = cuint(outbuf.len - total)
    let rc = inflate(addr inf.strm, zNoFlush)
    total = outbuf.len - int(inf.strm.availOut)
    if rc == zStreamError or rc == zDataError or rc == zMemError or
       rc == zNeedDict:
      status = dsError
      break
    if total > maxOut:
      status = dsTooBig
      break
    if inf.strm.availOut != 0 or rc == zStreamEnd:
      break                      # all available input processed
  if status != dsOk:
    return (status, "")
  outbuf.setLen(total)
  if inf.noContextTakeover:
    discard inflateReset(addr inf.strm)
  (dsOk, outbuf)
