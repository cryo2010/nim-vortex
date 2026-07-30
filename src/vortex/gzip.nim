## One-shot gzip (RFC 1952) for HTTP response compression, backed by system
## zlib. Compiled only under `-d:httpGzip` (link with `--passL:-lz`); without
## the flag the response path never imports this and no zlib is linked, so the
## default and `-d:plainHttp` builds keep their footprint.

when not defined(httpGzip):
  {.error: "vortex/gzip requires -d:httpGzip (and --passL:-lz)".}

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
  zOk = cint(0)
  zStreamEnd = cint(1)
  zFinish = cint(4)
  zDeflated = cint(8)
  zDefaultStrategy = cint(0)
  zDefaultCompression = cint(-1)
  zMemLevel = cint(8)
  gzipWindowBits = cint(15 + 16)   # 15-bit window + 16 = gzip header/trailer

proc zlibVersion(): cstring {.importc, cdecl.}
proc deflateInit2(strm: ptr ZStream, level, meth, windowBits, memLevel,
                  strategy: cint, version: cstring,
                  streamSize: cint): cint {.importc: "deflateInit2_", cdecl.}
proc deflate(strm: ptr ZStream, flush: cint): cint {.importc, cdecl.}
proc deflateEnd(strm: ptr ZStream): cint {.importc, cdecl.}

proc gzip*(data: openArray[char]): string =
  ## gzip-compress `data` in one shot; "" on failure (caller sends uncompressed).
  var strm: ZStream
  if deflateInit2(addr strm, zDefaultCompression, zDeflated, gzipWindowBits,
                  zMemLevel, zDefaultStrategy, zlibVersion(),
                  cint(sizeof(ZStream))) != zOk:
    return ""
  defer: discard deflateEnd(addr strm)
  if data.len > 0:
    strm.nextIn = cast[ptr uint8](unsafeAddr data[0])
  strm.availIn = cuint(data.len)
  result = newString(max(64, data.len div 3 + 64))
  var total = 0
  while true:
    if total == result.len: result.setLen(result.len * 2)
    strm.nextOut = cast[ptr uint8](addr result[total])
    strm.availOut = cuint(result.len - total)
    let rc = deflate(addr strm, zFinish)
    total = result.len - int(strm.availOut)
    if rc == zStreamEnd: break
    if rc != zOk: return ""        # compression error
  result.setLen(total)
