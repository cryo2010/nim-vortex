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
  zNoFlush = cint(0)
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
proc inflateInit2(strm: ptr ZStream, windowBits: cint, version: cstring,
                  streamSize: cint): cint {.importc: "inflateInit2_", cdecl.}
proc inflate(strm: ptr ZStream, flush: cint): cint {.importc, cdecl.}
proc inflateEnd(strm: ptr ZStream): cint {.importc, cdecl.}

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

# --- streaming gzip (res.sendHead/write/finish, SSE, file streaming) ---------
# A stateful encoder fed chunk by chunk. Each write flushes (Z_SYNC_FLUSH) so
# the bytes are deliverable now (SSE needs this); finish emits the trailer
# (Z_FINISH). It is a `ref object of RootObj` so a Connection / h2 / h3 stream
# can hold it as a RootRef, and its =destroy frees the zlib state when that
# stream is torn down (normal finish or abandonment) -- no manual cleanup.

const
  zSyncFlush = cint(2)
  zBufError = cint(-5)

type
  GzipStreamObj = object of RootObj
    strm: ZStream
    inited: bool
  GzipStream* = ref GzipStreamObj

proc `=destroy`(o: var GzipStreamObj) =
  if o.inited:
    discard deflateEnd(addr o.strm)
    o.inited = false

proc newGzipStream*(): GzipStream =
  ## A streaming gzip encoder, or nil on failure.
  result = GzipStream()
  if deflateInit2(addr result.strm, zDefaultCompression, zDeflated,
                  gzipWindowBits, zMemLevel, zDefaultStrategy, zlibVersion(),
                  cint(sizeof(ZStream))) == zOk:
    result.inited = true
  else:
    result = nil

proc compress*(s: GzipStream, data: openArray[char], last: bool): string =
  ## Feed one chunk; returns the compressed bytes to emit. `last` emits the
  ## gzip trailer. "" is a valid result (nothing to emit yet). On a hard error
  ## the stream is marked dead and returns "".
  if s == nil or not s.inited: return ""
  s.strm.nextIn =
    if data.len > 0: cast[ptr uint8](unsafeAddr data[0]) else: nil
  s.strm.availIn = cuint(data.len)
  let flush = if last: zFinish else: zSyncFlush
  var outbuf = newString(max(256, data.len div 2 + 128))
  var total = 0
  while true:
    if total == outbuf.len: outbuf.setLen(outbuf.len * 2)
    s.strm.nextOut = cast[ptr uint8](addr outbuf[total])
    s.strm.availOut = cuint(outbuf.len - total)
    let rc = deflate(addr s.strm, flush)
    total = outbuf.len - int(s.strm.availOut)
    if last:
      if rc == zStreamEnd: break
      if rc != zOk: s.inited = false; return ""
    else:
      if rc != zOk and rc != zBufError: s.inited = false; return ""
      if s.strm.availOut != 0: break     # all input consumed and flushed
  outbuf.setLen(total)
  outbuf

# --- bounded gunzip (inbound request-body decompression) ---------------------
# Decompress a gzip (or zlib) request body, capped at `maxOut` bytes so a
# decompression bomb (a tiny body inflating to gigabytes) can't exhaust memory:
# it stops and fails the moment the output would exceed the cap. Returns
# (false, "") on a corrupt stream or an over-cap body; the caller rejects it.

const inflateAutoWindowBits = cint(15 + 32)   # auto-detect gzip/zlib headers

proc gunzip*(data: openArray[char], maxOut: int):
    tuple[ok: bool, tooLarge: bool, data: string] =
  ## `tooLarge` distinguishes an over-cap body (-> 413) from a corrupt one.
  if maxOut <= 0: return (false, false, "")
  var strm: ZStream
  if inflateInit2(addr strm, inflateAutoWindowBits, zlibVersion(),
                  cint(sizeof(ZStream))) != zOk:
    return (false, false, "")
  defer: discard inflateEnd(addr strm)
  if data.len > 0:
    strm.nextIn = cast[ptr uint8](unsafeAddr data[0])
  strm.availIn = cuint(data.len)
  var res = newString(min(maxOut, max(1024, data.len * 4)))
  var total = 0
  while true:
    if total == res.len:
      if res.len >= maxOut: return (false, true, "")   # exceeds the cap (bomb)
      res.setLen(min(maxOut, res.len * 2))
    strm.nextOut = cast[ptr uint8](addr res[total])
    strm.availOut = cuint(res.len - total)
    let rc = inflate(addr strm, zNoFlush)
    total = res.len - int(strm.availOut)
    if rc == zStreamEnd: break
    if rc != zOk: return (false, false, "")            # corrupt/truncated
  res.setLen(total)
  (true, false, res)
