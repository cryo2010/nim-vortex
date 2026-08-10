## Zstandard (RFC 8878) for HTTP response compression, backed by the system
## libzstd. Compiled only under `-d:httpZstd` (link with `--passL:-lzstd`);
## without the flag the response path never imports this and no zstd is linked,
## so the default and `-d:plainHttp` builds keep their footprint. Mirrors
## gzip.nim / brotli.nim (one-shot + streaming encoders, plus a bounded decoder
## for inbound request-body decompression).

when not defined(httpZstd):
  {.error: "vortex/zstd requires -d:httpZstd (and --passL:-lzstd)".}

{.passL: "-lzstd".}

const
  # Level 3 is libzstd's default: fast, good ratio, suitable per-response.
  zstdLevel = cint(3)
  zstdCLevelParam = cint(100)   # ZSTD_c_compressionLevel
  zstdEFlush = cint(1)          # ZSTD_e_flush
  zstdEEnd = cint(2)            # ZSTD_e_end

type
  ZstdInBuffer {.bycopy.} = object
    src: pointer
    size: csize_t
    pos: csize_t
  ZstdOutBuffer {.bycopy.} = object
    dst: pointer
    size: csize_t
    pos: csize_t

proc zstdCompressBound(srcSize: csize_t): csize_t
  {.importc: "ZSTD_compressBound", cdecl.}
proc zstdCompress(dst: pointer, dstCap: csize_t, src: pointer, srcSize: csize_t,
                  level: cint): csize_t {.importc: "ZSTD_compress", cdecl.}
proc zstdIsError(code: csize_t): cuint {.importc: "ZSTD_isError", cdecl.}
proc zstdCreateCCtx(): pointer {.importc: "ZSTD_createCCtx", cdecl.}
proc zstdFreeCCtx(cctx: pointer): csize_t {.importc: "ZSTD_freeCCtx", cdecl.}
proc zstdCCtxSetParameter(cctx: pointer, param: cint, value: cint): csize_t
  {.importc: "ZSTD_CCtx_setParameter", cdecl.}
proc zstdCompressStream2(cctx: pointer, output: ptr ZstdOutBuffer,
                         input: ptr ZstdInBuffer, endOp: cint): csize_t
  {.importc: "ZSTD_compressStream2", cdecl.}
proc zstdCreateDCtx(): pointer {.importc: "ZSTD_createDCtx", cdecl.}
proc zstdFreeDCtx(dctx: pointer): csize_t {.importc: "ZSTD_freeDCtx", cdecl.}
proc zstdDecompressStream(dctx: pointer, output: ptr ZstdOutBuffer,
                          input: ptr ZstdInBuffer): csize_t
  {.importc: "ZSTD_decompressStream", cdecl.}

proc zstd*(data: openArray[char]): string =
  ## Zstd-compress `data` in one shot; "" on failure (caller sends uncompressed).
  let bound = zstdCompressBound(csize_t(data.len))
  if bound == 0: return ""
  result = newString(int(bound))
  let src = if data.len > 0: unsafeAddr data[0] else: nil
  let n = zstdCompress(addr result[0], bound, src, csize_t(data.len), zstdLevel)
  if zstdIsError(n) != 0: return ""
  result.setLen(int(n))

# --- streaming zstd (res.sendHead/write/finish, SSE, file streaming) ---------
# Stateful encoder fed chunk by chunk: each write uses ZSTD_e_flush so the bytes
# are deliverable now, finish uses ZSTD_e_end. A `ref object of RootObj` held as
# a RootRef by a Connection / h2 / h3 stream; its =destroy frees the ZSTD_CCtx
# when that stream is torn down. Mirrors gzip.GzipStream / brotli.BrotliStream.

type
  ZstdStreamObj = object of RootObj
    cctx: pointer            # ZSTD_CCtx*
  ZstdStream* = ref ZstdStreamObj

proc `=destroy`(o: var ZstdStreamObj) =
  if o.cctx != nil:
    discard zstdFreeCCtx(o.cctx)
    o.cctx = nil

proc newZstdStream*(): ZstdStream =
  ## A streaming zstd encoder, or nil on failure.
  result = ZstdStream()
  result.cctx = zstdCreateCCtx()
  if result.cctx == nil:
    return nil
  discard zstdCCtxSetParameter(result.cctx, zstdCLevelParam, zstdLevel)

proc compress*(s: ZstdStream, data: openArray[char], last: bool): string =
  ## Feed one chunk; returns the compressed bytes to emit (may be ""). `last`
  ## ends the frame. On error the encoder is dropped and returns "".
  if s == nil or s.cctx == nil: return ""
  var input = ZstdInBuffer(
    src: (if data.len > 0: unsafeAddr data[0] else: nil),
    size: csize_t(data.len), pos: 0)
  let endOp = if last: zstdEEnd else: zstdEFlush
  var chunk = newString(4096)
  result = ""
  while true:
    var output = ZstdOutBuffer(dst: addr chunk[0], size: csize_t(chunk.len),
                               pos: 0)
    let rem = zstdCompressStream2(s.cctx, addr output, addr input, endOp)
    if zstdIsError(rem) != 0:
      discard zstdFreeCCtx(s.cctx); s.cctx = nil
      return ""
    if output.pos > 0:
      result.add chunk[0 ..< int(output.pos)]
    # Done when all input is consumed and nothing remains to flush/end.
    if input.pos == input.size and rem == 0:
      break

# --- bounded zstd decode (inbound request-body decompression) ----------------
# Decompress a zstd request body, capped at `maxOut` bytes so a decompression
# bomb can't exhaust memory: it stops and fails the moment the output would
# exceed the cap. Returns (false, "") on a corrupt/truncated stream or an
# over-cap body; the caller rejects it. Mirrors gzip.gunzip / brotli.brotliDecode.

proc zstdDecode*(data: openArray[char], maxOut: int):
    tuple[ok: bool, tooLarge: bool, data: string] =
  ## `tooLarge` distinguishes an over-cap body (-> 413) from a corrupt one.
  if maxOut <= 0: return (false, false, "")
  let dctx = zstdCreateDCtx()
  if dctx == nil: return (false, false, "")
  defer: discard zstdFreeDCtx(dctx)
  var input = ZstdInBuffer(
    src: (if data.len > 0: unsafeAddr data[0] else: nil),
    size: csize_t(data.len), pos: 0)
  var res = newString(min(maxOut, max(1024, data.len * 4)))
  var total = 0
  while true:
    if total == res.len:
      if res.len >= maxOut: return (false, true, "")   # over the cap (bomb)
      res.setLen(min(maxOut, res.len * 2))
    var output = ZstdOutBuffer(dst: addr res[0], size: csize_t(res.len),
                               pos: csize_t(total))
    let rc = zstdDecompressStream(dctx, addr output, addr input)
    if zstdIsError(rc) != 0: return (false, false, "")  # corrupt
    total = int(output.pos)
    if rc == 0: break                                   # frame complete
    # rc != 0 with output space left means it wants more input; if the input is
    # already drained the stream is truncated.
    if total < res.len and input.pos == input.size:
      return (false, false, "")
  res.setLen(total)
  (true, false, res)
