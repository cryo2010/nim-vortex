## One-shot Brotli (RFC 7932) for HTTP response compression, backed by the
## system libbrotlienc. Compiled only under `-d:httpBrotli` (link with
## `--passL:"-lbrotlienc -lbrotlicommon"`); without the flag the response path
## never imports this and no brotli is linked, so the default and `-d:plainHttp`
## builds keep their footprint. Mirrors gzip.nim.

when not defined(httpBrotli):
  {.error: "vortex/brotli requires -d:httpBrotli (and --passL:\"-lbrotlienc -lbrotlicommon\")".}

{.passL: "-lbrotlienc -lbrotlicommon".}

const
  # Quality trades ratio for CPU. 11 (the library default) is far too slow to do
  # per-response; 5 is the common on-the-fly choice (nginx defaults to ~6) and
  # still beats gzip on text. lgwin 22 is the default 4 MiB window.
  brQuality = cint(5)
  brWindow = cint(22)
  brModeText = cint(1)      # BROTLI_MODE_TEXT (bodies here are text-ish)
  brTrue = cint(1)

proc brotliEncoderMaxCompressedSize(inputSize: csize_t): csize_t
  {.importc: "BrotliEncoderMaxCompressedSize", cdecl.}
proc brotliEncoderCompress(quality, lgwin, mode: cint, inputSize: csize_t,
                           inputBuffer: ptr uint8, encodedSize: ptr csize_t,
                           encodedBuffer: ptr uint8): cint
  {.importc: "BrotliEncoderCompress", cdecl.}

proc brotli*(data: openArray[char]): string =
  ## Brotli-compress `data` in one shot; "" on failure (caller sends uncompressed).
  let maxOut = brotliEncoderMaxCompressedSize(csize_t(data.len))
  if maxOut == 0: return ""
  result = newString(int(maxOut))
  var encSize = maxOut
  let inp =
    if data.len > 0: cast[ptr uint8](unsafeAddr data[0]) else: nil
  if brotliEncoderCompress(brQuality, brWindow, brModeText, csize_t(data.len),
                           inp, addr encSize,
                           cast[ptr uint8](addr result[0])) != brTrue:
    return ""
  result.setLen(int(encSize))

# --- streaming brotli (res.sendHead/write/finish, SSE, file streaming) -------
# Stateful encoder fed chunk by chunk: each write uses BROTLI_OPERATION_FLUSH so
# the bytes are deliverable now, finish uses BROTLI_OPERATION_FINISH. A
# `ref object of RootObj` (held as a RootRef by a Connection / h2 / h3 stream);
# its =destroy frees the encoder when that stream is torn down. Mirrors
# gzip.GzipStream.

const
  brParamMode = cint(0)
  brParamQuality = cint(1)
  brParamLgwin = cint(2)
  brOpFlush = cint(1)
  brOpFinish = cint(2)

proc brotliEncoderCreateInstance(alloc, free, opaque: pointer): pointer
  {.importc: "BrotliEncoderCreateInstance", cdecl.}
proc brotliEncoderDestroyInstance(s: pointer)
  {.importc: "BrotliEncoderDestroyInstance", cdecl.}
proc brotliEncoderSetParameter(s: pointer, param: cint, value: uint32): cint
  {.importc: "BrotliEncoderSetParameter", cdecl.}
proc brotliEncoderCompressStream(s: pointer, op: cint, availIn: ptr csize_t,
                                 nextIn: ptr ptr uint8, availOut: ptr csize_t,
                                 nextOut: ptr ptr uint8,
                                 totalOut: ptr csize_t): cint
  {.importc: "BrotliEncoderCompressStream", cdecl.}
proc brotliEncoderHasMoreOutput(s: pointer): cint
  {.importc: "BrotliEncoderHasMoreOutput", cdecl.}

type
  BrotliStreamObj = object of RootObj
    state: pointer            # BrotliEncoderState*
  BrotliStream* = ref BrotliStreamObj

proc `=destroy`(o: var BrotliStreamObj) =
  if o.state != nil:
    brotliEncoderDestroyInstance(o.state)
    o.state = nil

proc newBrotliStream*(): BrotliStream =
  ## A streaming brotli encoder, or nil on failure.
  result = BrotliStream()
  result.state = brotliEncoderCreateInstance(nil, nil, nil)
  if result.state == nil:
    return nil
  discard brotliEncoderSetParameter(result.state, brParamQuality,
                                    uint32(brQuality))
  discard brotliEncoderSetParameter(result.state, brParamLgwin,
                                    uint32(brWindow))
  discard brotliEncoderSetParameter(result.state, brParamMode,
                                    uint32(brModeText))

proc compress*(s: BrotliStream, data: openArray[char], last: bool): string =
  ## Feed one chunk; returns the compressed bytes to emit (may be ""). `last`
  ## finishes the stream. On error the encoder is dropped and returns "".
  if s == nil or s.state == nil: return ""
  var availIn = csize_t(data.len)
  var nextIn =
    if data.len > 0: cast[ptr uint8](unsafeAddr data[0]) else: nil
  let op = if last: brOpFinish else: brOpFlush
  var chunk = newString(4096)
  result = ""
  while true:
    var availOut = csize_t(chunk.len)
    var nextOut = cast[ptr uint8](addr chunk[0])
    if brotliEncoderCompressStream(s.state, op, addr availIn, addr nextIn,
                                   addr availOut, addr nextOut, nil) != brTrue:
      brotliEncoderDestroyInstance(s.state); s.state = nil
      return ""
    let produced = chunk.len - int(availOut)
    if produced > 0:
      result.add chunk[0 ..< produced]
    if brotliEncoderHasMoreOutput(s.state) != brTrue and availIn == 0:
      break
