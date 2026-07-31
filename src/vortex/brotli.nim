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
