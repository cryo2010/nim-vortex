## Shared Strategy for the streaming response compressors (gzip / brotli / zstd)
## plus the single type their bounded inbound decoders return. A leaf module (no
## vortex deps) so each encoder module can inherit the base without a cycle; the
## algorithm-name factory lives with the callers that already flag-gate the
## encoders. Lets a caller hold any encoder as one `CompressStream` and feed
## chunks through a single virtual `compress`, instead of a per-call `case` over
## the concrete ref types (an easy place for the three backends to drift).

type
  CompressStreamObj* = object of RootObj
    ## Base for a stateful streaming encoder. Each backend (GzipStream,
    ## BrotliStream, ZstdStream) inherits and overrides `compress`; a
    ## Connection / h2 / h3 stream holds one as a `CompressStream` (or the
    ## type-erased RootRef it already stores) for the length of a response.
  CompressStream* = ref CompressStreamObj

  DecodeResult* = tuple[ok, tooLarge: bool, data: string]
    ## Result of a bounded inbound decompression, shared by gunzip / brotliDecode
    ## / zstdDecode. `ok` false = corrupt or over-cap; `tooLarge` distinguishes an
    ## over-cap body (caller -> 413) from a corrupt one (-> 400); `data` holds the
    ## inflated bytes when `ok`.

method compress*(s: CompressStream, data: openArray[char], last: bool): string
    {.base, gcsafe.} =
  ## Feed one chunk; return the compressed bytes to emit (may be ""). `last`
  ## finishes the stream. The base is never reached in practice (every stored
  ## encoder is a concrete subtype); it yields identity "" defensively.
  ""
