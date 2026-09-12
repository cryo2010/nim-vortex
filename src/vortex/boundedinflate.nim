## Shared driver for bounded request-body decompression. gzip, brotli and zstd
## all decode inbound bodies into an output buffer that grows on demand but is
## capped at `maxOut`: the instant the output would exceed the cap, decoding
## stops and reports `tooLarge` (the decompression-bomb guard). That cap / bomb /
## truncation policy is security-critical, so it lives here once instead of in
## three near-identical copies that could silently drift; each codec supplies
## only its per-iteration decode step.

type
  InflateState* = enum
    infMore    ## produced output (maybe none); call again, growing if the buffer filled
    infDone    ## stream complete
    infError   ## corrupt or truncated input

  ## Decompress into `dst[0 ..< cap]`, returning how many bytes were produced this
  ## call and whether the stream is done / wants more room / failed.
  InflateStep* = proc(dst: ptr uint8, cap: int): tuple[produced: int,
                      state: InflateState] {.closure.}

proc boundedInflate*(dataLen, maxOut: int, step: InflateStep):
    tuple[ok: bool, tooLarge: bool, data: string] =
  ## Drive `step` into a bounded, on-demand-growing output buffer.
  ## `tooLarge` distinguishes an over-cap body (-> 413) from a corrupt one (-> 400).
  if maxOut <= 0: return (false, false, "")
  var res = newString(min(maxOut, max(1024, dataLen * 4)))
  var total = 0
  while true:
    if total == res.len:
      if res.len >= maxOut: return (false, true, "")     # exceeds the cap (bomb)
      res.setLen(min(maxOut, res.len * 2))
    let (produced, state) = step(cast[ptr uint8](addr res[total]), res.len - total)
    total += produced
    case state
    of infDone: break
    of infMore: discard           # loop; grow at the top if the buffer is full
    of infError: return (false, false, "")                # corrupt/truncated
  res.setLen(total)
  (true, false, res)
