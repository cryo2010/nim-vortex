## Shared, navi-free pieces of the compiled stress load client
## (conformance/stress/client/navi/stress_navi.nim).
##
## This is the Nim port of what `client/transport.py` owns for the Python
## clients: the VORTEX_* config, the deterministic byte generator, the typed
## payload catalogue, request-body compression, the status tallies and the
## report-line formatting. Deliberately navi-free, so it compiles the same under
## `navi/asyncdispatch` and `navi/chronos` and can be read (and unit-checked)
## without a transport in scope. Everything that needs a `Navi` -- the protocol
## pin, the client factory, the drive loop, the reporter and the workloads --
## lives in stress_navi.nim.
##
## The output grammar here is NOT ours to choose: the harness is driven as
## `nimble stress | tee stress.log` and read by watchers that match exact line
## forms, so a navi log must be greppable with the same patterns as a python log
## (see the stress README). Every formatting proc below reproduces
## stress_client.py's line byte for byte apart from the values.
##
## State lives in one `State` ref rather than module-level `var`s on purpose:
## the chronos async transform gcsafe-checks a coroutine body, so a global
## mutable tally would not compile under `-d:useChronos` (and `--threads:on`
## makes it wrong in any case). Pass the `State` down; it costs nothing.

import std/[os, strutils, tables, algorithm, math, monotimes, sysrand]
import checksums/sha1

# The codec encoders are vortex's own, linked with exactly the flags the server
# links (see the Dockerfile): the request bodies this client compresses must be
# the bytes the server's decompressRequest path is built to accept, and sharing
# the implementation is the only way to keep that true as the codecs change.
# All three are always compiled in so one image serves every
# VORTEX_REQ_COMPRESSION / VORTEX_RESP_COMPRESSION value.
when defined(httpGzip): import vortex/gzip
when defined(httpBrotli): import vortex/brotli
when defined(httpZstd): import vortex/zstd

const
  chunkSize* = 64 * 1024     ## streaming chunk, as transport.py's CHUNK
  mb* = 1024 * 1024

# The navi ref the image was built from, baked into the binary by the Dockerfile
# (`-d:naviRef=<sha>`) so the header line can name the exact client under
# measurement. "unknown" only when someone compiles this by hand.
const naviRef* {.strdefine.} = "unknown"

# Which navi backend this binary was built against. One source, two images: the
# Dockerfile passes -d:useChronos for VORTEX_NAVI_BACKEND=chronos.
const backendName* = when defined(useChronos): "chronos" else: "asyncdispatch"

type
  Fail* = object of CatchableError
    ## A fatal defect (corruption, bad status, a transport error, a protocol-pin
    ## violation). Ends the run non-zero at once; never retried or tallied, the
    ## same contract as the Python client's `Fail`.

  Config* = object
    ## One cell's configuration, from the same environment the Python client
    ## reads (transport.py's module-level block). Parsed once in `loadConfig`.
    workload*: string        ## VORTEX_WORKLOAD
    proto*: string           ## VORTEX_PROTO: h1 | h2 | h3 (concrete)
    server*: string          ## STRESS_SERVER: the runtime label, for the report prefix
    base*: string            ## STRESS_BASE, trailing '/' stripped
    seconds*: int            ## VORTEX_SECONDS
    clients*: int            ## VORTEX_CLIENTS: copies of the workload
    conc*: int               ## VORTEX_CONCURRENCY: workers per copy
    streamBytes*: int        ## VORTEX_STREAM_BYTES
    report*: int             ## VORTEX_REPORT_SECONDS
    reqComp*: string         ## VORTEX_REQ_COMPRESSION
    respComp*: string        ## VORTEX_RESP_COMPRESSION
    mix*: string             ## VORTEX_MIX (parsed by the mixed workload)
    collectEvery*: int       ## VORTEX_NAVI_COLLECT_SECONDS: explicit ORC cycle
                             ## collection cadence (0 = leave it to the runtime)
    unit*: string            ## the workload's rate unit, for the report line
    isH3*: bool
    streaming*: bool         ## the workload reports MB/s instead of ops/s
    isMixed*: bool
    expectVersion*: string   ## the exact res.httpVersion every response must carry
    accept*: string          ## the accept-encoding to pin ("" = send none)

  State* = ref object
    ## Everything one cell tallies. Threaded through the workloads instead of
    ## living in globals (see the module note).
    cfg*: Config
    codes*: Table[int, int]          ## HTTP status -> count, cell-wide
    okBy*: Table[string, int]        ## workload -> 2xx completions (mixed)
    abandonedBy*: Table[string, int] ## workload -> transfers abandoned at the deadline
    xfer*: int                       ## cumulative bytes on the wire, cell-wide
    xferBy*: Table[string, int]      ## the same, per slice (mixed)
    start*, deadline*: float         ## monotonic seconds
    rateAt*: float                   ## [bytes] last report time
    rateBytes*: int                  ## [bytes] xfer at the last report
    opsAt*: float                    ## [ops] last report time
    opsCount*: int                   ## [ops] 2xx count at the last report
    workersDone*: bool               ## set once every worker has stopped, read
                                     ## by the deadline+60 s stall net
    # --- mixed only ----------------------------------------------------------
    # The resolved split, and the previous report line's per-slice counters, so
    # a report can show each slice's DELTA and not just its cumulative total: a
    # cumulative count only ever goes up, so a slice that died at t=30s still
    # reads as a healthy five-figure total for the rest of the run.
    slices*: seq[(string, int)]      ## (workload, workers), in mix order
    mixLast*: Table[string, int]     ## tag -> okBy[tag] at the previous line
    mixAt*: float                    ## monotonic time of that line
    streamSha*: string               ## memoised expectedSha1(streamBytes);
                                     ## see `streamDigest`

proc emit*(line: string) =
  ## Print one line on STDOUT and flush it.
  ##
  ## Both halves matter. Stdout, because the harness is driven as
  ## `nimble stress | tee stress.log`, which tees stdout only -- a verdict or a
  ## cause on stderr never reaches the archived log and the cell shows a bare
  ## `FAILED (exit 1)` with no reason (#387). And flushed, because stdout inside
  ## `docker run` is a pipe and therefore fully buffered: without this a watcher
  ## tailing the log would see an hour's report lines arrive in bursts, which is
  ## indistinguishable from a client that stopped reporting.
  echo line
  flushFile(stdout)

proc monoNow*(): float =
  ## Monotonic seconds, the equivalent of Python's `time.monotonic()`. A wall
  ## clock would let an NTP step inside the container shorten or extend the cell.
  float(ticks(getMonoTime())) / 1_000_000_000.0

proc newFail*(msg: string): ref Fail =
  result = newException(Fail, msg)

# --- config ------------------------------------------------------------------

proc cfgError*(msg: string) =
  ## A configuration error: the message on STDOUT, exit 2. Stdout, not stderr,
  ## for the same reason run.sh's need_uint and the Python client's causes are on
  ## stdout: the harness is driven as `nimble stress | tee stress.log`, which
  ## tees stdout only, so a config error on stderr never reaches the archived log
  ## and the cell looks like it simply died (#387).
  emit msg
  quit(2)

proc envInt(name: string, def: int): int =
  let v = getEnv(name, "")
  if v.len == 0: return def
  try: parseInt(v.strip())
  except ValueError:
    cfgError(name & " must be a non-negative integer (got '" & v & "')")
    0

proc loadConfig*(): Config =
  ## Read one cell's config from the environment, the same variables and the
  ## same defaults as transport.py:22-31. A missing STRESS_BASE or a non-integer
  ## count is a config error (exit 2), never a soak failure: run.sh always sets
  ## these, so a bad one means the harness was invoked by hand.
  result.workload = getEnv("VORTEX_WORKLOAD", "requests")
  result.proto = getEnv("VORTEX_PROTO", "h2")
  result.server = getEnv("STRESS_SERVER", "sync")
  result.base = getEnv("STRESS_BASE", "").strip(leading = false, chars = {'/'})
  if result.base.len == 0:
    cfgError("STRESS_BASE is required (e.g. https://server:8443)")
  result.seconds = envInt("VORTEX_SECONDS", 60)
  result.clients = envInt("VORTEX_CLIENTS", 3)
  result.conc = envInt("VORTEX_CONCURRENCY", 32)
  result.streamBytes = envInt("VORTEX_STREAM_BYTES", 1 shl 30)
  result.report = envInt("VORTEX_REPORT_SECONDS", 60)
  result.reqComp = getEnv("VORTEX_REQ_COMPRESSION", "gzip")
  result.respComp = getEnv("VORTEX_RESP_COMPRESSION", "gzip")
  result.mix = getEnv("VORTEX_MIX", "")
  result.collectEvery = envInt("VORTEX_NAVI_COLLECT_SECONDS", 1)
  result.isH3 = result.proto == "h3"
  result.isMixed = result.workload == "mixed"
  result.streaming = result.workload in ["streamupload", "streamdownload"]
  # `mixed` drives all five workloads at one server, so there is no one unit for
  # it: its report line and pass banner list each workload's own tally instead of
  # a headline rate, and this is only the fallback the rare generic phrasing uses.
  result.unit =
    case result.workload
    of "requests": "requests"
    of "ws": "messages"
    of "sse": "events"
    of "streamupload", "streamdownload": "transfers"
    of "mixed": "ops"
    else: "ok"
  # The exact version every response must report. The cell exists to exercise one
  # protocol, so any upgrade OR downgrade is a hard failure -- navi ALPN- (and
  # Alt-Svc-) negotiates even with `config.http` pinned to one version, and the
  # h3 discovery leg is exempted internally, so verifying each response is what
  # turns a silent fallback into a verdict (transport.py's _pin_check).
  result.expectVersion =
    case result.proto
    of "h1": "HTTP/1.1"
    of "h2": "HTTP/2"
    of "h3": "HTTP/3"
    else: ""
  if result.expectVersion.len == 0:
    cfgError("unknown VORTEX_PROTO: " & result.proto)
  # accept-encoding is pinned to the codec under test, exactly as the Python
  # client does (transport.py's ACCEPT), so the server compresses with the codec
  # the cell is named after instead of whichever of navi's four defaults it
  # prefers. Confirmed against navi's request builder: the default
  # `accept-encoding: gzip, deflate, br, zstd` is added only when the caller did
  # NOT supply one (core/request.nim's `wantsDecompress` arm), so a per-request
  # header replaces it and no skip notice is needed here.
  result.accept = if result.respComp in ["", "none"]: "" else: result.respComp

proc newState*(cfg: Config): State =
  result = State(cfg: cfg, codes: initTable[int, int](),
                 okBy: initTable[string, int](),
                 abandonedBy: initTable[string, int](),
                 xferBy: initTable[string, int](),
                 mixLast: initTable[string, int]())

# --- tallies -----------------------------------------------------------------

proc bump*(st: State, status: int, tag: string, n = 1) =
  ## Record `n` completions of `status`, cell-wide and (under `mixed`) against
  ## the slice `tag` that earned them. `tag` is the workload name: exactly
  ## `cfg.workload` for the five single-workload soaks, the slice's own name
  ## under `mixed`, so a dead slice shows as a zero rather than disappearing
  ## into a healthy sum.
  st.codes.mgetOrPut(status, 0) += n
  if status >= 200 and status < 300 and st.cfg.isMixed:
    st.okBy.mgetOrPut(tag, 0) += n

proc addXfer*(st: State, n: int, tag: string) =
  ## Count `n` bytes on the wire, cell-wide and (under `mixed`) per slice.
  st.xfer += n
  if st.cfg.isMixed: st.xferBy.mgetOrPut(tag, 0) += n

proc abandon*(st: State, tag: string) =
  ## A streaming transfer that was started and then dropped at the deadline:
  ## neither verified nor counted, but recorded so a run where nothing completed
  ## can say why (see `noProgress`).
  st.abandonedBy.mgetOrPut(tag, 0) += 1

proc okOps*(st: State): int =
  ## Cumulative successful (2xx) completions: the throughput numerator.
  for c, n in st.codes:
    if c >= 200 and c < 300: result += n

proc moved*(st: State, tag: string): int =
  ## Bytes `tag` actually got on the wire. For a single-workload soak that is the
  ## cell total, since the cell is the one workload; under `mixed` five workloads
  ## share `xfer`, so only the per-slice tally answers `noProgress`'s question.
  if st.cfg.isMixed: st.xferBy.getOrDefault(tag, 0) else: st.xfer

proc fmtCodes*(st: State): string =
  var keys: seq[int]
  for k in st.codes.keys: keys.add k
  keys.sort()
  var parts: seq[string]
  for k in keys: parts.add $k & "x" & $st.codes[k]
  if parts.len == 0: "0" else: parts.join(" ")

proc noProgress*(st: State, tag: string): string =
  ## Why `tag` completed nothing. Three different diagnoses, ported from the
  ## Python client's `no_progress`, minus one arm: navi streams a request body
  ## chunk by chunk, so an h3 upload counts bytes as the producer hands them over
  ## and the "aioquic buffers the whole body, so the client cannot tell a stall
  ## from a slow transfer" case cannot arise here. That is the point of a
  ## compiled client with real streaming, so the message is always decidable.
  ##
  ## Either way it is a FAILURE (exit 1), not a skip: a soak that verified zero
  ## bytes must not read as a pass.
  let n = st.abandonedBy.getOrDefault(tag, 0)
  if n == 0:
    # Nothing was even started, so there is no transfer to explain.
    return "no successful iterations"
  let bytesMoved = st.moved(tag)
  let head = "no transfer of " & $st.cfg.streamBytes & " bytes completed within " &
    $st.cfg.seconds & " s on " & st.cfg.proto & " (" & $n &
    " abandoned at the deadline, " & $bytesMoved & " bytes moved)"
  if bytesMoved > 0:
    return head & "; the transfers are too big for this run: lower " &
      "VORTEX_STREAM_BYTES or raise VORTEX_SECONDS"
  head & ": the server delivered nothing, a stall rather than a sizing " &
    "problem; check the server log"

# --- report formatting -------------------------------------------------------

proc fmt0*(x: float): string =
  ## A float with no decimals, like Python's `f"{x:.0f}"`.
  $int(round(x))

proc fmtRate*(st: State, now: float): string =
  ## The per-interval throughput segment for the non-streaming workloads: the 2xx
  ## completion rate since the last report. Cumulative codes alone hide a dip or
  ## a declining trend, so surface the rate directly. 0 means nothing completed
  ## in the interval: a stall.
  let ops = st.okOps()
  let dt = now - st.opsAt
  let dn = ops - st.opsCount
  st.opsAt = now
  st.opsCount = ops
  let rate = if dt > 0: float(dn) / dt else: 0.0
  " | " & fmt0(rate) & " " & st.cfg.unit & "/s"

proc fmtXfer*(st: State, now: float): string =
  ## The throughput segment for the streaming workloads: cumulative bytes plus
  ## the MB/s since the last report. `xfer` tracks what actually moved on the
  ## wire; navi streams in both directions, so an upload counts bytes as the
  ## producer hands them over and a download counts them as they arrive. 0 MB/s
  ## means nothing moved in the interval.
  let dt = now - st.rateAt
  let db = st.xfer - st.rateBytes
  st.rateAt = now
  st.rateBytes = st.xfer
  let rate = if dt > 0: float(db) / dt / float(mb) else: 0.0
  " | " & $(st.xfer div mb) & "MB xfer @ " & fmt0(rate) & "MB/s"

proc fmtMem*(bytes: int): string =
  ## A /stats figure in MB, or `n/a` for a failed sample. Never a misleading
  ## `0MB`: a soak exists to watch RSS/heap/fds, so a silently-zeroed metric must
  ## look broken, not healthy. -1 is "no sample".
  if bytes < 0: "n/a" else: $(bytes div mb) & "MB"

proc fmtFds*(fds: int): string =
  if fds < 0: "n/a" else: $fds

proc selfRssBytes*(): int =
  ## This process's resident set size, from /proc/self/statm (the client runs in
  ## a Linux container). 0 when unavailable, which `selfLine` renders as n/a.
  try:
    let fields = readFile("/proc/self/statm").splitWhitespace()
    if fields.len >= 2: return parseInt(fields[1]) * 4096
  except CatchableError: discard
  0

proc selfFds*(): int =
  ## This process's open descriptors, counted from /proc/self/fd (includes the
  ## dirfd of the listing itself, a constant +1). -1 when unavailable.
  try:
    for _ in walkDir("/proc/self/fd"): inc result
  except CatchableError: result = -1

proc selfLine*(st: State): string =
  ## `client: rss <n>MB heap <n>MB fds <n> t=<n>s`, the client's OWN footprint,
  ## printed next to every report line. The Python canary never had this and it
  ## cost a soak its verdict: a 30-minute h3 `mixed` cell ended with
  ## `FAILED (exit 137)` and nothing else, because the kernel OOM-killed the
  ## client container -- a SIGKILL prints no FAIL line and leaves no trace -- and
  ## the only memory in the log was the server's, flat at 114 MB. The report
  ## line's RSS/heap/fds stay the SERVER's, byte for byte as before, so watchers
  ## keep matching; this is a separate line with its own `client:` prefix, the
  ## same prefix as the header line that names the client. RSS is the number that
  ## matters (it is what the OOM killer sees); the Nim heap beside it says whether
  ## a growth is this program's or the C side's (OpenSSL, ngtcp2, the allocator).
  "client: rss " & fmtMem(selfRssBytes()) & " heap " &
    fmtMem(getOccupiedMem()) & " fds " & fmtFds(selfFds()) &
    " t=" & $int(monoNow() - st.start) & "s"

proc reportLine*(st: State, prefix: string, rss, heap, fds: int, seg: string) =
  ## One report line, in the grammar the watchers match:
  ##   [<workload> <proto> <server>] <codes> | <segment> | RSS <n>MB | heap
  ##   <n>MB | fds <n> | t=<n>s
  ## `prefix` is "" for an interval line and "final " for the last one. The
  ## three-token bracket is deliberately unchanged from the Python client's: a
  ## grep that works on a python log must work on a navi log, and the client is
  ## named by the cell banner and the header line instead.
  let t = int(monoNow() - st.start)
  emit "[" & st.cfg.workload & " " & st.cfg.proto & " " & st.cfg.server & "] " &
    prefix & st.fmtCodes() & seg & " | RSS " & fmtMem(rss) & " | heap " &
    fmtMem(heap) & " | fds " & fmtFds(fds) & " | t=" & $t & "s"

# --- deterministic byte generator: byte i = i mod 256 (matches the server) ---

proc buildPattern(): string =
  result = newString(chunkSize + 256)
  for j in 0 ..< result.len: result[j] = char(j and 0xff)

const genPattern = buildPattern()
  ## `chunkSize + 256` bytes of the generator. The generator has period 256 and
  ## `chunkSize` is a whole number of periods, so any run of up to `chunkSize`
  ## bytes, from any global offset, is one contiguous slice of this starting at
  ## `offset mod 256`. That makes `genChunk` a copy instead of a per-byte loop,
  ## which matters on the streaming workloads: they call it once per 64 KiB for a
  ## whole multi-hundred-megabyte transfer.

proc genChunk*(start, n: int): string =
  ## `n` bytes of the deterministic generator starting at global index `start`
  ## (byte i = i mod 256). The cross-language contract with the server's own
  ## genChunk and with the Python client's gen_chunk, which every whole-stream
  ## SHA-1 check depends on.
  if n <= chunkSize:
    let s = start and 0xff
    result = genPattern[s ..< s + n]
  else:
    result = newString(n)
    var c = start and 0xff
    for j in 0 ..< n:
      result[j] = char(c)
      c = (c + 1) and 0xff

proc expectedSha1*(total: int): string =
  ## Lowercase hex SHA-1 of the first `total` bytes of the generator, computed
  ## client-side exactly as the Python client's expected_sha1 does. The server
  ## does not send a digest for /download, so this is the only expected value.
  var ctx = newSha1State()
  var off = 0
  while off < total:
    let n = min(chunkSize, total - off)
    ctx.update(genChunk(off, n))
    off += n
  ($SecureHash(ctx.finalize())).toLowerAscii()

type Digest* = object
  ## A running SHA-1 over a stream that is never buffered: the download workload
  ## hashes each chunk as it arrives and discards it, so a 1 GiB transfer costs
  ## one 64 KiB chunk of memory rather than a gigabyte. Wrapped here rather than
  ## used directly so `checksums/sha1` stays an implementation detail of this
  ## module: stress_navi.nim imports a navi backend, which exports its own SHA-1
  ## for the WebSocket handshake, and two `sha1` modules in one scope is an
  ## ambiguity waiting to happen on a navi bump.
  st: Sha1State

proc initDigest*(): Digest = Digest(st: newSha1State())

proc update*(d: var Digest, chunk: string) =
  if chunk.len > 0: d.st.update(chunk)

proc hex*(d: var Digest): string =
  ## Finalize to lowercase hex, the spelling `expectedSha1` and the server's
  ## `x-sha1` both use. Consumes the state: call once.
  ($SecureHash(d.st.finalize())).toLowerAscii()

proc streamDigest*(st: State): string =
  ## The expected whole-stream digest, computed ONCE per process and cached.
  ##
  ## Not a micro-optimisation. `expectedSha1` is synchronous and
  ## `checksums/sha1` is pure Nim at roughly 240 MB/s, so one 1 GiB stream costs
  ## about 4.3 s with the event loop BLOCKED -- and BOTH streaming workloads
  ## need the digest, once per VORTEX_CLIENTS copy, so the default 3 copies used
  ## to pay for it six times over. Measured on h3 + sync, 30 s, 1 GiB, before
  ## this cache existed: `WARN client event-loop stalled 12.6s (t=0s)` followed
  ## by three more 4.4 s stalls, about 26 s of a 30 s cell spent hashing, one
  ## upload and no downloads completed. The Python canary calls its own
  ## `expected_sha1` the same six times, but in C (hashlib) where each is about
  ## a second and never shows up; here it has to be hoisted.
  ##
  ## Safe to share without a lock: the computation has no `await` in it, so the
  ## first caller finishes before any other coroutine on this single-threaded
  ## loop can observe the empty string.
  if st.streamSha.len == 0:
    st.streamSha = expectedSha1(st.cfg.streamBytes)
  st.streamSha

# --- request-body compression (server decompresses via decompressRequest) ----

proc compressBody*(cfg: Config, raw: string): (string, string) =
  ## `(body, content-encoding)` for `raw` under VORTEX_REQ_COMPRESSION. The empty
  ## encoding means "send it as is". An unknown codec is a config error (exit 2),
  ## never a silently uncompressed run.
  case cfg.reqComp
  of "", "none": (raw, "")
  of "gzip":
    when defined(httpGzip): (gzip(raw), "gzip")
    else:
      cfgError("this client was built without -d:httpGzip"); (raw, "")
  of "br":
    when defined(httpBrotli): (brotli(raw), "br")
    else:
      cfgError("this client was built without -d:httpBrotli"); (raw, "")
  of "zstd":
    when defined(httpZstd): (zstd(raw), "zstd")
    else:
      cfgError("this client was built without -d:httpZstd"); (raw, "")
  else:
    cfgError("unknown VORTEX_REQ_COMPRESSION: " & cfg.reqComp)
    (raw, "")

# --- typed payload mix (shared with the requests / mixed workloads) ----------

const mpBoundary = "----vortexstressBoundary7MA4YWxkTrZu0gW"
  ## A fixed boundary so the outer content-type string and the raw multipart body
  ## agree exactly: the server echoes the content-type verbatim (boundary and
  ## all) and re-sends the decompressed body, so the boundary must round-trip.

proc multipartBody(boundary: string): string =
  ## Raw multipart/form-data bytes BY HAND: a couple of text fields plus one file
  ## part carrying genChunk(0, 4096) as application/octet-stream, closed with the
  ## final terminator boundary. Hand-built (not navi's `Multipart`) so the exact
  ## bytes get request-compressed and echoed like any other body -- a multipart
  ## encoder would own the framing and the round-trip could not be asserted
  ## byte-for-byte. navi keeps an explicit content-type for a `string` body, so
  ## this boundary is what goes on the wire (confirmed in core/request.nim: the
  ## inferred type is added only when the caller set none, and a raw string body
  ## infers nothing at all).
  let dash = "--" & boundary
  result = dash & "\r\n"
  result &= "Content-Disposition: form-data; name=\"field1\"\r\n\r\n"
  result &= "the quick brown fox\r\n"
  result &= dash & "\r\n"
  result &= "Content-Disposition: form-data; name=\"field2\"\r\n\r\n"
  result &= "jumps over the lazy dog\r\n"
  result &= dash & "\r\n"
  result &= "Content-Disposition: form-data; name=\"file\"; filename=\"blob.bin\"\r\n"
  result &= "Content-Type: application/octet-stream\r\n\r\n"
  result &= genChunk(0, 4096)
  result &= "\r\n"
  result &= dash & "--\r\n"

proc randomBytes(n: int): string =
  ## `n` incompressible bytes, the equivalent of Python's os.urandom. Used for
  ## the store-fallback entries: they are not deterministic, but the round-trip
  ## assertions only need self-consistency.
  result = newString(n)
  var buf = newSeq[byte](n)
  if not urandom(buf):
    # No system entropy (should not happen in the container); fall back to a
    # fixed high-entropy-ish filler rather than silently sending a compressible
    # body, which would quietly drop the store-fallback branch from the cell.
    cfgError("could not read system entropy for the incompressible payloads")
  for i in 0 ..< n: result[i] = char(buf[i])

proc payloadMix*(): seq[(string, string)] =
  ## The typed request-body mix: `(content_type, raw_bytes)`, ported from
  ## transport.py's payload_mix. Sizes cover the 0-length / 1-byte framing paths,
  ## the <1400 B no-compress threshold, the compressible >=1400 B branch per
  ## type, and the incompressible store-fallback. Built once at startup.
  # text/plain length ladder: empty and single byte (framing), a tiny body, one
  # around the compress threshold, and two large compressible bodies.
  for n in [0, 1, 13, 1280, 64 * 1024, 256 * 1024]:
    let filler = "the quick brown fox ".repeat(n div 20 + 1)
    result.add ("text/plain", filler[0 ..< n])
  result.add ("text/plain", randomBytes(64 * 1024))   # incompressible: store fallback
  # ~300 B realistic JSON object (a few string/number/bool/nested fields), padded
  # to ~300 B so it sits below the compress threshold. Written out in Python's
  # json.dumps spelling (", " and ": " separators) so the byte count matches the
  # Python client's entry.
  result.add ("application/json",
    "{\"user\": \"alice\", \"id\": 42, \"active\": true, \"score\": 3.14, " &
    "\"tags\": [\"a\", \"b\", \"c\"], \"meta\": {\"role\": \"admin\", \"seen\": 7}, " &
    "\"note\": \"" & "x".repeat(180) & "\"}")
  # ~9 KB JSON array (100 objects, several fields each): JSON-shaped entropy
  # compresses ~5-10x and is well over the 1400 B threshold, so the
  # application/json compression branch runs. Nim and Python both print the
  # shortest round-tripping decimal for a float, so `ratio` renders identically.
  var arr = "["
  for i in 0 ..< 100:
    if i > 0: arr &= ", "
    arr &= "{\"id\": " & $i & ", \"name\": \"name-" & align($i, 4, '0') &
      "\", \"ts\": \"2026-09-21T00:" & align($(i mod 60), 2, '0') &
      ":00Z\", \"ratio\": " & $(float(i) * 0.12345) & ", \"ok\": " &
      (if i mod 2 == 0: "true" else: "false") & "}"
  arr &= "]"
  result.add ("application/json", arr)
  # urlencoded with reserved characters (spaces, '&', '=', unicode) so the value
  # escaping is exercised on the wire. The literal is Python's urlencode output
  # for the same dict, kept verbatim rather than re-derived: the point of the
  # entry is the exact escaping, so it should not drift with a library.
  result.add ("application/x-www-form-urlencoded",
    "q=the+quick+%26+brown+%3D+fox&name=+query+with+spaces&sym=a%26b%3Dc+d" &
    "&u=caf%C3%A9+na%C3%AFve+%E2%9C%93")
  # multipart/form-data: the outer content-type carries the SAME boundary as the
  # hand-built body; the server echoes both verbatim.
  result.add ("multipart/form-data; boundary=" & mpBoundary,
              multipartBody(mpBoundary))
  result.add ("application/octet-stream", genChunk(0, 8192))
  # typed binary, incompressible: the server must NOT compress a non-compressible
  # response type -- this keeps that branch honest.
  result.add ("application/octet-stream", randomBytes(64 * 1024))
  # XML document >= 1400 B (repeated <item> elements): the application/xml branch.
  var xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><items>"
  for i in 0 ..< 40:
    xml &= "<item id=\"" & $i & "\">The quick brown fox jumps over the lazy dog</item>"
  xml &= "</items>"
  result.add ("application/xml", xml)
  # a few-KB CSV built from a loop.
  var csv = "id,name,value\n"
  for i in 0 ..< 200: csv &= $i & ",name-" & $i & "," & $(i * i) & "\n"
  result.add ("text/csv", csv)
  # small HTML page snippet -- intentionally can be < 1400 B (no-compress path).
  result.add ("text/html",
    "<!doctype html><html><body><h1>hi</h1>" &
    "<p>The quick brown fox.</p></body></html>")

proc expectedGets*(): seq[(string, string, string)] =
  ## The GET-route contract: `(path, expected_content_type, expected_body)` for
  ## the typed GET routes, with the exact deterministic bodies the server serves
  ## byte-for-byte. This one IS a cross-language contract: the same table lives
  ## in transport.py's expected_gets and in stress_server.nim's typed bodies, and
  ## the three must agree or a server change goes unnoticed by one client.
  var html = "<!doctype html><html><head><title>vortex stress</title></head><body>"
  html &= "<p>The quick brown fox jumps over the lazy dog.</p>".repeat(30)
  html &= "</body></html>"
  var xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><items>"
  for i in 0 ..< 40:
    xml &= "<item id=\"" & $i & "\">The quick brown fox jumps over the lazy dog</item>"
  xml &= "</items>"
  var csv = "id,name,value\n"
  for i in 0 ..< 200: csv &= $i & ",name-" & $i & "," & $(i * i) & "\n"
  @[("/plaintext", "text/plain", "Hello, World!"),
    ("/json", "application/json", "{\"message\":\"Hello, World!\"}"),
    ("/html", "text/html", html),
    ("/xml", "application/xml", xml),
    ("/csv", "text/csv", csv),
    ("/binary", "application/octet-stream", genChunk(0, 8192))]

# --- mixed: the VORTEX_MIX split and the per-slice report segment ------------
#
# Ported from stress_client.py's MIX_DEFAULT / parse_mix / split_mix /
# mix_segments / mix_tail. Pure procs on purpose: the allocation is the one piece
# of `mixed` that has a right answer independent of any transport, so it is
# unit-checkable (see the `isMainModule` block at the bottom of this file, which
# asserts the Python client's own table) rather than only observable by reading a
# soak log.

const mixDefault* = [("requests", 40), ("ws", 20), ("sse", 20),
                     ("streamupload", 10), ("streamdownload", 10)]
  ## The default split of one cell's worker budget. `requests` takes the bulk of
  ## the request-shaped share because its workers are the cheapest and its
  ## /echo + typed-GET path is what every other route competes with.
  ##
  ## The two STREAMING entries are different in kind: their number is not a share
  ## of the budget but a presence flag (see `mixFixed`), so their default weight
  ## is written as the 10 it has always been and read only as "> 0, so run it".

const mixFixed* = ["streamupload", "streamdownload"]
  ## The slices fixed at exactly ONE worker per client when present, mirroring
  ## the dedicated streamupload / streamdownload soaks: one worker there is one
  ## WHOLE transfer in flight, and those soaks take their parallelism from
  ## VORTEX_CLIENTS rather than from VORTEX_CONCURRENCY. The first cut gave each
  ## a tenth of CONC, i.e. 9 + 9 per cell at the default 3x32 -- three times the
  ## dedicated soaks' parallelism -- and that is what forced the mixed transfer
  ## size down to 2 MiB at every duration (#394).

const mixRate = ["requests", "ws", "sse"]
  ## Which slices show their per-interval delta as a RATE rather than a raw
  ## count. The request-shaped ones complete thousands per interval, where a raw
  ## delta is unreadable and a rate is directly comparable to the
  ## single-workload soaks' `N requests/s` segment; a mixed cell's streaming
  ## slices complete single digits, where the count is the information and
  ## `(+0)` is the thing worth seeing.

proc pyRepr(s: string): string = "'" & s & "'"
  ## A value quoted inside a config-error message, the way Python's `!r` does it,
  ## so a stray space or an empty weight is visible in the log. (stress_navi.nim
  ## has the same one-liner as `q` for its own failure messages; duplicating four
  ## characters is cheaper than making this module depend on that one.)

proc parseMix*(raw: string): seq[(string, int)] =
  ## The mix as `(workload, weight)`, from a VORTEX_MIX string.
  ##
  ## Form: `requests=40,ws=20,sse=20,streamupload=10,streamdownload=10`. Every
  ## key must name one of the five verified workloads; an omitted one keeps its
  ## default, a repeated one is rejected (the later value would silently win, so
  ## the knob would not mean what it says), and an explicit `0` drops that
  ## workload from the cell entirely -- the one way to run a subset, and then it
  ## is not checked for progress either, since it was never asked to make any.
  ##
  ## The numbers are WEIGHTS, normalised by the sum of the weights that compete
  ## for the same workers, not percentages: `requests=100` alone does not mean
  ## "100%", it means "requests takes all of the request-shaped share" (the other
  ## two keep their defaults, so a 32-worker budget really splits 22/4/4). They
  ## need not add to 100, though the defaults do because a reader expects it.
  ##
  ## For `streamupload` / `streamdownload` the weight is PRESENCE-ONLY: any value
  ## > 0 means "run this slice", at the one worker per client `mixFixed` pins it
  ## to, and 0 drops it. Weighting a slice that is fixed at one worker would have
  ## nothing to weigh.
  ##
  ## A malformed knob is a config error (exit 2) rather than a run of something
  ## other than what was asked for.
  let r = raw.strip()
  var share = initTable[string, int]()
  for (k, w) in mixDefault: share[k] = w
  var seen: seq[string]
  for item0 in r.split(','):
    let item = item0.strip()
    if item.len == 0: continue
    let eq = item.find('=')
    if eq < 0:
      cfgError("bad VORTEX_MIX entry " & pyRepr(item) & ": want name=weight")
    let k = item[0 ..< eq].strip()
    let v = item[eq + 1 .. ^1].strip()
    if k notin share:
      var names: seq[string]
      for (n, _) in mixDefault: names.add n
      cfgError("unknown VORTEX_MIX workload " & pyRepr(k) & "; want one of " &
        names.join(", "))
    if k in seen:
      cfgError("VORTEX_MIX names " & pyRepr(k) & " twice (" & pyRepr(r) &
        "): the second weight would silently win, so the knob would not mean " &
        "what it says. Give each workload at most one weight.")
    # ASCII digits ONLY, checked by hand rather than by attempting a parse: the
    # Python client's own arm here exists because `str.isdigit()` is True for
    # superscripts and other non-ASCII digit forms (`VORTEX_MIX=requests=4` with
    # a superscript two), which then die inside int() with a traceback instead of
    # this message. Keep the two clients failing identically, and reject a
    # leading sign while we are here.
    if v.len == 0 or not v.allCharsInSet({'0' .. '9'}):
      cfgError("bad VORTEX_MIX weight for " & k & ": " & pyRepr(v) &
        " (want a non-negative decimal integer)")
    seen.add k
    share[k] = parseInt(v)
  for (k, _) in mixDefault:
    if share[k] > 0: result.add (k, share[k])
  if result.len == 0:
    cfgError("VORTEX_MIX=" & pyRepr(r) & " leaves no workload to run")

proc splitMix*(budget: int, shares: seq[(string, int)]): seq[(string, int)] =
  ## Hand `budget` workers out over `shares`, as `(workload, workers)`.
  ##
  ## The streaming slices present take exactly ONE worker each -- one whole
  ## transfer in flight per client, which is what the dedicated streamupload /
  ## streamdownload soaks run (see `mixFixed`).
  ##
  ## The request-shaped slices present (requests, ws, sse) then split what is
  ## left -- `budget` minus one per streaming slice -- by their weights,
  ## normalised by the sum of just THOSE weights, allocated by largest remainder
  ## so the rounding loss is spread instead of piling on one workload and leaving
  ## workers idle (30 left at the default 40/20/20 is 15/8/7, not 15/7/7 with one
  ## idle). Every one of them gets at least one worker, paid for out of the
  ## largest allocations, because a slice with zero workers drives nothing and
  ## would then fail the cell's own per-slice progress check.
  ##
  ## The total is EXACTLY `budget` whenever at least one request-shaped slice is
  ## present, and exactly the number of streaming slices when none is (a slice
  ## fixed at one transfer in flight has nowhere to spend the rest, and inventing
  ## workers for it would change what is being measured). It is never MORE than
  ## `budget`: a budget below the slice count is refused here rather than
  ## overshot, since a mixed cell must neither drop a slice -- that would claim
  ## coverage it does not have -- nor quietly run wider than it was told to.
  if budget < shares.len:
    var names: seq[string]
    for (k, _) in shares: names.add k
    cfgError("VORTEX_CONCURRENCY=" & $budget & " is below the " & $shares.len &
      " workloads in the mix (" & names.join(", ") &
      "): a mixed cell cannot drop a slice (it would claim coverage it does " &
      "not have) and will not run more workers than it was given. Raise " &
      "VORTEX_CONCURRENCY to at least " & $shares.len &
      ", or drop a workload with VORTEX_MIX=<name>=0.")
  var alloc = initTable[string, int]()
  for (k, _) in shares: alloc[k] = 1          # the floor: every slice drives
  var rest: seq[(string, int)]
  for (k, w) in shares:
    if k notin mixFixed: rest.add (k, w)
  let extra = budget - shares.len             # >= 0, checked above
  if rest.len > 0 and extra > 0:
    # Largest remainder over everything the request-shaped slices share, which
    # is `extra` plus the one worker each already holds.
    let left = extra + rest.len
    var totalW = 0
    for (_, w) in rest: totalW += w
    if totalW == 0: totalW = rest.len         # all-zero weights: share evenly
    var exact: seq[(string, float)]
    for (k, w) in rest: exact.add (k, float(left) * float(w) / float(totalW))
    var sum = 0
    for (k, x) in exact:
      alloc[k] = int(x)
      sum += int(x)
    var spare = left - sum
    # A STABLE sort (std/algorithm's `sort` on a seq is a merge sort), so a
    # remainder tie goes to the earlier -- higher-weight -- workload and a given
    # VORTEX_MIX always splits the same way. 30 workers over 40/20/20 ties ws
    # and sse at .5 and must always read 15/8/7, never 15/7/8.
    var order = exact
    order.sort(proc (a, b: (string, float)): int =
      cmp(b[1] - float(int(b[1])), a[1] - float(int(a[1]))))
    for (k, _) in order:
      if spare <= 0: break
      alloc[k] = alloc[k] + 1
      dec spare
    # Pay a zeroed slice's floor out of the largest allocation: a slice with no
    # workers drives nothing and would fail the cell's own progress check
    # (`VORTEX_MIX=requests=1000` at a small budget rounds its companions to 0).
    for (k, _) in rest:
      if alloc[k] == 0:
        var donor = k
        for (j, _) in rest:
          if alloc[j] > alloc[donor]: donor = j
        alloc[donor] = alloc[donor] - 1
        alloc[k] = 1
  for (k, _) in shares: result.add (k, alloc[k])

proc fmtMb*(b: int): string =
  ## Bytes as MB for a report segment, with one decimal under 10 MB.
  ##
  ## A whole-number MB is what a soak-sized figure wants, but floor division
  ## printed `0MB` for every sub-MiB VORTEX_STREAM_BYTES -- so a mixed cell run
  ## at, say, 512 KiB reported its verified transfers as having moved nothing,
  ## which is exactly the reading the per-slice tally exists to prevent.
  let m = float(b) / float(mb)
  if m < 10.0: formatFloat(m, ffDecimal, 1) & "MB" else: $(b div mb) & "MB"

proc mixSeg(tag: string, n, streamBytes: int): string =
  ## How one workload renders its own cumulative tally in a `mixed` report line
  ## and pass banner. Unit words, not a shared rate: the five are not
  ## commensurable, and a headline ops/s over all of them would hide a dead slice
  ## in the sum. The streaming slices show completed transfers and the bytes
  ## those verified -- a partial transfer is never counted, so
  ## `count * VORTEX_STREAM_BYTES` is exactly what moved and was checksummed.
  case tag
  of "requests": "req " & $n
  of "ws": "ws " & $n & " msgs"
  of "sse": "sse " & $n & " ev"
  of "streamupload": "up " & $n & " xfers " & fmtMb(n * streamBytes)
  of "streamdownload": "down " & $n & " xfers " & fmtMb(n * streamBytes)
  else: tag & " " & $n

proc mixSegments*(st: State, now: float, withDelta: bool): string =
  ## The per-workload tally segment for `mixed`: cumulative only
  ## (`withDelta = false`, for the pass banner and the FAIL tail), cumulative
  ## plus the delta since the previous report line when `withDelta` is set.
  ## Measured, h3 + sync server, 10 s at the mixed default size, t=11s:
  ##
  ##   req 8820 (+340/s) | ws 17378 msgs (+803/s) | sse 219600 ev (+10052/s)
  ##   | up 6 xfers 12MB (+0) | down 3 xfers 6.0MB (+3)
  ##
  ## The delta is what makes a stalled slice visible: a cumulative count only
  ## ever goes up, so a slice that died at t=30s still reads as a healthy
  ## five-figure total for the rest of the run, and spotting it would mean
  ## diffing successive lines by eye -- the same reason the single-workload soaks
  ## print a rate next to their cumulative codes.
  ##
  ## There is deliberately no "stalled for N intervals" verdict on top of this. A
  ## wedged slice does not merely stop counting: it blocks `wMixed`, the cell
  ## then overruns the deadline+60 s stall net, and that already fails the run as
  ## the stall it is. A second detector here would be a second opinion about the
  ## same event, with its own threshold to tune and its own false positives on a
  ## loaded host.
  let dt = if withDelta: now - st.mixAt else: 0.0
  var parts: seq[string]
  for (tag, _) in st.slices:
    let n = st.okBy.getOrDefault(tag, 0)
    var seg = mixSeg(tag, n, st.cfg.streamBytes)
    if withDelta:
      let d = n - st.mixLast.getOrDefault(tag, 0)
      if tag in mixRate:
        seg &= " (+" & fmt0(if dt > 0: float(d) / dt else: 0.0) & "/s)"
      else:
        seg &= " (+" & $d & ")"
      st.mixLast[tag] = n
    parts.add seg
  # One interval for every slice, so the stamp moves after the whole line.
  if withDelta: st.mixAt = now
  parts.join(" | ")

proc mixTail*(st: State): string =
  ## The per-slice tallies appended to a `mixed` FAIL line, else "".
  ##
  ## A hard failure ends the run before its final report line, so without this
  ## the only record of what each slice had achieved when the defect hit -- which
  ## were healthy, which were already dead -- is lost, and that record is most of
  ## why a mixed cell is worth running (#394).
  if st.cfg.isMixed: " [" & st.mixSegments(0.0, withDelta = false) & "]" else: ""

# --- self-check --------------------------------------------------------------

when isMainModule:
  ## `nim r conformance/stress/client/navi/common.nim` asserts the Python
  ## client's own split table. The allocation is a cross-client contract -- a
  ## `mixed` cell under VORTEX_CLIENT=navi must drive the same shape as under
  ## python, or its numbers are not comparable -- it is pure arithmetic, and it
  ## is the one part of `mixed` a soak log cannot show you directly: a
  ## misallocated slice just looks like a slow one. Cheap to check, so check it.
  ##
  ## Only the ACCEPTING paths are asserted here. The rejections go through
  ## `cfgError`, which prints and exits 2 by design, so they are checked from the
  ## outside instead (`VORTEX_MIX=requests=4<superscript 2>` must exit 2 with its
  ## message on stdout, as the harness does for every other config error).
  proc table(got: seq[(string, int)]): string =
    var parts: seq[string]
    for (k, n) in got: parts.add k & "=" & $n
    parts.join(" ")

  proc expect(got: seq[(string, int)], want: string) =
    let g = table(got)
    if g != want:
      emit "selfcheck FAILED: got '" & g & "' want '" & want & "'"
      quit(1)

  # The default mix at the default VORTEX_CONCURRENCY: 30 request-shaped workers
  # over 40/20/20 by largest remainder, with the two streaming slices pinned at
  # one each.
  expect(splitMix(32, parseMix("")),
    "requests=15 ws=8 sse=7 streamupload=1 streamdownload=1")
  # Exactly the slice count: the floor is all there is to hand out.
  expect(splitMix(5, parseMix("")),
    "requests=1 ws=1 sse=1 streamupload=1 streamdownload=1")
  # A dropped slice: 8 - 2 pinned = 6 shared 40/20 -> 4/2.
  expect(splitMix(8, parseMix("ws=0")),
    "requests=4 sse=2 streamupload=1 streamdownload=1")
  # Weights, not percentages: `requests=100` leaves ws and sse at their defaults,
  # so the request-shaped share is normalised over 100/20/20, not over 100.
  expect(splitMix(32, parseMix("requests=100")),
    "requests=22 ws=4 sse=4 streamupload=1 streamdownload=1")
  # Whitespace and an empty entry are tolerated exactly as the Python client's
  # `item.strip()` / `if not item: continue` tolerate them.
  expect(splitMix(32,
    parseMix(" requests=40 , , ws=20,sse=20,streamupload=10,streamdownload=10 ")),
    "requests=15 ws=8 sse=7 streamupload=1 streamdownload=1")
  # The streaming-only mix: nowhere to spend the rest of the budget, so the total
  # is the slice count and NOT `budget` (see splitMix).
  expect(splitMix(32, parseMix("requests=0,ws=0,sse=0")),
    "streamupload=1 streamdownload=1")
  # One request-shaped slice left alone takes the whole shared budget; the floor
  # arm must not then steal a worker from it.
  expect(splitMix(32, parseMix("ws=0,sse=0")),
    "requests=30 streamupload=1 streamdownload=1")
  # fmtMb's one-decimal arm under 10 MB, and the whole-MB arm at or above it.
  doAssert fmtMb(2 * mb) == "2.0MB"
  doAssert fmtMb(512 * 1024) == "0.5MB"
  doAssert fmtMb(16 * mb) == "16MB"
  # The generator and its digest are the cross-language contract the streaming
  # workloads verify against: the incremental Digest the download drains through
  # must agree with the whole-stream expectedSha1 the comparison uses, and the
  # generator itself must be byte i = i mod 256 across a period boundary.
  var d = initDigest()
  d.update(genChunk(0, 1024))
  d.update(genChunk(1024, 3072))
  doAssert d.hex() == expectedSha1(4096)
  doAssert genChunk(1, 3) == "\x01\x02\x03"
  doAssert genChunk(255, 2) == "\xff\x00"
  emit "selfcheck ok"
