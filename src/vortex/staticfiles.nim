## Static file serving. File I/O blocks, so a request is served on the worker
## pool (`req.blocking:` path) and the bytes go out through `res.send`, which is
## thread-safe and protocol-neutral (identical over HTTP/1.1, /2 and /3, plain
## or TLS). Supports conditional requests (ETag / Last-Modified -> 304), byte
## ranges (206 / 416), a MIME table, and traversal-safe path resolution.
##
## ```nim
## let r = newRouter()
## let assets = staticHandler("public")      # serve ./public
## r.get("/assets", assets)                  # /assets, /assets/ -> index
## r.get("/assets/*", assets)                # /assets/<path>
## # or serve one file from any handler (router-free):
## r.get("/favicon.ico", proc(req: Request, res: Response) {.gcsafe.} =
##   res.sendFile("public/favicon.ico"))
## ```
##
## Large full-file GETs are streamed from the worker pool in bounded chunks
## (memory stays flat regardless of file size) with Content-Length preserved;
## small files, ranges, and HEAD are read in one shot. sendfile(2) is
## intentionally not used -- it does not compose with TLS or the readiness loop.

import std/[os, times, strutils, uri, httpcore, options]
from std/posix import nil          # qualified: its open/close would shadow File's
from std/oserrors import osLastError
import ./request
from ./conditional import evalPreconditions, ifRangeApplies,
                          pcProceed, pcNotModified, pcFailed, httpDate,
                          parseRanges

type
  StaticOptions* = object
    index*: string          ## directory index file ("" disables; default index.html)
    cacheControl*: string   ## Cache-Control value ("" omits the header)
    etag*: bool             ## emit ETag and honor If-None-Match
    lastModified*: bool     ## emit Last-Modified and honor If-Modified-Since

proc staticOptions*(index = "index.html", cacheControl = "",
                    etag = true, lastModified = true): StaticOptions =
  StaticOptions(index: index, cacheControl: cacheControl,
                etag: etag, lastModified: lastModified)

# --- MIME ------------------------------------------------------------------

proc mimeType(path: string): string =
  ## Content-Type from the file extension; text types carry a charset.
  ## Unknown extensions fall back to application/octet-stream.
  let (_, _, extDot) = path.splitFile()
  let ext = (if extDot.len > 0 and extDot[0] == '.': extDot[1..^1] else: extDot).toLowerAscii
  case ext
  of "html", "htm": "text/html; charset=utf-8"
  of "css": "text/css; charset=utf-8"
  of "js", "mjs": "text/javascript; charset=utf-8"
  of "json": "application/json"
  of "map": "application/json"
  of "xml": "application/xml"
  of "txt", "text", "md": "text/plain; charset=utf-8"
  of "csv": "text/csv; charset=utf-8"
  of "svg": "image/svg+xml"
  of "png": "image/png"
  of "jpg", "jpeg": "image/jpeg"
  of "gif": "image/gif"
  of "webp": "image/webp"
  of "avif": "image/avif"
  of "ico": "image/x-icon"
  of "bmp": "image/bmp"
  of "woff": "font/woff"
  of "woff2": "font/woff2"
  of "ttf": "font/ttf"
  of "otf": "font/otf"
  of "eot": "application/vnd.ms-fontobject"
  of "wasm": "application/wasm"
  of "pdf": "application/pdf"
  of "mp4": "video/mp4"
  of "webm": "video/webm"
  of "ogg", "ogv": "video/ogg"
  of "mp3": "audio/mpeg"
  of "wav": "audio/wav"
  of "zip": "application/zip"
  of "gz", "gzip": "application/gzip"
  of "wasmmap": "application/json"
  else: "application/octet-stream"

# --- HTTP-date + validators ------------------------------------------------

proc makeEtag(size: int64, mtime: Time): string =
  ## Strong validator from size + mtime; opaque to the client.
  "\"" & $size & "-" & $mtime.toUnix & "\""

# Conditional-request evaluation (If-Match / If-None-Match / If-(Un)Modified-
# Since / If-Range) is shared with request.serveContent -- see conditional.nim.

# --- path safety -----------------------------------------------------------

proc resolveTail(raw: string): (bool, string) =
  ## Decode + normalize the wildcard tail into a relative path with no `.`/`..`
  ## segments. Returns (false, "") on any escape above the root, NUL byte, or
  ## bad percent-encoding. The router captures `*` raw (undecoded) precisely so
  ## an encoded `%2e%2e`/`%2f` is normalized here, not silently turned into path
  ## structure before we can reject it.
  let dec = try: decodeUrl(raw, decodePlus = false)
            except CatchableError: return (false, "")
  if '\0' in dec: return (false, "")
  var parts: seq[string]
  for seg in dec.split('/'):
    if seg.len == 0 or seg == ".": continue
    if seg == "..":
      if parts.len == 0: return (false, "")   # would escape above the root
      parts.setLen(parts.len - 1)
    else:
      parts.add seg
  (true, parts.join("/"))

# --- worker: stat, validate, range, read, send -----------------------------

proc notFound(res: Response) = res.send(Http404, "404 Not Found")

proc serverError(res: Response) = res.send(Http500, "500 Internal Server Error")

proc readAt(path: string, start: int64, buf: pointer, length: int): int
           {.raises: [IOError].} =
  ## Read `length` bytes of `path` at offset `start` into `buf` (a loop-owned
  ## pool buffer). No allocation -- the read buffer IS the message.
  ##
  ## Fills the buffer: `pread` is retried until `length` bytes are in, so a
  ## SHORT result means one thing only, end of file, and a failure raises. Both
  ## of those distinctions are load-bearing (#248-style truncation, class D of
  ## the stress soak). `read(2)` may legally return fewer bytes than asked for
  ## on a regular file, and the previous single buffered `readBuffer` call
  ## additionally RAISED on a short read whose stream had its error flag set --
  ## discarding the bytes it had already copied. Either way the caller saw 0 or a
  ## short count and could not tell "the file ended here" from "this read did not
  ## finish", so it reported the shortfall as end-of-body and closed a
  ## Content-Length-delimited response short of its declared length.
  if buf == nil or length <= 0: return 0
  let fd = posix.open(path.cstring, posix.O_RDONLY)
  if fd < 0: raise newException(IOError, "cannot open: " & path)
  try:
    let p = cast[ptr UncheckedArray[byte]](buf)
    while result < length:
      let n = posix.pread(fd, addr p[result], length - result,
                          posix.Off(start + int64(result)))
      if n > 0: result += n
      elif n == 0: break                             # genuine end of file
      elif cint(osLastError()) == posix.EINTR: continue
      else: raise newException(IOError, "read failed: " & path)
  finally:
    discard posix.close(fd)

proc readSlice(path: string, start, length: int): string =
  ## `length` bytes at `start`, short only at end of file (see readAt); a read
  ## failure raises IOError, which every caller answers with a status code.
  result = newString(length)
  if length > 0:
    let n = readAt(path, int64(start), addr result[0], length)
    result.setLen(n)

const
  fileStreamChunk = 256 * 1024      ## bytes per worker read hop. Larger chunks
                                    ## amortize the per-hop open/lseek/close
                                    ## (readAt reopens each hop): a 1 GiB file
                                    ## is ~4K hops, not ~8K (issue #274). MUST be
                                    ## <= connection.fileChunkCap (the pool
                                    ## buffer each hop fills); keep the two equal.
  fileStreamThreshold = 512 * 1024  ## stream full-file GETs larger than this

proc readChunkTramp(req: Request, res: Response, data: string)
                   {.nimcall, gcsafe.} =
  ## Worker: read the next chunk into the pool buffer whose pointer rides in
  ## `data` ("path\0offset\0remaining\0bufptr"), then hand the buffer back. The
  ## worker never allocates the payload -- it fills a buffer the loop owns.
  ##
  ## A hop that cannot deliver its `want` bytes reports `fileChunkFailed`, which
  ## makes the loop ABORT the response (see request.applyFileChunk). It must
  ## never report the shortfall as the end of the body: the head is already on
  ## the wire with the Content-Length taken from stat, so a clean terminator here
  ## claims a complete response that is short of its declared length -- over
  ## HTTP/2 a client sees END_STREAM and raises (stress soak class D), and over
  ## HTTP/1 keep-alive framing desyncs.
  let f = data.split('\0')
  var buf: pointer = nil
  if f.len >= 4:
    buf = cast[pointer](try: parseUInt(f[3]) except CatchableError: 0'u)
  template giveUp =
    emitFileChunk(res, buf, fileChunkFailed, "",
                  cast[pointer](readChunkTramp), true)
    return
  if f.len < 4: giveUp
  let path = f[0]
  let off = try: parseBiggestInt(f[1]) except CatchableError: -1'i64
  let remaining = try: parseBiggestInt(f[2]) except CatchableError: -1'i64
  if off < 0 or remaining <= 0: giveUp     # a hop is dispatched only with bytes
                                           # left to read; anything else is a
                                           # mangled continuation, not an EOF
  let want = int(min(int64(fileStreamChunk), remaining))
  var got = -1
  try: got = readAt(path, off, buf, want)
  except CatchableError: got = -1
  if got < want: giveUp                    # failed, or the file shrank under us
  let nextRemaining = remaining - int64(got)
  let last = nextRemaining <= 0
  let nextRead = if last: ""
                 else: path & '\0' & $(off + int64(got)) & '\0' & $nextRemaining
  emitFileChunk(res, buf, got, nextRead, cast[pointer](readChunkTramp), last)

proc serveResolved(req: Request, res: Response, data: string)
                  {.nimcall, gcsafe.} =
  ## Worker body: `data` packs candidate\0rootReal\0index\0cacheControl\0flags
  ## (flags = <etag><lastModified> as '0'/'1'). rootReal "" = trusted path
  ## (sendFile), skip the containment check.
  let f = data.split('\0')
  if f.len != 5: notFound(res); return
  let candidate = f[0]
  let rootReal = f[1]
  let index = f[2]
  let cacheControl = f[3]
  let useEtag = f[4].len >= 1 and f[4][0] == '1'
  let useLastMod = f[4].len >= 2 and f[4][1] == '1'

  # Resolve symlinks + normalize; missing path -> 404. Containment closes any
  # symlink that points outside the root.
  var real: string
  try: real = expandFilename(candidate)
  except CatchableError: notFound(res); return
  if rootReal.len > 0 and real != rootReal and not real.isRelativeTo(rootReal):
    notFound(res); return

  var info: FileInfo
  try: info = getFileInfo(real)
  except CatchableError: notFound(res); return
  if info.kind == pcDir:
    if index.len == 0: notFound(res); return
    real = real / index
    # Re-resolve + re-check containment (R8): the index entry may itself be a
    # symlink pointing outside the root. Without this, getFileInfo would follow
    # it and serve a file outside the served directory.
    if rootReal.len > 0:
      try: real = expandFilename(real)
      except CatchableError: notFound(res); return
      if real != rootReal and not real.isRelativeTo(rootReal):
        notFound(res); return
    try: info = getFileInfo(real)
    except CatchableError: notFound(res); return
    if info.kind == pcDir: notFound(res); return

  let size = info.size
  let mtime = info.lastWriteTime
  let etag = makeEtag(size, mtime)
  let lastMod = httpDate(mtime)

  var hdrs: seq[(string, string)]
  hdrs.add ("Accept-Ranges", "bytes")
  if useEtag: hdrs.add ("ETag", etag)
  if useLastMod: hdrs.add ("Last-Modified", lastMod)
  if cacheControl.len > 0: hdrs.add ("Cache-Control", cacheControl)

  # Preconditions (RFC 9110 13.2.2): If-Match / If-Unmodified-Since -> 412, then
  # If-None-Match / If-Modified-Since -> 304. Shared with request.serveContent.
  let condEtag = if useEtag: etag else: ""
  let condLastMod = if useLastMod: some(mtime) else: none(Time)
  case evalPreconditions(req.header("if-match"), req.header("if-none-match"),
      req.header("if-modified-since"), req.header("if-unmodified-since"),
      condEtag, condLastMod, req.method in {HttpGet, HttpHead})
  of pcNotModified: res.send(Http304, "", hdrs); return
  of pcFailed:      res.send(HttpCode(412), "", hdrs); return
  of pcProceed:     discard

  # Range (single). If-Range gates it: only apply when the validator still
  # matches, else serve the full 200. (Multiple ranges are served as full 200
  # here; request.serveContent emits multipart/byteranges for in-memory bodies.)
  var s = 0'i64
  var e = size - 1
  var partial = false
  let rangeHdr = req.header("range")
  if rangeHdr.len > 0 and size > 0:
    if ifRangeApplies(req.header("if-range"), condEtag, condLastMod):
      let (satisfiable, ranges) = parseRanges(rangeHdr, size)
      if not satisfiable:
        hdrs.add ("Content-Range", "bytes */" & $size)
        res.send(HttpCode(416), "", hdrs); return
      # parseRanges already collapses a whole-body single range to `@[]` (200);
      # a genuine multi-range set is served as a full 200 here (streaming emits
      # one window -- request.serveContent handles multipart/byteranges).
      if ranges.len == 1:
        s = ranges[0].start; e = ranges[0].finish; partial = true

  let mime = mimeType(real)
  # The byte window to serve: the requested range, or the whole file.
  let startOff = if partial: s else: 0'i64
  let respLen  = if partial: e - s + 1 else: size
  let status   = if partial: 206 else: 200
  if partial:
    hdrs.add ("Content-Range", "bytes " & $s & "-" & $e & "/" & $size)

  # HEAD: report the headers (with the Content-Length a GET would return) and no
  # body -- never read the file. The response codec drops the body for HEAD, so
  # this streams zero bytes and just carries the right Content-Length/-Range.
  if req.method == HttpHead:
    emitFileStart(res, status, mime, hdrs, respLen, "", "",
                  cast[pointer](readChunkTramp), true)
    return

  # Stream any large window -- full file OR a large range -- so the whole thing
  # never sits in memory at once (a partial range is NOT inherently small: e.g.
  # `Range: bytes=1-` on a multi-GB file). Only small responses are buffered.
  if respLen > fileStreamThreshold:
    let want = int(min(int64(fileStreamChunk), respLen))
    var first: string
    try: first = readSlice(real, int(startOff), want)
    except CatchableError: notFound(res); return
    if first.len < want:
      # stat sized the window at respLen but the file cannot supply even the
      # first `want` bytes of it, so the Content-Length about to be declared
      # would be a lie. Nothing has been sent yet -- answer with a status code
      # rather than opening a body that can only end short.
      serverError(res); return
    let got = int64(first.len)
    let remaining = respLen - got
    let last = remaining <= 0
    let nextRead = if last: ""
                   else: real & '\0' & $(startOff + got) & '\0' & $remaining
    emitFileStart(res, status, mime, hdrs, respLen, first, nextRead,
                  cast[pointer](readChunkTramp), last)
    return

  var body: string
  try:
    body = if partial: readSlice(real, int(startOff), int(respLen))
           else: readFile(real)
  except CatchableError: notFound(res); return
  hdrs.add ("Content-Type", mime)
  res.send(HttpCode(status), body, hdrs)

proc pack(candidate, rootReal: string, opts: StaticOptions): string =
  candidate & '\0' & rootReal & '\0' & opts.index & '\0' & opts.cacheControl &
    '\0' & (if opts.etag: "1" else: "0") & (if opts.lastModified: "1" else: "0")

# --- public API ------------------------------------------------------------

proc sendFile*(res: Response, path: string, opts = staticOptions()) =
  ## Serve one specific file (a trusted path -- no traversal resolution) on the
  ## worker pool. Honors conditional requests and ranges. Call from a handler
  ## (router-free): `res.sendFile("public/index.html")`. Request and Response
  ## are the same handle; the worker rebuilds both from it.
  dispatchBlockingData(
    Request(core: res.core, fd: res.fd, gen: res.gen, stream: res.stream),
    serveResolved, pack(path, "", opts))

proc staticHandler*(rootDir: string, opts = staticOptions()): RequestHandler =
  ## A handler serving files under `rootDir`, keyed off the route's trailing
  ## `*` wildcard (`req.param("*")`). Register it on a `/prefix/*` route (and,
  ## for the directory index, the bare `/prefix`):
  ##
  ## ```nim
  ## let h = staticHandler("public")
  ## r.get("/assets", h)       # /assets and /assets/ -> index
  ## r.get("/assets/*", h)     # /assets/<path>
  ## ```
  ##
  ## `rootDir` is resolved once here (at setup), and the resolved path bounds
  ## every request (symlinks included), so traversal cannot escape it.
  let rootReal =
    try: expandFilename(rootDir)
    except CatchableError: rootDir
  proc (req: Request, res: Response) {.gcsafe.} =
    let (ok, rel) = resolveTail(req.param("*"))
    if not ok:
      res.send(Http404, "404 Not Found")
      return
    let candidate = if rel.len == 0: rootReal else: rootReal / rel
    dispatchBlockingData(req, serveResolved, pack(candidate, rootReal, opts))
