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
import ./request
from ./conditional import evalPreconditions, ifRangeApplies,
                          pcProceed, pcNotModified, pcFailed

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

const httpDateFmt = "ddd, dd MMM yyyy HH:mm:ss 'GMT'"

proc httpDate(t: Time): string =
  t.utc.format(httpDateFmt)

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

proc readSlice(path: string, start, length: int): string =
  var f = open(path, fmRead)
  defer: f.close()
  if start > 0: f.setFilePos(start)
  result = newString(length)
  if length > 0:
    let n = f.readBuffer(addr result[0], length)
    result.setLen(n)

proc parseRange(hdr: string, size: int64): (bool, int64, int64) =
  ## Parse a single `bytes=start-end` range against `size`. Returns
  ## (satisfiable, start, endInclusive). Multiple ranges / malformed values
  ## return satisfiable=true with the full [0, size-1] (caller sends 200).
  if not hdr.startsWith("bytes="): return (true, 0, size - 1)
  let spec = hdr[6..^1]
  if ',' in spec: return (true, 0, size - 1)   # multi-range: serve full 200
  let dash = spec.find('-')
  if dash < 0: return (true, 0, size - 1)
  let startS = spec[0..<dash].strip()
  let endS = spec[dash+1..^1].strip()
  var s, e: int64
  try:
    if startS.len == 0:                        # suffix: last N bytes
      if endS.len == 0: return (true, 0, size - 1)
      let n = parseBiggestInt(endS)
      s = max(0'i64, size - n); e = size - 1
    else:
      s = parseBiggestInt(startS)
      e = if endS.len == 0: size - 1 else: parseBiggestInt(endS)
  except ValueError:
    return (true, 0, size - 1)
  if s > e or s >= size: return (false, 0, 0)  # unsatisfiable -> 416
  if e >= size: e = size - 1
  (true, s, e)

const
  fileStreamChunk = 128 * 1024      ## bytes per worker read hop
  fileStreamThreshold = 512 * 1024  ## stream full-file GETs larger than this

proc readInto(path: string, start: int, buf: pointer, length: int): int =
  ## Read up to `length` bytes at `start` directly into `buf` (a loop-owned pool
  ## buffer); returns bytes read. No allocation -- the read buffer IS the message.
  if buf == nil or length <= 0: return 0
  var f = open(path, fmRead)
  defer: f.close()
  if start > 0: f.setFilePos(start)
  result = f.readBuffer(buf, length)

proc readChunkTramp(req: Request, res: Response, data: string)
                   {.nimcall, gcsafe.} =
  ## Worker: read the next chunk into the pool buffer whose pointer rides in
  ## `data` ("path\0offset\0remaining\0bufptr"), then hand the buffer back. The
  ## worker never allocates the payload -- it fills a buffer the loop owns.
  let f = data.split('\0')
  var buf: pointer = nil
  if f.len >= 4:
    buf = cast[pointer](try: parseUInt(f[3]) except CatchableError: 0'u)
  if f.len < 4:
    emitFileChunk(res, buf, 0, "", cast[pointer](readChunkTramp), true); return
  let path = f[0]
  let off = try: parseBiggestInt(f[1]) except CatchableError: 0'i64
  let remaining = try: parseBiggestInt(f[2]) except CatchableError: 0'i64
  let want = int(min(int64(fileStreamChunk), remaining))
  var got = 0
  try: got = readInto(path, int(off), buf, want)
  except CatchableError: got = 0
  let nextRemaining = remaining - int64(got)
  let last = got == 0 or nextRemaining <= 0
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
      let (satisfiable, rs, re) = parseRange(rangeHdr, size)
      if not satisfiable:
        hdrs.add ("Content-Range", "bytes */" & $size)
        res.send(HttpCode(416), "", hdrs); return
      if not (rs == 0 and re == size - 1):
        s = rs; e = re; partial = true

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
    var first: string
    try: first = readSlice(real, int(startOff),
                           int(min(int64(fileStreamChunk), respLen)))
    except CatchableError: notFound(res); return
    let got = int64(first.len)
    let remaining = respLen - got
    let last = got == 0 or remaining <= 0
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
