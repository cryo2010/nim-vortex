## Shared HTTP conditional-request + byte-range logic (RFC 9110 13 preconditions,
## RFC 9110 8.8 validators, RFC 9110 14 ranges). Pure and allocation-light so it
## is unit-testable and reusable: `request.serveContent` (in-memory bodies) uses
## all of it; `staticfiles` uses the date/etag/precondition parts.

import std/[strutils, times, options]

const httpDateFmt* = "ddd, dd MMM yyyy HH:mm:ss 'GMT'"
  ## RFC 7231 IMF-fixdate; the only format we emit and the primary one we parse.

proc httpDate*(t: Time): string = t.utc.format(httpDateFmt)

proc parseHttpDate*(s: string): Option[Time] =
  ## Parse an IMF-fixdate (the form a well-behaved client echoes back from our
  ## Last-Modified). Returns none on anything unparseable.
  try: some(s.strip().parse(httpDateFmt, utc()).toTime)
  except CatchableError: none(Time)

proc etagIn*(headerVal, etag: string, strong: bool): bool =
  ## True if `etag` matches any entry in a comma-separated If-Match /
  ## If-None-Match list (or the list is "*"). `strong` selects the comparison
  ## (RFC 9110 8.8.3.2): strong forbids a weak validator on either side (used by
  ## If-Match and If-Range); weak compares opaque-tag values (If-None-Match).
  let oursWeak = etag.startsWith("W/")
  let oursTag = if oursWeak: etag[2..^1].strip() else: etag
  for raw in headerVal.split(','):
    var t = raw.strip()
    if t == "*": return true
    let theirsWeak = t.startsWith("W/")
    if theirsWeak: t = t[2..^1].strip()
    if strong and (theirsWeak or oursWeak): continue   # strong: no weak tag
    if t == oursTag: return true
  false

type Precondition* = enum
  pcProceed       ## no precondition blocks the request; serve normally
  pcNotModified   ## respond 304 (keep validators, no body)
  pcFailed        ## respond 412 Precondition Failed

proc evalPreconditions*(ifMatch, ifNoneMatch, ifModSince, ifUnmodSince, etag: string,
                        lastMod: Option[Time], isGetHead: bool): Precondition =
  ## Evaluate conditional-request headers in RFC 9110 13.2.2 precedence:
  ## If-Match, then If-Unmodified-Since, then If-None-Match, then
  ## If-Modified-Since. `etag`/`lastMod` are the resource's current validators
  ## ("" / none when absent). `isGetHead` gates the not-modified (304) outcomes;
  ## a failing If-None-Match on a non-GET/HEAD is 412, not 304.
  if ifMatch.len > 0:
    if not (etag.len > 0 and etagIn(ifMatch, etag, strong = true)):
      return pcFailed
  elif ifUnmodSince.len > 0 and lastMod.isSome:
    let t = parseHttpDate(ifUnmodSince)
    if t.isSome and lastMod.get.toUnix > t.get.toUnix:
      return pcFailed
  if ifNoneMatch.len > 0:
    if etag.len > 0 and etagIn(ifNoneMatch, etag, strong = false):
      return (if isGetHead: pcNotModified else: pcFailed)
  elif isGetHead and ifModSince.len > 0 and lastMod.isSome:
    let t = parseHttpDate(ifModSince)
    if t.isSome and lastMod.get.toUnix <= t.get.toUnix:
      return pcNotModified
  pcProceed

proc ifRangeApplies*(ifRange, etag: string, lastMod: Option[Time]): bool =
  ## RFC 9110 13.1.5: honor Range only if the If-Range validator still matches.
  ## An entity-tag If-Range uses a *strong* comparison; a date uses exact
  ## equality against Last-Modified. Empty If-Range -> always apply.
  if ifRange.len == 0: return true
  if ifRange[0] == '"' or ifRange.startsWith("W/"):
    return etag.len > 0 and etagIn(ifRange, etag, strong = true)
  let t = parseHttpDate(ifRange)
  t.isSome and lastMod.isSome and t.get.toUnix == lastMod.get.toUnix

type ByteRange* = tuple[start, finish: int64]   ## inclusive [start, finish]

const maxRanges = 64
  ## Cap on the number of ranges honored (a huge range set is a small-DoS
  ## amplifier: many 206 parts from one request). Beyond this, serve the whole.

proc parseRanges*(hdr: string, size: int64): (bool, seq[ByteRange]) =
  ## Parse a `bytes=` Range header against a known `size`. Returns
  ## (satisfiable, ranges):
  ##  - satisfiable=false, empty  -> 416 (every range was out of bounds)
  ##  - satisfiable=true, empty   -> ignore Range, serve the whole 200
  ##  - satisfiable=true, ranges  -> 206 (one range) or multipart (several)
  ## Unsupported/oversized/other-unit specs fall back to the whole (200).
  if not hdr.startsWith("bytes=") or size <= 0: return (true, @[])
  let spec = hdr[6..^1]
  var ranges: seq[ByteRange]
  var sawUnsatisfiable = false
  var n = 0
  for part in spec.split(','):
    let p = part.strip()
    if p.len == 0: continue
    inc n
    if n > maxRanges: return (true, @[])          # too many: serve whole
    let dash = p.find('-')
    if dash < 0: return (true, @[])               # malformed: serve whole
    let startS = p[0..<dash].strip()
    let endS = p[dash+1..^1].strip()
    var s, e: int64
    try:
      if startS.len == 0:                          # -N : final N bytes
        if endS.len == 0: return (true, @[])
        let nlast = parseBiggestInt(endS)
        if nlast <= 0: sawUnsatisfiable = true; continue
        s = max(0'i64, size - nlast); e = size - 1
      else:
        s = parseBiggestInt(startS)
        e = if endS.len == 0: size - 1 else: parseBiggestInt(endS)
    except ValueError:
      return (true, @[])                           # malformed: serve whole
    if s > e or s >= size: sawUnsatisfiable = true; continue  # this one 416s
    if e >= size: e = size - 1
    ranges.add (s, e)
  if ranges.len == 0:
    return (if sawUnsatisfiable: (false, @[]) else: (true, @[]))
  # A single range covering the whole body is just a 200.
  if ranges.len == 1 and ranges[0].start == 0 and ranges[0].finish == size - 1:
    return (true, @[])
  (true, ranges)
