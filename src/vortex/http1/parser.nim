## Incremental, zero-copy HTTP/1.1 request parser.
##
## The parser scans a connection's receive buffer in place and records
## index/length slices for the request line and headers; nothing is copied
## on the fast path. Bodies with Content-Length are exposed as a slice of
## the receive buffer once fully buffered; chunked bodies are decoded into
## a caller-supplied buffer (reused across requests).
##
## `parse` is resumable: call it again with the same buffer after more
## bytes arrive. On `prError`, `errorStatus` holds the HTTP status to send.

import std/httpcore

const tokenDelims = {'"', '(', ')', ',', '/', ':', ';', '<', '=', '>',
                     '?', '@', '[', '\\', ']', '{', '}'}
  ## RFC 9110 5.6.2 token separators: bytes that may not appear in a field
  ## name (VCHARs outside this set are valid token characters).

type
  ParseResult* = enum
    prNeedMore   ## incomplete input, read more bytes and call again
    prComplete   ## a full request (incl. body) is available
    prError      ## protocol error; respond with errorStatus and close

  ParsePhase = enum
    ppReqLine, ppHeaders, ppBody,
    ppChunkSize, ppChunkData, ppChunkCRLF, ppTrailers,
    ppComplete, ppError

  HeaderSlice* = object
    nameStart*, nameLen*: int32
    valStart*, valLen*: int32

  ParserLimits* = object
    maxHeaderSize*: int
    maxHeaderCount*: int
    maxBodySize*: int

  RequestParser* = object
    phase: ParsePhase
    reqStart*: int            ## buffer offset where this request begins
    pos*: int                 ## scan position (end of consumed input)
    httpMethod*: HttpMethod
    pathStart*, pathLen*: int32
    minor*: int8              ## HTTP/1.<minor>
    headers*: seq[HeaderSlice]
    contentLength*: int64     ## -1 when absent
    chunked*: bool
    keepAlive*: bool
    expectContinue*: bool
    bodyStart*: int           ## valid when not chunked
    bodyLen*: int             ## non-chunked body length
    chunkRemaining: int64
    seenContentLength: bool
    seenHost: bool
    errorStatus*: HttpCode

proc c_memchr(s: pointer, c: cint, n: csize_t): pointer
  {.importc: "memchr", header: "<string.h>".}

proc findByte(buf: openArray[char], start, endPos: int, ch: char): int =
  ## Index of `ch` in buf[start ..< endPos], or -1.
  if start >= endPos: return -1
  let p = c_memchr(unsafeAddr buf[start], cint(ch), csize_t(endPos - start))
  if p == nil: -1
  else: cast[int](p) -% cast[int](unsafeAddr buf[0])

proc toLowerA(c: char): char {.inline.} =
  if c in 'A'..'Z': char(uint8(c) or 0x20'u8) else: c

proc ieqLit(buf: openArray[char], start, len: int, lit: static string): bool =
  ## Case-insensitive equality against a lowercase literal, no allocation.
  if len != lit.len: return false
  for i in 0 ..< lit.len:
    if toLowerA(buf[start + i]) != lit[i]: return false
  true

proc hasToken(buf: openArray[char], start, len: int, token: static string): bool =
  ## True if a comma-separated list value contains `token` (lowercase literal).
  var i = start
  let last = start + len
  while i < last:
    while i < last and buf[i] in {' ', '\t', ','}: inc i
    var j = i
    while j < last and buf[j] notin {' ', '\t', ','}: inc j
    if ieqLit(buf, i, j - i, token): return true
    i = j
  false

proc inBody*(p: RequestParser): bool {.inline.} =
  ## True once the request head is parsed and body bytes are pending.
  p.phase in {ppBody, ppChunkSize, ppChunkData, ppChunkCRLF, ppTrailers}

proc started*(p: RequestParser): bool {.inline.} =
  ## True if any bytes of the current request have been consumed.
  p.phase != ppReqLine or p.pos != p.reqStart

proc reset*(p: var RequestParser, reqStart: int) =
  ## Prepare for the next request starting at `reqStart` in the buffer.
  p.phase = ppReqLine
  p.reqStart = reqStart
  p.pos = reqStart
  p.pathStart = 0
  p.pathLen = 0
  p.minor = 1
  p.headers.setLen(0)
  p.contentLength = -1
  p.chunked = false
  p.keepAlive = true
  p.expectContinue = false
  p.bodyStart = 0
  p.bodyLen = 0
  p.chunkRemaining = 0
  p.seenContentLength = false
  p.seenHost = false

proc fail(p: var RequestParser, status: HttpCode): ParseResult =
  p.phase = ppError
  p.errorStatus = status
  prError

proc parseMethod(p: var RequestParser, buf: openArray[char],
                 start, len: int): bool =
  # Methods are case-sensitive per RFC, but ieqLit over the exact literal is
  # fine because clients send them uppercase; the length check comes first.
  if len == 3 and buf[start] == 'G': p.httpMethod = HttpGet; return true
  if len == 4 and buf[start] == 'P' and buf[start+1] == 'O':
    p.httpMethod = HttpPost; return true
  case len
  of 3:
    if ieqLit(buf, start, len, "put"): p.httpMethod = HttpPut; return true
  of 4:
    if ieqLit(buf, start, len, "head"): p.httpMethod = HttpHead; return true
  of 5:
    if ieqLit(buf, start, len, "patch"): p.httpMethod = HttpPatch; return true
    if ieqLit(buf, start, len, "trace"): p.httpMethod = HttpTrace; return true
  of 6:
    if ieqLit(buf, start, len, "delete"): p.httpMethod = HttpDelete; return true
  of 7:
    if ieqLit(buf, start, len, "options"): p.httpMethod = HttpOptions; return true
    if ieqLit(buf, start, len, "connect"): p.httpMethod = HttpConnect; return true
  else: discard
  false

proc parseReqLine(p: var RequestParser, buf: openArray[char],
                  lineEnd: int): ParseResult =
  # buf[p.pos ..< lineEnd] is the request line without CRLF.
  let sp1 = findByte(buf, p.pos, lineEnd, ' ')
  if sp1 < 0: return p.fail(Http400)
  if not p.parseMethod(buf, p.pos, sp1 - p.pos): return p.fail(Http501)
  let sp2 = findByte(buf, sp1 + 1, lineEnd, ' ')
  if sp2 < 0 or sp2 == sp1 + 1: return p.fail(Http400)
  p.pathStart = int32(sp1 + 1)
  p.pathLen = int32(sp2 - sp1 - 1)
  # Version: exactly "HTTP/1.0" or "HTTP/1.1"
  let vs = sp2 + 1
  if lineEnd - vs != 8 or not (buf[vs] == 'H' and buf[vs+1] == 'T' and
      buf[vs+2] == 'T' and buf[vs+3] == 'P' and buf[vs+4] == '/' and
      buf[vs+6] == '.'):
    return p.fail(Http400)
  if buf[vs+5] != '1': return p.fail(Http505)
  case buf[vs+7]
  of '0':
    p.minor = 0
    p.keepAlive = false
  of '1':
    p.minor = 1
    p.keepAlive = true
  else:
    return p.fail(Http505)
  p.phase = ppHeaders
  prNeedMore

proc processHeader(p: var RequestParser, buf: openArray[char],
                   h: HeaderSlice): ParseResult =
  ## Extract connection-management headers as they are parsed.
  if ieqLit(buf, h.nameStart, h.nameLen, "content-length"):
    if p.seenContentLength or p.chunked: return p.fail(Http400)
    var v: int64 = 0
    if h.valLen == 0: return p.fail(Http400)
    for i in h.valStart ..< h.valStart + h.valLen:
      let c = buf[i]
      if c notin '0'..'9': return p.fail(Http400)
      if v > (int64.high - 9) div 10: return p.fail(Http413)
      v = v * 10 + int64(uint8(c) - uint8('0'))
    p.contentLength = v
    p.seenContentLength = true
  elif ieqLit(buf, h.nameStart, h.nameLen, "transfer-encoding"):
    if p.seenContentLength: return p.fail(Http400)
    # Transfer-Encoding is an HTTP/1.1 feature; an HTTP/1.0 request carrying
    # it is treated as faulty framing (RFC 9112 6.1), a smuggling guard.
    if p.minor == 0: return p.fail(Http400)
    # Walk the comma-separated transfer-coding list. chunked (the only coding
    # we decode) must be the final one; a non-final chunked leaves the body
    # length unreliable -> 400 (RFC 9112 6.1). Any other coding we do not
    # understand -> 501.
    var i = h.valStart
    let last = h.valStart + h.valLen
    var codings = 0
    var prevChunked = false
    var lastChunked = false
    var chunkedNonFinal = false
    while i < last:
      while i < last and buf[i] in {' ', '\t', ','}: inc i     # skip OWS/commas
      if i >= last: break
      let ns = i
      while i < last and buf[i] notin {' ', '\t', ',', ';'}: inc i
      let isChunked = ieqLit(buf, ns, i - ns, "chunked")
      if prevChunked: chunkedNonFinal = true    # a coding follows a chunked
      prevChunked = isChunked
      lastChunked = isChunked
      inc codings
      while i < last and buf[i] != ',': inc i    # skip parameters to next comma
    if codings == 0 or chunkedNonFinal: return p.fail(Http400)
    if lastChunked and codings == 1:
      p.chunked = true
    else:
      return p.fail(Http501)                     # unknown / unsupported coding
  elif ieqLit(buf, h.nameStart, h.nameLen, "connection"):
    if hasToken(buf, h.valStart, h.valLen, "close"):
      p.keepAlive = false
    elif hasToken(buf, h.valStart, h.valLen, "keep-alive"):
      p.keepAlive = true
  elif ieqLit(buf, h.nameStart, h.nameLen, "expect"):
    if ieqLit(buf, h.valStart, h.valLen, "100-continue"):
      p.expectContinue = true
  elif ieqLit(buf, h.nameStart, h.nameLen, "host"):
    # RFC 9112 3.2: reject more than one Host field (smuggling guard).
    if p.seenHost: return p.fail(Http400)
    p.seenHost = true
    # The Host value is a uri-host[:port] (RFC 9112 3.2 / 9110 4): whitespace
    # or controls make it invalid.
    for i in h.valStart ..< h.valStart + h.valLen:
      if uint8(buf[i]) <= 0x20'u8 or uint8(buf[i]) == 0x7f'u8:
        return p.fail(Http400)
  prNeedMore

proc parseHeaderLine(p: var RequestParser, buf: openArray[char],
                     lineEnd: int, limits: ParserLimits): ParseResult =
  if p.headers.len >= limits.maxHeaderCount: return p.fail(Http431)
  let colon = findByte(buf, p.pos, lineEnd, ':')
  if colon < 0 or colon == p.pos: return p.fail(Http400)
  # Field name must be a token (RFC 9110 5.1 / 5.6.2). Rejecting everything
  # outside the token set closes smuggling via a bare CR, TAB, NUL, or space
  # embedded in the name (a downstream proxy may re-split such a "name").
  for i in p.pos ..< colon:
    let b = uint8(buf[i])
    if b <= 0x20'u8 or b >= 0x7f'u8 or char(b) in tokenDelims:
      return p.fail(Http400)
  var vs = colon + 1
  while vs < lineEnd and buf[vs] in {' ', '\t'}: inc vs
  var ve = lineEnd
  while ve > vs and buf[ve-1] in {' ', '\t'}: dec ve
  # Field values must not contain control characters (RFC 9110 5.5): a NUL,
  # a bare CR, or other C0 control is a request-smuggling / header-injection
  # vector. HTAB is allowed; obs-text (0x80+) is opaque and permitted.
  for i in vs ..< ve:
    let b = uint8(buf[i])
    if (b < 0x20'u8 and b != 0x09'u8) or b == 0x7f'u8:
      return p.fail(Http400)
  let h = HeaderSlice(
    nameStart: int32(p.pos), nameLen: int32(colon - p.pos),
    valStart: int32(vs), valLen: int32(ve - vs))
  p.headers.add h
  p.processHeader(buf, h)

proc parse*(p: var RequestParser, buf: openArray[char], dataEnd: int,
            limits: ParserLimits, chunkBody: var string): ParseResult =
  ## Advance the parser over buf[p.pos ..< dataEnd]. Chunked body bytes are
  ## appended to `chunkBody`; caller must clear it between requests.
  while true:
    case p.phase
    of ppReqLine, ppHeaders:
      let nl = findByte(buf, p.pos, dataEnd, '\n')
      if nl < 0:
        if dataEnd - p.reqStart > limits.maxHeaderSize:
          return p.fail(if p.phase == ppReqLine: Http414 else: Http431)
        return prNeedMore
      if nl == p.pos or buf[nl-1] != '\r': return p.fail(Http400)
      let lineEnd = nl - 1   # exclusive end, before CR
      if nl - p.reqStart > limits.maxHeaderSize:
        return p.fail(if p.phase == ppReqLine: Http414 else: Http431)
      if p.phase == ppReqLine:
        if lineEnd == p.pos:
          # Tolerate a stray CRLF before the request line (RFC 9112 2.2).
          p.pos = nl + 1
          p.reqStart = p.pos
          continue
        let res = p.parseReqLine(buf, lineEnd)
        if res == prError: return res
      else:
        if lineEnd == p.pos:
          # Blank line: headers finished.
          # RFC 9112 3.2: an HTTP/1.1 request MUST carry a Host field.
          if p.minor == 1 and not p.seenHost:
            return p.fail(Http400)
          p.pos = nl + 1
          if p.chunked:
            p.phase = ppChunkSize
          elif p.contentLength > 0:
            if p.contentLength > int64(limits.maxBodySize):
              return p.fail(Http413)
            p.bodyStart = p.pos
            p.bodyLen = int(p.contentLength)
            p.phase = ppBody
          else:
            p.bodyStart = p.pos
            p.bodyLen = 0
            p.phase = ppComplete
            return prComplete
          continue
        let res = p.parseHeaderLine(buf, lineEnd, limits)
        if res == prError: return res
      p.pos = nl + 1

    of ppBody:
      let have = dataEnd - p.bodyStart
      if have < p.bodyLen: return prNeedMore
      p.pos = p.bodyStart + p.bodyLen
      p.phase = ppComplete
      return prComplete

    of ppChunkSize:
      let nl = findByte(buf, p.pos, dataEnd, '\n')
      if nl < 0:
        if dataEnd - p.pos > 128: return p.fail(Http400)
        return prNeedMore
      if nl == p.pos or buf[nl-1] != '\r': return p.fail(Http400)
      var size: int64 = 0
      var i = p.pos
      var digits = 0
      while i < nl - 1:
        let c = buf[i]
        var d: int64
        if c in '0'..'9': d = int64(uint8(c) - uint8('0'))
        elif c in 'a'..'f': d = int64(uint8(c) - uint8('a') + 10)
        elif c in 'A'..'F': d = int64(uint8(c) - uint8('A') + 10)
        elif c == ';': break   # chunk extensions: ignored
        else: return p.fail(Http400)
        if size > (int64.high - 15) shr 4: return p.fail(Http413)
        size = size shl 4 or d
        inc digits
        inc i
      if digits == 0: return p.fail(Http400)
      if int64(chunkBody.len) + size > int64(limits.maxBodySize):
        return p.fail(Http413)
      p.pos = nl + 1
      p.chunkRemaining = size
      p.phase = if size == 0: ppTrailers else: ppChunkData

    of ppChunkData:
      let avail = dataEnd - p.pos
      if avail <= 0: return prNeedMore
      let take = int(min(int64(avail), p.chunkRemaining))
      let oldLen = chunkBody.len
      chunkBody.setLen(oldLen + take)
      copyMem(addr chunkBody[oldLen], unsafeAddr buf[p.pos], take)
      p.pos += take
      p.chunkRemaining -= int64(take)
      if p.chunkRemaining == 0:
        p.phase = ppChunkCRLF
      else:
        return prNeedMore

    of ppChunkCRLF:
      if dataEnd - p.pos < 2: return prNeedMore
      if buf[p.pos] != '\r' or buf[p.pos+1] != '\n': return p.fail(Http400)
      p.pos += 2
      p.phase = ppChunkSize

    of ppTrailers:
      let nl = findByte(buf, p.pos, dataEnd, '\n')
      if nl < 0:
        if dataEnd - p.pos > limits.maxHeaderSize: return p.fail(Http431)
        return prNeedMore
      if nl == p.pos or buf[nl-1] != '\r': return p.fail(Http400)
      let empty = nl - 1 == p.pos
      p.pos = nl + 1
      if empty:
        p.phase = ppComplete
        return prComplete
      # Trailer fields are discarded.

    of ppComplete:
      return prComplete
    of ppError:
      return prError
