## Shared header-field validation rules for the h1, h2, and h3 request paths.
## A leaf module (no vortex imports) so the h1 parser, the h2 codec, and the
## h3 backend all share one token-delimiter set and one pseudo-header state
## machine instead of drifting mirrors (a divergence here is a smuggling
## vector: bytes one protocol accepts that another would reject).

const tokenDelims* = {'"', '(', ')', ',', '/', ':', ';', '<', '=', '>',
                      '?', '@', '[', '\\', ']', '{', '}'}
  ## RFC 9110 5.6.2 token separators: bytes that may not appear in a field
  ## name (VCHARs outside this set are valid token characters).

func eqIgnoreAsciiCase*(s: string, lit: static string): bool =
  ## Case-insensitive ASCII equality against a lowercase literal, allocating
  ## nothing (unlike `s.toLowerAscii == lit`). The length guard short-circuits
  ## the common non-match on the response header hot path. `lit` must already be
  ## lowercase (a compile-time literal).
  if s.len != lit.len: return false
  for i in 0 ..< lit.len:
    var c = s[i]
    if c in 'A'..'Z': c = char(uint8(c) or 0x20'u8)
    if c != lit[i]: return false
  true

func isLowerAscii*(s: string): bool =
  ## True when `s` contains no ASCII uppercase letter, i.e. it is already in
  ## HTTP/2 lowercase wire form and needs no `toLowerAscii` copy.
  for c in s:
    if c in 'A'..'Z': return false
  true

func validFieldValue*(val: string): bool =
  ## RFC 9113 8.2.1 / RFC 9114 4.1.2: no field (pseudo or regular) may carry
  ## NUL, CR, or LF in its value -- a header-injection / smuggling vector if
  ## reflected or proxied to h1. The strict h1 parser rejects these bytes
  ## outright. A value that starts or ends with SP or HTAB is also malformed.
  for ch in val:
    let b = uint8(ch)
    if b == 0x00'u8 or b == 0x0a'u8 or b == 0x0d'u8: return false
  if val.len > 0:
    let f = uint8(val[0])
    let l = uint8(val[^1])
    if f == 0x20'u8 or f == 0x09'u8 or l == 0x20'u8 or l == 0x09'u8:
      return false                             # leading/trailing SP/HTAB (#240.7)
  true

func isKnownMethod*(m: string): bool =
  ## An exact-match check against the HTTP methods this server can route
  ## (std/httpcore's HttpMethod set). Unknown or mis-cased methods have no
  ## handler and must NOT silently fall back to GET: that lets `PURGE` (or a
  ## method carrying a space) execute the GET handler, a method-ACL-bypass
  ## differential with the h1 parser, which 501s them (#240.4).
  case m
  of "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE",
     "CONNECT": true
  else: false

func validFieldName*(name: string): bool =
  ## RFC 9113 8.2.1 / RFC 9114 4.2: a regular field name must be a valid
  ## lowercase token; uppercase, controls, or separators make it malformed
  ## (mirrors the h1 parser's token check so h2/h3 cannot smuggle a name h1
  ## would reject).
  for ch in name:
    let b = uint8(ch)
    if ch in 'A'..'Z' or b <= 0x20'u8 or b >= 0x7f'u8 or ch in tokenDelims:
      return false
  true

type ContentLengthResult* = enum
  clOk          ## parsed into the out-param
  clMalformed   ## empty, or not 1*DIGIT (-> 400 / stream error)
  clOverflow    ## in-grammar but exceeds int64 (h1 maps this to 413)
  clConflict    ## valid but differs from a previously-seen content-length

func parseContentLength*(val: openArray[char], prev: int64,
                         value: var int64): ContentLengthResult =
  ## RFC 9110 8.6: Content-Length is 1*DIGIT. Rejects an empty value and any
  ## non-ASCII-digit byte, so a leading '+'/'-' or a Nim-style underscore (which
  ## `parseBiggestInt` would accept, 1_0 -> 10) cannot parse to a value a
  ## re-serializing proxy would read differently (parser-differential smuggling).
  ## `prev` is the previously-seen content-length (-1 when none); a valid value
  ## that differs from a non-negative `prev` is clConflict (RFC 9113 8.1.1 /
  ## RFC 9114 duplicate rule). digits-only makes the result non-negative. Takes
  ## an openArray so the h1 parser can validate a read-buffer slice without
  ## allocating a string. Shared by the h1, h2 and h3 parsers so the
  ## smuggling-sensitive grammar lives in one place.
  if val.len == 0: return clMalformed
  var v: int64 = 0
  for ch in val:
    if ch notin '0'..'9': return clMalformed
    if v > (int64.high - 9) div 10: return clOverflow
    v = v * 10 + int64(uint8(ch) - uint8('0'))
  if prev >= 0 and prev != v: return clConflict
  value = v
  clOk

type RequestHeadClass* = enum
  rhInvalid    ## malformed: reject the request / reset the stream
  rhRequest    ## a normal request (:method/:path/:scheme present, authority ok)
  rhWebSocket  ## RFC 8441/9220 Extended CONNECT with :protocol == "websocket"

proc classifyRequestHead*(headers: openArray[(string, string)];
                          meth, path, scheme, authority,
                          protocol: var string): RequestHeadClass =
  ## Validate a decoded h2/h3 request field list (RFC 9113 8.3 / RFC 9114
  ## 4.3): pseudo-header dedup and ordering (none after a regular field),
  ## unknown pseudo names, field name/value byte validation, the
  ## authority-or-Host rule for http(s) schemes (RFC 9113 8.3.1), and
  ## Extended CONNECT classification. Extracts the pseudo-header values into
  ## the out-params. Pure (no live connection), so it is unit-testable.
  var seenMethod, seenPath, seenScheme, seenAuthority, seenProtocol = false
  var hasHost = false
  var pseudoDone = false
  for (name, val) in headers:
    if name.len == 0: return rhInvalid
    if not validFieldValue(val): return rhInvalid
    if name[0] == ':':
      if pseudoDone: return rhInvalid          # pseudo after regular
      case name
      of ":method":
        if seenMethod: return rhInvalid
        seenMethod = true; meth = val
      of ":path":
        if seenPath: return rhInvalid
        seenPath = true; path = val
      of ":scheme":
        if seenScheme: return rhInvalid
        seenScheme = true; scheme = val
      of ":authority":
        if seenAuthority: return rhInvalid
        seenAuthority = true; authority = val
      of ":protocol":                          # RFC 8441 Extended CONNECT
        if seenProtocol: return rhInvalid
        seenProtocol = true; protocol = val
      else: return rhInvalid                   # unknown/response pseudo
    else:
      pseudoDone = true
      if not validFieldName(name): return rhInvalid
      if name == "host": hasHost = true
  # An Extended CONNECT websocket carries :protocol plus a full
  # :scheme/:path/:authority (unlike a plain CONNECT, which omits them and
  # we do not support).
  if meth == "CONNECT" and protocol == "websocket":
    if path.len == 0 or scheme.len == 0 or not seenAuthority: return rhInvalid
    return rhWebSocket
  if seenProtocol: return rhInvalid            # :protocol only for a ws-connect
  if meth == "CONNECT":
    # RFC 9113 8.5: a plain (non-Extended) CONNECT carries :authority and MUST
    # omit :scheme and :path. This server does not tunnel, so a well-formed plain
    # CONNECT is unsupported; and a malformed one (carrying :scheme/:path, which
    # 8.5 forbids) must NOT be dispatched as a normal request. Reject both -- the
    # old generic check rejected the legal form and let the malformed one through
    # (#240.5).
    return rhInvalid
  if not isKnownMethod(meth): return rhInvalid  # no silent GET fallback (#240.4)
  if path.len == 0 or scheme.len == 0: return rhInvalid
  # RFC 9113 8.3.1 / RFC 9110 7.2: an http(s) request needs a target
  # authority, from :authority or a Host field.
  if (scheme == "http" or scheme == "https") and not seenAuthority and
      not hasHost: return rhInvalid
  rhRequest
