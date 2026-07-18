## HTTP/1.1 response serialization. Appends directly into a connection's
## write buffer; status lines are precomputed at compile time and the Date
## header is cached per event loop, so a fixed-header response costs a few
## memcopies and one integer format.

import std/httpcore

proc addField*(wbuf: var string, s: string) =
  ## Append a handler-supplied header name or value with CR and LF removed,
  ## so reflected user input can never inject a header or split the response
  ## (RFC 9110 5.5). The common (clean) case bulk-copies; only a value that
  ## actually contains CR/LF pays the per-byte strip.
  var clean = true
  for ch in s:
    if ch == '\r' or ch == '\n':
      clean = false
      break
  if clean:
    wbuf.add s
  else:
    for ch in s:
      if ch != '\r' and ch != '\n':
        wbuf.add ch

const weekdayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

proc add2(s: var string, v: int) {.inline.} =
  s.add char(ord('0') + v div 10)
  s.add char(ord('0') + v mod 10)

proc httpDate*(unixSec: int64): string =
  ## RFC 7231 IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT"). Pure
  ## arithmetic; no std/times, whose timezone singletons are not safe to
  ## share across threads.
  var days = unixSec div 86400
  var rem = unixSec mod 86400
  if rem < 0:
    rem += 86400
    dec days
  let weekday = int((days + 4) mod 7 + 7) mod 7   # 1970-01-01 was a Thursday
  # Civil-from-days (Howard Hinnant's algorithm).
  let z = days + 719468
  let era = (if z >= 0: z else: z - 146096) div 146097
  let doe = z - era * 146097
  let yoe = (doe - doe div 1460 + doe div 36524 - doe div 146096) div 365
  let y = yoe + era * 400
  let doy = doe - (365 * yoe + yoe div 4 - yoe div 100)
  let mp = (5 * doy + 2) div 153
  let d = int(doy - (153 * mp + 2) div 5 + 1)
  let m = int(if mp < 10: mp + 3 else: mp - 9)
  let year = int(if m <= 2: y + 1 else: y)
  result = newStringOfCap(29)
  result.add weekdayNames[weekday]
  result.add ", "
  result.add2 d
  result.add ' '
  result.add monthNames[m - 1]
  result.add ' '
  result.add2 year div 100
  result.add2 year mod 100
  result.add ' '
  result.add2 int(rem div 3600)
  result.add ':'
  result.add2 int(rem mod 3600 div 60)
  result.add ':'
  result.add2 int(rem mod 60)
  result.add " GMT"

const statusLines = block:
  var lines: array[100 .. 599, string]
  for c in 100 .. 599:
    lines[c] = "HTTP/1.1 " & $HttpCode(c) & "\r\n"
  lines

proc appendResponse*(wbuf: var string, code: HttpCode,
                     dateStr, serverHeader, contentType: string,
                     body: openArray[char],
                     extraHeaders: openArray[(string, string)],
                     keepAlive: bool, skipBody: bool,
                     announceKeepAlive = false, altSvc = "") =
  ## Serialize a full response. `skipBody` (HEAD) writes the head with the
  ## real Content-Length but omits the body bytes.
  let codeInt = int(code)
  # RFC 9110 8.6: 1xx, 204, and 304 responses carry no representation, so
  # they must not advertise Content-Length (or Content-Type). This is
  # distinct from HEAD (skipBody), which keeps the Content-Length a GET
  # would have sent.
  let bodiless = codeInt in 100 .. 199 or codeInt == 204 or codeInt == 304
  if codeInt in 100 .. 599:
    wbuf.add statusLines[codeInt]
  else:
    wbuf.add "HTTP/1.1 "
    wbuf.addInt codeInt
    wbuf.add "\r\n"
  if serverHeader.len > 0:
    wbuf.add "Server: "
    wbuf.add serverHeader
    wbuf.add "\r\n"
  wbuf.add "Date: "
  wbuf.add dateStr
  wbuf.add "\r\n"
  if contentType.len > 0 and not bodiless:
    wbuf.add "Content-Type: "
    wbuf.addField contentType
    wbuf.add "\r\n"
  if not bodiless:
    wbuf.add "Content-Length: "
    wbuf.addInt body.len
    wbuf.add "\r\n"
  if not keepAlive:
    wbuf.add "Connection: close\r\n"
  elif announceKeepAlive:
    # HTTP/1.0 clients assume close unless keep-alive is announced.
    wbuf.add "Connection: keep-alive\r\n"
  if altSvc.len > 0:
    wbuf.add "Alt-Svc: "
    wbuf.add altSvc
    wbuf.add "\r\n"
  for (name, val) in extraHeaders:
    wbuf.addField name
    wbuf.add ": "
    wbuf.addField val
    wbuf.add "\r\n"
  wbuf.add "\r\n"
  if body.len > 0 and not skipBody and not bodiless:
    let oldLen = wbuf.len
    wbuf.setLen(oldLen + body.len)
    copyMem(addr wbuf[oldLen], unsafeAddr body[0], body.len)

const continue100* = "HTTP/1.1 100 Continue\r\n\r\n"

# --- streaming responses (res.sendHead / write / finish) --------------------

proc addHex(s: var string, v: int) =
  ## Minimal-width lowercase hex, for chunk sizes.
  if v == 0:
    s.add '0'
    return
  const digits = "0123456789abcdef"
  var buf: array[16, char]
  var n = v
  var i = 0
  while n > 0:
    buf[i] = digits[n and 0xf]
    n = n shr 4
    inc i
  while i > 0:
    dec i
    s.add buf[i]

proc appendStreamHead*(wbuf: var string, code: HttpCode,
                       dateStr, serverHeader, contentType: string,
                       extraHeaders: openArray[(string, string)],
                       chunked: bool, keepAlive: bool,
                       announceKeepAlive = false, altSvc = "") =
  ## Serialize the head of a streaming response: no Content-Length. When
  ## `chunked` the body is Transfer-Encoding: chunked (HTTP/1.1); otherwise
  ## it is delimited by connection close (HTTP/1.0 clients) and the caller
  ## must close after the final byte.
  let codeInt = int(code)
  if codeInt in 100 .. 599:
    wbuf.add statusLines[codeInt]
  else:
    wbuf.add "HTTP/1.1 "
    wbuf.addInt codeInt
    wbuf.add "\r\n"
  if serverHeader.len > 0:
    wbuf.add "Server: "
    wbuf.add serverHeader
    wbuf.add "\r\n"
  wbuf.add "Date: "
  wbuf.add dateStr
  wbuf.add "\r\n"
  if contentType.len > 0:
    wbuf.add "Content-Type: "
    wbuf.addField contentType
    wbuf.add "\r\n"
  if chunked:
    wbuf.add "Transfer-Encoding: chunked\r\n"
  if not keepAlive or not chunked:
    wbuf.add "Connection: close\r\n"
  elif announceKeepAlive:
    wbuf.add "Connection: keep-alive\r\n"
  if altSvc.len > 0:
    wbuf.add "Alt-Svc: "
    wbuf.add altSvc
    wbuf.add "\r\n"
  for (name, val) in extraHeaders:
    wbuf.addField name
    wbuf.add ": "
    wbuf.addField val
    wbuf.add "\r\n"
  wbuf.add "\r\n"

proc appendChunk*(wbuf: var string, data: openArray[char]) =
  ## One Transfer-Encoding chunk. Empty data is skipped (a zero-length chunk
  ## would terminate the body).
  if data.len == 0: return
  wbuf.addHex data.len
  wbuf.add "\r\n"
  let oldLen = wbuf.len
  wbuf.setLen(oldLen + data.len)
  copyMem(addr wbuf[oldLen], unsafeAddr data[0], data.len)
  wbuf.add "\r\n"

proc appendLastChunk*(wbuf: var string,
                      trailers: openArray[(string, string)] = []) =
  ## Terminate a chunked body: the zero-length chunk plus optional trailers.
  wbuf.add "0\r\n"
  for (name, val) in trailers:
    wbuf.addField name
    wbuf.add ": "
    wbuf.addField val
    wbuf.add "\r\n"
  wbuf.add "\r\n"
