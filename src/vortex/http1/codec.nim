## HTTP/1.1 response serialization. Appends directly into a connection's
## write buffer; status lines are precomputed at compile time and the Date
## header is cached per event loop, so a fixed-header response costs a few
## memcopies and one integer format.

import std/httpcore

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
    wbuf.add contentType
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
    wbuf.add name
    wbuf.add ": "
    wbuf.add val
    wbuf.add "\r\n"
  wbuf.add "\r\n"
  if body.len > 0 and not skipBody and not bodiless:
    let oldLen = wbuf.len
    wbuf.setLen(oldLen + body.len)
    copyMem(addr wbuf[oldLen], unsafeAddr body[0], body.len)

const continue100* = "HTTP/1.1 100 Continue\r\n\r\n"
