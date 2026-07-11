## Minimal frame-level HTTP/2 client for security tests: connect, send the
## preface, and build/inject individual frames (HEADERS, RST_STREAM, PING,
## SETTINGS), then read and classify what the server sends back. Built on
## src/vortex/http2/frames; requests use the three static-table HPACK
## indexes (:method GET / :scheme http / :path /), so no encoder is needed.

import std/[net, posix]
import vortex/http2/frames

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const getRequest = "\x82\x86\x84"    # :method GET, :scheme http, :path /

type
  H2TestConn* = object
    sock*: Socket
    buf: string                      # unparsed received bytes

proc setTimeout(c: var H2TestConn, ms: int) =
  var tv: Timeval
  tv.tv_sec = posix.Time(ms div 1000)
  tv.tv_usec = Suseconds((ms mod 1000) * 1000)
  discard setsockopt(c.sock.getFd, SOL_SOCKET, SO_RCVTIMEO,
                     addr tv, SockLen(sizeof(tv)))

proc sendRaw*(c: var H2TestConn, data: string) =
  if data.len > 0: c.sock.send(data)

proc newH2TestConn*(port: Port): H2TestConn =
  ## Connect and send the client preface plus an empty SETTINGS frame.
  result.sock = newSocket(buffered = false)
  result.sock.connect("127.0.0.1", port)
  var hello = preface
  hello.addFrameHeader(0, ftSettings, 0, 0)
  result.sock.send(hello)

# Frame builders append to a buffer so a flood can be sent in one write
# (sending many frames and only then reading avoids a send/recv deadlock
# for volumes that fit in the socket buffers).

proc addHeaders*(buf: var string, sid: uint32, endStream = true) =
  let flags = flagEndHeaders or (if endStream: flagEndStream else: 0'u8)
  buf.addFrameHeader(getRequest.len, ftHeaders, flags, sid)
  buf.add getRequest

proc addPing*(buf: var string) =
  buf.addFrameHeader(8, ftPing, 0, 0)
  buf.add "\0\0\0\0\0\0\0\0"

proc addSettingsFrame*(buf: var string) =
  var payload = ""
  payload.addSetting(setMaxConcurrentStreams, 100)
  buf.addFrameHeader(payload.len, ftSettings, 0, 0)
  buf.add payload

proc sendHeaders*(c: var H2TestConn, sid: uint32, endStream = true) =
  var f = ""
  f.addHeaders(sid, endStream)
  c.sendRaw(f)

proc sendRst*(c: var H2TestConn, sid: uint32, err = errCancel) =
  var f = ""
  f.addRstStream(sid, err)
  c.sendRaw(f)

proc pump(c: var H2TestConn, timeoutMs: int): bool =
  ## Read one chunk into the buffer. False on EOF/timeout.
  c.setTimeout(timeoutMs)
  var chunk = newString(16 * 1024)
  let n = recv(c.sock.getFd, addr chunk[0], chunk.len, cint(0))
  if n <= 0: return false
  c.buf.add chunk[0 ..< n]
  true

type Frame* = tuple[typ: uint8, flags: uint8, streamId: uint32, payload: string]

proc readFrames*(c: var H2TestConn, timeoutMs = 1500,
                 maxFrames = 100000): seq[Frame] =
  ## Collect complete frames (with payloads) until EOF or a quiet period.
  var pos = 0
  while result.len < maxFrames:
    while c.buf.len - pos >= frameHeaderLen:
      let fh = parseFrameHeader(c.buf, pos)
      if c.buf.len - pos < frameHeaderLen + fh.length: break
      let ps = pos + frameHeaderLen
      result.add (fh.typ, fh.flags, fh.streamId,
                  c.buf.substr(ps, ps + fh.length - 1))
      pos += frameHeaderLen + fh.length
    if pos > 0:
      c.buf = c.buf.substr(pos)
      pos = 0
    if not c.pump(timeoutMs): break

proc goawayError*(frames: seq[Frame]): int =
  ## Error code of the first GOAWAY frame, or -1 if none. GOAWAY payload
  ## is lastStreamId(4) + errorCode(4) + optional debug data.
  for f in frames:
    if f.typ == uint8(ftGoaway) and f.payload.len >= 8:
      return int(get32(f.payload, 4))
  -1

proc count*(frames: seq[Frame], typ: FrameType): int =
  for f in frames:
    if f.typ == uint8(typ): inc result

proc close*(c: var H2TestConn) =
  c.sock.close()
