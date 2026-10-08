## Minimal frame-level HTTP/2 client for security tests: connect, send the
## preface, and build/inject individual frames (HEADERS, CONTINUATION,
## RST_STREAM, PING, SETTINGS), then read and classify what the server sends
## back. Built on src/vortex/http2/frames; requests use three static-table HPACK
## indexes (:method GET / :scheme http / :path /) plus a literal :authority (RFC
## 9113 8.3.1 requires one for http(s) schemes), so no encoder is needed. The
## two hand-rolled HPACK primitives below (incremental indexing, indexed field)
## are the exception: they exist so a suite can observe the server's dynamic
## table across blocks.

import std/[net, posix, oserrors, tables]
import vortex/http2/frames
import vortex/http2/hpack
import ./helper
import ./wsclient                      # WebSocket framing inside DATA payloads

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const getRequest = "\x82\x86\x84\x01\x09localhost"
  # :method GET, :scheme http, :path / (static indexes), then :authority
  # "localhost" as a literal without indexing (0x01 = name index 1)

type
  H2TestConn* = object
    sock*: Socket
    buf: string                      # unparsed received bytes
    data: Table[uint32, string]      # DATA payload bytes, per stream
    resp: Table[uint32, seq[(string, string)]]  # response fields, per stream

proc setTimeout(c: var H2TestConn, ms: int) =
  c.sock.setRecvTimeout(ms)

proc sendRaw*(c: var H2TestConn, data: string) =
  if data.len > 0: c.sock.send(data)

proc sendAll*(c: var H2TestConn, data: string) =
  ## posix send with correct partial-write handling: std/net's `send` re-sends
  ## from offset 0 after a partial write (duplicating bytes on the wire) and then
  ## spins forever if the peer has gone. Use this for anything larger than a
  ## frame or two, and for a flood the server may answer by closing mid-write.
  ## A closed peer must surface as a short count, not a signal: macOS sockets
  ## get SO_NOSIGPIPE from the server, Linux has no such option, so pass
  ## MSG_NOSIGNAL there as std/net does. The suites do not depend on the
  ## server process having ignored SIGPIPE before the first send.
  const noSig = when defined(linux): MSG_NOSIGNAL else: cint(0)
  var off = 0
  while off < data.len:
    let n = posix.send(c.sock.getFd, unsafeAddr data[off], data.len - off, noSig)
    if n <= 0: return
    off += n

proc sendAndDrain*(c: var H2TestConn, data: string, chunk = 4096) =
  ## Send `data` in chunks, draining any already-available response bytes into
  ## the read buffer between chunks. A single blocking send of a large request
  ## burst can deadlock: the server's replies fill the socket buffers while the
  ## client is still blocked in `send()` and not yet reading. Interleaving a
  ## short non-blocking drain keeps the buffers flowing, so the send always
  ## completes and no responses are lost (they are parsed later from `c.buf`).
  var i = 0
  var buf = newString(16 * 1024)
  while i < data.len:
    let hi = min(i + chunk, data.len)
    c.sock.send(data[i ..< hi])
    i = hi
    c.setTimeout(1)                    # drain only what is already buffered
    while true:
      let n = recv(c.sock.getFd, addr buf[0], buf.len, cint(0))
      if n <= 0: break                 # nothing (more) available right now
      c.buf.add buf[0 ..< n]
      if n < buf.len: break            # drained the available bytes

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

proc addSettingFrame*(buf: var string, id: uint16, value: uint32) =
  ## SETTINGS frame carrying exactly one entry (e.g. a zero
  ## SETTINGS_INITIAL_WINDOW_SIZE, which parks every response body the server
  ## produces, or a lowered SETTINGS_HEADER_TABLE_SIZE).
  var payload = ""
  payload.addSetting(id, value)
  buf.addFrameHeader(payload.len, ftSettings, 0, 0)
  buf.add payload

proc addExtendedConnect*(buf: var string, sid: uint32,
                         headers: openArray[(string, string)]) =
  ## HEADERS frame for an RFC 8441 Extended CONNECT: END_HEADERS but NOT
  ## END_STREAM, so the stream stays open for WebSocket framing. Headers are
  ## HPACK literals (server decodes them the same as a browser's).
  var hb = ""
  for (n, v) in headers: hb.encodeHeader(n, v)
  buf.addFrameHeader(hb.len, ftHeaders, flagEndHeaders, sid)
  buf.add hb

proc addRequest*(buf: var string, sid: uint32,
                 headers: openArray[(string, string)], endStream = true) =
  ## HEADERS frame with an explicit HPACK-literal field list (END_HEADERS, and
  ## END_STREAM unless told otherwise). Encodes names/values verbatim -- HPACK is
  ## length-prefixed, so malformed bytes (CR/LF/NUL, bad names) reach the server's
  ## validator intact. For malformed-header security tests.
  var hb = ""
  for (n, v) in headers: hb.encodeHeader(n, v)
  let flags = flagEndHeaders or (if endStream: flagEndStream else: 0'u8)
  buf.addFrameHeader(hb.len, ftHeaders, flags, sid)
  buf.add hb

proc addRawHeaders*(buf: var string, sid: uint32, fragment: string,
                    flags: uint8) =
  ## HEADERS frame with an arbitrary (already HPACK-encoded) field-block fragment
  ## and arbitrary flags: for a block that deliberately omits END_HEADERS (a
  ## CONTINUATION follows), carries the PRIORITY flag (the 5-byte dependency
  ## prefix belongs at the front of `fragment`), or moves the server's HPACK
  ## dynamic table.
  buf.addFrameHeader(fragment.len, ftHeaders, flags, sid)
  buf.add fragment

proc addContinuation*(buf: var string, sid: uint32, fragment: string,
                      endHeaders = true) =
  ## CONTINUATION frame carrying the rest of a field block (RFC 9113 6.10).
  buf.addFrameHeader(fragment.len, ftContinuation,
                     (if endHeaders: flagEndHeaders else: 0'u8), sid)
  buf.add fragment

proc addIndexedLiteral*(buf: var string, name, value: string) =
  ## HPACK "literal header field with incremental indexing" (RFC 7541 6.2.1):
  ## the peer's decoder MUST insert (name, value) at the front of its dynamic
  ## table, so the entry is index 62 for every later block on the connection.
  ## The project's encoder only emits literals without indexing, so the suites
  ## that need the server's decoder state to actually move encode this by hand.
  encodeInt(buf, 0, 6, 0x40)            # 01 pattern, new (literal) name
  encodeInt(buf, name.len, 7, 0x00)     # H=0: raw
  buf.add name
  encodeInt(buf, value.len, 7, 0x00)
  buf.add value

proc addDynamicIndex*(buf: var string, index = 62) =
  ## HPACK "indexed header field" (RFC 7541 6.1). 62 is the newest dynamic-table
  ## entry, so a block using it decodes only if the peer decoded the block that
  ## added it.
  encodeInt(buf, index, 7, 0x80)

proc addData*(buf: var string, sid: uint32, payload: string,
              endStream = false) =
  buf.addFrameHeader(payload.len, ftData,
                     (if endStream: flagEndStream else: 0'u8), sid)
  buf.add payload

proc decodeHeaders*(payload: string): seq[(string, string)] =
  ## Decode a response HEADERS block (the server uses static-table/literal
  ## encoding, so a fresh decoder per block is fine).
  var dec = initHpackDecoder(4096, maxDecoded = 1 shl 20)
  dec.decodeHeaderBlock(payload, 0, payload.len, result)

proc sendHeaders*(c: var H2TestConn, sid: uint32, endStream = true) =
  var f = ""
  f.addHeaders(sid, endStream)
  c.sendRaw(f)

proc sendRst*(c: var H2TestConn, sid: uint32, err = errCancel) =
  var f = ""
  f.addRstStream(sid, err)
  c.sendRaw(f)

proc pump(c: var H2TestConn, timeoutMs: int): bool =
  ## Read one chunk into the buffer. False on EOF or a real (SO_RCVTIMEO)
  ## timeout; a transient EINTR is retried so an interrupted syscall never
  ## ends the read early and drops responses that are still in flight.
  c.setTimeout(timeoutMs)
  var chunk = newString(16 * 1024)
  while true:
    let n = recv(c.sock.getFd, addr chunk[0], chunk.len, cint(0))
    if n > 0:
      c.buf.add chunk[0 ..< n]
      return true
    if n < 0 and cint(osLastError()) == EINTR:
      continue                         # interrupted: retry
    return false                       # EOF or timeout

type Frame* = tuple[typ: uint8, flags: uint8, streamId: uint32, payload: string]

proc readFrames*(c: var H2TestConn, timeoutMs = 1500, maxFrames = 100000,
                 until: proc(frames: seq[Frame]): bool = nil): seq[Frame] =
  ## Collect complete frames (with payloads). Returns as soon as `until` is
  ## satisfied (e.g. "all N responses arrived"), else on EOF or a quiet
  ## period. The `until` form is deterministic: it stops on the expected
  ## outcome instead of waiting out a fixed quiet timeout, so it is not
  ## sensitive to how fast the responses trickle in under load.
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
    if until != nil and until(result): break
    if not c.pump(timeoutMs): break

proc goawayError*(frames: seq[Frame]): int =
  ## Error code of the first GOAWAY frame, or -1 if none. GOAWAY payload
  ## is lastStreamId(4) + errorCode(4) + optional debug data.
  for f in frames:
    if f.typ == uint8(ftGoaway) and f.payload.len >= 8:
      return int(get32(f.payload, 4))
  -1

proc goaways*(frames: seq[Frame]): seq[tuple[lastId: int, err: int]] =
  ## Every GOAWAY in arrival order as (last-stream-id, error code). RFC 9113 6.8
  ## forbids a later GOAWAY from naming a HIGHER last-stream-id than one already
  ## sent, so checking that rule needs the whole sequence, not just the first.
  for f in frames:
    if f.typ == uint8(ftGoaway) and f.payload.len >= 8:
      result.add (int(get32(f.payload, 0)), int(get32(f.payload, 4)))

proc goawayLastStreamId*(frames: seq[Frame]): int =
  ## Last-stream-id of the first GOAWAY, or -1 if there is none: the highest
  ## stream this server processed, so a client may retry everything above it.
  let gs = frames.goaways()
  if gs.len == 0: -1 else: gs[0].lastId

proc count*(frames: seq[Frame], typ: FrameType): int =
  for f in frames:
    if f.typ == uint8(typ): inc result

proc rstError*(frames: seq[Frame], sid: uint32): int =
  ## Error code of the first RST_STREAM on `sid`, or -1 if none.
  for f in frames:
    if f.typ == uint8(ftRstStream) and f.streamId == sid and f.payload.len >= 4:
      return int(get32(f.payload, 0))
  -1

proc hasResponse*(frames: seq[Frame], sid: uint32): bool =
  ## True when a response HEADERS frame arrived on `sid`, i.e. the request was
  ## answered rather than reset (or lost with the whole connection).
  for f in frames:
    if f.typ == uint8(ftHeaders) and f.streamId == sid: return true

proc headerPayload*(frames: seq[Frame], sid: uint32): string =
  ## The still-HPACK-encoded payload of the first response HEADERS on `sid`
  ## ("" if none), for assertions about the encoding itself.
  for f in frames:
    if f.typ == uint8(ftHeaders) and f.streamId == sid: return f.payload

# --- Extended CONNECT (RFC 8441) streams ------------------------------------

proc keepData(c: var H2TestConn, frames: seq[Frame]) =
  ## Retain every DATA payload, per stream: one read batch may interleave
  ## streams, so a later read for another stream still finds its bytes.
  for f in frames:
    if f.typ == uint8(ftData): c.data.mgetOrPut(f.streamId, "").add f.payload

proc extendedConnect*(c: var H2TestConn, sid: uint32, path: string,
                      extra: openArray[(string, string)] = [],
                      version = "13"): string =
  ## Open an RFC 8441 Extended CONNECT stream (`:method CONNECT`,
  ## `:protocol websocket`) for `path` and return the negotiated `:status`
  ## ("" if the server answered with no HEADERS). The handshake is END_HEADERS
  ## without END_STREAM, so the stream stays open for WebSocket framing in DATA;
  ## any DATA already alongside the handshake is kept for `streamData`, and the
  ## response fields for `respField`.
  ##
  ## `version` is the `Sec-WebSocket-Version` offered, omitted entirely when
  ## empty: the two shapes RFC 6455 4.2.2(4) refuses are an unsupported version
  ## and no version at all.
  var hdrs = @[(":method", "CONNECT"), (":protocol", "websocket"),
               (":scheme", "http"), (":path", path), (":authority", "x")]
  if version.len > 0: hdrs.add ("sec-websocket-version", version)
  for e in extra: hdrs.add e
  var f = ""
  f.addExtendedConnect(sid, hdrs)
  c.sendRaw(f)
  let frames = c.readFrames(1500, until = proc(fr: seq[Frame]): bool =
    for x in fr:
      if x.typ == uint8(ftHeaders) and x.streamId == sid: return true
    false)
  c.keepData(frames)
  for x in frames:
    if x.typ == uint8(ftHeaders) and x.streamId == sid:
      let fields = decodeHeaders(x.payload)
      c.resp[sid] = fields
      for (n, v) in fields:
        if n == ":status": result = v

proc respField*(c: H2TestConn, sid: uint32, name: string): string =
  ## A field of the response HEADERS `extendedConnect` read on `sid` ("" if the
  ## server did not send it), for a refusal that carries one -- RFC 6455
  ## 4.2.2(4)'s `Sec-WebSocket-Version` on a 426. Names are HPACK-lowercase.
  for (n, v) in c.resp.getOrDefault(sid):
    if n == name: return v

proc firstWsFrame*(acc: string): bool =
  ## A `streamData` predicate: at least one complete WebSocket frame has
  ## arrived in the stream's accumulated DATA bytes.
  parseFrames(acc)[0].len >= 1

proc sendData*(c: var H2TestConn, sid: uint32, payload: string) =
  ## One DATA frame on `sid` (no END_STREAM): the carrier for WebSocket frames.
  var f = ""
  f.addData(sid, payload)
  c.sendRaw(f)

proc streamData*(c: var H2TestConn, sid: uint32,
                 ready: proc(acc: string): bool, tries = 30): string =
  ## Every DATA byte received on `sid` so far, reading more until `ready`
  ## accepts the accumulation (e.g. "a complete WebSocket frame has arrived")
  ## or the server goes quiet. Deterministic like `readFrames`'s `until`: it
  ## stops on the expected outcome, not on a fixed wait.
  var left = tries
  while left > 0:
    if ready(c.data.getOrDefault(sid)): break
    dec left
    let frames = c.readFrames(1000, until = proc(fr: seq[Frame]): bool =
      for f in fr:
        if f.typ == uint8(ftData) and f.streamId == sid: return true
      false)
    c.keepData(frames)
    if frames.len == 0: break
  c.data.getOrDefault(sid)

proc close*(c: var H2TestConn) =
  c.sock.close()
