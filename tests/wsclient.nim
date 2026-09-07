## Minimal raw WebSocket test client (RFC 6455), the WS counterpart of
## tests/h2client.nim: the HTTP/1.1 upgrade handshake plus a full frame codec
## (7-bit/126/127 lengths, FIN/RSV1, client-side masking). Suites layer thin
## wrappers over the rich frame tuple where their assertions want a narrower
## shape; the wire codec itself lives only here.

import std/[net, posix, strutils]
import ./helper

const wsTestKey* = "dGhlIHNhbXBsZSBub25jZQ=="

type WsFrame* = tuple[fin: bool, rsv1: bool, op: int, payload: string]

proc recvN*(s: Socket, n: int): string =
  ## Read exactly n bytes; IOError on EOF/timeout.
  result = newString(n)
  var got = 0
  while got < n:
    let k = recv(s.getFd, addr result[got], n - got, cint(0))
    if k <= 0: raise newException(IOError, "short read")
    got += k

proc recvFrame*(s: Socket): WsFrame =
  ## One server frame (server frames must be unmasked), any length encoding.
  let h = recvN(s, 2)
  let b0 = uint8(h[0])
  let b1 = uint8(h[1])
  doAssert (b1 and 0x80) == 0, "server frame must be unmasked"
  var ln = int(b1 and 0x7f)
  if ln == 126:
    let e = recvN(s, 2)
    ln = (int(uint8(e[0])) shl 8) or int(uint8(e[1]))
  elif ln == 127:
    let e = recvN(s, 8)
    ln = 0
    for i in 0 ..< 8: ln = (ln shl 8) or int(uint8(e[i]))
  ((b0 and 0x80) != 0, (b0 and 0x40) != 0, int(b0 and 0x0f),
   (if ln > 0: recvN(s, ln) else: ""))

proc parseFrames*(buf: string): (seq[WsFrame], int) =
  ## All complete (unmasked) server frames in `buf` plus the bytes consumed;
  ## for reassembling WebSocket framing carried inside HTTP/2 DATA payloads.
  var pos = 0
  while pos + 2 <= buf.len:
    let b0 = uint8(buf[pos])
    let b1 = uint8(buf[pos + 1])
    doAssert (b1 and 0x80) == 0, "server frame must be unmasked"
    var ln = int(b1 and 0x7f)
    var hdr = 2
    if ln == 126:
      if pos + 4 > buf.len: break
      ln = (int(uint8(buf[pos + 2])) shl 8) or int(uint8(buf[pos + 3]))
      hdr = 4
    elif ln == 127:
      if pos + 10 > buf.len: break
      ln = 0
      for i in 0 ..< 8: ln = (ln shl 8) or int(uint8(buf[pos + 2 + i]))
      hdr = 10
    if pos + hdr + ln > buf.len: break
    result[0].add ((b0 and 0x80) != 0, (b0 and 0x40) != 0, int(b0 and 0x0f),
                   buf[pos + hdr ..< pos + hdr + ln])
    pos += hdr + ln
  result[1] = pos

proc buildFrame*(op: int, payload: string, fin = true, rsv1 = false,
                 masked = true): string =
  ## A client frame as raw bytes (send on a socket, or embed in h2 DATA).
  result = newStringOfCap(payload.len + 14)
  result.add char((if fin: 0x80 else: 0) or (if rsv1: 0x40 else: 0) or op)
  let n = payload.len
  let maskBit = if masked: 0x80 else: 0
  if n <= 125:
    result.add char(maskBit or n)
  elif n <= 0xffff:
    result.add char(maskBit or 126)
    result.add char((n shr 8) and 0xff)
    result.add char(n and 0xff)
  else:
    result.add char(maskBit or 127)
    for i in countdown(7, 0): result.add char((n shr (i * 8)) and 0xff)
  if masked:
    const mask = [0x37'u8, 0xfa, 0x21, 0x3d]
    for m in mask: result.add char(m)
    for i in 0 ..< n: result.add char(uint8(payload[i]) xor mask[i and 3])
  else:
    result.add payload

proc sendFrame*(s: Socket, op: int, payload: string, fin = true,
                rsv1 = false, masked = true) =
  s.send(buildFrame(op, payload, fin, rsv1, masked))

proc sendText*(s: Socket, p: string) = s.sendFrame(0x1, p)
proc sendBin*(s: Socket, p: string) = s.sendFrame(0x2, p)
proc sendClose*(s: Socket, payload = "") = s.sendFrame(0x8, payload)
proc sendPing*(s: Socket, payload = "") = s.sendFrame(0x9, payload)
proc sendPong*(s: Socket, payload = "") = s.sendFrame(0xA, payload)

proc openWs*(port: Port, path = "/", extraHeaders = "", expectCode = 101,
             timeoutMs = 2000, key = wsTestKey):
    tuple[sock: Socket, resp: string] =
  ## HTTP/1.1 WebSocket upgrade against 127.0.0.1:port. Returns the socket and
  ## the raw response head so callers can assert on Sec-WebSocket-* fields.
  ## `extraHeaders` are raw "Name: value\r\n" lines appended to the handshake.
  result.sock = newSocket(buffered = false)
  result.sock.connect("127.0.0.1", port)
  result.sock.send(
    "GET " & path & " HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
    "Connection: Upgrade\r\nSec-WebSocket-Key: " & key & "\r\n" &
    "Sec-WebSocket-Version: 13\r\n" & extraHeaders & "\r\n")
  result.sock.setRecvTimeout(timeoutMs)
  var one = newString(1)
  while not result.resp.endsWith("\r\n\r\n"):
    let k = recv(result.sock.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    result.resp.add one[0]
  doAssert ($expectCode) in result.resp, result.resp
