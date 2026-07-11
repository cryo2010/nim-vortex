## RFC 6455 WebSocket framing: parse client frames (masked) and serialize
## server frames (unmasked). Parsing is resumable: it consumes a whole
## frame from the buffer or reports that more bytes are needed, leaving
## `pos` untouched, so it composes with the event loop's growing recv
## buffer the same way the HTTP/1 parser and HTTP/2 frame reader do.

type
  WsOpcode* = enum
    opContinuation = 0x0
    opText = 0x1
    opBinary = 0x2
    opClose = 0x8
    opPing = 0x9
    opPong = 0xA

  WsFrame* = object
    fin*: bool
    opcode*: WsOpcode
    payload*: string          ## already unmasked

  WsParse* = enum
    wpNeedMore                 ## incomplete; call again with more bytes
    wpFrame                    ## a full frame was produced
    wpError                    ## protocol violation (close the connection)

proc isControl*(op: WsOpcode): bool {.inline.} =
  op in {opClose, opPing, opPong}

proc knownOpcode(v: uint8): bool {.inline.} =
  v in {0x0'u8, 0x1, 0x2, 0x8, 0x9, 0xA}

proc parseFrame*(buf: string, avail: int, pos: var int,
                 maxPayload: int, frame: var WsFrame): WsParse =
  ## Parse one frame from buf[pos ..< avail]. On wpFrame, `pos` advances
  ## past it and `frame` is filled (payload unmasked). Client frames must
  ## be masked (RFC 6455 5.1); control frames must be final and <= 125
  ## bytes. A single frame larger than `maxPayload` is rejected.
  let start = pos
  if avail - start < 2: return wpNeedMore
  let b0 = uint8(buf[start])
  let b1 = uint8(buf[start + 1])
  if (b0 and 0x70) != 0: return wpError        # RSV bits set, no extensions
  let opByte = b0 and 0x0f
  if not knownOpcode(opByte): return wpError
  let op = cast[WsOpcode](opByte)   # validated above; cast avoids HoleEnumConv
  let fin = (b0 and 0x80) != 0
  let masked = (b1 and 0x80) != 0
  if not masked: return wpError                # client frames must be masked
  let len7 = int(b1 and 0x7f)

  if op.isControl and (not fin or len7 > 125):
    return wpError                             # control frames: final, <=125

  var header = 2
  var payloadLen = len7
  if len7 == 126:
    if avail - start < 4: return wpNeedMore
    payloadLen = (int(uint8(buf[start+2])) shl 8) or int(uint8(buf[start+3]))
    header = 4
  elif len7 == 127:
    if avail - start < 10: return wpNeedMore
    payloadLen = 0
    for i in 0 ..< 8:
      let bv = int(uint8(buf[start + 2 + i]))
      # High bit must be 0 (RFC 6455); and reject anything past our cap so
      # a huge advertised length can never drive an allocation.
      if (i == 0 and bv >= 0x80) or payloadLen > maxPayload:
        return wpError
      payloadLen = (payloadLen shl 8) or bv
    header = 10
  if payloadLen > maxPayload: return wpError

  let maskOff = start + header
  let dataOff = maskOff + 4
  if avail - start < header + 4 + payloadLen: return wpNeedMore

  frame.fin = fin
  frame.opcode = op
  frame.payload.setLen(payloadLen)
  let m0 = uint8(buf[maskOff]); let m1 = uint8(buf[maskOff+1])
  let m2 = uint8(buf[maskOff+2]); let m3 = uint8(buf[maskOff+3])
  let mask = [m0, m1, m2, m3]
  for i in 0 ..< payloadLen:
    frame.payload[i] = char(uint8(buf[dataOff + i]) xor mask[i and 3])
  pos = dataOff + payloadLen
  wpFrame

proc appendFrame*(dst: var string, opcode: WsOpcode,
                  payload: openArray[char], fin = true) =
  ## Serialize a server frame (unmasked) into `dst`.
  dst.add char((if fin: 0x80'u8 else: 0'u8) or uint8(opcode))
  let n = payload.len
  if n <= 125:
    dst.add char(uint8(n))
  elif n <= 0xffff:
    dst.add char(126'u8)
    dst.add char(uint8((n shr 8) and 0xff))
    dst.add char(uint8(n and 0xff))
  else:
    dst.add char(127'u8)
    for i in countdown(7, 0):
      dst.add char(uint8((uint64(n) shr (uint64(i) * 8)) and 0xff))
  let old = dst.len
  if n > 0:
    dst.setLen(old + n)
    copyMem(addr dst[old], unsafeAddr payload[0], n)

proc appendClose*(dst: var string, code: uint16, reason: openArray[char] = "") =
  ## A close frame: 2-byte big-endian status code, then an optional reason.
  var payload = newStringOfCap(2 + reason.len)
  payload.add char(uint8((code shr 8) and 0xff))
  payload.add char(uint8(code and 0xff))
  for c in reason: payload.add c
  dst.appendFrame(opClose, payload)
