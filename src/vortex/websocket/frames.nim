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
    rsv1*: bool               ## permessage-deflate: a compressed message
    opcode*: WsOpcode
    payload*: string          ## already unmasked (still compressed if rsv1)

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
  # RSV2/RSV3 are unused (no extension defines them); RSV1 is permessage-
  # deflate's "compressed" flag, validated in context by the codec.
  if (b0 and 0x30) != 0: return wpError
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
    # Accumulate the 64-bit length into a uint64 so it can never truncate before
    # the cap check (a native int is only 32 bits on a 32-bit target, where the
    # shift would wrap a huge advertised length down to a small accepted value).
    var ext: uint64 = 0
    for i in 0 ..< 8:
      let bv = uint8(buf[start + 2 + i])
      if i == 0 and bv >= 0x80'u8: return wpError   # high bit must be 0 (RFC 6455)
      ext = (ext shl 8) or uint64(bv)
    # Reject anything past our cap (which also bounds it below high(int)) before
    # narrowing, so a huge advertised length can never drive an allocation.
    if ext > uint64(maxPayload): return wpError
    payloadLen = int(ext)
    header = 10
  if payloadLen > maxPayload: return wpError

  let maskOff = start + header
  let dataOff = maskOff + 4
  if avail - start < header + 4 + payloadLen: return wpNeedMore

  frame.fin = fin
  frame.rsv1 = (b0 and 0x40) != 0
  frame.opcode = op
  # `frame` is the pump's reusable frame (#336), so setLen keeps the payload
  # buffer it already owns: a steady stream of same-sized messages allocates
  # nothing here after the first one.
  frame.payload.setLen(payloadLen)
  if payloadLen > 0:
    # Unmask 8 bytes per step. The 4-byte key repeats every 4 bytes, so one word
    # holding two copies of it XORs a whole 8-byte block; building that word with
    # copyMem from the key bytes (rather than by shifting) gives it the same byte
    # order in memory as the data word, so the block XOR is exact on either
    # endianness. The tail stays byte-wise, and `i and 3` picks up exactly where
    # the blocks stopped because each block consumes a multiple of 4 bytes.
    let mask = [uint8(buf[maskOff]), uint8(buf[maskOff+1]),
                uint8(buf[maskOff+2]), uint8(buf[maskOff+3])]
    let keyBytes = [mask[0], mask[1], mask[2], mask[3],
                    mask[0], mask[1], mask[2], mask[3]]
    var key8: uint64
    copyMem(addr key8, unsafeAddr keyBytes[0], 8)
    let src = cast[ptr UncheckedArray[uint8]](unsafeAddr buf[dataOff])
    let dst = cast[ptr UncheckedArray[uint8]](addr frame.payload[0])
    var i = 0
    while i + 8 <= payloadLen:
      var blk: uint64
      copyMem(addr blk, addr src[i], 8)
      blk = blk xor key8
      copyMem(addr dst[i], addr blk, 8)
      i += 8
    while i < payloadLen:
      dst[i] = src[i] xor mask[i and 3]
      inc i
  pos = dataOff + payloadLen
  wpFrame

proc appendFrame*(dst: var string, opcode: WsOpcode,
                  payload: openArray[char], fin = true, rsv1 = false) =
  ## Serialize a server frame (unmasked) into `dst`. `rsv1` marks a
  ## permessage-deflate compressed message (first frame only).
  dst.add char((if fin: 0x80'u8 else: 0'u8) or
               (if rsv1: 0x40'u8 else: 0'u8) or uint8(opcode))
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
  ## A control frame's payload is capped at 125 bytes (RFC 6455 5.5); with the
  ## 2-byte code that leaves 123 for the reason, so truncate rather than emit an
  ## illegal oversized control frame.
  let rlen = min(reason.len, 123)
  var payload = newStringOfCap(2 + rlen)
  payload.add char(uint8((code shr 8) and 0xff))
  payload.add char(uint8(code and 0xff))
  for i in 0 ..< rlen: payload.add reason[i]
  dst.appendFrame(opClose, payload)
