## HTTP/3 wire primitives: QUIC variable-length integers (RFC 9000
## section 16) and h3 frame/stream-type constants (RFC 9114).

type
  VarintResult* = enum
    viOk, viIncomplete

const
  # Frame types
  h3fData* = 0x00'u64
  h3fHeaders* = 0x01'u64
  h3fCancelPush* = 0x03'u64
  h3fSettings* = 0x04'u64
  h3fPushPromise* = 0x05'u64
  h3fGoaway* = 0x07'u64
  h3fMaxPushId* = 0x0d'u64

  # Unidirectional stream types
  h3sControl* = 0x00'u64
  h3sPush* = 0x01'u64
  h3sQpackEncoder* = 0x02'u64
  h3sQpackDecoder* = 0x03'u64

  # Settings
  h3SetQpackMaxTableCapacity* = 0x01'u64
  h3SetMaxFieldSectionSize* = 0x06'u64
  h3SetQpackBlockedStreams* = 0x07'u64
  h3SetEnableConnectProtocol* = 0x08'u64   # RFC 9220: Extended CONNECT (WS)

  # Error codes (RFC 9114 section 8.1)
  h3NoError* = 0x0100'u64
  h3GeneralProtocolError* = 0x0101'u64
  h3InternalError* = 0x0102'u64
  h3StreamCreationError* = 0x0103'u64
  h3ClosedCriticalStream* = 0x0104'u64
  h3FrameUnexpected* = 0x0105'u64
  h3FrameError* = 0x0106'u64
  h3ExcessiveLoad* = 0x0107'u64
  h3IdError* = 0x0108'u64
  h3SettingsError* = 0x0109'u64
  h3MissingSettings* = 0x010a'u64
  h3RequestRejected* = 0x010b'u64
  h3MessageError* = 0x010e'u64
  # QPACK error codes (RFC 9204 section 6)
  qpackDecompressionFailed* = 0x0200'u64
  qpackEncoderStreamError* = 0x0201'u64
  qpackDecoderStreamError* = 0x0202'u64

proc getVarint*(buf: openArray[char], pos: var int, endPos: int,
                value: var uint64): VarintResult =
  if pos >= endPos: return viIncomplete
  let first = uint8(buf[pos])
  let lenBytes = 1 shl (first shr 6)
  if pos + lenBytes > endPos: return viIncomplete
  value = uint64(first and 0x3f)
  for i in 1 ..< lenBytes:
    value = (value shl 8) or uint64(uint8(buf[pos + i]))
  pos += lenBytes
  viOk

proc addVarint*(buf: var string, v: uint64) =
  if v < 1'u64 shl 6:
    buf.add char(uint8(v))
  elif v < 1'u64 shl 14:
    buf.add char(uint8(v shr 8) or 0x40)
    buf.add char(uint8(v))
  elif v < 1'u64 shl 30:
    buf.add char(uint8(v shr 24) or 0x80)
    buf.add char(uint8(v shr 16))
    buf.add char(uint8(v shr 8))
    buf.add char(uint8(v))
  else:
    buf.add char(uint8(v shr 56) or 0xc0)
    for shift in [48, 40, 32, 24, 16, 8, 0]:
      buf.add char(uint8(v shr shift))

proc addFrame*(buf: var string, typ: uint64, payload: openArray[char]) =
  buf.addVarint typ
  buf.addVarint uint64(payload.len)
  let old = buf.len
  if payload.len > 0:
    buf.setLen(old + payload.len)
    copyMem(addr buf[old], unsafeAddr payload[0], payload.len)
