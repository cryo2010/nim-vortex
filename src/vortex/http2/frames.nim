## HTTP/2 frame layer (RFC 9113 section 4): the 9-byte frame header and
## byte-order helpers. Frame semantics live in codec.nim.

type
  FrameType* = enum
    ftData = 0'u8
    ftHeaders = 1
    ftPriority = 2
    ftRstStream = 3
    ftSettings = 4
    ftPushPromise = 5
    ftPing = 6
    ftGoaway = 7
    ftWindowUpdate = 8
    ftContinuation = 9

  FrameHeader* = object
    length*: int
    typ*: uint8               ## raw: unknown types must be ignored
    flags*: uint8
    streamId*: uint32

const
  frameHeaderLen* = 9
  flagEndStream* = 0x01'u8
  flagAck* = 0x01'u8
  flagEndHeaders* = 0x04'u8
  flagPadded* = 0x08'u8
  flagPriority* = 0x20'u8

  # Error codes (RFC 9113 section 7)
  errNoError* = 0'u32
  errProtocol* = 1'u32
  errInternal* = 2'u32
  errFlowControl* = 3'u32
  errStreamClosed* = 5'u32
  errFrameSize* = 6'u32
  errRefusedStream* = 7'u32
  errCancel* = 8'u32
  errCompression* = 9'u32
  errEnhanceYourCalm* = 11'u32

  # SETTINGS identifiers
  setHeaderTableSize* = 1'u16
  setEnablePush* = 2'u16
  setMaxConcurrentStreams* = 3'u16
  setInitialWindowSize* = 4'u16
  setMaxFrameSize* = 5'u16
  setMaxHeaderListSize* = 6'u16
  setEnableConnectProtocol* = 8'u16   # RFC 8441: Extended CONNECT (WebSockets)
  setNoRfc7540Priorities* = 9'u16     # RFC 9218: deprecate the 7540 priority tree

  # RFC 9218 extensible prioritization. The PRIORITY_UPDATE frame type is outside
  # the RFC 9113 0..9 range, so it is matched by raw value in the codec dispatch.
  ftPriorityUpdate* = 0x10'u8

  connectionPreface* = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  defaultMaxFrameSize* = 16384
  defaultInitialWindow* = 65535'i32

proc get24*(buf: openArray[char], pos: int): int {.inline.} =
  (int(uint8(buf[pos])) shl 16) or (int(uint8(buf[pos+1])) shl 8) or
   int(uint8(buf[pos+2]))

proc get32*(buf: openArray[char], pos: int): uint32 {.inline.} =
  (uint32(uint8(buf[pos])) shl 24) or (uint32(uint8(buf[pos+1])) shl 16) or
  (uint32(uint8(buf[pos+2])) shl 8) or uint32(uint8(buf[pos+3]))

proc get16*(buf: openArray[char], pos: int): uint16 {.inline.} =
  (uint16(uint8(buf[pos])) shl 8) or uint16(uint8(buf[pos+1]))

proc add24*(buf: var string, v: int) {.inline.} =
  buf.add char(uint8(v shr 16))
  buf.add char(uint8(v shr 8))
  buf.add char(uint8(v))

proc add32*(buf: var string, v: uint32) {.inline.} =
  buf.add char(uint8(v shr 24))
  buf.add char(uint8(v shr 16))
  buf.add char(uint8(v shr 8))
  buf.add char(uint8(v))

proc add16*(buf: var string, v: uint16) {.inline.} =
  buf.add char(uint8(v shr 8))
  buf.add char(uint8(v))

proc parseFrameHeader*(buf: openArray[char], pos: int): FrameHeader =
  ## Caller guarantees frameHeaderLen bytes are available.
  FrameHeader(
    length: get24(buf, pos),
    typ: uint8(buf[pos + 3]),
    flags: uint8(buf[pos + 4]),
    streamId: get32(buf, pos + 5) and 0x7fffffff'u32)

proc addFrameHeader*(buf: var string, length: int, typ: FrameType,
                     flags: uint8, streamId: uint32) =
  buf.add24 length
  buf.add char(uint8(typ))
  buf.add char(flags)
  buf.add32 streamId

proc addRstStream*(buf: var string, streamId: uint32, err: uint32) =
  buf.addFrameHeader(4, ftRstStream, 0, streamId)
  buf.add32 err

proc addGoaway*(buf: var string, lastStreamId: uint32, err: uint32) =
  buf.addFrameHeader(8, ftGoaway, 0, 0)
  buf.add32 lastStreamId
  buf.add32 err

proc addWindowUpdate*(buf: var string, streamId: uint32, increment: int) =
  buf.addFrameHeader(4, ftWindowUpdate, 0, streamId)
  buf.add32 uint32(increment)

proc addPingAck*(buf: var string, payload: openArray[char]) =
  buf.addFrameHeader(8, ftPing, flagAck, 0)
  for c in payload: buf.add c

proc addSetting*(buf: var string, id: uint16, value: uint32) =
  buf.add16 id
  buf.add32 value
