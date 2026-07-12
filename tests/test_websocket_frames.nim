import std/[unittest, base64]
import vortex/websocket/frames
import vortex/websocket/sha1

const cap = 1 shl 20

proc masked(op: int, payload: string, fin = true,
            mask = [0x12'u8, 0x34, 0x56, 0x78]): string =
  ## Build a masked client frame (what parseFrame expects to consume).
  result.add char((if fin: 0x80 else: 0) or op)
  let n = payload.len
  if n <= 125:
    result.add char(0x80 or n)
  elif n <= 0xffff:
    result.add char(0x80 or 126)
    result.add char(char((n shr 8) and 0xff)); result.add char(char(n and 0xff))
  else:
    result.add char(0x80 or 127)
    for i in countdown(7, 0): result.add char(char((n shr (i*8)) and 0xff))
  for m in mask: result.add char(m)
  for i in 0 ..< n: result.add char(uint8(payload[i]) xor mask[i and 3])

proc parseOne(buf: string, avail = -1): tuple[res: WsParse, f: WsFrame, pos: int] =
  var pos = 0
  var f: WsFrame
  let n = if avail < 0: buf.len else: avail
  let r = parseFrame(buf, n, pos, cap, f)
  (r, f, pos)

suite "websocket handshake":
  test "RFC 6455 Sec-WebSocket-Accept vector":
    const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    check encode(sha1("dGhlIHNhbXBsZSBub25jZQ==" & magic)) ==
      "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

  test "SHA-1 of \"abc\"":
    let d = sha1("abc")
    var hex = ""
    const hexd = "0123456789abcdef"
    for b in d:
      hex.add hexd[int(b shr 4)]; hex.add hexd[int(b and 0xf)]
    check hex == "a9993e364706816aba3e25717850c26c9cd0d89d"

suite "frame parsing":
  test "masked text frame round-trips (payload unmasked)":
    let (r, f, pos) = parseOne(masked(0x1, "hello"))
    check r == wpFrame
    check f.opcode == opText
    check f.fin
    check f.payload == "hello"
    check pos == masked(0x1, "hello").len

  test "binary opcode":
    let (r, f, _) = parseOne(masked(0x2, "\x00\xff"))
    check r == wpFrame and f.opcode == opBinary and f.payload == "\x00\xff"

  test "16-bit and 64-bit length forms":
    let big = newString(300)
    check parseOne(masked(0x2, big)).f.payload.len == 300
    let bigger = newString(70000)
    check parseOne(masked(0x2, bigger)).f.payload.len == 70000

  test "incomplete frame needs more (pos untouched)":
    let full = masked(0x1, "hello")
    for cut in 1 ..< full.len:
      var pos = 0
      var f: WsFrame
      check parseFrame(full, cut, pos, cap, f) == wpNeedMore
      check pos == 0
    # the whole thing parses
    check parseOne(full).res == wpFrame

  test "unmasked client frame is rejected":
    var f = "\x81\x02hi"                    # fin+text, len 2, no mask bit
    check parseOne(f).res == wpError

  test "RSV2/RSV3 are rejected":
    for bit in [0x20'u8, 0x10]:             # RSV2, RSV3: no extension uses them
      var buf = masked(0x1, "x")
      buf[0] = char(uint8(buf[0]) or bit)
      check parseOne(buf).res == wpError

  test "RSV1 is accepted and exposed (permessage-deflate flag)":
    var buf = masked(0x1, "x")
    buf[0] = char(uint8(buf[0]) or 0x40)    # RSV1: the codec decides legality
    let (r, f, _) = parseOne(buf)
    check r == wpFrame
    check f.rsv1

  test "unknown opcode is rejected":
    check parseOne(masked(0x3, "x")).res == wpError

  test "control frame must be final":
    check parseOne(masked(0x9, "x", fin = false)).res == wpError

  test "control frame payload capped at 125":
    check parseOne(masked(0x9, newString(126))).res == wpError

  test "payload larger than the cap is rejected":
    var pos = 0
    var f: WsFrame
    check parseFrame(masked(0x2, newString(200)), 300, pos, 100, f) == wpError

  test "two frames back to back":
    let two = masked(0x1, "aa") & masked(0x1, "bb")
    var pos = 0
    var f: WsFrame
    check parseFrame(two, two.len, pos, cap, f) == wpFrame
    check f.payload == "aa"
    check parseFrame(two, two.len, pos, cap, f) == wpFrame
    check f.payload == "bb"
    check pos == two.len

suite "frame serialization":
  test "small payload uses the 7-bit length":
    var s = ""
    s.appendFrame(opText, "hi")
    check s.len == 4
    check uint8(s[0]) == 0x81                # fin + text
    check uint8(s[1]) == 2                   # unmasked, len 2
    check s[2..3] == "hi"

  test "126..65535 uses the 16-bit length":
    var s = ""
    s.appendFrame(opBinary, newString(300))
    check uint8(s[1]) == 126
    check ((int(uint8(s[2])) shl 8) or int(uint8(s[3]))) == 300

  test "over 65535 uses the 64-bit length":
    var s = ""
    s.appendFrame(opBinary, newString(70000))
    check uint8(s[1]) == 127

  test "close frame carries a big-endian code":
    var s = ""
    s.appendClose(1009, "too big")
    check uint8(s[0]) == 0x88                # fin + close
    check ((int(uint8(s[2])) shl 8) or int(uint8(s[3]))) == 1009
