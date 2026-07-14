## QPACK dynamic table (RFC 9204 3.2): insertion, byte-size eviction, capacity
## changes, and stable absolute indexing.

import std/unittest
import vortex/http3/qpack

suite "QPACK dynamic table":
  test "capacity 0 rejects inserts":
    var t: QpackDynTable
    check t.capacity == 0
    check not t.insert("a", "b")
    check t.insertCount == 0

  test "insert, lookup by absolute index, insertCount":
    var t: QpackDynTable
    t.setCapacity(200)
    check t.insert(":method", "GET")      # size 7+3+32 = 42
    check t.insert("accept", "*/*")       # size 6+3+32 = 41
    check t.insertCount == 2
    check t.has(0) and t.has(1)
    check not t.has(2)
    check t.get(0) == (":method", "GET")
    check t.get(1) == ("accept", "*/*")

  test "oldest entries evict to fit capacity; indices stay absolute":
    var t: QpackDynTable
    t.setCapacity(100)                    # holds two 34-byte entries (a/b)
    check t.insert("a", "b")              # abs 0
    check t.insert("c", "d")              # abs 1
    check t.insert("e", "f")              # abs 2 -> evicts abs 0
    check t.insertCount == 3
    check not t.has(0)                    # evicted
    check t.has(1) and t.has(2)
    check t.get(1) == ("c", "d")
    check t.get(2) == ("e", "f")

  test "shrinking capacity evicts":
    var t: QpackDynTable
    t.setCapacity(200)
    check t.insert("a", "b")
    check t.insert("c", "d")
    t.setCapacity(34)                     # room for one entry only
    check t.insertCount == 2              # absolute count is unchanged
    check not t.has(0)
    check t.has(1)
    check t.get(1) == ("c", "d")

  test "an entry larger than capacity is not inserted":
    var t: QpackDynTable
    t.setCapacity(40)
    check not t.insert("longname", "longvalue")   # 8+9+32 = 49 > 40
    check t.insertCount == 0

suite "QPACK encoder-stream instructions":
  test "insert with literal name":
    var t: QpackDynTable
    t.setCapacity(200)
    let buf = "\x41a\x01b"                 # 01 H0 len1 'a' | H0 len1 'b'
    check t.decodeEncoderInstructions(buf, 4096) == buf.len
    check t.insertCount == 1
    check t.get(0) == ("a", "b")

  test "insert with static name reference":
    var t: QpackDynTable
    t.setCapacity(200)
    let buf = "\xC1\x01x"                   # 1 T1 idx1 (:path) | value "x"
    check t.decodeEncoderInstructions(buf, 4096) == buf.len
    check t.get(0) == (":path", "x")

  test "insert with dynamic name reference":
    var t: QpackDynTable
    t.setCapacity(200)
    discard t.decodeEncoderInstructions("\x41a\x01b", 4096)   # abs 0 = (a,b)
    let buf = "\x80\x01c"                   # 1 T0 idx0 (dyn abs0 name "a") | "c"
    check t.decodeEncoderInstructions(buf, 4096) == buf.len
    check t.get(1) == ("a", "c")

  test "set dynamic table capacity instruction":
    var t: QpackDynTable
    let buf = "\x3E"                        # 001 11110 = capacity 30
    check t.decodeEncoderInstructions(buf, 4096) == 1
    check t.capacity == 30

  test "capacity over the advertised maximum is an error":
    var t: QpackDynTable
    let buf = "\x3F\x01"                    # 001 11111 + 1 = 32
    expect QpackError:
      discard t.decodeEncoderInstructions(buf, 20)

  test "duplicate":
    var t: QpackDynTable
    t.setCapacity(200)
    discard t.decodeEncoderInstructions("\x41a\x01b", 4096)   # abs 0 = (a,b)
    check t.decodeEncoderInstructions("\x00", 4096) == 1      # 000 00000: dup 0
    check t.insertCount == 2
    check t.get(1) == ("a", "b")

  test "a partial trailing instruction is left buffered":
    var t: QpackDynTable
    t.setCapacity(200)
    let buf = "\x41a\x01b\xC1"              # one complete insert + a truncated one
    check t.decodeEncoderInstructions(buf, 4096) == 4
    check t.insertCount == 1

  test "an oversized capacity is a protocol error, not treated as incomplete":
    # A complete Set Dynamic Table Capacity whose value overflows the integer
    # decoder must raise (not be buffered as a partial instruction).
    var t: QpackDynTable
    expect QpackError:
      discard t.decodeEncoderInstructions("\x3F\x80\x80\x80\x80\x01", 4096)

suite "QPACK field-section decode":
  test "static indexed (RIC 0) still decodes":
    var t: QpackDynTable                   # empty = capacity-0 mode
    var h: seq[(string, string)]
    check decodeFieldSection("\x00\x00\xC0", 0, 3, h, t) == 0   # indexed static 0
    check h == @[(":authority", "")]

  test "dynamic indexed field line":
    var t: QpackDynTable
    t.setCapacity(200)
    discard t.insert(":method", "GET")     # abs 0
    var h: seq[(string, string)]
    # prefix RIC=1 (enc 2), base=1 (S0,delta0); indexed dynamic index 0.
    check decodeFieldSection("\x02\x00\x80", 0, 3, h, t) == 1
    check h == @[(":method", "GET")]

  test "post-base indexed field line":
    var t: QpackDynTable
    t.setCapacity(200)
    discard t.insert(":method", "GET")     # abs 0
    var h: seq[(string, string)]
    # RIC=1, base=0 (S1,delta0); post-base index 0 -> abs 0.
    check decodeFieldSection("\x02\x80\x10", 0, 3, h, t) == 1
    check h == @[(":method", "GET")]

  test "literal field line with dynamic name reference":
    var t: QpackDynTable
    t.setCapacity(200)
    discard t.insert("x", "1")             # abs 0
    var h: seq[(string, string)]
    # RIC=1, base=1; literal w/ dynamic name index 0, value "2".
    discard decodeFieldSection("\x02\x00\x40\x012", 0, 5, h, t)
    check h == @[("x", "2")]

  test "a dynamic reference with an empty table is an error":
    var t: QpackDynTable                   # capacity 0
    var h: seq[(string, string)]
    expect QpackError:
      discard decodeFieldSection("\x02\x00\x80", 0, 3, h, t)

  test "static encoder round-trips through the decoder":
    var enc = ""
    addPrefix(enc)
    encodeStatus(enc, 200)
    encodeHeader(enc, "content-type", "text/plain")
    encodeHeader(enc, "x-custom", "hi")
    var h: seq[(string, string)]
    var t: QpackDynTable
    discard decodeFieldSection(enc, 0, enc.len, h, t)
    check h == @[(":status", "200"), ("content-type", "text/plain"),
                 ("x-custom", "hi")]

echo "qpack dynamic table ok"
