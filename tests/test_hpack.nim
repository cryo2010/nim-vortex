import std/[unittest, strutils]
import vortex/http2/hpack

proc fromHex(s: string): string =
  result = newString(s.len div 2)
  for i in 0 ..< result.len:
    result[i] = char(parseHexInt(s[2*i .. 2*i+1]))

proc decode(d: var HpackDecoder, hexData: string): seq[(string, string)] =
  let data = fromHex(hexData)
  d.decodeHeaderBlock(data, 0, data.len, result)

suite "hpack decoding (RFC 7541 Appendix C)":
  test "C.2.1 literal with indexing":
    var d = initHpackDecoder()
    check decode(d, "400a637573746f6d2d6b65790d637573746f6d2d686561646572") ==
      @[("custom-key", "custom-header")]

  test "C.2.2 literal without indexing":
    var d = initHpackDecoder()
    check decode(d, "040c2f73616d706c652f70617468") ==
      @[(":path", "/sample/path")]

  test "C.2.3 literal never indexed":
    var d = initHpackDecoder()
    check decode(d, "100870617373776f726406736563726574") ==
      @[("password", "secret")]

  test "C.2.4 indexed field":
    var d = initHpackDecoder()
    check decode(d, "82") == @[(":method", "GET")]

  test "C.3 request sequence without huffman":
    var d = initHpackDecoder()
    check decode(d, "828684410f7777772e6578616d706c652e636f6d") == @[
      (":method", "GET"), (":scheme", "http"), (":path", "/"),
      (":authority", "www.example.com")]
    check decode(d, "828684be58086e6f2d6361636865") == @[
      (":method", "GET"), (":scheme", "http"), (":path", "/"),
      (":authority", "www.example.com"), ("cache-control", "no-cache")]
    check decode(d, "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565") == @[
      (":method", "GET"), (":scheme", "https"), (":path", "/index.html"),
      (":authority", "www.example.com"), ("custom-key", "custom-value")]

  test "C.4 request sequence with huffman":
    var d = initHpackDecoder()
    check decode(d, "828684418cf1e3c2e5f23a6ba0ab90f4ff") == @[
      (":method", "GET"), (":scheme", "http"), (":path", "/"),
      (":authority", "www.example.com")]
    check decode(d, "828684be5886a8eb10649cbf") == @[
      (":method", "GET"), (":scheme", "http"), (":path", "/"),
      (":authority", "www.example.com"), ("cache-control", "no-cache")]
    check decode(d, "408825a849e95ba97d7f8925a849e95bb8e8b4bf") == @[
      ("custom-key", "custom-value")]

  test "C.6 response sequence with huffman and eviction":
    var d = initHpackDecoder(settingsMax = 256)
    check decode(d, "488264025885aec3771a4b6196d07abe941054d444a8200595040b81" &
                    "66e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3") == @[
      (":status", "302"), ("cache-control", "private"),
      ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
      ("location", "https://www.example.com")]
    check decode(d, "4883640effc1c0bf") == @[
      (":status", "307"), ("cache-control", "private"),
      ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
      ("location", "https://www.example.com")]
    check decode(d, "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a" &
                    "839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f36" &
                    "72c1ab270fb5291f9587316065c003ed4ee5b1063d5007") == @[
      (":status", "200"), ("cache-control", "private"),
      ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
      ("location", "https://www.example.com"), ("content-encoding", "gzip"),
      ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")]

  test "malformed input raises":
    var d = initHpackDecoder()
    expect HpackError: discard decode(d, "80")      # index 0
    expect HpackError: discard decode(d, "ff")      # truncated integer
    expect HpackError: discard decode(d, "0a")      # truncated string

suite "hpack encoding":
  test "roundtrip through our decoder":
    var buf = ""
    encodeStatus(buf, 200)
    encodeHeader(buf, "content-type", "text/plain")
    encodeHeader(buf, "x-custom", "abc")
    var d = initHpackDecoder()
    var headers: seq[(string, string)]
    d.decodeHeaderBlock(buf, 0, buf.len, headers)
    check headers == @[(":status", "200"), ("content-type", "text/plain"),
                       ("x-custom", "abc")]

  test "non-static status roundtrip":
    var buf = ""
    encodeStatus(buf, 418)
    var d = initHpackDecoder()
    var headers: seq[(string, string)]
    d.decodeHeaderBlock(buf, 0, buf.len, headers)
    check headers == @[(":status", "418")]
