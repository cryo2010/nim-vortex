## Unit tests for the HTTP/3 (RFC 9220) Extended CONNECT header classifier.
## The QUIC round trip is covered by the aioquic conformance harness
## (conformance/h3websocket); this locks the pseudo-header validation, which
## needs no live connection. Excluded from the zero-dependency plainHttp build
## (the h3 codec is not compiled there).

import std/unittest

when not defined(plainHttp):
  import vortex/http3/codec

  suite "HTTP/3 Extended CONNECT classification (RFC 9220)":
    test "a normal request is classified as a request":
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/")]) == h3hRequest

    test "Extended CONNECT websocket with authority is a websocket":
      check classifyH3Headers(
        [(":method", "CONNECT"), (":protocol", "websocket"),
         (":scheme", "https"), (":path", "/chat"),
         (":authority", "example.com")]) == h3hWebSocket

    test "websocket connect without authority is invalid":
      check classifyH3Headers(
        [(":method", "CONNECT"), (":protocol", "websocket"),
         (":scheme", "https"), (":path", "/chat")]) == h3hInvalid

    test "websocket connect without path is invalid":
      check classifyH3Headers(
        [(":method", "CONNECT"), (":protocol", "websocket"),
         (":scheme", "https"), (":authority", "example.com")]) == h3hInvalid

    test ":protocol on a non-CONNECT method is invalid":
      check classifyH3Headers(
        [(":method", "GET"), (":protocol", "websocket"),
         (":scheme", "https"), (":path", "/")]) == h3hInvalid

    test "plain CONNECT (no scheme/path) is invalid":
      check classifyH3Headers(
        [(":method", "CONNECT"), (":authority", "example.com")]) == h3hInvalid

    test "a pseudo-header after a regular header is invalid":
      check classifyH3Headers(
        [(":method", "GET"), ("x-foo", "bar"), (":path", "/")]) == h3hInvalid

    test "an uppercase header name is invalid":
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/"),
         ("X-Foo", "bar")]) == h3hInvalid

    test "an unknown websocket subprotocol still classifies (negotiation later)":
      check classifyH3Headers(
        [(":method", "CONNECT"), (":protocol", "websocket"),
         (":scheme", "https"), (":path", "/"), (":authority", "x"),
         ("sec-websocket-protocol", "chat")]) == h3hWebSocket

else:
  echo "SKIP: plainHttp build has no HTTP/3"
