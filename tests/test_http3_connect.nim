## Unit tests for the HTTP/3 (RFC 9220) Extended CONNECT header classifier.
## The QUIC round trip is covered by the aioquic conformance harness
## (conformance/h3websocket); this locks the pseudo-header validation, which
## needs no live connection. Excluded from the zero-dependency plainHttp build
## (the h3 codec is not compiled there).

import std/unittest

when not defined(plainHttp):
  import vortex/http3/ngtcp2/backend

  suite "HTTP/3 Extended CONNECT classification (RFC 9220)":
    test "a normal request is classified as a request":
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/"),
         (":authority", "example.com")]) == h3hRequest

    test "an https request needs an authority (:authority or Host)":
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/")]) == h3hInvalid
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/"),
         ("host", "example.com")]) == h3hRequest

    test "a duplicated pseudo-header is invalid":
      check classifyH3Headers(
        [(":method", "GET"), (":method", "POST"), (":scheme", "https"),
         (":path", "/"), (":authority", "x")]) == h3hInvalid

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

    test "CONNECT carrying :scheme/:path is invalid (RFC 9113 8.5, #240.5)":
      # The shape 8.5 forbids. It used to satisfy the generic :scheme/:path
      # checks and dispatch as an ordinary request.
      check classifyH3Headers(
        [(":method", "CONNECT"), (":scheme", "https"), (":path", "/"),
         (":authority", "example.com")]) == h3hInvalid

    test "an unknown method is invalid, never a silent GET (#240.4)":
      check classifyH3Headers(
        [(":method", "PURGE"), (":scheme", "https"), (":path", "/"),
         (":authority", "x")]) == h3hInvalid
      check classifyH3Headers(
        [(":method", "GET X"), (":scheme", "https"), (":path", "/"),
         (":authority", "x")]) == h3hInvalid

    test "a field value starting or ending with SP/HTAB is invalid (#240.7)":
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/"),
         (":authority", "x"), ("x-ws", " v")]) == h3hInvalid
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/"),
         (":authority", "x"), ("x-ws", "v\t")]) == h3hInvalid

    test "a pseudo-header after a regular header is invalid":
      check classifyH3Headers(
        [(":method", "GET"), ("x-foo", "bar"), (":path", "/")]) == h3hInvalid

    test "an uppercase header name is invalid":
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/"),
         ("X-Foo", "bar")]) == h3hInvalid

    test "NUL/CR/LF in a field value is invalid (shared with h2, RFC 9114 4.1.2)":
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/"),
         (":authority", "x"), ("x-bad", "a\x00b")]) == h3hInvalid
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/"),
         (":authority", "x"), ("x-bad", "a\r\nb")]) == h3hInvalid

    test "a separator in a field name is invalid (shared token rules)":
      check classifyH3Headers(
        [(":method", "GET"), (":scheme", "https"), (":path", "/"),
         (":authority", "x"), ("x(bad)", "v")]) == h3hInvalid

    test "an unknown websocket subprotocol still classifies (negotiation later)":
      check classifyH3Headers(
        [(":method", "CONNECT"), (":protocol", "websocket"),
         (":scheme", "https"), (":path", "/"), (":authority", "x"),
         ("sec-websocket-protocol", "chat")]) == h3hWebSocket

else:
  echo "SKIP: plainHttp build has no HTTP/3"
