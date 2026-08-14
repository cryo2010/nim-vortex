# HTTP/3 WebSocket conformance (RFC 9220)

Verifies vortex's HTTP/3 Extended CONNECT WebSocket support end to end, using
[aioquic](https://github.com/aiortc/aioquic) (the reference RFC 9220-capable
QUIC/HTTP/3 stack) as the client. There is no browser or `curl` that speaks
WebSockets over HTTP/3, so this stands in for the h1 Autobahn / h2 frame-level
coverage.

## Running

```sh
nimble h3websocket      # or: sh conformance/h3websocket/run.sh
```

Needs Docker. `run.sh` builds two images and connects them over a private
docker network (QUIC is UDP):

- **server** (`Dockerfile`, `echo_server.nim`) — a vortex HTTP/3 WebSocket
  echo server on `archlinux` (for OpenSSL >= 3.5, which ngtcp2's ossl crypto backend
  needs). It advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` and echoes each
  message with its kind.
- **client** (`client.Dockerfile`, `client.py`) — an aioquic client that
  opens an Extended CONNECT WebSocket and checks: the 200 handshake, text and
  binary echo, ping→pong, subprotocol negotiation, a fragmented message, and
  the close handshake. It exits non-zero (failing the run) on any mismatch.

The WebSocket framing in `client.py` is hand-rolled so the test owns exactly
what goes on the wire; aioquic supplies only the QUIC + HTTP/3 transport.
