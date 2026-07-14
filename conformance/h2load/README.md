# Load/stress smoke (h2load)

Fires many concurrent HTTP/1.1 and HTTP/2 (h2c prior-knowledge) requests at a
vortex server with [h2load](https://nghttp2.org/documentation/h2load-howto.html)
(nghttp2's load tester) and fails if any request does not complete with a 2xx.

This is **not** a benchmark — CI throughput numbers are too noisy to gate on.
It stress-tests the event loop, connection lifecycle, and concurrency, catching
hangs, dropped requests, or crashes under load that the functional tests
(single connection at a time) do not.

## Running

```sh
nimble h2load      # or: sh conformance/h2load/run.sh
```

Needs Docker. `run.sh` builds two images and connects them over a private
docker network:

- **server** (`Dockerfile`, `h2load_server.nim`) — an always-200 vortex server
  built `-d:plainHttp` (plain HTTP, no OpenSSL), one loop per core.
- **client** (`client.Dockerfile`) — `nghttp2-client` (provides `h2load`).

It runs two rounds (HTTP/2 then HTTP/1.1); the run fails if h2load reports any
failed, errored, or timed-out request, or any non-2xx status. Override the load
with `H2LOAD_REQUESTS` / `H2LOAD_CONNS`.
