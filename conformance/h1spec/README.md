# HTTP/1.1 conformance (h1spec)

Runs [dropseed/h1spec](https://github.com/dropseed/h1spec) — an HTTP/1.1
conformance tester in the spirit of h2spec (RFC 9112 / 9110) — against
vortex's HTTP/1.1 server. It checks request-line and target forms, header and
Host validation, body framing (chunked, Content-Length, Expect), response
semantics, connection handling, and hardening limits.

## Running

```sh
nimble h1spec      # or: sh conformance/h1spec/run.sh
```

Needs Docker. `run.sh` builds two images and connects them over a private
docker network:

- **server** (`Dockerfile`, `h1spec_server.nim`) — a trivial always-200
  vortex server built `-d:plainHttp` (plain HTTP, no OpenSSL).
- **client** (`client.Dockerfile`) — `h1spec`, pinned to a commit.

h1spec exits non-zero on any failing case, which fails the run. vortex passes
all cases (32/32), deterministically.

Note: h1spec exercises the `shutdown(SHUT_WR)` half-close pattern (send a
request, half-close the write side, read the response). A server that mishandles
that races the response and produces flaky results; vortex serves it reliably,
so the run is deterministic.
