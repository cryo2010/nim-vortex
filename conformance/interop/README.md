# Cross-client interop test

Drives a single vortex server with **real HTTP clients from five ecosystems**,
each using that ecosystem's standard HTTP library, over **HTTP/2 + TLS with
gzip**, exercising **every HTTP method**. It catches interop regressions that a
single client (or curl) would miss — header casing, ALPN negotiation, gzip
framing, flow control, trailers, and mTLS — because each library stresses the
wire protocol slightly differently.

| Backend | Library | HTTP/2 | gzip check |
|---------|---------|--------|------------|
| node    | built-in `http2` module      | native | gunzips itself |
| python  | `httpx[http2]` (h2 backend)   | asserted via `http_version` | transparent, round-trip |
| go      | stdlib `net/http` (ALPN)     | asserted via `resp.Proto`   | gunzips itself |
| rust    | `reqwest` + `tokio`          | asserted via `resp.version()` | transparent, round-trip |
| java    | `java.net.http.HttpClient`   | pinned + asserted via `version()` | gunzips itself |

Each client, for the whole run window, cycles `GET POST PUT PATCH DELETE HEAD
OPTIONS` against `/echo`, asserting a `200`, that the negotiated protocol is
HTTP/2, and that the response round-trips (the padded body decompresses back to
`method=<M>`; `HEAD` is checked via the `X-Echo-Method` header since it carries
no body). A request-gating middleware on the server rejects anything without
`X-Api-Key: interop`, so the clients also prove header round-tripping.

## Running

```sh
nimble interop     # or: sh conformance/interop/run.sh
```

Needs Docker, plus `openssl` on the host to mint the certs. `run.sh`:

1. Generates a throwaway **CA** and, signed by it, a **server** cert
   (`SAN DNS:server`) and a **client** cert, shared with every container via a
   read-only `/certs` mount (so they all trust the same CA). Written to
   `conformance/interop/certs/` (git-ignored) and removed on exit.
2. Builds the vortex server image (`Dockerfile`, `interop_server.nim`, built
   `-d:ssl -d:httpGzip` for TLS + gzip) and the five client images.
3. Starts the server on a private docker network, then does an independent
   `curl --http2` check asserting `HTTP/2 200` **and** `Content-Encoding: gzip`.
4. Runs each backend **sequentially** (so total wall time ≈ runtime × 5),
   distributing the client budget evenly across the five.

The run fails if any backend reports an error or a failed assertion.

## Env knobs

| Var | Default | Meaning |
|-----|---------|---------|
| `INTEROP_RUNTIME` | `5`  | seconds each backend runs (total ≈ ×5 backends) |
| `INTEROP_CLIENTS` | `10` | total concurrent clients, split evenly (min 1 each) |
| `INTEROP_MTLS`    | `0`  | `1` = require + present client certs; each client also checks `/whoami` reports its cert subject |

```sh
INTEROP_MTLS=1 INTEROP_RUNTIME=10 INTEROP_CLIENTS=20 nimble interop
```
