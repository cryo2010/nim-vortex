# Reverse-proxy interop (nginx / caddy / HAProxy)

Stands each reverse proxy in front of the vortex origin and verifies the core
features work **through the proxy**: TLS, every HTTP method, streaming (up +
down), SSE, and WebSockets. This hardens vortex's HTTP/1.1 **origin** behavior
against three battle-tested proxies, the most common production topology.

```
client --TLS (h1/h2/h3)--> proxy (nginx|caddy|haproxy) --HTTP/1.1--> vortex origin
```

```sh
nimble proxy                 # all three proxies
PROXY=nginx nimble proxy     # one proxy
PROXY_PROTOS="h1 h2" nimble proxy
```

A green run ends with `RESULT: proxy interop passed`.

## What it reuses

- **Origin**: the stress server (`conformance/stress/stress_server.nim`) built
  `-d:plainHttp` (cleartext h1), serving `/plaintext`, `/echo` (all methods),
  `/ws`, `/sse`, `/upload`, `/download`, `/whoami`.
- **Client**: the stress client (`conformance/stress/client`), pointed at the
  proxy via `STRESS_BASE`. Feature checks map to stress workloads: `methods`,
  `streamupload`, `streamdownload`, `sse`, `ws`. The client's protocol pin makes
  the client<->proxy leg provably h1/h2/h3.
- **Certs**: one minted CA -> proxy server cert (the client's TLS check validates
  the chain with `curl --cacert`).

## Configuration

| Var | Default | Meaning |
|-----|---------|---------|
| `PROXY` | `all` | `nginx` \| `caddy` \| `haproxy` \| `all` |
| `PROXY_PROTOS` | `h1 h2 h3` | client<->proxy protocols to drive |
| `VORTEX_SECONDS` | `3` | per-cell runtime |
| `VORTEX_STREAM_BYTES` | `8 MiB` | streaming transfer size |
| `VORTEX_RUN_ID` | this PID | docker network/container/image isolation id |

## Sparse matrix

Unsupported cells render `n/a` (never dialed):

- **`ws` is h1 only** -- proxies do not translate h2/h3 Extended CONNECT into an
  h1 upstream WebSocket Upgrade.
- **`streamupload` x h3 = n/a** -- vortex does not yet ack HTTP/3 request-body
  flow control (`h3AckBody` gap); the client already skips it.
- **h3 for a proxy whose image lacks a QUIC bind = n/a** -- nginx (>=1.25) and
  caddy serve h3; HAProxy needs a QUIC-enabled build, so run.sh starts it with a
  `bind quic4@` and, if the container fails readiness (a config it can't accept),
  restarts it without the QUIC bind and marks h3 `n/a`. The probe checks that the
  QUIC bind config is *accepted*, not that the QUIC listener actually serves h3;
  if the bind is accepted the h3 cells run and would fail loudly if h3 were
  broken.

## HAProxy PROXY-protocol check

For HAProxy only, an extra scenario starts the origin with
`STRESS_PROXY_PROTOCOL=require` and a `send-proxy-v2` backend, then asserts
`GET /whoami` returns a real client IP. Because `require` drops any connection
without a valid PROXY header, a 200 proves vortex's `proxyprotocol.nim` parsed
the header HAProxy prepended.

## Notes

- Proxy images are official and pinned (`nginx:1.27`, `caddy:2.11.4-alpine`,
  `haproxy:3.0`); the origin/client images build from the repo (cached vortex
  layers). Pinning by digest is a reasonable follow-up hardening.
- Caddy must be >= 2.9 for the h3 `methods` cell. The client sends some h3 POST
  bodies without a `Content-Length` header, and quic-go (caddy's HTTP/3 server)
  < v0.47 left `req.ContentLength = 0` for such requests; Go's reverse proxy then
  treats that as "no body" and forwards zero bytes upstream, so vortex echoed an
  empty body. Fixed by quic-go [#4645](https://github.com/quic-go/quic-go/pull/4645)
  (v0.47.0), shipped in caddy 2.9.0 (quic-go v0.48.2). Not a vortex or caddy-code
  bug -- nginx handled it correctly. Pinned `caddy:2.11.4-alpine`.
- This is a functional pass/fail suite, not a benchmark. Client<->proxy is TLS;
  proxy<->vortex is cleartext h1. Upstream-over-TLS is out of scope for now.
