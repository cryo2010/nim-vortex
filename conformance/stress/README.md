# Stress test (h2load + Grafana/Prometheus)

Saturation stress test: [h2load](https://nghttp2.org/documentation/h2load.1.html)
fires as many requests as it can at a vortex backend while Grafana shows the
**server container's own CPU and memory** (sampled from `docker stats`) live, and
the **achieved req/s** as a summary. h2load is the driver instead of k6 so the
client is not the bottleneck at saturation.

Companion to `nimble loadtest` (k6): loadtest *holds a chosen load* and charts
client-side latency; stress *saturates* and charts the server.

```sh
sh conformance/stress/run.sh          # or: nimble stress
```

Then open **http://localhost:3001** (Grafana, anonymous admin) and select the
dashboard **"vortex stress (h2load)"**. (Its own ports — 3001/9190/9191 — so it
never clashes with the loadtest stack on 3000/9090/9091.)

## What you see, and why

- **Live: Server CPU (cores) and Server memory (RSS)** — the point of a
  saturation test is to watch the *server* under maximum load. These stream from
  `docker stats` via a Pushgateway.
- **Summary: Achieved req/s, requests total/succeeded** — shown as stat panels,
  one value per backend. This is *not* a live curve on purpose: h2load (like
  wrk) reports only a final summary, so a live rate would mean restarting it in
  short windows, which breaks the sustained saturation the test exists to create.
  End-of-run req/s is the honest way these tools report throughput.

Use the server CPU chart to read headroom: if req/s is high while CPU sits under
the core count, the client (or the network) is the limit; if CPU is pinned, the
server is.

## Configuration

| Var        | Values                        | Default      | Meaning                              |
|------------|-------------------------------|--------------|--------------------------------------|
| `BACKEND`  | `h1` `h2` `h2-gzip` `all`     | `h1`         | Which backend(s) to saturate         |
| `DURATION` | seconds                       | `30`         | How long to saturate (h2load `-D`)   |
| `CONNS`    | integer                       | `100`        | Concurrent connections (`-c`)        |
| `STREAMS`  | integer                       | `32`         | Concurrent streams/conn, h2 (`-m`)   |
| `ENDPOINT` | `/plaintext` `/json` `/big`   | `/plaintext` | Path to hit (`/big` for gzip)        |

### Backends

| name      | build          | h2load drives            | port |
|-----------|----------------|--------------------------|------|
| `h1`      | `-d:plainHttp` | HTTP/1.1 (`--h1`)        | 8080 |
| `h2`      | default (TLS)  | HTTP/2 over TLS (`-m`)   | 8443 |
| `h2-gzip` | `-d:httpGzip`  | HTTP/2 + gzip (`-H accept-encoding:gzip`) | 8443 |

The server is the shared `conformance/loadtest/loadtest_server.nim` (same
`/plaintext`, `/json`, `/big` handlers), built here as a plain sync `-d:danger`
binary.

### Examples

```sh
# Saturate h2 over TLS for a minute with 200 connections
BACKEND=h2 DURATION=60 CONNS=200 sh conformance/stress/run.sh

# Compare all backends' ceilings back-to-back
BACKEND=all sh conformance/stress/run.sh

# Push h1 hard and watch the server's cores pin
BACKEND=h1 CONNS=400 DURATION=60 sh conformance/stress/run.sh

# Exercise gzip under load (compressible body)
BACKEND=h2-gzip ENDPOINT=/big sh conformance/stress/run.sh

# Stop Grafana/Prometheus (add -v to also drop retained history)
sh conformance/stress/run.sh --down
sh conformance/stress/run.sh --down -v
```

## Limitations

- h2load drives HTTP/1.1, h2c, and HTTP/2-over-TLS. For **HTTP/3** saturation use
  `conformance/h3load` (a real QUIC client).
- On Docker Desktop the `docker stats` figures reflect the shared Linux VM, so
  read them as relative/trend rather than absolute host numbers.
- Interactive tool, not a CI gate (the Grafana stack is meant to stay up).
