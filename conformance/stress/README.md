# Stress test (k6 + Grafana/Prometheus)

A configurable, time-boxed load test that drives a chosen vortex backend (or all
of them) with [k6](https://k6.io) and streams live throughput / latency / error
charts to Grafana. Unlike `conformance/h2load` and `conformance/h3load` (pass/fail
smoke checks), this is an interactive tool for watching the server under load and
comparing backends over time.

```sh
sh conformance/stress/run.sh          # or: nimble stress
```

Then open **http://localhost:3000** (Grafana, anonymous admin) and select the
dashboard **"vortex stress (k6)"**. Prometheus retains history, so successive
runs stay comparable via the **test id** dashboard variable.

## Watching charts in real time

The Grafana/Prometheus stack starts *before* k6, so open the dashboard as soon
as `run.sh` prints "starting Prometheus + Grafana" and watch data stream in.
Give the run enough time to watch:

```sh
BACKEND=h2 MODE=throughput DURATION=5m VUS=200 nimble stress
```

The dashboard auto-refreshes every **1s** over a `now-5m` window, and k6 pushes
metrics on a **1s** interval (`K6_PROMETHEUS_RW_PUSH_INTERVAL`), so the charts
track roughly a second behind live. The `Request rate` and latency panels update
the smoothest; percentiles step once per push. `BACKEND=all` runs backends
sequentially, so their series appear one after another (each its own `test id`),
not concurrently.

### Extending the runtime

`DURATION` takes any k6 duration string and sets how long each backend runs:

```sh
DURATION=10m nimble stress            # ten minutes
DURATION=1h  nimble stress            # one hour
DURATION=1h30m BACKEND=h2 nimble stress
BACKEND=all DURATION=2m nimble stress  # 2m per backend -> ~6m total
```

There is no fixed cap; the run ends when `DURATION` elapses (throughput mode) or
after holding `RATE` for `DURATION` (rate mode). Prometheus keeps 15 days of
history (`--storage.tsdb.retention.time` in `docker-compose.yml`).

## Configuration

All knobs are environment variables:

| Var        | Values                        | Default      | Meaning                                   |
|------------|-------------------------------|--------------|-------------------------------------------|
| `BACKEND`  | `h1` `h2` `h2-gzip` `all`     | `h1`         | Which server backend(s) to drive          |
| `RUNTIME`  | `sync` `async` `async-await` `chronos` `chronos-await` `all` | `sync` | Handler execution model |
| `MODE`     | `throughput` `rate`           | `throughput` | Saturate for the ceiling, or hold a rate  |
| `DURATION` | k6 duration (`30s`, `2m`, …)  | `30s`        | How long to run                           |
| `VUS`      | integer                       | `50`         | Virtual users (throughput mode)           |
| `RATE`     | integer                       | `5000`       | Target req/s (rate mode)                   |
| `ENDPOINT` | `/plaintext` `/json` `/big`   | `/plaintext` | Path to hit (`/big` is ~9 KB, compressible)|

### Backends

| name      | build            | protocol            | port   |
|-----------|------------------|---------------------|--------|
| `h1`      | `-d:plainHttp`   | HTTP/1.1 cleartext  | 8080   |
| `h2`      | default (TLS)    | HTTP/2 over TLS     | 8443   |
| `h2-gzip` | `-d:httpGzip`    | HTTP/2 + gzip       | 8443   |

The server (`stress_server.nim`) serves the same `/plaintext` and `/json`
handlers as `bench/handlers.nim`, plus `/big` for exercising compression.

### Handler execution model (`RUNTIME`)

An orthogonal axis: how the handler is dispatched. Selected by a build-time flag
(the adapters can't share a binary), so each variant is its own server image.

| `RUNTIME`       | Handler                                                        |
|-----------------|---------------------------------------------------------------|
| `sync`          | plain `{.gcsafe.}` handler, `res.send` (the future-agnostic core) |
| `async`         | asyncdispatch adapter, `{.async.}` handler that never suspends |
| `async-await`   | asyncdispatch adapter, one real `await` (suspend) per request  |
| `chronos`       | chronos adapter, `{.async.}` handler that never suspends       |
| `chronos-await` | chronos adapter, one real `await` (suspend) per request        |

`chronos`/`chronos-await` pull chronos into the server image at build time
(`nimble install chronos`); the others need no extra dependency. `async`/`chronos`
measure the adapter's overhead versus `sync`; the `-await` variants add a forced
loop suspend/resume per request (the worst case). `RUNTIME=all` builds and runs
all five; combined with `BACKEND=all` that is 15 runs (each its own `test id`).

### Examples

```sh
# Find the h2 ceiling for 1 minute with 200 VUs
BACKEND=h2 MODE=throughput DURATION=1m VUS=200 sh conformance/stress/run.sh

# Compare all three backends back-to-back (side by side in Grafana)
BACKEND=all DURATION=30s sh conformance/stress/run.sh

# Compare the handler execution models on h2 (sync vs the adapters)
BACKEND=h2 RUNTIME=all DURATION=30s sh conformance/stress/run.sh

# The adapter tax of a suspending chronos handler vs plain sync, h2
BACKEND=h2 RUNTIME=chronos-await DURATION=1m sh conformance/stress/run.sh
BACKEND=h2 RUNTIME=sync          DURATION=1m sh conformance/stress/run.sh

# Hold 10k req/s at h2 and watch latency under load
BACKEND=h2 MODE=rate RATE=10000 DURATION=2m sh conformance/stress/run.sh

# See gzip's effect: compare h2 vs h2-gzip on the compressible endpoint
BACKEND=h2      ENDPOINT=/big sh conformance/stress/run.sh
BACKEND=h2-gzip ENDPOINT=/big sh conformance/stress/run.sh

# Stop Grafana/Prometheus (add -v to also drop retained history)
sh conformance/stress/run.sh --down
sh conformance/stress/run.sh --down -v
```

## Keeping k6 (not the server) honest

k6 is convenient and scriptable but slower per core than a native client, so at
very high request rates **k6 itself can become the bottleneck** before the server
does. The script already minimizes client cost (`discardResponseBodies`, a single
request + check, connection reuse). If you push hard, watch the dashboard:

- **Dropped iterations/s > 0** (rate mode) means k6 can't keep up — the number is
  a client limit, not a server limit. Give the k6 container more CPU, or measure
  the raw ceiling with `conformance/h2load` instead.
- **Virtual users** pinned at the max with flat request rate means the same.

### k6 client memory on long, fast runs

k6 retains a sample per request for its metrics, so its memory grows with the
**total** request count — roughly **1 GiB per minute at ~130k req/s**, regardless
of push interval or `--no-summary` (it is the client's Trend sinks, not the
Prometheus output, which stays flat now that latency ships as a native
histogram). A long high-rate run can therefore exhaust Docker's memory and the
k6 container gets OOM-killed (exit 137); `run.sh` reports this explicitly. The
**vortex server is unaffected** — it holds flat at ~45 MiB throughout.

Rule of thumb: keep `DURATION × req/s` within your Docker memory. To go longer or
faster, raise Docker Desktop's memory limit, lower `VUS`/`RATE`, split one long
run into several shorter ones (Prometheus keeps the history), or use
`conformance/h2load` for a pure ceiling number without the metrics overhead.

Latency is recorded as a **Prometheus native histogram**
(`k6_http_req_duration_seconds`); the dashboard reads percentiles with
`histogram_quantile`, which keeps Prometheus ingestion cheap even at high rates.

## Limitations

k6 cannot drive **HTTP/3 (QUIC)**, and its HTTP/2 client requires TLS, so **h2c**
(cleartext HTTP/2) is out of reach too. Those protocols are covered by:

- `conformance/h3load` — real ngtcp2/nghttp3 QUIC client (HTTP/3)
- `conformance/h2load` — nghttp2 `h2load` (h2c and HTTP/1.1)

This tool is intentionally not wired into CI (it is interactive and the Grafana
stack is meant to stay up); it complements the pass/fail load smokes there.
