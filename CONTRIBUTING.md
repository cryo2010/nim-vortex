# Contributing to vortex

Thanks for your interest in vortex. This guide covers the prerequisites
and, in detail, how to run the tests and benchmarks.

## Prerequisites

- **Nim >= 2.2.10** and a C compiler (gcc or clang).
- **OpenSSL >= 3.5** at build and run time for TLS, HTTP/2 over TLS, and
  HTTP/3 (the QUIC server API landed in 3.5). Build with `-d:plainHttp`
  for a zero-dependency cleartext build (HTTP/1.1 + h2c) that does not
  link OpenSSL at all.
- The suite builds with `--mm:orc --threads:on -d:ssl`. `tests/config.nims`
  sets those, so `nimble test` needs no extra flags; keep them in mind
  when compiling a single test file by hand.
- **Docker** for the manual conformance and fuzz checks (`nimble redbot`,
  `nimble fuzz`), which package their toolchains in an image. Both also
  have host-only paths (`sh conformance/run.sh`, `sh fuzz/run.sh`) if you
  would rather not use Docker.

vortex is developed and tested on Linux and macOS. Windows is not yet
supported.

## Testing

### Unit and integration tests

```sh
nimble test
```

runs the full default suite with no dependencies beyond `curl` and
OpenSSL:

- RFC-vector unit tests for the HTTP/1.1 parser and the HPACK / QPACK
  codecs.
- Integration suites driven against a live server for HTTP/1.1, HTTP/2
  (via `curl --http2-prior-knowledge`), HTTP/3 (via an HTTP/3-capable
  `curl`, self-skipping when none is present), TLS, the `blocking:`
  worker pool, the router, and the response framing codec.
- Security suites: request-smuggling and integer-overflow parsing checks,
  plus live DoS-defense checks (Rapid Reset, framing floods, decompression
  bombs, slowloris, oversized requests, connection caps).

To run one file, compile it with the same flags the suite uses:

```sh
nim c -r --mm:orc --threads:on -d:ssl -p:src tests/test_http1_parser.nim
```

CI also compiles the zero-dependency variant to keep the OpenSSL-free
path healthy; run it locally with:

```sh
nim c --mm:orc --threads:on -d:plainHttp -o:/tmp/vortex_plain src/vortex.nim
```

### chronos adapter test

The chronos async adapter has its own suite, kept out of `nimble test`
because chronos is an opt-in dependency rather than a vortex requirement:

```sh
nimble testchronos      # installs chronos, then runs tests/chronos_adapter.nim
```

### Manual tests

These use external tools and are not part of `nimble test`.

**HTTP/1.1 conformance (REDbot).** The simplest path needs only Docker:

```sh
nimble redbot           # builds an image bundling Nim + REDbot, runs the check
```

It runs [REDbot](https://redbot.org) against a live server and exits
non-zero on any BAD-level finding. On a host with REDbot installed
(`pipx install redbot`) you can skip Docker with `sh conformance/run.sh`.
See [conformance/README.md](conformance/README.md).

**HTTP/2 conformance (h2spec).** Start a TLS server, then point
[h2spec](https://github.com/summerwind/h2spec) at it:

```sh
h2spec -t -k -p <port>
```

vortex passes 145/146 (1 skipped, 0 failed).

**Fuzzing.** Fuzz the HTTP/1.1 parser and the HPACK / QPACK decoders with
libFuzzer. The simplest path needs only Docker:

```sh
nimble fuzz             # build an image with clang + libFuzzer, fuzz each target
```

`fuzz/Dockerfile` bundles clang and the libFuzzer runtime, fuzzes each
target for 30s by default, and exits non-zero on a crash. Override the
duration or pick targets on the `docker run`:

```sh
docker run --rm -e DUR=120 vortex-fuzz      # 120s per target
docker run --rm vortex-fuzz hpack           # a single target
```

On a host with clang and compiler-rt (the libFuzzer runtime) you can skip
Docker with `sh fuzz/run.sh` (`DUR=60 sh fuzz/run.sh`, or a target name to
narrow it). Apple clang does not ship libFuzzer, so macOS hosts want the
Docker path or Homebrew LLVM.

### Benchmarks

Benchmark numbers are only meaningful on **Linux**. Linux `SO_REUSEPORT`
balances incoming connections across the per-thread listeners; macOS
delivers them all to a single listener, so multi-thread scaling does not
show up there. `bench/Dockerfile` provides a ready Arch environment.

Build and drive the benchmark server directly:

```sh
nimble bench            # builds bench/handlers (TechEmpower-style /plaintext, /json)
./bench/handlers 8080   # serve on a port
sh bench/run.sh         # drive load: wrk / oha / ab, plus h2load for HTTP/2
```

`bench/run.sh` honors `PORT`, `DUR`, and `CONNS` environment variables.

Comparison benchmarks pit vortex against httpbeast, std/asynchttpserver,
and chronos. The task requirements (httpbeast, chronos) install
automatically:

```sh
nimble perf             # HTTP/1.1 throughput comparison table
nimble perf2            # HTTP/2 throughput
nimble h3load           # HTTP/3 throughput (real QUIC client, Docker)
```

`nimble h3load` drives the HTTP/3 server with a real QUIC client (h2load built
with ngtcp2 + nghttp3); see [conformance/h3load](conformance/h3load). There is
no in-process HTTP/3 benchmark -- a hand-rolled QUIC client is client-bound and
under-reports the server.

For representative Linux HTTP/1.1 and HTTP/2 numbers, run them in Docker:

```sh
docker build -f bench/Dockerfile -t vortex-bench .
# x86_64 hosts add: --build-arg BASE=archlinux:latest
docker run --rm vortex-bench                     # HTTP/1.1 comparison table
docker run --rm vortex-bench ./bench/perf_http2  # HTTP/2
```

Emulated or shared environments are noisy: run a benchmark a few times
and compare, rather than trusting a single figure.

## Before you open a PR

- `nimble test` passes.
- If you touched TLS, HTTP/2, HTTP/3, or OpenSSL usage, confirm the
  `-d:plainHttp` build still compiles.
- If you touched the HTTP/1.1 response path, `nimble redbot` still comes
  back clean.
- Use semantic branch names and commit messages (for example
  `fix/...`, `feat/...`, `docs/...`).
