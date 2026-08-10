# Package

version       = "0.1.0"
author        = "Craig Younker"
description   = "A fast HTTP/1.1, HTTP/2 and HTTP/3 server with TLS and WebSockets"
license       = "MIT"
srcDir        = "src"


# Dependencies

import std/strutils

requires "nim >= 2.2.10"

task bench, "Build benchmark server with release flags":
  exec "nim c --mm:orc --threads:on -d:danger --passC:-flto -o:bench/handlers bench/handlers.nim"

task docs, "Generate the public API documentation into htmldocs/":
  exec "nim doc --project --index:on --outdir:htmldocs src/vortex.nim"

proc ensureNimblePath() =
  ## The perf/testchronos tasks compile the third-party comparison servers
  ## (httpbeast, chronos, mummy) with a raw `nim c`, which resolves them from
  ## the global nimble package path. `nimble setup`/`install` regenerates
  ## nimble.paths with `--noNimblePath`, which disables that path and breaks
  ## the build (`cannot open file: pkg/chronos`); strip the line so the deps
  ## resolve. nimble.paths is machine-local, so this only touches local state.
  let p = "nimble.paths"
  if not fileExists(p): return
  var kept: seq[string]
  var changed = false
  for ln in readFile(p).splitLines():
    if ln.strip() == "--noNimblePath": changed = true
    elif ln.len > 0: kept.add ln
  if changed: writeFile(p, kept.join("\n") & "\n")

taskRequires "perf", "httpbeast >= 0.4.0"
taskRequires "perf", "chronos >= 4.0.0"
taskRequires "perf", "mummy >= 0.4.0"
taskRequires "perf", "powpow >= 0.1.8"

task perf, "Run the HTTP/1.1 throughput comparison benchmark":
  ensureNimblePath()
  var extra = ""
  when defined(macosx):
    # powpow links -lssl/-lcrypto directly (vortex loads OpenSSL dynamically),
    # so point the linker at Homebrew's OpenSSL. Missing -L dirs are ignored, so
    # listing both Apple-silicon and Intel prefixes is harmless.
    extra = " --passL:-L/opt/homebrew/lib --passL:-L/usr/local/lib"
  exec "nim c -r --mm:orc --threads:on -d:danger" & extra &
       " -o:bench/perf_http1_1 bench/perf_http1_1.nim"

taskRequires "perf2", "chronos >= 4.0.0"

task perf2, "Run the HTTP/2 throughput benchmark":
  ensureNimblePath()
  exec "nim c -r --mm:orc --threads:on -d:danger -o:bench/perf_http2 bench/perf_http2.nim"

# HTTP/3 throughput is measured with a real QUIC client via `nimble h3load`
# (conformance/h3load, Docker): an in-process hand-rolled QUIC client is
# client-bound and under-reports the server, so there is no local perf3.

taskRequires "testchronos", "chronos >= 4.0.0"

task testchronos, "Test the chronos async adapter (needs chronos)":
  ensureNimblePath()
  exec "nim c -r --mm:orc --threads:on -d:ssl -p:src " &
       "-o:tests/chronos_adapter tests/chronos_adapter.nim"

task testdeflate, "Test WebSocket permessage-deflate (needs zlib)":
  exec "nim c -r --mm:orc --threads:on -d:ssl -d:wsDeflate --passL:-lz -p:src " &
       "-o:tests/websocket_deflate tests/websocket_deflate.nim"
  # The HTTP/2 (RFC 8441) suite gains a permessage-deflate case under the flag.
  exec "nim c -r --mm:orc --threads:on -d:ssl -d:wsDeflate --passL:-lz -p:src " &
       "-o:tests/test_http2_websocket tests/test_http2_websocket.nim"

task testgzip, "Test gzip response compression (needs zlib)":
  exec "nim c -r --mm:orc --threads:on -d:ssl -d:httpGzip --passL:-lz -p:src " &
       "-o:tests/test_compression tests/test_compression.nim"

task teststreamcomp, "Test streaming response compression (needs zlib + brotli)":
  # Streaming (res.sendHead/write/finish, SSE, file streaming) compressed with
  # gzip + brotli, over HTTP/1.1 (chunked) and h2c; curl + the gzip/brotli CLIs
  # verify the framing and a byte-exact round-trip.
  exec "nim c -r --mm:orc --threads:on -d:ssl -d:httpGzip -d:httpBrotli " &
       "--passL:-lz --passL:\"-lbrotlienc -lbrotlicommon\" -p:src " &
       "-o:tests/test_streaming_compression tests/test_streaming_compression.nim"

task testreqdecomp, "Test request-body decompression (needs zlib + brotli + zstd)":
  # Inbound gzip/br/zstd request bodies decoded into req.body (settings.
  # decompressRequest), bounded by maxBodySize: over-cap -> 413, corrupt -> 400.
  exec "nim c -r --mm:orc --threads:on -d:ssl -d:httpGzip -d:httpBrotli " &
       "-d:httpZstd --passL:-lz " &
       "--passL:\"-lbrotlienc -lbrotlidec -lbrotlicommon\" --passL:-lzstd -p:src " &
       "-o:tests/test_request_decompression tests/test_request_decompression.nim"

task testzstd, "Test zstd response compression (needs zstd + zlib + brotli)":
  # Buffered + streamed zstd responses over HTTP/1.1 and h2c, plus br/zstd/gzip
  # Accept-Encoding negotiation (built with all three encoders); curl + the
  # gzip/brotli/zstd CLIs verify framing and a byte-exact round-trip.
  exec "nim c -r --mm:orc --threads:on -d:ssl -d:httpGzip -d:httpBrotli " &
       "-d:httpZstd --passL:-lz --passL:\"-lbrotlienc -lbrotlicommon\" " &
       "--passL:-lzstd -p:src " &
       "-o:tests/test_zstd_compression tests/test_zstd_compression.nim"

task testrace, "ThreadSanitizer regressions for the cross-thread races":
  # Two TSan stress tests; TSan aborts the process on any data race, failing the
  # task. -d:plainHttp keeps OpenSSL out of the report; -d:useMalloc lets TSan
  # see all allocations.
  #  - test_thread_race: start()/shutdown handler-closure refcount race.
  #  - test_blocking_race: a req.blocking: worker reading a snapshot, not live
  #    h2 state (C3 / IMP2) -- concurrent h2c blocking requests.
  for t in ["test_thread_race", "test_blocking_race"]:
    exec "nim c -r --mm:orc --threads:on -d:plainHttp -d:useMalloc " &
         "--passC:-fsanitize=thread --passL:-fsanitize=thread --debugger:native " &
         "-p:src -o:tests/" & t & " tests/" & t & ".nim"

task fuzz, "Fuzz the parser/HPACK/QPACK decoders in Docker (needs docker)":
  # The Dockerfile bundles clang + the libFuzzer runtime; the image's
  # default base is arm64, so override it on x86_64 hosts. Fuzzes each
  # target for 30s (override with `-e DUR=<seconds>` on the docker run).
  let base =
    if hostCPU == "amd64": " --build-arg BASE=archlinux:latest" else: ""
  exec "docker build -f fuzz/Dockerfile -t vortex-fuzz" & base & " ."
  exec "docker run --rm vortex-fuzz"

task redbot, "HTTP conformance check with REDbot in Docker (needs docker)":
  # The Dockerfile bundles Nim + REDbot; the image's default base is
  # arm64, so override it on x86_64 hosts. Exits non-zero on a BAD finding.
  let base =
    if hostCPU == "amd64": " --build-arg BASE=archlinux:latest" else: ""
  exec "docker build -f conformance/Dockerfile -t vortex-redbot" & base & " ."
  exec "docker run --rm vortex-redbot"

task autobahn, "WebSocket conformance via the Autobahn testsuite (Docker)":
  # run.sh builds a vortex echo server image and runs the
  # crossbario/autobahn-testsuite fuzzingclient against it; it picks the
  # image base by host arch and exits non-zero on any failing case.
  exec "sh conformance/autobahn/run.sh"

task h1spec, "HTTP/1.1 conformance via h1spec (Docker)":
  # run.sh builds a plaintext vortex HTTP/1.1 server image and a
  # dropseed/h1spec client image, then runs h1spec against it over a private
  # docker network; h1spec exits non-zero on any failing case.
  exec "sh conformance/h1spec/run.sh"

task h2spec, "HTTP/2 conformance via h2spec over TLS (Docker)":
  # run.sh builds a vortex HTTP/2-over-TLS server image and runs the
  # summerwind/h2spec image against it; h2spec exits non-zero on failures.
  exec "sh conformance/h2spec/run.sh"

task h3websocket, "HTTP/3 WebSocket conformance (RFC 9220) via aioquic (Docker)":
  # run.sh builds a vortex h3 WebSocket echo server image and an aioquic
  # client image, then runs the client against the server over a private
  # docker network; the client exits non-zero on any mismatch.
  exec "sh conformance/h3websocket/run.sh"

task h3spec, "HTTP/3 conformance via h3spec, HTTP/3-servers group (Docker)":
  # run.sh builds a vortex h3 server image and an h3spec client image, then
  # runs h3spec's HTTP/3 + QPACK error-case group against it; h3spec exits
  # non-zero on any failure. (The QUIC transport group is OpenSSL's stack,
  # not vortex, so it is excluded.)
  exec "sh conformance/h3spec/run.sh"

task zap, "Security scan via the OWASP ZAP baseline scanner (Docker)":
  # run.sh builds a plaintext vortex site image and runs ZAP's packaged
  # zap-baseline.py against it over a private docker network. zap.conf
  # promotes the security-header rules the app satisfies to FAIL, so the run
  # exits non-zero if a regression drops one of those headers.
  exec "sh conformance/zap/run.sh"

task h2load, "HTTP/1.1 + HTTP/2 load/stress smoke via h2load (Docker)":
  # run.sh builds a plaintext vortex server image and an nghttp2 h2load client
  # image, then fires many concurrent h1 and h2c requests at it over a private
  # docker network; it fails on any failed/errored/timed-out or non-2xx request.
  exec "sh conformance/h2load/run.sh"

task h3load, "HTTP/3 (QUIC) throughput/stress via h2load-http3 (Docker)":
  # run.sh builds a vortex HTTP/3 server image and an h2load client image built
  # with HTTP/3 (ngtcp2 + nghttp3 on OpenSSL >= 3.5), then drives many concurrent
  # QUIC connections/streams at it, printing req/s and failing on any
  # failed/errored/timed-out or non-2xx request. A real QUIC client, so the
  # number reflects the server -- the HTTP/3 throughput/regression measurement.
  exec "sh conformance/h3load/run.sh"

task loadtest, "Configurable k6 load test with live Grafana/Prometheus charts (Docker)":
  # run.sh brings up Prometheus + Grafana, builds the selected vortex backend
  # image(s) (h1 / h2 / h2-gzip, or all), and drives k6 load into them for a
  # configurable duration, streaming metrics to Grafana (http://localhost:3000).
  # Env knobs: BACKEND, RUNTIME, MODE (throughput|rate), DURATION, VUS, RATE,
  # ENDPOINT. Interactive, so not a CI gate. See conformance/loadtest/README.md.
  exec "sh conformance/loadtest/run.sh"

task stress, "Saturation stress test via h2load with live Grafana charts (Docker)":
  # run.sh saturates the selected backend(s) with h2load (max req/s) while
  # Grafana (http://localhost:3001) shows the server's own CPU/memory live (from
  # docker stats) and the achieved req/s as a summary. Env knobs: BACKEND,
  # DURATION, CONNS, STREAMS, ENDPOINT. Interactive, so not a CI gate. See
  # conformance/stress/README.md.
  exec "sh conformance/stress/run.sh"

task interop, "Cross-client interop test (Node/Python/Go/Rust/Java) (Docker)":
  # run.sh mints a shared CA, builds a vortex TLS server (h1/h2, gzip) image and
  # five language-client images, then drives every HTTP method from each client
  # over HTTP/2 with gzip (sequentially, so runtime x 5 backends). Each client
  # asserts h2 + gzip round-trip; INTEROP_MTLS=1 adds mutual-TLS with a
  # client-cert subject check. Fails if any backend errors. Needs docker +
  # host openssl. Knobs: INTEROP_RUNTIME / INTEROP_CLIENTS / INTEROP_MTLS.
  exec "sh conformance/interop/run.sh"

task brotli, "Cross-client brotli interop test (Node/Python/Go/Rust/Java) (Docker)":
  # Same harness as `interop`, but every client requests and asserts
  # Content-Encoding: br (INTEROP_ENCODING=br). The server image is built with
  # -d:httpBrotli, and each client decodes brotli with its ecosystem's library
  # (Node zlib, Python brotli, Go andybalholm/brotli, Rust brotli, Java
  # org.brotli.dec). Needs docker + host openssl.
  exec "INTEROP_ENCODING=br sh conformance/interop/run.sh"

task testssl, "TLS configuration scan via testssl.sh (Docker)":
  # run.sh builds a vortex TLS server image and runs drwetter/testssl.sh against
  # it over a private docker network, checking protocols/ciphers/vulnerabilities;
  # it fails on any HIGH/CRITICAL finding.
  exec "sh conformance/testssl/run.sh"
