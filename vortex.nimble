# Package

version       = "0.1.0"
author        = "Craig Younker"
description   = "A fast HTTP/1.1, HTTP/2 and HTTP/3 server"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.2.10"

task bench, "Build benchmark server with release flags":
  exec "nim c --mm:orc --threads:on -d:danger --passC:-flto -o:bench/handlers bench/handlers.nim"

taskRequires "perf", "httpbeast >= 0.4.0"
taskRequires "perf", "chronos >= 4.0.0"
taskRequires "perf", "mummy >= 0.4.0"

task perf, "Run the HTTP/1.1 throughput comparison benchmark":
  exec "nim c -r --mm:orc --threads:on -d:danger -o:bench/perf_http1_1 bench/perf_http1_1.nim"

task perf2, "Run the HTTP/2 throughput benchmark":
  exec "nim c -r --mm:orc --threads:on -d:danger -o:bench/perf_http2 bench/perf_http2.nim"

# HTTP/3 throughput is measured with a real QUIC client via `nimble h3load`
# (conformance/h3load, Docker): an in-process hand-rolled QUIC client is
# client-bound and under-reports the server, so there is no local perf3.

taskRequires "testchronos", "chronos >= 4.0.0"

task testchronos, "Test the chronos async adapter (needs chronos)":
  exec "nim c -r --mm:orc --threads:on -d:ssl -p:src " &
       "-o:tests/chronos_adapter tests/chronos_adapter.nim"

task testdeflate, "Test WebSocket permessage-deflate (needs zlib)":
  exec "nim c -r --mm:orc --threads:on -d:ssl -d:wsDeflate --passL:-lz -p:src " &
       "-o:tests/websocket_deflate tests/websocket_deflate.nim"
  # The HTTP/2 (RFC 8441) suite gains a permessage-deflate case under the flag.
  exec "nim c -r --mm:orc --threads:on -d:ssl -d:wsDeflate --passL:-lz -p:src " &
       "-o:tests/test_http2_websocket tests/test_http2_websocket.nim"

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

task testssl, "TLS configuration scan via testssl.sh (Docker)":
  # run.sh builds a vortex TLS server image and runs drwetter/testssl.sh against
  # it over a private docker network, checking protocols/ciphers/vulnerabilities;
  # it fails on any HIGH/CRITICAL finding.
  exec "sh conformance/testssl/run.sh"
