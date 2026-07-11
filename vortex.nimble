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

task perf, "Run the HTTP/1.1 throughput comparison benchmark":
  exec "nim c -r --mm:orc --threads:on -d:danger -o:bench/perf_http1_1 bench/perf_http1_1.nim"

task perf2, "Run the HTTP/2 throughput benchmark":
  exec "nim c -r --mm:orc --threads:on -d:danger -o:bench/perf_http2 bench/perf_http2.nim"

task perf3, "Run the HTTP/3 throughput benchmark":
  exec "nim c -r --mm:orc --threads:on -d:danger -o:bench/perf_http3 bench/perf_http3.nim"

taskRequires "testchronos", "chronos >= 4.0.0"

task testchronos, "Test the chronos async adapter (needs chronos)":
  exec "nim c -r --mm:orc --threads:on -d:ssl -p:src " &
       "-o:tests/chronos_adapter tests/chronos_adapter.nim"

task fuzz, "Fuzz the parser/HPACK/QPACK decoders (needs clang + libFuzzer)":
  exec "sh fuzz/run.sh"

task redbot, "HTTP conformance check with REDbot in Docker (needs docker)":
  # The Dockerfile bundles Nim + REDbot; the image's default base is
  # arm64, so override it on x86_64 hosts. Exits non-zero on a BAD finding.
  let base =
    if hostCPU == "amd64": " --build-arg BASE=archlinux:latest" else: ""
  exec "docker build -f conformance/Dockerfile -t vortex-redbot" & base & " ."
  exec "docker run --rm vortex-redbot"
