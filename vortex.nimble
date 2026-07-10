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
