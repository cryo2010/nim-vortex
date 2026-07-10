# Arch Linux environment for the HTTP/1.1 comparison benchmark.
# Linux SO_REUSEPORT actually balances connections across the per-thread
# listeners (macOS delivers everything to one), so multi-thread scaling
# is only visible here.
#
# Build from the repository root:
#   docker build -f bench/Dockerfile -t nhs-bench .
# On x86_64 hosts use the official image instead of the arm64 one:
#   docker build -f bench/Dockerfile -t nhs-bench --build-arg BASE=archlinux:latest .
# Run:
#   docker run --rm nhs-bench                      # HTTP/1.1 comparison table
#   docker run --rm nhs-bench ./bench/perf_http2   # HTTP/2 benchmark
#   docker run --rm nhs-bench ./bench/perf_http3   # HTTP/3 benchmark
#   docker run --rm nhs-bench nimble test          # test suite on epoll

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

# --disable-sandbox: pacman's Landlock sandbox cannot apply in a container.
RUN pacman -Syu --noconfirm --needed --disable-sandbox \
      nim gcc git curl openssl && \
    pacman -Scc --noconfirm

WORKDIR /nhs
COPY nim_http_server.nimble ./
COPY src ./src
COPY tests ./tests
COPY bench/*.nim bench/run.sh ./bench/

RUN nimble install httpbeast chronos -y
RUN nim c --mm:orc --threads:on -d:danger \
      -o:bench/perf_http1_1 bench/perf_http1_1.nim && \
    nim c --mm:orc --threads:on -d:danger \
      -o:bench/perf_http2 bench/perf_http2.nim && \
    nim c --mm:orc --threads:on -d:danger \
      -o:bench/perf_http3 bench/perf_http3.nim

CMD ["./bench/perf_http1_1"]
