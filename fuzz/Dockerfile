# Runs the libFuzzer harnesses (HTTP/1.1 parser, HPACK, QPACK decoders) in
# a container, so you do not need a clang libFuzzer runtime on the host
# (Apple clang does not ship libclang_rt.fuzzer).
#
# Build from the repository root:
#   docker build -f fuzz/Dockerfile -t vortex-fuzz .
# On x86_64 hosts use the official Arch image instead of the arm64 one:
#   docker build -f fuzz/Dockerfile -t vortex-fuzz \
#     --build-arg BASE=archlinux:latest .
# Run (DUR seconds per target, default 30; optional target list):
#   docker run --rm vortex-fuzz                 # http1 hpack qpack
#   docker run --rm -e DUR=120 vortex-fuzz      # 120s per target
#   docker run --rm vortex-fuzz hpack           # a single target

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

# clang + compiler-rt provide the libFuzzer runtime; nim/gcc build the
# harnesses; openssl is vortex's link dependency; zlib backs the
# permessage-deflate (wsdeflate) target.
# --disable-sandbox: pacman's Landlock sandbox cannot apply in a container.
RUN pacman -Syu --noconfirm --needed --disable-sandbox \
      nim gcc clang compiler-rt openssl zlib && \
    pacman -Scc --noconfirm

WORKDIR /vortex
COPY src ./src
COPY fuzz ./fuzz

# run.sh builds each target (with ASAN + libFuzzer) then fuzzes it; DUR and
# the target list pass through as env/args.
ENTRYPOINT ["sh", "fuzz/run.sh"]
