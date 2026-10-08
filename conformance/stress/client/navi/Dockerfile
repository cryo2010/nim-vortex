# Compiled navi load client for the vortex stress soaks (VORTEX_CLIENT=navi).
#
# The alternative to client.Dockerfile's Python canary: one Nim binary that
# speaks h1/h2/h3 via navi (github.com/cryo2010/nim-navi) and verifies every
# byte, so a cell can be driven by a client that is not the bottleneck and is
# not a second implementation of the same opinion of the spec. Python stays the
# default; see conformance/stress/README.md for which to pick.
#
# Modelled on conformance/bench/client/navi/Dockerfile, which already proves
# -d:naviHttp3 links against Arch's libngtcp2 / libnghttp3 / openssl packages
# with no from-source toolchain, on the same base as the stress server image.
# x86_64 override: --build-arg BASE=archlinux:latest (run.sh passes it).
ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

# brotli / zstd / zlib on top of the bench image's list: this client compresses
# its own request bodies with vortex's OWN encoders (src/vortex/{gzip,brotli,
# zstd}.nim, copied in below), so it links exactly what the server links and the
# bytes it sends are the bytes the server's decompressRequest path is built for.
RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        nim gcc git openssl zlib brotli zstd libngtcp2 libnghttp3 pkgconf && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && pacman -Scc --noconfirm

# Pinned by SHA, never `navi` latest. A soak is a measurement, and an unpinned
# client silently changes the thing being measured: the bench image installs
# latest, and that is exactly what made its numbers move under it (nim-navi #401
# doubled the download client's throughput between two rebuilds of an unchanged
# Dockerfile). Bump this deliberately, and re-run the soaks when you do.
# Override per run with VORTEX_NAVI_REF. Pass a SHA: the clone below is one
# layer keyed on this value, so a branch or tag name is frozen by the docker
# build cache at whatever it pointed to the first time it was built on this
# host, which is the inverse of what a moving ref looks like it promises.
ARG NAVI_REF=62244a8b24e38e5d3ec8f25fc38c01eaab5a1c52

WORKDIR /client
# navi is used from a WORKTREE at the pinned ref (`--path:/navi/src` below),
# not from `nimble install`. Two reasons, in order:
#
#  1. It has to be. navi's package spec ships `.nim` and `.cpp`
#     (`installExt = @["nim", "cpp"]`) but not the HTTP/3 driver's own header,
#     so `h3client.cpp` in an INSTALLED package cannot find `h3client.h` and a
#     -d:naviHttp3 build fails at the C++ step (nim-navi #465); until it is
#     fixed, a worktree is the only way to build an h3 client from a pinned ref.
#  2. It is a stricter pin anyway: the binary is compiled from exactly the tree
#     at $NAVI_REF, with nothing in between that could resolve differently.
#
# `--detach` so a tag or branch name also resolves (see the cache note above
# for why a sha is still what to pass). checksums is navi's one required Nim
# dependency (and this client's SHA-1).
RUN git clone https://github.com/cryo2010/nim-navi.git /navi && \
    git -C /navi checkout --detach "$NAVI_REF" && \
    nimble install -y checksums

# chronos (default) or asyncdispatch: a BUILD arg, not a cell knob, because it
# selects which navi client the single binary is compiled against
# (-d:useChronos picks `import navi/chronos`). chronos is the default because
# navi's asyncdispatch total-timeout guard keeps a completed request reachable
# until its timer fires (nim-navi #468), which on a soak is memory proportional
# to request rate x timeout, measured as a 750 MB plateau on `requests` and an
# OOM on a 30-minute mixed cell; the chronos guard cancels its timer. One image
# per backend, fixed at build time. Declared
# BELOW the clone so that flipping the backend reuses the cloned navi layer and
# only this install plus the compile differ between the two images; chronos is
# installed only for the chronos backend, so the default image stays free of it.
ARG NAVI_BACKEND=chronos
RUN if [ "$NAVI_BACKEND" = "chronos" ]; then nimble install -y "chronos@>= 4.0.0"; fi

# Only the codec modules the client compiles against (gzip/brotli/zstd and the
# three modules they import), reached with -p:src below. Not `COPY src`: the
# whole vortex tree in this layer would invalidate the compile on every edit
# anywhere in src/, i.e. on every server change the stress harness exists to
# test, and the point of building the client once per run is to not pay for it.
COPY src/vortex/gzip.nim src/vortex/brotli.nim src/vortex/zstd.nim \
     src/vortex/zlibffi.nim src/vortex/boundedinflate.nim \
     src/vortex/compresscodec.nim ./src/vortex/
COPY conformance/stress/client/navi/common.nim ./common.nim
COPY conformance/stress/client/navi/stress_navi.nim ./stress_navi.nim

# ONE binary for all three protocols: it reads VORTEX_PROTO at run time, so the
# h1 and h2 cells simply never touch the h3 code and the image is built once per
# run instead of once per proto (measured on a 14-cpu arm64 host: about a
# minute for the whole image with --no-cache, of which the -d:naviHttp3 compile
# with traces on is 10-12 s; cheap per run, not per cell, and the h3 matrix
# already contends for the host).
#
# -d:release, NOT -d:danger (which is what the bench client uses): this binary
# is a verifier, so a crash must say where it died. Hence the traces too -- the
# client prints its own stack trace on stdout for an unexpected exception,
# because stderr is not teed by `nimble stress | tee stress.log` (#387). And
# NOT --panics:on, unlike the server's soak profile: with it a Defect is fatal
# at the raise site, goes to stderr only and never reaches the client's own
# `FAIL <workload>: unexpected ...` handler, which is exactly the bare
# `FAILED (exit 1)` with no cause that #387 was about. Without it the handler
# catches the Defect, prints the cause and the trace on stdout, and exits 1.
#
# All three codecs are always compiled in, so one image serves every
# VORTEX_REQ_COMPRESSION / VORTEX_RESP_COMPRESSION value; the defines and link
# flags are run.sh's codec_flags, verbatim, so client and server link the same
# libraries.
#
# -d:naviRef bakes the pin into the binary for the `client: navi/<backend> <ref>`
# header line: a log has to be able to say which navi produced its numbers.
RUN set -eu; \
    extra=""; \
    if [ "$NAVI_BACKEND" = "chronos" ]; then extra="-d:useChronos"; fi; \
    nim c --mm:orc --threads:on -d:release -d:ssl -d:naviHttp3 \
      --stackTrace:on --stackTraceMsgs:on --lineTrace:on \
      --debugger:native -p:src --path:/navi/src \
      -d:httpGzip --passL:-lz \
      -d:httpBrotli --passL:-lbrotlienc --passL:-lbrotlidec --passL:-lbrotlicommon \
      -d:httpZstd --passL:-lzstd \
      -d:naviRef="$NAVI_REF" $extra \
      --hints:off -o:stress_navi stress_navi.nim

ENTRYPOINT ["./stress_navi"]
