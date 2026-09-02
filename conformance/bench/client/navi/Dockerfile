# navi load client for the cross-language bench (conformance/bench/run.sh).
# One compiled Nim binary that speaks h1/h2/h3 + ws + sse + streaming via navi
# (github.com/cryo2010/nim-navi), so it runs anywhere. h3 needs -d:naviHttp3,
# which links ngtcp2 + nghttp3 + OpenSSL >=3.5 -- all available from Arch's repos
# (same base as the vortex stress/bench server image), so no from-source toolchain.
# x86_64 override: --build-arg BASE=archlinux:latest
ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        nim gcc git openssl zlib libngtcp2 libnghttp3 pkgconf && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && pacman -Scc --noconfirm

WORKDIR /client
# navi (latest) from the user's repo; checksums is a transitive dep.
RUN nimble install -y navi checksums

COPY conformance/bench/client/navi/bench_navi.nim ./bench_navi.nim
RUN nim c --mm:orc --threads:on -d:danger -d:ssl -d:naviHttp3 \
      --hints:off -o:bench_navi bench_navi.nim

ENTRYPOINT ["./bench_navi"]
