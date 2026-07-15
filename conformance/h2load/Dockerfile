# Builds the vortex server under test for the h2load stress smoke.
# conformance/h2load/run.sh (or `nimble h2load`) starts this alongside the
# nghttp2 h2load client image on a private docker network.
#
# Built from the repository root by run.sh. A -d:plainHttp build needs no
# OpenSSL. Base defaults to arm64 and is overridden to archlinux:latest on
# x86_64 hosts.

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        nim gcc && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && \
    pacman -Scc --noconfirm

WORKDIR /vortex
COPY src ./src
COPY conformance/h2load/h2load_server.nim ./h2load_server.nim
RUN nim c --mm:orc --threads:on -d:release -d:plainHttp -p:src \
      -o:h2load_server h2load_server.nim

EXPOSE 8080
CMD ["./h2load_server"]
