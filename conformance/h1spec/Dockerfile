# Builds the vortex HTTP/1.1 server under test for the h1spec conformance
# run. conformance/h1spec/run.sh (or `nimble h1spec`) starts this alongside
# the h1spec client image on a private docker network.
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
RUN nimble install -y "nimcrypto@>= 0.6.0"   # core dep (HMAC for signed cookies)
COPY src ./src
COPY conformance/h1spec/h1spec_server.nim ./h1spec_server.nim
RUN nim c --mm:orc --threads:on -d:release -d:plainHttp -p:src \
      -o:h1spec_server h1spec_server.nim

EXPOSE 8080
CMD ["./h1spec_server"]
