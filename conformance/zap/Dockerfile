# Builds the vortex server under test for the OWASP ZAP baseline scan.
# conformance/zap/run.sh (or `nimble zap`) starts this alongside the ZAP
# scanner image on a private docker network.
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
COPY conformance/zap/zap_server.nim ./zap_server.nim
RUN nim c --mm:orc --threads:on -d:release -d:plainHttp -p:src \
      -o:zap_server zap_server.nim

EXPOSE 8080
CMD ["./zap_server"]
