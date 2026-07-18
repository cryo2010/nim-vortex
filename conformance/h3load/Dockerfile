# Builds the vortex HTTP/3 server under test for the h3load throughput test.
# conformance/h3load/run.sh (or `nimble h3load`) starts this alongside the
# h2load-http3 client image on a private docker network (QUIC is UDP).
#
# Built from the repository root by run.sh; archlinux ships OpenSSL >= 3.5,
# which vortex needs for the QUIC server API. Base defaults to arm64 and is
# overridden to archlinux:latest on x86_64 hosts.

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        nim gcc openssl && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && \
    pacman -Scc --noconfirm

WORKDIR /vortex
COPY src ./src
COPY conformance/h3load/h3load_server.nim ./h3load_server.nim
RUN nim c --mm:orc --threads:on -d:release -p:src \
      -o:h3load_server h3load_server.nim

# Throwaway self-signed cert; the client runs without verification.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:server,DNS:localhost"

EXPOSE 4433/udp
CMD ["./h3load_server"]
