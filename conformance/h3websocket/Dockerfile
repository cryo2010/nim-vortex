# Builds the vortex HTTP/3 WebSocket echo server under test for the RFC 9220
# conformance run. conformance/h3websocket/run.sh (or `nimble h3websocket`)
# starts this alongside the aioquic client image on a private docker network.
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
COPY conformance/h3websocket/echo_server.nim ./echo_server.nim
RUN nim c --mm:orc --threads:on -d:release -p:src \
      -o:echo_server echo_server.nim

# Throwaway self-signed cert; the client runs without verification.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:server,DNS:localhost"

EXPOSE 4433/udp
CMD ["./echo_server"]
