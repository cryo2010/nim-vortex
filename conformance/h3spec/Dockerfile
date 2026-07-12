# Builds the vortex HTTP/3 server under test for the h3spec conformance run.
# conformance/h3spec/run.sh (or `nimble h3spec`) starts this alongside the
# h3spec client image on a private docker network.
#
# Built from the repository root by run.sh; archlinux ships OpenSSL >= 3.5,
# which vortex needs for the QUIC server API. Base defaults to arm64 and is
# overridden to archlinux:latest on x86_64 hosts.

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN pacman -Syu --noconfirm --needed --disable-sandbox \
      nim gcc openssl && \
    pacman -Scc --noconfirm

WORKDIR /vortex
COPY src ./src
COPY conformance/h3spec/h3spec_server.nim ./h3spec_server.nim
RUN nim c --mm:orc --threads:on -d:release -p:src \
      -o:h3spec_server h3spec_server.nim

# Throwaway self-signed cert; h3spec runs with --no-validate.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:server,DNS:localhost"

EXPOSE 4433/udp
CMD ["./h3spec_server"]
