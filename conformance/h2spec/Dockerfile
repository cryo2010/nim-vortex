# Builds the vortex HTTP/2-over-TLS server under test for the h2spec
# conformance run. conformance/h2spec/run.sh (or `nimble h2spec`) starts
# this alongside the summerwind/h2spec image on a private docker network.
#
# Built from the repository root by run.sh; the base defaults to arm64 and
# is overridden to archlinux:latest on x86_64 hosts.

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN pacman -Syu --noconfirm --needed --disable-sandbox \
      nim gcc openssl && \
    pacman -Scc --noconfirm

WORKDIR /vortex
COPY src ./src
COPY conformance/h2spec/h2spec_server.nim ./h2spec_server.nim
RUN nim c --mm:orc --threads:on -d:release -p:src \
      -o:h2spec_server h2spec_server.nim

# Throwaway self-signed cert; h2spec runs with -k (no verification).
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:server,DNS:localhost"

EXPOSE 8443
CMD ["./h2spec_server"]
