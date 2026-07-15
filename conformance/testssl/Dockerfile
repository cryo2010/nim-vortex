# Builds the vortex TLS server under test for the testssl.sh scan.
# conformance/testssl/run.sh (or `nimble testssl`) starts this alongside the
# drwetter/testssl.sh client image on a private docker network.
#
# Built from the repository root by run.sh; the base defaults to arm64 and is
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
COPY conformance/testssl/testssl_server.nim ./testssl_server.nim
RUN nim c --mm:orc --threads:on -d:release -p:src \
      -o:testssl_server testssl_server.nim

# Throwaway self-signed cert; the scan checks the TLS config, not the cert
# chain (run.sh runs the protocol/cipher/vulnerability groups, not cert trust).
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:server,DNS:localhost"

EXPOSE 8443
CMD ["./testssl_server"]
