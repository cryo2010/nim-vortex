# Builds the vortex server under test for the k6 stress harness.
# conformance/stress/run.sh (or `nimble stress`) builds this once per backend,
# passing BUILD_FLAGS to select the protocol surface:
#   h1       BUILD_FLAGS="-d:plainHttp"                 (cleartext, no OpenSSL)
#   h2       BUILD_FLAGS=""                             (default, TLS + h2 via ALPN)
#   h2-gzip  BUILD_FLAGS="-d:httpGzip --passL:-lz"      (TLS + gzip responses)
#
# Built with -d:danger (like bench/) so the server, not runtime checks, sets the
# throughput ceiling. Built from the repository root by run.sh; the base
# defaults to arm64 and is overridden to archlinux:latest on x86_64 hosts.

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        nim gcc openssl zlib && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && \
    pacman -Scc --noconfirm

WORKDIR /vortex
COPY src ./src
COPY conformance/stress/stress_server.nim ./stress_server.nim

ARG BUILD_FLAGS=""
RUN nim c --mm:orc --threads:on -d:danger $BUILD_FLAGS -p:src \
      -o:stress_server stress_server.nim

# Throwaway self-signed cert for the TLS backends (unused by the h1 build).
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:server,DNS:localhost"

EXPOSE 8080 8443
CMD ["./stress_server"]
