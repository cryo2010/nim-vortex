# Builds the vortex server under test for the h2load stress harness.
# conformance/stress/run.sh (or `nimble stress`) builds this once per backend,
# passing BUILD_FLAGS for the protocol surface:
#   h1       "-d:plainHttp"                 (cleartext, no OpenSSL)
#   h2       ""                             (default, TLS + h2 via ALPN)
#   h2-gzip  "-d:httpGzip --passL:-lz"      (TLS + gzip responses)
#
# The server source is shared with the loadtest harness (same /plaintext, /json,
# /big handlers); stress only needs the plain sync build, so there is no RUNTIME
# axis here. Built -d:danger so the server, not runtime checks, sets the ceiling.
# Built from the repository root by run.sh; base defaults to arm64, overridden to
# archlinux:latest on x86_64.

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        nim gcc git openssl zlib libngtcp2 libnghttp3 && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && \
    pacman -Scc --noconfirm

WORKDIR /vortex
RUN nimble install -y "nimcrypto@>= 0.6.0"   # core dep (HMAC for signed cookies)
COPY src ./src
COPY conformance/loadtest/loadtest_server.nim ./stress_server.nim

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
