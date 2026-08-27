# Builds the vortex workload server for the per-workload stress soaks
# (conformance/stress/run.sh). Two build-args, as loadtest's Dockerfile:
#
#   BUILD_FLAGS  protocol + response/request codecs, e.g.
#     "-d:plainHttp"                        h1 (cleartext, no OpenSSL)
#     ""                                    h2 over TLS (ALPN)
#     "-d:httpGzip --passL:-lz"             + gzip; likewise -d:httpBrotli / -d:httpZstd
#
#   RUNTIME  handler execution model -> a -d:lt* flag (and, for chronos, the dep):
#     sync | async | async-await | chronos | chronos-await
#   so VORTEX_SERVER sweeps the sync / asyncdispatch / chronos servers under load.
#
# Built -d:danger so the server, not runtime checks, sets the ceiling. Built from
# the repository root by run.sh; base defaults to arm64, overridden to
# archlinux:latest on x86_64.

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        nim gcc git openssl zlib brotli zstd libngtcp2 libnghttp3 && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && \
    pacman -Scc --noconfirm

WORKDIR /vortex
RUN nimble install -y "nimcrypto@>= 0.6.0"   # core dep (HMAC for signed cookies)
COPY src ./src
COPY conformance/stress/stress_server.nim ./stress_server.nim

ARG BUILD_FLAGS=""
ARG RUNTIME=sync
RUN case "$RUNTIME" in \
      sync)          rtflag="" ;; \
      async)         rtflag="-d:ltAsync" ;; \
      async-await)   rtflag="-d:ltAsyncAwait" ;; \
      chronos)       rtflag="-d:ltChronos" ;; \
      chronos-await) rtflag="-d:ltChronosAwait" ;; \
      *) echo "unknown RUNTIME: $RUNTIME (sync|async|async-await|chronos|chronos-await)" >&2; exit 1 ;; \
    esac; \
    case "$RUNTIME" in \
      chronos|chronos-await) nimble install -y "chronos@>= 4.0.0" ;; \
    esac; \
    nim c --mm:orc --threads:on -d:danger $BUILD_FLAGS $rtflag -p:src \
      -o:stress_server stress_server.nim

# Throwaway self-signed cert for the TLS protocols (unused by the h1 build).
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:server,DNS:localhost"

EXPOSE 8080 8443
CMD ["./stress_server"]
