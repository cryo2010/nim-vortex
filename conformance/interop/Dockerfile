# Builds the vortex server under test for the cross-client interop test
# (conformance/interop/run.sh, `nimble interop` / `nimble brotli`). Built with
# -d:httpGzip AND -d:httpBrotli so the server can compress with either encoding
# (settings.compress = true; the client's Accept-Encoding selects one), and with
# OpenSSL for TLS/ALPN (h1 + h2). archlinux ships a recent OpenSSL; the base
# defaults to arm64 and is overridden to archlinux:latest on x86_64 hosts.
#
# The TLS material is not baked in: run.sh generates one CA + server + client
# cert set on the host and mounts it read-only at /certs, shared by the server
# and every language client so they all trust the same CA.

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        nim gcc openssl zlib brotli && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && \
    pacman -Scc --noconfirm

WORKDIR /vortex
COPY src ./src
COPY conformance/interop/interop_server.nim ./interop_server.nim
RUN nim c --mm:orc --threads:on -d:release -d:ssl -d:httpGzip -d:httpBrotli \
      --passL:-lz --passL:"-lbrotlienc -lbrotlicommon" \
      -p:src -o:interop_server interop_server.nim

EXPOSE 8443/tcp
CMD ["./interop_server"]
