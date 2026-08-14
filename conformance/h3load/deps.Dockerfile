# Build environment for vortex's HTTP/3 (ngtcp2 + nghttp3).
#
# Nim + ngtcp2 (QUIC transport) + nghttp3 (HTTP/3 framing/QPACK), the ngtcp2
# `ossl` crypto backend on OpenSSL >= 3.5 -- the same TLS stack vortex already
# links, and the same library build the h2load client uses (client.Dockerfile),
# so client and server interoperate. Distro packages either omit ngtcp2/nghttp3
# or build a non-OpenSSL crypto backend, so the stack is built from source.
#
# Used two ways:
#   1. Dev/CI build+link check and unit tests, with the repo bind-mounted:
#        docker build -f conformance/h3load/deps.Dockerfile -t vortex-ngtcp2-deps .
#        docker run --rm -v "$PWD":/work -w /work vortex-ngtcp2-deps \
#          nim c --mm:orc --threads:on -d:ssl -p:src ...
#   2. As the base image for the h3 server images (the conformance Dockerfiles).
#
# Base defaults to arm64 and is overridden to archlinux:latest on x86_64 hosts
# (archlinux ships OpenSSL >= 3.5, which the `ossl` crypto backend requires).

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        nim gcc base-devel git cmake openssl && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && \
    pacman -Scc --noconfirm

# Keep these in lockstep with conformance/h3load/client.Dockerfile so the client
# and server run the same QUIC/HTTP3 versions.
ARG NGHTTP3_VERSION=v1.11.0
ARG NGTCP2_VERSION=v1.15.0

WORKDIR /build
RUN git clone --depth 1 -b ${NGHTTP3_VERSION} https://github.com/ngtcp2/nghttp3 && \
    git clone --depth 1 -b ${NGTCP2_VERSION}  https://github.com/ngtcp2/ngtcp2 && \
    (cd nghttp3 && git submodule update --init --depth 1) && \
    (cd ngtcp2  && git submodule update --init --depth 1)

# Make /usr/local/lib visible to the dynamic loader and pkg-config.
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
RUN echo /usr/local/lib > /etc/ld.so.conf.d/usrlocal.conf

# nghttp3: HTTP/3 framing + QPACK. --enable-lib-only skips the examples.
RUN cd nghttp3 && autoreconf -i && \
    ./configure --prefix=/usr/local --enable-lib-only && \
    make -j"$(nproc)" && make install && ldconfig

# ngtcp2: QUIC transport with the OpenSSL 3.5 `ossl` crypto backend
# (auto-selected by --with-openssl when OpenSSL >= 3.5 is present). This builds
# both libngtcp2 and libngtcp2_crypto_ossl.
RUN cd ngtcp2 && autoreconf -i && \
    ./configure --prefix=/usr/local --enable-lib-only --with-openssl && \
    make -j"$(nproc)" && make install && ldconfig && \
    cd / && rm -rf /build

# Sanity: fail the build if the three libs pkg-config expects are missing, so a
# broken stack is caught here rather than at the first vortex link.
RUN pkg-config --exists libnghttp3 libngtcp2 libngtcp2_crypto_ossl && \
    pkg-config --modversion libngtcp2 libngtcp2_crypto_ossl libnghttp3
