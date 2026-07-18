# h2load HTTP/3 client image: nghttp2's load tester built with HTTP/3 support
# (ngtcp2 + nghttp3) against OpenSSL >= 3.5's native QUIC API -- the same TLS
# stack the vortex server uses, so client and server interoperate. Distro
# nghttp2 packages omit HTTP/3, so the stack is built from source. Run by
# conformance/h3load/run.sh against the vortex h3 server over a private docker
# network (QUIC is UDP).
#
# Base defaults to arm64 and is overridden to archlinux:latest on x86_64 hosts
# (archlinux ships OpenSSL >= 3.5, whose QUIC API ngtcp2's `ossl` crypto
# backend requires).

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN for i in 1 2 3 4 5; do \
      pacman -Syu --noconfirm --needed --disable-sandbox \
        base-devel git cmake openssl libev zlib c-ares && break; \
      [ "$i" = 5 ] && exit 1; \
      echo "pacman failed (attempt $i/5); retrying in 15s"; sleep 15; \
    done && \
    pacman -Scc --noconfirm

# Bump these to pull newer releases of the HTTP/3 stack.
ARG NGHTTP3_VERSION=v1.11.0
ARG NGTCP2_VERSION=v1.15.0
ARG NGHTTP2_VERSION=v1.66.0

# Clone all three (with submodules) up front, while system git/curl still use
# the distro's own ngtcp2. Installing our newer ngtcp2 into /usr/local below
# would otherwise break git's libcurl (ABI mismatch) mid-build.
WORKDIR /build
RUN git clone --depth 1 -b ${NGHTTP3_VERSION} https://github.com/ngtcp2/nghttp3 && \
    git clone --depth 1 -b ${NGTCP2_VERSION}  https://github.com/ngtcp2/ngtcp2 && \
    git clone --depth 1 -b ${NGHTTP2_VERSION} https://github.com/nghttp2/nghttp2 && \
    (cd nghttp3 && git submodule update --init --depth 1) && \
    (cd ngtcp2  && git submodule update --init --depth 1) && \
    (cd nghttp2 && git submodule update --init --depth 1)

# Make /usr/local/lib visible to the dynamic loader via ld.so.conf rather than
# LD_LIBRARY_PATH, so only the loader (for h2load) sees it; no more git/curl is
# needed past this point. PKG_CONFIG_PATH only affects configure/link, not the
# loader, so it is safe to set globally.
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
RUN echo /usr/local/lib > /etc/ld.so.conf.d/usrlocal.conf

# nghttp3: HTTP/3 framing.
RUN cd nghttp3 && autoreconf -i && \
    ./configure --prefix=/usr/local --enable-lib-only && \
    make -j"$(nproc)" && make install && ldconfig

# ngtcp2: QUIC transport with the OpenSSL 3.5 `ossl` crypto backend
# (auto-selected by --with-openssl when OpenSSL >= 3.5 is present).
RUN cd ngtcp2 && autoreconf -i && \
    ./configure --prefix=/usr/local --enable-lib-only --with-openssl && \
    make -j"$(nproc)" && make install && ldconfig

# nghttp2: build the apps (h2load) with HTTP/3, linking ngtcp2 + nghttp3.
RUN cd nghttp2 && autoreconf -i && \
    ./configure --prefix=/usr/local --enable-app --enable-http3 \
      --with-openssl --with-libngtcp2 --with-libnghttp3 \
      --without-jemalloc --without-libxml2 && \
    make -j"$(nproc)" && make install && ldconfig && \
    cd / && rm -rf /build

ENV PATH=/usr/local/bin:$PATH

# Sanity: fail the build if h2load lacks HTTP/3, so a broken stack never
# silently falls back to h1/h2 at run time.
RUN h2load --version && \
    ldd "$(command -v h2load)" | grep -q nghttp3
