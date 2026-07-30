# Rust interop client (reqwest + tokio, HTTP/2 via ALPN). reqwest's native-tls
# backend links OpenSSL; a glibc (Debian) base links it dynamically, avoiding
# the static-OpenSSL link failure musl/Alpine hits.
FROM rust:1-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/client .
CMD ["./client"]
