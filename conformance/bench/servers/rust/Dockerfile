# syntax=docker/dockerfile:1
# Rust bench server (salvo): h1/h2 (rustls) + h3 (quinn) + ws + sse + streaming.
# Built from conformance/bench/servers/rust as the context. Cargo registry + target
# are cache mounts so iterating on main.rs recompiles only this crate.
FROM rust:latest AS build
WORKDIR /app
COPY Cargo.toml .
COPY src ./src
COPY nodelay_preload.c .
RUN cc -shared -fPIC -O2 -o /nodelay.so nodelay_preload.c -ldl
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && cp target/release/bench-rust /bench-rust

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /bench-rust ./server
COPY --from=build /nodelay.so /app/nodelay.so
# force TCP_NODELAY on accepted sockets (salvo can't; see nodelay_preload.c)
ENV LD_PRELOAD=/app/nodelay.so
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:server,DNS:localhost"
ENTRYPOINT ["./server"]
