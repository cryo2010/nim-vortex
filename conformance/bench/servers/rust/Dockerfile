# Rust bench server (salvo): h1/h2 (rustls) + h3 (quinn) + ws + sse + streaming.
# Built from conformance/bench/servers/rust as the context.
FROM rust:latest AS build
WORKDIR /app
COPY Cargo.toml .
COPY src ./src
RUN cargo build --release

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/bench-rust ./server
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:server,DNS:localhost"
ENTRYPOINT ["./server"]
