# Go bench server: net/http (h1/h2) + quic-go (h3) + coder/websocket. Built from
# conformance/bench/servers/go as the context.
FROM golang:1.26 AS build
WORKDIR /app
COPY go.mod .
COPY main.go .
ENV CGO_ENABLED=0
RUN go get github.com/coder/websocket@latest github.com/quic-go/quic-go@latest \
 && go mod tidy && go build -o server .

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/server .
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:server,DNS:localhost"
ENTRYPOINT ["./server"]
