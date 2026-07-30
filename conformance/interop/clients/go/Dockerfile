# Go interop client (standard net/http, HTTP/2 via ALPN; no external deps).
FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod client.go ./
RUN go build -o client .

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/client .
CMD ["./client"]
