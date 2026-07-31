# Go interop client (standard net/http, HTTP/2 via ALPN; brotli decode via
# andybalholm/brotli). go mod tidy fetches the module and writes go.sum.
FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod client.go ./
RUN go mod tidy && go build -o client .

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/client .
CMD ["./client"]
