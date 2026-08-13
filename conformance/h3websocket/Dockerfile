# Builds the vortex HTTP/3 WebSocket echo server under test for the RFC 9220
# conformance run. conformance/h3websocket/run.sh (or `nimble h3websocket`)
# starts this alongside the aioquic client image on a private docker network.
#
# Based on the deps image (Nim + ngtcp2 + nghttp3 with the ossl crypto backend);
# run.sh builds that first. vortex's HTTP/3 runs on ngtcp2 + nghttp3.

FROM vortex-ngtcp2-deps
WORKDIR /vortex
COPY src ./src
COPY conformance/h3websocket/echo_server.nim ./echo_server.nim
RUN nim c --mm:orc --threads:on -d:release -d:ssl -p:src \
      -o:echo_server echo_server.nim

# Throwaway self-signed cert; the client runs without verification.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:server,DNS:localhost"

EXPOSE 4433/udp
CMD ["./echo_server"]
