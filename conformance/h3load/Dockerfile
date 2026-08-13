# Builds the vortex HTTP/3 server under test for the h3load throughput test.
# conformance/h3load/run.sh (or `nimble h3load`) starts this alongside the
# h2load-http3 client image on a private docker network (QUIC is UDP).
#
# Based on the deps image (Nim + ngtcp2 + nghttp3 with the ossl crypto backend);
# run.sh builds that first. vortex's HTTP/3 runs on ngtcp2 + nghttp3.

FROM vortex-ngtcp2-deps
WORKDIR /vortex
COPY src ./src
COPY conformance/h3load/h3load_server.nim ./h3load_server.nim
RUN nim c --mm:orc --threads:on -d:release -d:ssl -p:src \
      -o:h3load_server h3load_server.nim

# Throwaway self-signed cert; the client runs without verification.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:server,DNS:localhost"

EXPOSE 4433/udp
CMD ["./h3load_server"]
