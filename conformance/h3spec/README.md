# HTTP/3 conformance (h3spec)

Runs [h3spec](https://github.com/kazu-yamamoto/h3spec) against vortex's HTTP/3
server to verify the RFC 9114 / RFC 9204 **error cases** — control-stream
validation, malformed requests, and QPACK stream errors — each of which must
close the connection (or reset the stream) with the correct error code.

## Running

```sh
nimble h3spec      # or: sh conformance/h3spec/run.sh
```

Needs Docker. `run.sh` builds two images and connects them over a private
docker network (QUIC is UDP):

- **server** (`Dockerfile`, `h3spec_server.nim`) — a trivial always-200
  vortex HTTP/3 server on `archlinux` (for OpenSSL >= 3.5).
- **client** (`client.Dockerfile`) — the pinned prebuilt `h3spec` binary.

## Scope: the "HTTP/3 servers" group only

h3spec has two groups. Only the **"HTTP/3 servers"** group (HTTP/3 + QPACK,
15 cases) is vortex's responsibility, and the harness runs exactly that
(`-m "HTTP/3 servers"`). The **"QUIC servers"** group (RFC 9000 transport:
transport parameters, flow control, frame encoding, TLS) is enforced by
**OpenSSL's QUIC stack**, which vortex delegates to — those cases are out of
vortex's control and are excluded.

Note: h3spec resolves a plain hostname; run it against an IPv4 address or a
name with an A record (vortex's UDP socket is IPv4). Inside the docker
network the `server` alias resolves to the container's IPv4, so this is
automatic here.
