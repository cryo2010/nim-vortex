# HTTP/2 conformance (h2spec)

A manual test that runs [h2spec](https://github.com/summerwind/h2spec),
the reference conformance suite for HTTP/2 (RFC 7540 / 9113), against a
live vortex server over TLS. It is the HTTP/2 analogue of the Autobahn
check for WebSockets and the REDbot check for HTTP/1.1.

## Run

```sh
nimble h2spec           # or: sh conformance/h2spec/run.sh
```

Needs only Docker. The run:

1. builds a vortex HTTP/2-over-TLS server image (`Dockerfile`), which also
   generates a throwaway self-signed cert;
2. starts it and the `summerwind/h2spec` image on a private docker
   network, with h2spec connecting over TLS (`-t -k`) so HTTP/2 is
   negotiated by ALPN;
3. exits non-zero if h2spec reports any failed test.

## Notes

- TLS is used (not h2c) because it matches how browsers reach HTTP/2 and
  exercises the ALPN path. `-k` skips certificate verification, so the
  self-signed cert is fine.
- HTTP/3 is disabled in the server under test; h2spec is TCP-only.
- The `summerwind/h2spec` image is x86_64 only, so on an arm64 host it
  runs under emulation (slower, but functional). The server image is built
  for the host architecture.
