# WebSocket conformance (Autobahn|Testsuite)

A manual test that runs the [Autobahn|Testsuite](https://github.com/crossbario/autobahn-testsuite),
the reference conformance suite for RFC 6455, against a live vortex
WebSocket server. It is the WebSocket analogue of the `h2spec` check used
for HTTP/2 and the REDbot check used for HTTP/1.1.

## Run

```sh
nimble autobahn          # or: sh conformance/autobahn/run.sh
```

Needs only Docker and `python3`. The run:

1. builds a vortex echo server image (`Dockerfile`);
2. starts it and the `crossbario/autobahn-testsuite` `fuzzingclient` on a
   private docker network, so the testsuite (the client) drives every case
   against the server;
3. parses the JSON report and exits non-zero if any executed case reports
   a failing behavior.

The full human-readable report is written to
`conformance/autobahn/reports/index.html`.

## What is covered

The `fuzzingclient` runs the standard case groups: framing (1), pings and
pongs (2), reserved bits (3), opcodes (4), fragmentation (5), UTF-8
handling (6), close handling (7), and limits/performance (9-10).

`fuzzingclient.json` excludes the compression cases (12-13): vortex does
not yet implement the permessage-deflate extension (RFC 7692), which is
tracked in the WebSocket roadmap in the top-level README. Everything else
is expected to pass; the suite validates it independently.

## Notes

- The `crossbario/autobahn-testsuite` image is x86_64 only, so on an arm64
  host it runs under emulation (slower, but functional). The echo server
  image is built for the host architecture.
- A case's grade is `behavior` (and `behaviorClose`): `OK` / `NON-STRICT`
  / `INFORMATIONAL` pass; `FAILED` / `WRONG CODE` fail the run.
