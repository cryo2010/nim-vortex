# HTTP conformance check (REDbot)

A manual test that points [REDbot](https://redbot.org)
([source](https://github.com/mnot/redbot)) at a live vortex server and
reports HTTP protocol problems. REDbot is a resource linter: for a given
URL it re-requests it under many conditions (conditional GET, byte
ranges, compression negotiation, connection reuse, HEAD, method
handling) and flags responses that violate the HTTP specs, with each
finding graded GOOD / INFO / WARN / BAD.

This complements the automated suite (`nimble test`) and the HTTP/2
`h2spec` check: it exercises the HTTP/1.1 wire output end to end against
an independent third-party implementation.

## Run

The simplest path needs only Docker: `conformance/Dockerfile` bundles the
Nim toolchain and REDbot.

```sh
nimble redbot          # build the image and run the check
```

That is equivalent to building and running by hand (the image's default
base is arm64, so override it on x86_64 hosts):

```sh
docker build -f conformance/Dockerfile -t vortex-redbot .
# x86_64 hosts:
docker build -f conformance/Dockerfile -t vortex-redbot \
  --build-arg BASE=archlinux:latest .

docker run --rm vortex-redbot          # checks / and /json
docker run --rm vortex-redbot /json    # a specific path
```

The container exits non-zero on any BAD-level finding, so it is CI-usable.

### On the host (without Docker)

Needs REDbot on `PATH` (`pipx install redbot`, or `pip install redbot`),
plus `curl` and the Nim toolchain. Then:

```sh
sh conformance/run.sh              # checks / and /json
sh conformance/run.sh /json        # a specific path
PORT=8123 sh conformance/run.sh    # override the port
```

Both paths run the same `run.sh`, which builds and starts
`redbot_server.nim`, waits for it, then runs REDbot against each path,
prints each report, and writes the full
colourised reports to `conformance/reports/`. REDbot marks severity with
colour only (no text label), so the script runs it through a pty to keep
the colours and counts the red (BAD) findings: it exits non-zero if any
appear. WARN/INFO items are printed but do not fail the run.

## The server under test

`redbot_server.nim` serves a small, deliberately conformant set so
REDbot exercises the interesting paths rather than only noting their
absence:

- `/` — `text/plain`, cacheable (`Cache-Control: max-age=60`), with an
  `ETag` and `Last-Modified`, and full conditional handling: a matching
  `If-None-Match` / `If-Modified-Since` gets a `304 Not Modified`.
- `/json` — `application/json`, cacheable.
- anything else — `404`.

## Interpreting results

- **BAD (red)** is what matters: it means a genuine protocol problem in
  vortex's output. The script fails on these. Report them.
- **WARN / INFO** are advisory and expected for a low-level server. vortex
  leaves representation concerns to the application, so REDbot will note
  things like "no compression was offered" or "no `Accept-Ranges`" — those
  are choices, not bugs. A caching/validator note against `/json` (no
  `ETag`/`Last-Modified`) is likewise by design.
- REDbot inspects the response the application produced. Findings about
  caching policy or validators reflect these example handlers, not the
  server core; the wire-level checks (framing, `Content-Length`, `Date`,
  `Connection`, chunked encoding, HEAD and 304 semantics) are the ones
  that validate vortex itself.
