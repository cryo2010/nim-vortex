# Security scan (OWASP ZAP baseline)

Runs the [OWASP ZAP](https://www.zaproxy.org/) packaged
[baseline scan](https://www.zaproxy.org/docs/docker/baseline-scan/) against a
vortex server. The baseline is a *passive* scan: ZAP spiders the site for a
minute and inspects the responses without attacking, which mainly surfaces
missing or weak security response headers.

## Running

```sh
nimble zap        # or: sh conformance/zap/run.sh
```

Needs Docker. `run.sh` builds one image, pulls one, and connects them over a
private docker network:

- **server** (`Dockerfile`, `zap_server.nim`) — a small vortex site (a few
  cross-linked HTML pages plus a JSON `/health`) built `-d:plainHttp` (plain
  HTTP, no OpenSSL). It sets a hardened set of security headers (CSP,
  `X-Content-Type-Options`, anti-clickjacking, `Permissions-Policy`,
  `Cache-Control`, and the `Cross-Origin-*` site-isolation trio) on every
  response.
- **scanner** — `ghcr.io/zaproxy/zaproxy:stable`, running `zap-baseline.py`.

## How it gates

The baseline scan reports every finding as a warning by default, so on its own
it never fails a build. To make it a useful regression gate, `zap.conf`
promotes the security-header rules the server satisfies to **FAIL**, and the
run passes `-I` so remaining warnings do not fail. HTTPS-only rules (HSTS) are
ignored because the scan runs over plain HTTP.

The effect: the scan passes today (vortex serves all the required headers),
and if a future change stops emitting one of them, the matching rule fires and
the run exits non-zero. The scanner exits `0` on a clean/warn-only run, `1` on
any FAIL, and `3` on an operational error; `run.sh` treats anything non-zero as
a failure and dumps the server log.

Override the scanner image with `ZAP_IMAGE=...` (e.g. to pin a digest).
