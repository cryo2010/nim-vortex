# TLS configuration scan (testssl.sh)

Scans vortex's OpenSSL-backed TLS with [testssl.sh](https://testssl.sh/) for
weak protocol versions, weak ciphers, and known vulnerabilities. Complements the
ZAP scan (application layer) by validating the transport layer you configure via
`minTlsVersion`, `tlsCipherList`, `tlsCipherSuites`, and ALPN.

## Running

```sh
nimble testssl      # or: sh conformance/testssl/run.sh
```

Needs Docker. `run.sh` builds a vortex TLS server image and pulls
`drwetter/testssl.sh`, then scans it over a private docker network.

It runs the **protocol** (`-p`), **cipher** (`-s`), and **vulnerability** (`-U`)
groups — not the cert-trust group, since the test cert is a throwaway
self-signed one — and **fails on any HIGH/CRITICAL finding** (`--severity HIGH`,
so a non-empty findings array is the gate).

With the defaults, vortex passes: TLS 1.0/1.1 refused, TLS 1.2/1.3 offered, no
NULL/anonymous/export/weak ciphers, and no HIGH/CRITICAL vulnerabilities.
Override the scanner image with `TESTSSL_IMAGE=...`.
