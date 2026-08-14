# Security Policy

Thank you for helping keep vortex and its users safe. vortex terminates
untrusted protocol bytes (HTTP/1.1, HTTP/2, HTTP/3/QUIC, WebSockets, TLS), so we
take reports seriously and handle them under coordinated disclosure.

This file is the reporting policy. For the design analysis see
[THREAT_MODEL.md](THREAT_MODEL.md); for how to configure vortex defensively see
[HARDENING.md](HARDENING.md).

## Supported versions

vortex is pre-1.0. Only the latest release and the current `main` are supported;
fixes are not back-ported to older tags. Please confirm a report against the
latest `main` when you can.

| Version        | Supported |
|----------------|-----------|
| latest `main`  | yes       |
| latest release | yes       |
| older          | no        |

## Reporting a vulnerability

**Please report privately. Do not open a public issue or pull request for a
suspected vulnerability.**

- **Preferred:** GitHub private vulnerability reporting. Go to the repository's
  **Security** tab and click **Report a vulnerability**. This opens a private
  advisory visible only to you and the maintainers, with a place to discuss and
  propose a fix.
- **Fallback:** if you cannot use the Security tab, email the maintainer, Craig
  Younker, at **cryo2010@gmail.com**. If you want to encrypt the report, say so
  and we will arrange a key.

### What to include

A short description and a reproducing input are enough to start. The more of the
following you can provide, the faster we can triage:

- affected version or commit (ideally reproduced on the latest `main`);
- the component: HTTP/1.1, HTTP/2, HTTP/3/QUIC, WebSocket, or TLS;
- a description of the issue and its impact (what an attacker gains);
- a reproduction: a request, a byte sequence, a script, or a proof-of-concept.

## What to expect

- **Acknowledgement** within 3 business days.
- **Coordinated disclosure.** We will work with you on a fix and agree a
  disclosure date before anything is made public. We aim to ship a fix and
  publish a GitHub Security Advisory (requesting a CVE where warranted) promptly;
  complex issues may take longer, and we will keep you updated.
- **Credit.** We will credit you in the advisory unless you prefer to remain
  anonymous.
- **No bug bounty.** vortex is a solo-maintained, pre-1.0 project, so there is no
  paid bounty program. Reports are still very welcome and appreciated.

## Scope

In scope is anything that lets an attacker, through traffic to a vortex server,
cause memory corruption, crash the loop, bypass a documented limit or check,
smuggle or split requests, exhaust resources beyond the configured bounds, or
read data across a connection boundary. See [THREAT_MODEL.md](THREAT_MODEL.md)
for the full model, trust boundaries, and what is deliberately out of scope
(for example, strict per-IP rate limiting that belongs at a fronting proxy).

Vulnerabilities in dependencies (OpenSSL, ngtcp2, nghttp3) should be reported to
those projects; if vortex uses one unsafely, that is in scope here.
