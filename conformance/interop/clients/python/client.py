"""Python interop client for the vortex cross-client test.

Uses httpx with the h2 backend so every request genuinely negotiates HTTP/2
over TLS, trusting the shared CA, exercising every method against /echo. httpx
transparently decompresses gzip and brotli (the brotli package is installed),
so a correct round-trip proves the compression path; we also assert the
negotiated protocol is HTTP/2 and the response's Content-Encoding.

Env: INTEROP_URL, INTEROP_RUNTIME (s), INTEROP_CLIENTS, INTEROP_MTLS (0/1),
     INTEROP_ENCODING (gzip|br).
Certs: /certs/ca.pem, and for mTLS /certs/client.pem + /certs/client.key.
"""
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

URL = os.environ.get("INTEROP_URL", "https://server:8443")
RUNTIME = int(os.environ.get("INTEROP_RUNTIME", "5"))
CLIENTS = max(1, int(os.environ.get("INTEROP_CLIENTS", "1")))
MTLS = os.environ.get("INTEROP_MTLS") == "1"
ENC = os.environ.get("INTEROP_ENCODING", "gzip")
NAME = "python"
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def fail(reason):
    print(f"INTEROP FAIL {NAME}: {reason}", file=sys.stderr)
    os._exit(1)


def make_client():
    kwargs = dict(http2=True, verify="/certs/ca.pem", timeout=30.0,
                  headers={"x-api-key": "interop", "accept-encoding": ENC})
    if MTLS:
        kwargs["cert"] = ("/certs/client.pem", "/certs/client.key")
    return httpx.Client(**kwargs)


def worker(deadline):
    n = 0
    with make_client() as client:
        while time.monotonic() < deadline:
            for m in METHODS:
                body = f"hello from {NAME}" if m in ("POST", "PUT", "PATCH") else None
                r = client.request(m, f"{URL}/echo", content=body)
                if r.status_code != 200:
                    raise RuntimeError(f"{m} status {r.status_code}")
                if r.http_version != "HTTP/2":
                    raise RuntimeError(f"{m} not HTTP/2: {r.http_version}")
                if r.headers.get("content-encoding") != ENC:
                    raise RuntimeError(
                        f"{m} not {ENC}-encoded: {r.headers.get('content-encoding')}")
                if m == "HEAD":
                    if r.headers.get("x-echo-method") != "HEAD":
                        raise RuntimeError("HEAD missing x-echo-method")
                elif f"method={m}" not in r.text:
                    raise RuntimeError(f"{m} body did not echo method")
                n += 1
            if MTLS:
                r = client.get(f"{URL}/whoami")
                if r.status_code != 200 or r.text.strip() in ("", "-"):
                    raise RuntimeError("mTLS /whoami did not report a client subject")
                n += 1
    return n


def main():
    deadline = time.monotonic() + RUNTIME
    total = 0
    try:
        with ThreadPoolExecutor(max_workers=CLIENTS) as pool:
            futures = [pool.submit(worker, deadline) for _ in range(CLIENTS)]
            for f in futures:
                total += f.result()
    except Exception as e:  # noqa: BLE001
        fail(str(e))
    print(f"INTEROP OK {NAME}: requests={total} "
          f"(clients={CLIENTS}, runtime={RUNTIME}s, mtls={1 if MTLS else 0}, "
          f"enc={ENC})")


if __name__ == "__main__":
    main()
