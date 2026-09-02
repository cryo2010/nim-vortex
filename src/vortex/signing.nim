## HMAC message authentication for tamper-proof (signed) cookies.
##
## In the default (TLS) build the HMAC runs through OpenSSL (hardware SHA via
## SHA-NI / ARMv8 crypto extensions where available); under `-d:plainHttp`,
## where OpenSSL is absent, it falls back to nimcrypto (pure Nim). HMAC provides
## integrity/authenticity only, not confidentiality (a signed cookie value is
## readable, just not forgeable without the secret). HMAC-SHA256 is the default;
## SHA-1 is kept for interop and SHA-512 for a larger tag.

import std/[base64, strutils]
when defined(plainHttp):
  import nimcrypto/[hmac, sha, sha2]
else:
  import ./hwcrypto

type
  CookieMac* = enum   ## HMAC hash used to sign a cookie
    macSha256         ## HMAC-SHA256 (default)
    macSha512         ## HMAC-SHA512
    macSha1           ## HMAC-SHA1 (interop with older tags)

proc rawHmac(algo: CookieMac, secret, msg: string): seq[byte] =
  when defined(plainHttp):
    case algo
    of macSha256: @(hmac(sha256, secret, msg).data)
    of macSha512: @(hmac(sha512, secret, msg).data)
    of macSha1:   @(hmac(sha1, secret, msg).data)
  else:
    case algo
    of macSha256: hmacSha256(secret, msg)
    of macSha512: hmacSha512(secret, msg)
    of macSha1:   hmacSha1(secret, msg)

proc constantTimeEq*(a, b: string): bool =
  ## Length-independent-of-content compare: no early return on the first
  ## differing byte, so a signature check does not leak position via timing.
  if a.len != b.len: return false
  var diff = 0'u8
  for i in 0 ..< a.len: diff = diff or (uint8(a[i]) xor uint8(b[i]))
  diff == 0

proc b64url(bytes: openArray[byte]): string =
  var s = newString(bytes.len)
  for i in 0 ..< bytes.len: s[i] = char(bytes[i])
  # URL/cookie-safe base64 without padding: no '+', '/', or '=' to collide with
  # cookie syntax or the value/signature '.' separator.
  encode(s).replace('+', '-').replace('/', '_').strip(chars = {'='})

proc sign*(secret, msg: string, algo = macSha256): string =
  ## A URL-safe, unpadded base64 HMAC tag for `msg` under `secret`.
  b64url(rawHmac(algo, secret, msg))

proc verify*(secret, msg, sig: string, algo = macSha256): bool =
  ## True if `sig` is the correct tag for `msg` under `secret` and `algo`
  ## (constant time). Use the same `algo` that produced the tag.
  constantTimeEq(sign(secret, msg, algo), sig)
