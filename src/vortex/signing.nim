## HMAC-SHA1 message authentication, used for tamper-proof (signed) cookies.
##
## Built on the bundled pure-Nim SHA-1 so it works in every build mode,
## including `-d:plainHttp` where OpenSSL is absent. HMAC-SHA1 is a sound MAC
## for this purpose: the SHA-1 collision attacks do not weaken HMAC-SHA1's
## unforgeability. It provides integrity/authenticity only, not confidentiality
## (a signed cookie value is readable, just not forgeable without the secret).

import std/[base64, strutils]
import ./websocket/sha1

const blockSize = 64   # SHA-1 block size, in bytes

proc hmacSha1*(key, msg: string): Sha1Digest =
  ## HMAC-SHA1(key, msg) per RFC 2104.
  var k = newString(blockSize)                 # key, zero-padded to the block
  if key.len > blockSize:
    let kh = sha1(key)                          # long keys are hashed first
    for i in 0 ..< kh.len: k[i] = char(kh[i])
  else:
    for i in 0 ..< key.len: k[i] = key[i]
  var ipad = newString(blockSize)
  var opad = newString(blockSize)
  for i in 0 ..< blockSize:
    ipad[i] = char(uint8(k[i]) xor 0x36'u8)
    opad[i] = char(uint8(k[i]) xor 0x5c'u8)
  let inner = sha1(ipad & msg)
  var innerStr = newString(inner.len)
  for i in 0 ..< inner.len: innerStr[i] = char(inner[i])
  result = sha1(opad & innerStr)

proc constantTimeEq*(a, b: string): bool =
  ## Length-independent-of-content compare: no early return on the first
  ## differing byte, so a signature check does not leak position via timing.
  if a.len != b.len: return false
  var diff = 0'u8
  for i in 0 ..< a.len: diff = diff or (uint8(a[i]) xor uint8(b[i]))
  diff == 0

proc b64url(d: Sha1Digest): string =
  var s = newString(d.len)
  for i in 0 ..< d.len: s[i] = char(d[i])
  # URL/cookie-safe base64 without padding: no '+', '/', or '=' to collide with
  # cookie syntax or the value/signature '.' separator.
  encode(s).replace('+', '-').replace('/', '_').strip(chars = {'='})

proc sign*(secret, msg: string): string =
  ## A URL-safe, unpadded base64 HMAC-SHA1 tag for `msg` under `secret`.
  b64url(hmacSha1(secret, msg))

proc verify*(secret, msg, sig: string): bool =
  ## True if `sig` is the correct tag for `msg` under `secret` (constant time).
  constantTimeEq(sign(secret, msg), sig)
