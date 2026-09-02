## OpenSSL EVP-backed hashing: SHA-1 digests and HMAC-SHA{1,256,512}.
##
## OpenSSL routes these through the CPU's crypto extensions (Intel SHA-NI,
## ARMv8 crypto) when available, so they are markedly faster than a pure-Nim
## implementation. libcrypto is already linked for TLS in the default build, so
## this costs no new dependency.
##
## Only compile this in a TLS build: `-d:plainHttp` omits OpenSSL, so callers
## must guard their import with `when not defined(plainHttp)` and fall back to a
## pure-Nim implementation (websocket/sha1 for SHA-1, nimcrypto for HMAC).

when defined(plainHttp):
  {.error: "hwcrypto requires OpenSSL; guard its import with `when not defined(plainHttp)`".}

const cryptoLibName {.strdefine.} =
  when defined(macosx):
    "(/opt/homebrew/opt/openssl@3/lib/|/usr/local/opt/openssl@3/lib/|)libcrypto.3.dylib"
  else:
    "libcrypto.so(.3|)"

{.push importc, cdecl, dynlib: cryptoLibName.}
proc EVP_sha1(): pointer
proc EVP_sha256(): pointer
proc EVP_sha512(): pointer
proc EVP_Digest(data: pointer, count: csize_t, md: ptr uint8, size: ptr cuint,
                typ: pointer, engine: pointer): cint
proc HMAC(evpMd: pointer, key: pointer, keyLen: cint, d: pointer, n: csize_t,
          md: ptr uint8, mdLen: ptr cuint): ptr uint8
{.pop.}

type Sha1Digest* = array[20, uint8]

# HMAC() dereferences `key` even when key_len is 0, so an empty secret needs a
# valid (0-byte-read) pointer rather than nil. A signing secret is never empty
# in practice, but keep it crash-safe.
var hmacKeyPad: byte

proc sha1*(msg: openArray[char]): Sha1Digest =
  ## SHA-1 of `msg` via OpenSSL EVP (hardware-accelerated where supported).
  ## Drop-in for websocket/sha1.sha1 (same signature and digest type).
  var n: cuint
  let data = if msg.len > 0: unsafeAddr msg[0] else: nil
  discard EVP_Digest(data, csize_t(msg.len), addr result[0], addr n,
                     EVP_sha1(), nil)

proc hmacDigest(evpMd: pointer, secret, msg: string, digestLen: int): seq[byte] =
  result = newSeq[byte](digestLen)
  var n: cuint
  let key = if secret.len > 0: cast[pointer](unsafeAddr secret[0])
            else: cast[pointer](addr hmacKeyPad)
  let d = if msg.len > 0: cast[pointer](unsafeAddr msg[0]) else: nil
  discard HMAC(evpMd, key, cint(secret.len), d, csize_t(msg.len),
               addr result[0], addr n)
  result.setLen(int(n))

proc hmacSha1*(secret, msg: string): seq[byte] =
  hmacDigest(EVP_sha1(), secret, msg, 20)
proc hmacSha256*(secret, msg: string): seq[byte] =
  hmacDigest(EVP_sha256(), secret, msg, 32)
proc hmacSha512*(secret, msg: string): seq[byte] =
  hmacDigest(EVP_sha512(), secret, msg, 64)
