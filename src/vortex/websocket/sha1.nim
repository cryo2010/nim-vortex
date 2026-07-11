## Minimal SHA-1 (FIPS 180-1), used only to compute the WebSocket
## handshake's Sec-WebSocket-Accept value. Bundled so `ws://` keeps
## working in the `-d:plainHttp` build, where OpenSSL is absent and
## std/sha1 is deprecated (it now redirects to a nimble package).

type Sha1Digest* = array[20, uint8]

proc rotl(x: uint32, n: int): uint32 {.inline.} =
  (x shl uint32(n)) or (x shr uint32(32 - n))

proc sha1*(msg: openArray[char]): Sha1Digest =
  ## SHA-1 of `msg`. Unsigned arithmetic wraps mod 2^32 in Nim, as the
  ## algorithm requires.
  var h = [0x67452301'u32, 0xEFCDAB89'u32, 0x98BADCFE'u32,
           0x10325476'u32, 0xC3D2E1F0'u32]
  let bitLen = uint64(msg.len) * 8

  # Padded message: 0x80, zero fill to 56 mod 64, then the 64-bit length.
  var data = newSeq[uint8](msg.len)
  for i in 0 ..< msg.len: data[i] = uint8(msg[i])
  data.add 0x80'u8
  while data.len mod 64 != 56: data.add 0'u8
  for i in countdown(7, 0):
    data.add uint8((bitLen shr (uint64(i) * 8)) and 0xff)

  var w: array[80, uint32]
  var chunk = 0
  while chunk < data.len:
    for i in 0 ..< 16:
      let o = chunk + i * 4
      w[i] = (uint32(data[o]) shl 24) or (uint32(data[o+1]) shl 16) or
             (uint32(data[o+2]) shl 8) or uint32(data[o+3])
    for i in 16 ..< 80:
      w[i] = rotl(w[i-3] xor w[i-8] xor w[i-14] xor w[i-16], 1)

    var a = h[0]
    var b = h[1]
    var c = h[2]
    var d = h[3]
    var e = h[4]
    for i in 0 ..< 80:
      var f, k: uint32
      if i < 20:
        f = (b and c) or ((not b) and d); k = 0x5A827999'u32
      elif i < 40:
        f = b xor c xor d; k = 0x6ED9EBA1'u32
      elif i < 60:
        f = (b and c) or (b and d) or (c and d); k = 0x8F1BBCDC'u32
      else:
        f = b xor c xor d; k = 0xCA62C1D6'u32
      let tmp = rotl(a, 5) + f + e + k + w[i]
      e = d; d = c; c = rotl(b, 30); b = a; a = tmp

    h[0] = h[0] + a; h[1] = h[1] + b; h[2] = h[2] + c
    h[3] = h[3] + d; h[4] = h[4] + e
    chunk += 64

  for i in 0 ..< 5:
    result[i*4]     = uint8((h[i] shr 24) and 0xff)
    result[i*4 + 1] = uint8((h[i] shr 16) and 0xff)
    result[i*4 + 2] = uint8((h[i] shr 8) and 0xff)
    result[i*4 + 3] = uint8(h[i] and 0xff)
