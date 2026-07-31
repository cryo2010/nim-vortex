## PROXY protocol (v1 text + v2 binary) parsing, for recovering the real client
## address when vortex sits behind a Layer-4 / TLS-passthrough load balancer
## (HAProxy, AWS NLB, ...). The proxy prepends this header to the TCP stream
## ahead of the TLS ClientHello / HTTP request; the event loop peeks it, and on
## a trusted peer uses the carried source address for `req.remoteAddress`.
##
## Spec: https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt
##
## Trust is the caller's responsibility: a source-spoofed header from an
## untrusted client must never be believed (see `isTrustedProxy` and
## settings.trustedProxies / proxyProtocol).

import std/[net, strutils]

type
  ProxyParse* = enum
    ppNeedMore     ## the header has not fully arrived; peek again after more bytes
    ppNotPresent   ## the first bytes are not a PROXY header (normal traffic)
    ppLocal        ## a valid header with no usable client address (v2 LOCAL,
                   ## v1 UNKNOWN, or a UNIX/UNSPEC family): keep the direct peer
    ppProxy        ## a valid PROXY header carrying a client IP (`src`)
    ppError        ## malformed or over-long header: reject the connection

  ProxyResult* = object
    kind*: ProxyParse
    consumed*: int    ## header length in bytes, to remove from the socket
    src*: string      ## origin client IP (ppProxy only)

const
  v2sig = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"  ## 12-byte v2 signature
  v1prefix = "PROXY "
  v1max = 107        ## spec cap for a v1 line including CRLF
  v2hdr = 16         ## 12 sig + ver/cmd + fam/proto + 2-byte length

proc r(kind: ProxyParse, consumed = 0, src = ""): ProxyResult =
  ProxyResult(kind: kind, consumed: consumed, src: src)

proc prefixState(buf: openArray[char], want: string): tuple[matches, complete: bool] =
  ## Does `buf` match `want` as far as it goes? complete = the whole of `want`
  ## is present and matched.
  let n = min(buf.len, want.len)
  for i in 0 ..< n:
    if buf[i] != want[i]: return (false, false)
  (true, buf.len >= want.len)

proc parseV1(buf: openArray[char]): ProxyResult =
  # Find CRLF within the line-length cap.
  var i = 0
  let limit = min(buf.len, v1max)
  while i + 1 < limit:
    if buf[i] == '\r' and buf[i + 1] == '\n': break
    inc i
  if i + 1 >= limit:
    # No CRLF yet: need more, unless we already hit the cap (malformed).
    return if buf.len >= v1max: r(ppError) else: r(ppNeedMore)
  let consumed = i + 2
  var line = newString(i)
  for k in 0 ..< i: line[k] = buf[k]
  let parts = line.split(' ')
  if parts.len < 2 or parts[0] != "PROXY": return r(ppError)
  case parts[1]
  of "UNKNOWN":
    r(ppLocal, consumed)                 # ignore addresses up to the CRLF
  of "TCP4", "TCP6":
    if parts.len != 6: return r(ppError)
    try: discard parseIpAddress(parts[2])
    except ValueError: return r(ppError)
    r(ppProxy, consumed, parts[2])
  else:
    r(ppError)

proc parseV2(buf: openArray[char]): ProxyResult =
  if buf.len < v2hdr: return r(ppNeedMore)
  let verCmd = uint8(buf[12])
  if (verCmd shr 4) != 2: return r(ppError)   # only version 2
  let cmd = verCmd and 0x0f
  let fam = uint8(buf[13]) shr 4              # 1 = INET, 2 = INET6, 3 = UNIX
  let addrLen = (int(uint8(buf[14])) shl 8) or int(uint8(buf[15]))
  let total = v2hdr + addrLen
  if buf.len < total: return r(ppNeedMore)
  if cmd == 0: return r(ppLocal, total)        # LOCAL (health check)
  if cmd != 1: return r(ppError)               # not PROXY
  case fam
  of 1:                                        # AF_INET
    if addrLen < 12: return r(ppError)
    var a = IpAddress(family: IpAddressFamily.IPv4)
    for k in 0 ..< 4: a.address_v4[k] = uint8(buf[v2hdr + k])
    r(ppProxy, total, $a)
  of 2:                                        # AF_INET6
    if addrLen < 36: return r(ppError)
    var a = IpAddress(family: IpAddressFamily.IPv6)
    for k in 0 ..< 16: a.address_v6[k] = uint8(buf[v2hdr + k])
    r(ppProxy, total, $a)
  else:                                        # UNIX / UNSPEC: no IP override
    r(ppLocal, total)

proc parseProxyHeader*(buf: openArray[char]): ProxyResult =
  ## Classify the first bytes of a connection. `buf` is the peeked prefix; call
  ## again with more bytes on `ppNeedMore`. Detection is unambiguous: the v2
  ## signature starts with 0x0D, v1 with "PROXY " (distinct from any HTTP method
  ## or a TLS record, which starts with 0x16).
  if buf.len == 0: return r(ppNeedMore)
  block v2:
    let (m, complete) = prefixState(buf, v2sig)
    if m:
      return if complete: parseV2(buf) else: r(ppNeedMore)
  block v1:
    let (m, complete) = prefixState(buf, v1prefix)
    if m:
      return if complete: parseV1(buf) else: r(ppNeedMore)
  r(ppNotPresent)

proc toV4(ip: IpAddress): IpAddress =
  ## Fold an IPv4-mapped IPv6 address (::ffff:a.b.c.d) down to IPv4 so it can be
  ## matched against IPv4 trust entries; other addresses pass through.
  result = ip
  if ip.family == IpAddressFamily.IPv6:
    var mapped = true
    for k in 0 ..< 10:
      if ip.address_v6[k] != 0: mapped = false; break
    if mapped and ip.address_v6[10] == 0xff and ip.address_v6[11] == 0xff:
      var v4 = IpAddress(family: IpAddressFamily.IPv4)
      for k in 0 ..< 4: v4.address_v4[k] = ip.address_v6[12 + k]
      return v4

proc inNetwork(ip, net: IpAddress, bits: int): bool =
  if ip.family != net.family: return false
  let nbytes = if ip.family == IpAddressFamily.IPv4: 4 else: 16
  if bits < 0 or bits > nbytes * 8: return false
  template byteAt(a: IpAddress, i: int): uint8 =
    (if a.family == IpAddressFamily.IPv4: a.address_v4[i] else: a.address_v6[i])
  var remaining = bits
  for i in 0 ..< nbytes:
    if remaining <= 0: break
    let take = min(8, remaining)
    let mask = if take == 8: 0xff'u8 else: uint8(0xff'u8 shl (8 - take))
    if (byteAt(ip, i) and mask) != (byteAt(net, i) and mask): return false
    remaining -= take
  true

proc isTrustedProxy*(peer: string, trusted: openArray[string]): bool =
  ## True if `peer` (a direct-peer IP string) is allowed to supply a PROXY
  ## header. An empty `trusted` list trusts any direct peer -- only safe when the
  ## listener is not publicly reachable (the LB is the sole ingress). Entries are
  ## plain IPs or CIDR ranges (`10.0.0.0/8`, `2001:db8::/32`); IPv4-mapped IPv6
  ## peers are matched against IPv4 entries.
  if trusted.len == 0: return true
  var pip: IpAddress
  try: pip = toV4(parseIpAddress(peer))
  except ValueError: return false
  for entry in trusted:
    let e = entry.strip
    if e.len == 0: continue
    try:
      if '/' in e:
        let slash = e.rfind('/')
        let net = parseIpAddress(e[0 ..< slash])
        let bits = parseInt(e[slash + 1 .. ^1])
        if inNetwork(pip, net, bits): return true
      elif parseIpAddress(e) == pip:
        return true
    except ValueError, OverflowDefect:
      continue
  false
