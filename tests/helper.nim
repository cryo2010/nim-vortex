## Shared test helpers.
##
## Reads use posix recv + SO_RCVTIMEO instead of std/net's
## `recv(size, timeout)`: the stdlib variant tries to fill `size` bytes
## and misreports EOF when data+FIN are already buffered before the first
## read, which made responses "vanish" in earlier test versions.

import std/[net, posix]

proc setRecvTimeout*(s: Socket, ms: int) =
  var tv: Timeval
  tv.tv_sec = posix.Time(ms div 1000)
  tv.tv_usec = Suseconds((ms mod 1000) * 1000)
  discard setsockopt(s.getFd, SOL_SOCKET, SO_RCVTIMEO,
                     addr tv, SockLen(sizeof(tv)))

proc recvAvailable*(s: Socket, timeoutMs = 2000): string =
  ## One blocking read: whatever arrives first (or "" on timeout/EOF).
  s.setRecvTimeout(timeoutMs)
  var buf = newString(8192)
  let n = recv(s.getFd, addr buf[0], buf.len, cint(0))
  if n <= 0: return ""
  buf.substr(0, n - 1)

proc recvUntilClose*(s: Socket, timeoutMs = 2000): string =
  ## Read until EOF (or a quiet period of timeoutMs).
  s.setRecvTimeout(timeoutMs)
  var buf = newString(8192)
  while true:
    let n = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if n <= 0: break                     # EOF, timeout, or error
    result.add buf.substr(0, n - 1)

proc waitForClose*(s: Socket, tries = 8, stepMs = 500): bool =
  ## True if the peer closes within tries*stepMs.
  s.setRecvTimeout(stepMs)
  var buf = newString(64)
  for i in 0 ..< tries:
    let n = recv(s.getFd, addr buf[0], buf.len, cint(0))
    if n == 0: return true             # EOF
    # n < 0: receive timeout; keep waiting
  false

proc rawExchange*(port: Port, data: string, timeoutMs = 2000): string =
  ## Connect, send raw bytes, read until close/quiet.
  let s = newSocket(buffered = false)
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send(data)
  s.recvUntilClose(timeoutMs)
