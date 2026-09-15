## Shared test helpers.
##
## Reads use posix recv + SO_RCVTIMEO instead of std/net's
## `recv(size, timeout)`: the stdlib variant tries to fill `size` bytes
## and misreports EOF when data+FIN are already buffered before the first
## read, which made responses "vanish" in earlier test versions.

import std/[net, posix, os, osproc, strutils, times]

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

proc connectTimeout*(port: Port, ms = 2000): Socket =
  ## Connect to 127.0.0.1:port with a receive timeout already applied.
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.setRecvTimeout(ms)

# --- curl helpers -------------------------------------------------------------

proc h2curl*(args: string): (string, int) =
  ## Run curl with HTTP/2 prior knowledge; returns (stripped output, exit code).
  let (output, rc) = execCmdEx("curl -s --http2-prior-knowledge " & args)
  (output.strip(), rc)

proc h3curl*(bin, args: string): (string, int) =
  ## Run an HTTP/3-capable curl (`bin`, from findH3Curl) with --http3-only.
  let (output, rc) = execCmdEx(bin & " -sk --http3-only -m 10 " & args)
  (output.strip(), rc)

proc findH3Curl*(): string =
  ## Any curl advertising HTTP3 (system, then Homebrew). "" if none.
  var cands: seq[string]
  let sys = findExe("curl")
  if sys.len > 0: cands.add sys
  cands.add "/opt/homebrew/opt/curl/bin/curl"
  for exe in cands:
    if fileExists(exe):
      let (ver, rc) = execCmdEx(exe & " --version")
      if rc == 0 and "HTTP3" in ver.toUpperAscii: return exe
  ""

proc requireCurl*(msg = "SKIP: no curl"): string =
  ## The curl executable, or echo the suite's SKIP line and exit cleanly.
  result = findExe("curl")
  if result.len == 0:
    echo msg
    quit 0

proc requireH3Curl*(msg = "SKIP: no HTTP/3-capable curl found"): string =
  ## An HTTP/3-capable curl, or echo the suite's SKIP line and exit cleanly.
  result = findH3Curl()
  if result.len == 0:
    echo msg
    quit 0

# --- TLS fixtures -------------------------------------------------------------

proc genCert*(cert, key: string, cn = "localhost") =
  ## Self-signed RSA-2048 cert + unencrypted key at the given paths.
  let (o, rc) = execCmdEx(
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout " & key &
    " -out " & cert & " -days 2 -subj '/CN=" & cn & "'")
  doAssert rc == 0, o

proc makeCertPair*(dirPrefix: string, cn = "localhost"):
    tuple[cert, key: string] =
  ## A fresh per-process temp dir (getTempDir()/dirPrefix<pid>) holding a
  ## vanilla self-signed cert.pem/key.pem. Not cached across processes: tests
  ## may mutate or reload the files. Clean up with removeDir(result.cert.parentDir).
  let dir = getTempDir() / (dirPrefix & $getCurrentProcessId())
  removeDir(dir)
  createDir(dir)
  result = (cert: dir / "cert.pem", key: dir / "key.pem")
  genCert(result.cert, result.key, cn)

# --- OCSP fixtures (Nim-only; no python3) --------------------------------------

proc opensslOk(cmd: string): bool =
  ## Run an openssl command; true on exit 0. Failures make mintOcsp return "",
  ## which the OCSP suites treat as "skip" (openssl too old / different).
  execCmdEx(cmd)[1] == 0

proc genOcspCa*(dir: string) =
  ## An OCSP-signing CA (CN=OCSP-CA) at dir/ca.pem + dir/ca.key. Reused as the
  ## OCSP responder (rsigner/rkey) in mintOcsp.
  let (o, rc) = execCmdEx("openssl req -x509 -newkey rsa:2048 -nodes -keyout " &
    dir & "/ca.key -out " & dir & "/ca.pem -days 2 -subj /CN=OCSP-CA")
  doAssert rc == 0, o

proc genSignedCert*(dir, name, cn: string) =
  ## A server cert dir/<name>.pem + dir/<name>.key (CN=<cn>) signed by the CA
  ## from genOcspCa. -CAcreateserial gives each call a fresh serial, so two
  ## certs minted from one CA get distinct serials (the rotation test needs it).
  let key = dir / (name & ".key")
  let csr = dir / (name & ".csr")
  let crt = dir / (name & ".pem")
  var o: string
  var rc: int
  (o, rc) = execCmdEx("openssl req -newkey rsa:2048 -nodes -keyout " & key &
    " -out " & csr & " -subj /CN=" & cn)
  doAssert rc == 0, o
  (o, rc) = execCmdEx("openssl x509 -req -in " & csr & " -CA " & dir &
    "/ca.pem -CAkey " & dir & "/ca.key -CAcreateserial -out " & crt & " -days 2")
  doAssert rc == 0, o

proc mintOcsp*(dir, certName, respName: string): string =
  ## Sign a "good" OCSP response for dir/<certName>.pem into dir/<respName>.der
  ## (CA from genOcspCa), and return the cert's serial as uppercase hex. Returns
  ## "" if any openssl step fails (older openssl differs) so callers can skip.
  let crt = dir / (certName & ".pem")
  let serialOut = execCmdEx("openssl x509 -in " & crt &
                            " -noout -serial")[0].strip()
  if '=' notin serialOut: return ""
  let serial = serialOut.split('=', 1)[1]
  # index.txt: one "Valid" entry, expiry formatted in Nim (no python3 date math).
  let expiry = (now().utc + 2.years).format("yyMMddHHmmss") & "Z"
  writeFile(dir / "index.txt",
            "V\t" & expiry & "\t\t" & serial & "\tunknown\t/CN=localhost\n")
  # -no_nonce: s_client doesn't send one, so a nonce would make the staple mismatch.
  if not opensslOk("openssl ocsp -issuer " & dir & "/ca.pem -cert " & crt &
                   " -reqout " & dir & "/req.der -no_nonce"): return ""
  if not opensslOk("openssl ocsp -index " & dir & "/index.txt -CA " & dir &
      "/ca.pem -rsigner " & dir & "/ca.pem -rkey " & dir & "/ca.key -reqin " &
      dir & "/req.der -respout " & dir / (respName & ".der") & " -ndays 1 " &
      "-no_nonce"): return ""
  let resp = dir / (respName & ".der")
  if not fileExists(resp) or getFileSize(resp) == 0: return ""
  serial.toUpperAscii

# --- server fixture -----------------------------------------------------------

template withServer*(handler, cfg, pred, srvVar, body: untyped) =
  ## Start a vortex server (with a stream-route predicate) on port 0, expose it
  ## as `srvVar`, and guarantee close when `body` exits.
  mixin newVortex, start, close
  block:
    var srvVar = newVortex(handler, cfg, pred).start(0)
    try:
      body
    finally:
      srvVar.close()

template withServer*(handler, cfg, srvVar, body: untyped) =
  ## Start a vortex server on port 0, expose it as `srvVar`, and guarantee
  ## close when `body` exits.
  mixin newVortex, start, close
  block:
    var srvVar = newVortex(handler, cfg).start(0)
    try:
      body
    finally:
      srvVar.close()

template withServer*(handler, srvVar, body: untyped) =
  ## withServer with the default config.
  mixin initVortexConfig
  withServer(handler, initVortexConfig(), srvVar, body)
