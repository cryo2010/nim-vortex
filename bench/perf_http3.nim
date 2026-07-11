## HTTP/3 throughput benchmark. The client speaks QUIC via OpenSSL's
## (>= 3.2) client API in blocking mode: one QUIC connection per client
## thread, batches of concurrent request streams, responses counted by
## stream FIN. Requests are a hand-built h3 HEADERS frame of three
## static-table QPACK indexes (":method GET, :scheme https, :path /").
##
##   perf_http3                     orchestrator (spawns itself as servers)
##   perf_http3 serve <name> <port> [cert key]
##
## Build and run:  nimble perf3
## Tunables: -d:benchSeconds=5 -d:benchConns=32 -d:benchStreams=32
##
## Caveats: QUIC pays for per-packet crypto on both sides of the loopback
## and the OpenSSL client is not a tuned load generator, so absolute
## numbers are far below h1/h2; the value is h3-vs-h1 on the same server
## and the thread-scaling ratio. The h1 row runs against a cleartext
## instance of the same server and handler.

import std/[os, osproc, strutils, atomics, posix, nativesockets, net,
            httpcore]
import ../src/vortex
import ../src/vortex/http3/frames
import ./perf_common

const
  benchSeconds {.intdefine.} = 5
  benchConns {.intdefine.} = 32
  benchStreams {.intdefine.} = 32   # concurrent streams per batch
  benchDepth {.intdefine.} = 8      # h1 pipeline depth (reference row)

proc serveOurs(port: int, threads: int, cert, key: string) =
  proc handler(req: vortex.Request, res: vortex.Response) {.gcsafe.} =
    vortex.send(res, Http200, "Hello, World!", "text/plain")
  vortex.run(handler,
    vortex.initSettings(port = net.Port(port), numThreads = threads,
                                 certFile = cert, keyFile = key))

# --- OpenSSL QUIC client bindings -------------------------------------------

const sslLibName {.strdefine.} =
  when defined(macosx):
    "(/opt/homebrew/opt/openssl@3/lib/|/usr/local/opt/openssl@3/lib/|)libssl.3.dylib"
  else:
    "libssl.so(.3|)"

type SslPtr = pointer

{.push importc, cdecl, dynlib: sslLibName.}
proc OSSL_QUIC_client_method(): pointer
proc SSL_CTX_new(m: pointer): pointer
proc SSL_CTX_free(ctx: pointer)
proc SSL_CTX_set_verify(ctx: pointer, mode: cint, cb: pointer)
proc SSL_new(ctx: pointer): SslPtr
proc SSL_free(ssl: SslPtr)
proc SSL_set_fd(ssl: SslPtr, fd: cint): cint
proc SSL_set_alpn_protos(ssl: SslPtr, protos: cstring, len: cuint): cint
proc SSL_connect(ssl: SslPtr): cint
proc SSL_new_stream(ssl: SslPtr, flags: uint64): SslPtr
proc SSL_stream_conclude(ssl: SslPtr, flags: uint64): cint
proc SSL_read(ssl: SslPtr, buf: pointer, num: cint): cint
proc SSL_write(ssl: SslPtr, buf: pointer, num: cint): cint
proc SSL_get_error(ssl: SslPtr, ret: cint): cint
{.pop.}

const SSL_ERROR_ZERO_RETURN = cint(6)

proc connectUdp(port: int): SocketHandle =
  ## Blocking UDP socket connected to the server (QUIC client transport).
  result = createNativeSocket(Domain.AF_INET, SockType.SOCK_DGRAM,
                              Protocol.IPPROTO_UDP)
  let ai = getAddrInfo("127.0.0.1", net.Port(port), Domain.AF_INET,
                       SockType.SOCK_DGRAM, Protocol.IPPROTO_UDP)
  let rc = connect(result, ai.ai_addr, SockLen(ai.ai_addrlen))
  freeAddrInfo(ai)
  if rc < 0:
    result.close()
    return osInvalidSocket

proc buildH3Request(): string =
  ## h3 HEADERS frame around a QPACK field section of prefix 00 00 plus
  ## indexed statics 17 (:method GET), 23 (:scheme https), 1 (:path /),
  ## each encoded as 0xc0 | index.
  var payload = "\x00\x00"
  payload.add char(0xc0 or 17)
  payload.add char(0xc0 or 23)
  payload.add char(0xc0 or 1)
  result = ""
  result.addFrame(h3fHeaders, payload)

proc h3ClientLoop(ctx: ClientCtx) {.thread.} =
  let h3Request = buildH3Request()
  let sslCtx = SSL_CTX_new(OSSL_QUIC_client_method())
  if sslCtx == nil: return
  SSL_CTX_set_verify(sslCtx, 0, nil)         # self-signed test certs
  var count = 0'i64
  var fd = osInvalidSocket
  var conn: SslPtr = nil
  var buf = newString(16 * 1024)
  var streams = newSeq[SslPtr](ctx.depth)

  template teardown() =
    if conn != nil:
      SSL_free(conn)
      conn = nil
    if fd != osInvalidSocket:
      fd.close()
      fd = osInvalidSocket

  while not ctx.stop[].load(moRelaxed):
    if conn == nil:
      fd = connectUdp(ctx.port)
      if fd == osInvalidSocket:
        sleep(10)
        continue
      conn = SSL_new(sslCtx)
      if conn == nil or SSL_set_fd(conn, cint(fd)) != 1 or
          SSL_set_alpn_protos(conn, "\x02h3", 3) != 0 or
          SSL_connect(conn) != 1:
        teardown()
        sleep(10)
        continue
    block batch:
      # Open a batch of request streams, send, then drain each to FIN.
      var opened = 0
      for i in 0 ..< ctx.depth:
        let s = SSL_new_stream(conn, 0)
        if s == nil: break
        streams[i] = s
        inc opened
        if SSL_write(s, unsafeAddr h3Request[0], cint(h3Request.len)) <=
            0 or SSL_stream_conclude(s, 0) != 1:
          for j in 0 .. i: SSL_free(streams[j])
          teardown()
          break batch
      if opened == 0:
        teardown()
        break batch
      for i in 0 ..< opened:
        var done = false
        while not done:
          let n = SSL_read(streams[i], addr buf[0], cint(buf.len))
          if n > 0:
            continue                       # body bytes; discard
          if SSL_get_error(streams[i], n) == SSL_ERROR_ZERO_RETURN:
            done = true                    # FIN: response complete
          else:
            for j in i ..< opened: SSL_free(streams[j])
            teardown()
            break batch
        SSL_free(streams[i])
        inc count
  teardown()
  SSL_CTX_free(sslCtx)
  discard ctx.total[].fetchAdd(count, moRelaxed)

# --- orchestration -----------------------------------------------------------

proc orchestrate() =
  let certDir = getTempDir() / "nhs_perf3_" & $getCurrentProcessId()
  createDir(certDir)
  defer: removeDir(certDir)
  let cert = certDir / "cert.pem"
  let key = certDir / "key.pem"
  doAssert execCmdEx("openssl req -x509 -newkey rsa:2048 -nodes -keyout " &
    key & " -out " & cert & " -days 2 -subj /CN=localhost")[1] == 0

  echo "HTTP/3 (QUIC) throughput: ", benchConns, " connections, ",
       benchStreams, " concurrent streams, ", benchSeconds, "s per row; ",
       "h1 row: pipeline depth ", benchDepth
  echo ""
  var results: seq[(string, float)]

  proc bench(label, server: string, port: int, client: ClientProc,
             depth: int) =
    var args = @["serve", server, $port]
    if server.startsWith("nhs-tls"):
      args.add cert
      args.add key
    let p = startProcess(getAppFilename(), args = args,
                         options = {poParentStreams})
    defer:
      p.kill()
      p.close()
      sleep(300)
    if not waitReady(port):                # TCP listener shares the port
      echo label, ": failed to start"
      return
    discard runLoad(client, port, benchConns, 1, depth)       # warmup
    let rps = runLoad(client, port, benchConns, benchSeconds, depth)
    results.add (label, rps)
    printRow(label, rps)

  bench("h3", "nhs-tls", 9301, h3ClientLoop, benchStreams)
  bench("h3-1thread", "nhs-tls-1t", 9302, h3ClientLoop, benchStreams)
  bench("h1 (cleartext)", "nhs-plain", 9303, h1ClientLoop, benchDepth)
  report(results)

when isMainModule:
  if paramCount() >= 3 and paramStr(1) == "serve":
    let port = parseInt(paramStr(3))
    let cert = if paramCount() >= 5: paramStr(4) else: ""
    let key = if paramCount() >= 5: paramStr(5) else: ""
    case paramStr(2)
    of "nhs-tls": serveOurs(port, 0, cert, key)
    of "nhs-tls-1t": serveOurs(port, 1, cert, key)
    of "nhs-plain": serveOurs(port, 0, "", "")
    else: quit "unknown server: " & paramStr(2)
  else:
    orchestrate()
