import std/[unittest, net, httpcore, osproc, strutils, os]
import vortex/[settings, request, server, connection, staticfiles]
import ./helper

# HTTP/3 needs a curl built with HTTP/3 (libnghttp3/ngtcp2 or OpenSSL QUIC);
# helper.requireH3Curl prefers any system curl that advertises HTTP3 and falls
# back to Homebrew's path.
let h3curlBin = requireH3Curl()

let (certFile, keyFile) = makeCertPair("nhs_h3_certs_")
let certDir = certFile.parentDir

const bigBody = "0123456789abcdef".repeat(8 * 1024)   # 128 KiB
const bigFilePath = "/tmp/nhs_h3_bigfile.dat"
writeFile(bigFilePath, "0123456789abcdef".repeat(64 * 1024))  # 1 MiB, > stream threshold

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/":
    res.send(Http200, "hello h3")
  of "/whoami":
    res.send(Http200, req.remoteAddress)
  of "/bigfile":
    res.sendFile(bigFilePath)   # > stream threshold: streams over h3
  of "/echo":
    res.send(Http200, req.body, @[("Content-Type", req.header("Content-Type")),
                                   ("X-Proto", $req.httpVersion)])
  of "/big":
    res.send(Http200, bigBody, @[("Content-Type", "application/octet-stream")])
  of "/slow":
    req.blocking:
      sleep(100)
      res.send(Http200, "slow h3 done")
  of "/stream":
    res.sendHead(Http200, "text/plain")
    res.write("Hello, ")
    res.write("streamed ")
    res.write("h3!")
    res.finish()
  of "/streambig":
    res.sendHead(Http200, "application/octet-stream")
    let chunk = repeat('y', 4096)
    for i in 0 ..< 64:
      discard res.write(chunk)
    res.finish()
  of "/trailer":
    res.sendHead(Http200, "text/plain")
    res.write("body")
    res.trailers["X-Checksum"] = "abc123"
    res.finish()
  of "/boom":
    res.stream(Http200, "text/plain"):
      res.write("partial")
      raise newException(ValueError, "boom mid-stream")
  of "/up":
    # Streaming request body: consume via onBody, reply with the byte count.
    let acc = new(int)
    req.onBody proc(chunk: openArray[char], last: bool) {.gcsafe.} =
      acc[] += chunk.len
      if last: res.send(Http200, "got " & $acc[])
  of "/drain":
    # Streaming route that responds immediately WITHOUT reading the body. The
    # received-but-unread body bytes must be credited back to the connection
    # window at stream teardown, or a long-lived connection leaks MAX_DATA.
    res.send(Http200, "ok")
  else:
    res.send(Http404, "nope")

proc streamPred(core: ptr LoopCore, fd: int32, gen: uint32,
                stream: uint32): bool {.gcsafe.} =
  let req = Request(core: core, fd: fd, gen: gen, stream: stream)
  req.path in ["/up", "/drain"] and req.method == HttpPost

withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, workerThreads = 2,
                            certFile = certFile, keyFile = keyFile,
                            maxBodySize = 1024 * 1024), streamPred, srv):
  let base = "https://localhost:" & $srv.port

  proc h3curl(args: string): (string, int) = helper.h3curl(h3curlBin, args)

  suite "HTTP/3 (QUIC, via curl)":
    test "GET":
      let (output, rc) = h3curl("-w '|%{http_version}' " & base & "/")
      check rc == 0
      check output == "hello h3|3"

    test "POST echo":
      let (output, rc) = h3curl(
        "-H 'Content-Type: text/plain' -d 'payload h3' " &
        "-w '|%{http_version}' " & base & "/echo")
      check rc == 0
      check output == "payload h3|3"

    test "404":
      let (output, rc) = h3curl("-o /dev/null -w '%{http_code}' " & base & "/x")
      check rc == 0
      check output == "404"

    test "HEAD has no body":
      let (output, rc) = h3curl("-I -w '%{size_download}' " & base & "/")
      check rc == 0
      check "HTTP/3 200" in output
      check output.endsWith("0")

    test "large response":
      let (output, rc) = h3curl("-o /dev/null -w '%{size_download}' " & base & "/big")
      check rc == 0
      check output == $bigBody.len

    test "blocking route over h3 (worker respond path)":
      let (output, rc) = h3curl(base & "/slow")
      check rc == 0
      check output == "slow h3 done"

    test "several sequential requests":
      for i in 0 ..< 3:
        check h3curl(base & "/")[0] == "hello h3"

    test "streamed response over h3":
      let (output, rc) = h3curl("-w '|%{http_version}' " & base & "/stream")
      check rc == 0
      check output == "Hello, streamed h3!|3"

    test "large streamed response over h3":
      let (output, rc) = h3curl(
        "-o /dev/null -w '%{size_download}' " & base & "/streambig")
      check rc == 0
      check output == $(64 * 4096)

    test "response trailers are emitted over h3 (trailing HEADERS)":
      # curl surfaces h3 trailers by dumping them with the response headers (-D).
      # Before the fix the h3 finish path dropped res.trailers entirely.
      let (output, rc) = h3curl("-D - -o /dev/null -sS " & base & "/trailer")
      check rc == 0
      check "x-checksum: abc123" in output.toLowerAscii

    test "a mid-stream exception resets the h3 stream (client sees an error)":
      let (_, rc) = h3curl("-o /dev/null " & base & "/boom")
      check rc != 0

    test "streamed request body over h3 (DATA -> onBody)":
      let tmp = certDir / "up.bin"
      writeFile(tmp, "u".repeat(300 * 1024))
      let (output, rc) = h3curl("--data-binary @" & tmp & " " & base & "/up")
      check rc == 0
      check output == "got " & $(300 * 1024)

    test "streamed upload beyond both QUIC windows":
      # 9 MiB > 1 MiB stream window AND > 4 MiB connection window, so a completed
      # transfer proves both MAX_STREAM_DATA and MAX_DATA replenish as the handler
      # reads (deliverBody auto-ack), plus the maxBodySize streaming exemption.
      # -m 60 makes a flow-control stall fail (timeout) instead of hanging.
      let big = certDir / "up9.bin"
      let n = 9 * 1024 * 1024
      writeFile(big, "u".repeat(n))
      let (output, rc) = h3curl("-m 60 --data-binary @" & big & " " & base & "/up")
      check rc == 0
      check output == "got " & $n

    test "unread streaming upload does not leak the connection window":
      # Regression for the teardown credit-remainder fix. Ten 512 KiB POSTs to
      # /drain (a streaming route that responds without reading the body) over ONE
      # reused QUIC connection: cumulative 5 MiB > the 4 MiB connection window.
      # Each unread body's bytes must return to MAX_DATA at stream teardown (a
      # clean close, appErr 0) or requests past the 4 MiB mark stall
      # flow-control-blocked. All ten must return 200. Verified to time out
      # (0 codes) with the counter change stashed, and pass with it.
      #
      # Driven with --next (not one multi-URL invocation): --next completes each
      # transfer before the next, so no concurrent unread streams pile up and
      # starve the pump; a single invocation multiplexes all ten at once and
      # deadlocks regardless of the fix. --http3-only/-sk are re-specified per
      # segment because they do not carry across --next (curl would otherwise
      # fall back to h2/TCP and abort on the self-signed cert). num_connects is 1
      # on the first transfer and 0 after, confirming one reused h3 connection.
      # 512 KiB stays under the 1 MiB stream window so each upload completes.
      let drainBody = certDir / "drain.bin"
      writeFile(drainBody, "d".repeat(512 * 1024))
      let seg = "-o /dev/null -w '%{http_code}\\n' --data-binary @" & drainBody &
        " " & base & "/drain"
      var args = "-m 30 " & seg
      for i in 1 ..< 10:
        args &= " --next -sk --http3-only -m 30 " & seg
      let (output, rc) = h3curl(args)
      check rc == 0
      let codes = output.splitLines()
      check codes.len == 10
      for c in codes:
        check c == "200"

    test "remoteAddress reports the QUIC peer IP":
      # Over h3 the peer address comes from ngtcp2 (the connection path's remote
      # sockaddr), reported at accept; it must be a loopback here (empty allowed
      # only defensively for a stale handle).
      let (output, rc) = h3curl(base & "/whoami")
      check rc == 0
      check output in ["", "127.0.0.1", "::1"]

    test "large file streams over h3 (full body)":
      let (output, rc) = h3curl("-o /dev/null -w '%{size_download}' " & base & "/bigfile")
      check rc == 0
      check output == "1048576"

    test "alt-svc advertised on h1/h2":
      let (output, rc) = execCmdEx(
        "curl -skI -m 5 " & base & "/")
      check rc == 0
      check ("h3=\":" & $srv.port & "\"") in output

removeDir(certDir)
echo "server shut down cleanly"
