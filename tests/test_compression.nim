## gzip response compression (settings.compress, -d:httpGzip). Run via
## `nimble testgzip`; under the default build it skips (the feature is compiled
## out). curl handles the gzip round-trip.
##
## The worker-send cases (#413) send the same compressible body from off the
## loop thread: a `blocking:` body, a small `.txt` served by `staticHandler`
## (buffered on the worker), a kept handle another worker task answers, and a
## handle answered from a thread the application owns. Negotiation read the
## Accept-Encoding header through the live connection table, which is
## loop-thread only, so every one of them answered 500. A worker task's own
## handle now negotiates through the task's request snapshot; any other
## off-loop handle has no snapshot to read and answers identity.

# The test body after the compile-time skip below is intentionally unreachable
# when the flag is absent (the SKIP path quits).
{.warning[UnreachableCode]: off.}

when not defined(httpGzip):
  echo "SKIP: gzip response compression needs -d:httpGzip"
  quit 0

import std/[unittest, os, osproc, strutils, httpcore, net, atomics]
import vortex/[settings, request, server, routing, staticfiles]
import ./helper

let curlBin = requireCurl()

const bigText = "The quick brown fox jumps over the lazy dog. ".repeat(120)  # ~5 KiB

var keptRes: Response            # a parked handle (plain words, no GC'd fields)
var keptReady: Atomic[bool]      # /park stored keptRes
var appRes: Response             # the handle the app-owned thread answers
var appReady: Atomic[bool]
var stopApp: Atomic[bool]
var appThread: Thread[void]

proc appMain() {.thread.} =
  ## A thread the application owns (no worker task, no snapshot): answers each
  ## handle /app parks with a compressible body.
  while not stopApp.load:
    if appReady.load:
      {.cast(gcsafe).}:
        let r = appRes
      appReady.store(false)
      r.send(Http200, bigText)
    sleep(5)

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/big":   res.send(Http200, bigText)
  of "/small": res.send(Http200, "tiny")
  of "/png":   res.send(Http200, bigText, @[("Content-Type", "image/png")])   # not compressible
  of "/worker":
    # A buffered send from a worker thread (#413).
    req.blocking:
      res.send(Http200, bigText)
  of "/park":
    {.cast(gcsafe).}:
      keptRes = res
    keptReady.store(true)
  of "/answer-kept":
    # A worker task answering a handle that is not its own: no snapshot of
    # that request exists on this thread, so it must answer identity.
    req.blocking:
      {.cast(gcsafe).}:
        let k = keptRes
      k.send(Http200, bigText)
      res.send(Http200, "answered")
  of "/app":
    {.cast(gcsafe).}:
      appRes = res
    appReady.store(true)
  else:        res.send(Http404)

let tmp = getTempDir() / "vortex_gzip_" & $getCurrentProcessId()
createDir(tmp)
let assetDir = tmp / "assets"
createDir(assetDir)
writeFile(assetDir / "doc.txt", bigText)     # buffered (< stream threshold), compressible
writeFile(assetDir / "doc.bin", bigText)     # buffered, not compressible

let r = newRouter()
let sh = staticHandler(assetDir)
r.get("/assets/*", sh)
for p in ["/big", "/small", "/png", "/worker", "/park", "/answer-kept", "/app"]:
  r.get(p, RequestHandler(handler))
var srv = newVortex(r.toHandler(),
  initVortexConfig(numThreads = 1, workerThreads = 2, compress = true)).start(0)
let base = "http://127.0.0.1:" & $srv.port
createThread(appThread, appMain)

proc fetch(path, acceptEnc: string): (string, string) =
  ## Returns (headers, decompressed-or-raw body). Body written to a file and,
  ## if gzip, gunzipped; headers captured with -D.
  let bodyf = tmp / "body.bin"
  ## An empty `acceptEnc` sends no Accept-Encoding header at all.
  let aeArg = if acceptEnc.len == 0: ""
              else: " -H 'Accept-Encoding: " & acceptEnc & "'"
  let (hdrs, rc) = execCmdEx(curlBin & " -s" & aeArg &
    " -D - -o " & bodyf & " " & base & path)
  check rc == 0
  let ce = block:
    var v = ""
    for ln in hdrs.splitLines:
      let c = ln.find(':')
      if c > 0 and cmpIgnoreCase(ln[0..<c].strip, "content-encoding") == 0:
        v = ln[c+1..^1].strip
    v
  let body =
    if ce == "gzip":
      # Decompress to a file and read it back byte-exactly (capturing gunzip's
      # stdout through a pipe is not byte-faithful).
      let outf = tmp / "plain.out"
      check execCmdEx("gunzip -c " & bodyf & " > " & outf)[1] == 0
      readFile(outf)
    else: readFile(bodyf)
  (hdrs.toLowerAscii, body)

suite "gzip response compression":
  test "compressible body with Accept-Encoding: gzip is gzipped and round-trips":
    let (hdrs, body) = fetch("/big", "gzip")
    check "content-encoding: gzip" in hdrs
    check "vary: accept-encoding" in hdrs
    check body == bigText                    # gunzip matches the original

  test "no Accept-Encoding: gzip -> identity":
    let (hdrs, body) = fetch("/big", "identity")
    check "content-encoding: gzip" notin hdrs
    check body == bigText

  test "small bodies are not compressed":
    let (hdrs, _) = fetch("/small", "gzip")
    check "content-encoding: gzip" notin hdrs

  test "non-compressible content-type is not compressed":
    let (hdrs, _) = fetch("/png", "gzip")
    check "content-encoding: gzip" notin hdrs

proc rawGet(s: Socket, path: string) =
  s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")

suite "gzip on a worker-thread send (#413)":
  test "blocking: body, Accept-Encoding: gzip -> 200 gzip, round-trips":
    let (hdrs, body) = fetch("/worker", "gzip")
    check hdrs.startsWith("http/1.1 200")
    check "content-encoding: gzip" in hdrs
    check "vary: accept-encoding" in hdrs
    check body == bigText

  test "blocking: body, no Accept-Encoding -> 200 identity":
    let (hdrs, body) = fetch("/worker", "")
    check hdrs.startsWith("http/1.1 200")
    check "content-encoding" notin hdrs
    check body == bigText

  test "staticHandler, buffered .txt with Accept-Encoding: gzip -> 200 gzip":
    let (hdrs, body) = fetch("/assets/doc.txt", "gzip")
    check hdrs.startsWith("http/1.1 200")
    check "content-encoding: gzip" in hdrs
    check body == bigText

  test "staticHandler, buffered .txt without Accept-Encoding -> 200 identity":
    let (hdrs, body) = fetch("/assets/doc.txt", "")
    check hdrs.startsWith("http/1.1 200")
    check "content-encoding" notin hdrs
    check body == bigText

  test "staticHandler, buffered .bin is not compressed":
    let (hdrs, body) = fetch("/assets/doc.bin", "gzip")
    check hdrs.startsWith("http/1.1 200")
    check "content-encoding" notin hdrs
    check body == bigText

  test "a kept handle another worker task answers -> 200 identity":
    keptReady.store(false)
    let a = connectTimeout(srv.port, 3000)
    defer: a.close()
    a.rawGet("/park")
    var waited = 0
    while not keptReady.load and waited < 3000:
      sleep(5); waited += 5
    check keptReady.load
    let b = connectTimeout(srv.port, 3000)
    defer: b.close()
    b.rawGet("/answer-kept")
    let br = b.readHttpResponse()
    check br.ok and br.body == "answered"
    let ar = a.readHttpResponse()
    checkpoint "kept got: " & ar.head
    check ar.ok
    check ar.head.startsWith("HTTP/1.1 200")
    check "content-encoding" notin ar.head.toLowerAscii
    check ar.body == bigText

  test "a handle answered from an app-owned thread -> 200 identity":
    let s = connectTimeout(srv.port, 3000)
    defer: s.close()
    s.rawGet("/app")
    let rr = s.readHttpResponse()
    checkpoint "app got: " & rr.head
    check rr.ok
    check rr.head.startsWith("HTTP/1.1 200")
    check "content-encoding" notin rr.head.toLowerAscii
    check rr.body == bigText

proc gunzipBytes(data: string): string =
  ## gunzip `data` through files (a pipe is not byte-faithful).
  let inf = tmp / "raw.gz"
  let outf = tmp / "raw.out"
  writeFile(inf, data)
  check execCmdEx("gunzip -c " & inf & " > " & outf)[1] == 0
  readFile(outf)

proc splitResponse(wire: string, pos: var int): tuple[head, body: string] =
  ## One Content-Length-framed HTTP/1.1 response starting at `pos` in `wire`;
  ## advances `pos` past it. An incomplete response leaves `head` empty.
  let he = wire.find("\r\n\r\n", pos)
  if he < 0: return
  let head = wire[pos ..< he]
  var clen = -1
  for line in head.split("\r\n"):
    if line.toLowerAscii.startsWith("content-length:"):
      clen = parseInt(line.split(':', 1)[1].strip)
  if clen < 0 or wire.len < he + 4 + clen: return
  result = (head, wire[he + 4 ..< he + 4 + clen])
  pos = he + 4 + clen

suite "gzip on a worker-thread send, h1 connection handling (#413)":
  test "a compressed blocking: send, then a pipelined request on the same connection":
    # Both requests arrive in one segment: the worker's gzip answer must be
    # emitted whole and in order, and the pipelined request answered after it.
    let s = connectTimeout(srv.port, 3000)
    defer: s.close()
    s.send("GET /worker HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n" &
           "GET /small HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n" &
           "Connection: close\r\n\r\n")
    let wire = s.recvUntilClose(3000)
    var pos = 0
    let first = splitResponse(wire, pos)
    let second = splitResponse(wire, pos)
    checkpoint "wire head: " & wire[0 ..< min(wire.len, 200)]
    check first.head.startsWith("HTTP/1.1 200")
    check "content-encoding: gzip" in first.head.toLowerAscii
    check gunzipBytes(first.body) == bigText
    check second.head.startsWith("HTTP/1.1 200")
    check "content-encoding" notin second.head.toLowerAscii
    check second.body == "tiny"
    check pos == wire.len                    # nothing after the second response

  test "a compressed blocking: send with Connection: close, then the server closes":
    let s = connectTimeout(srv.port, 3000)
    defer: s.close()
    s.send("GET /worker HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n" &
           "Connection: close\r\n\r\n")
    let r = s.readHttpResponse()
    check r.ok
    check r.head.startsWith("HTTP/1.1 200")
    check "content-encoding: gzip" in r.head.toLowerAscii
    check gunzipBytes(r.body) == bigText
    check s.waitForClose()

stopApp.store(true)
joinThread(appThread)
srv.close()

# The worker path over HTTP/3 (#413): the h3 branch of the request accessors
# had no loop-thread assertion, so a worker send read the loop's QUIC state
# unsynchronised. Coverage rather than a regression test. Skipped without an
# HTTP/3-capable curl.
let h3curlBin = findH3Curl()
if h3curlBin.len == 0:
  echo "SKIP: gzip on a worker-thread send over HTTP/3 (no HTTP/3-capable curl found)"
else:
  let (certFile, keyFile) = makeCertPair("vortex_gzip_h3_")
  withServer(r.toHandler(),
             initVortexConfig(numThreads = 1, workerThreads = 2, compress = true,
                              certFile = certFile, keyFile = keyFile), srv3):
    suite "gzip on a worker-thread send over HTTP/3 (#413)":
      test "h3: blocking: body, Accept-Encoding: gzip -> 200 gzip, round-trips":
        let bodyf = tmp / "h3body.bin"
        let (hdrs, rc) = h3curl(h3curlBin, "-H 'Accept-Encoding: gzip' -D - -o " &
          bodyf & " https://localhost:" & $srv3.port & "/worker")
        check rc == 0
        let low = hdrs.toLowerAscii
        checkpoint low
        check low.startsWith("http/3 200")
        check "content-encoding: gzip" in low
        check gunzipBytes(readFile(bodyf)) == bigText
  removeDir(certFile.parentDir)
removeDir(tmp)
echo "gzip compression ok"
