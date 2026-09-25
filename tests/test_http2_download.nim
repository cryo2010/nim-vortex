## Regressions for the HTTP/2 streaming-download path, driven frame-by-frame so
## the client controls flow control exactly (curl would hide it).
##
## The client here behaves like a real one on a long download: it reads DATA and
## returns the credit as WINDOW_UPDATEs, keeping the send windows small so the
## server's per-stream backlog never reaches zero.

import std/[unittest, httpcore, strutils, atomics]
import vortex/[settings, request, server, routing]
import vortex/asyncdispatch
import vortex/http2/frames
from vortex/connection import conn
from vortex/http2/codec import h2Stream
import ./h2client

const
  totalBytes = 4 * 1024 * 1024    ## response size the tests download
  writeChunk = 8192               ## producer chunk size

var peakPending: Atomic[int]      ## high-water mark of H2Stream.pendingBody.len

proc notePeak(res: Response) =
  ## Sample the RAW pendingBody buffer (not the backlog `len - pendingPos` that
  ## res.bufferedAmount reports): #331 was invisible to backpressure precisely
  ## because the dead prefix does not count towards the backlog. Runs on the
  ## loop thread (an async route), so touching codec state is safe.
  if res.stream == 0: return
  let c = conn(res.core, res.fd, res.gen)
  if c == nil: return
  let st = h2Stream(c, res.stream)
  if st == nil: return
  if st.pendingBody.len > peakPending.load():
    peakPending.store(st.pendingBody.len)

proc bigDownload(req: Request, res: Response) {.async.} =
  res.sendHead(Http200, "application/octet-stream")
  let chunk = repeat('x', writeChunk)
  var sent = 0
  while sent < totalBytes:
    # Low-level bool form (a string arg would resolve to `await res.write`).
    let ok = res.write(chunk.toOpenArray(0, chunk.high))
    sent += writeChunk
    notePeak(res)
    if not ok:
      await res.drained()
      notePeak(res)
  res.finish()

var rt = newRouter()
rt.get("/big", bigDownload)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)

type DlResult = tuple[bytes: int, goaway: int, connUpdates: int]

proc download(port: Port, connCreditChunk: int): DlResult =
  ## Fetch /big, returning the credit as WINDOW_UPDATEs. `connCreditChunk`
  ## splits the connection-level credit into that many bytes per frame, so a
  ## small value models a client that emits a lot of benign conn updates.
  var c = newH2TestConn(port)
  var req = ""
  req.addRequest(1, {":method": "GET", ":scheme": "http",
                     ":path": "/big", ":authority": "localhost"}, endStream = true)
  c.sendRaw(req)
  result.goaway = -1
  var guard = 0
  while result.bytes < totalBytes and guard < 200000:
    inc guard
    let frames = c.readFrames(3000,
      until = proc(f: seq[Frame]): bool = f.len >= 1)
    if frames.len == 0: break                 # EOF or a quiet period: give up
    var consumed = 0
    for f in frames:
      if f.typ == uint8(ftData): consumed += f.payload.len
      elif f.typ == uint8(ftGoaway) and f.payload.len >= 8:
        if result.goaway < 0: result.goaway = int(get32(f.payload, 4))
    result.bytes += consumed
    if consumed > 0:
      var wu = ""
      wu.addWindowUpdate(1, consumed)         # stream credit: one frame
      var left = consumed
      while left > 0:                         # connection credit: many frames
        let n = min(left, connCreditChunk)
        wu.addWindowUpdate(0, n)
        inc result.connUpdates
        left -= n
      c.sendRaw(wu)
    if result.goaway >= 0: break
  c.close()

suite "HTTP/2 streaming download":
  test "pendingBody stays bounded while the backlog never reaches zero (#331)":
    peakPending.store(0)
    let dl = download(srv.port, connCreditChunk = 1 shl 30)
    check dl.bytes == totalBytes
    check dl.goaway == -1
    # The producer parks at respHighWater (64 KiB) of backlog, so a compacting
    # buffer settles near 2 x respHighWater plus one write chunk. Before #331 the
    # consumed prefix was never reclaimed and this grew to the whole response
    # (4 MiB here, tens of MB per stream on a real download).
    check peakPending.load() > 0              # the sampler actually ran
    check peakPending.load() < 512 * 1024

srv.close()
echo "server shut down cleanly"
