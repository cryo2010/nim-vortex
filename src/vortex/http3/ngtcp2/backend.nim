## HTTP/3 backend over ngtcp2 (QUIC) + nghttp3, via the vq_ngtcp2 C++ shim.
## The HTTP/3 implementation for vortex: request.nim and eventloop.nim import it
## as `h3codec`. nghttp3 does the framing/QPACK; this module holds per-request
## state and translates request/response calls to the shim. Loop-thread only
## (one engine per thread). Building HTTP/3 (any non -d:plainHttp build) links
## ngtcp2 + nghttp3 (see the passL below).

import std/[tables, strutils, json, os, monotimes, atomics]
import ../../connection
import ../../fieldrules   # pseudo-header machine shared with the h2 codec
import ../../websocket/codec as wscodec

# The shim is a C++ TU compiled by g++ (via {.compile.} on a .cpp), while the
# rest of vortex stays on the C backend -- so no -std on passC (it would reach
# Nim's generated .c files). -lstdc++ links the C++ runtime the shim needs.
{.passC: "-I" & currentSourcePath().parentDir.}
{.passL: "-lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto -lstdc++".}
{.compile: "vq_ngtcp2.cpp".}

# --- shim ABI ---------------------------------------------------------------
type
  VqEngine {.importc, header: "vq_ngtcp2.h", incompleteStruct.} = object
  VqConn {.importc, header: "vq_ngtcp2.h", incompleteStruct.} = object
  VqHeader {.importc, header: "vq_ngtcp2.h", bycopy.} = object
    name: cstring
    name_len: csize_t
    value: cstring
    value_len: csize_t

  OnAccept = proc(user: pointer, conn: ptr VqConn, peerIp: cstring): pointer {.cdecl.}
  OnHeaders = proc(user, connUd: pointer, sid: int64, hdrs: ptr VqHeader, n: csize_t) {.cdecl.}
  OnBody = proc(user, connUd: pointer, sid: int64, data: ptr uint8, len: csize_t) {.cdecl.}
  OnStream = proc(user, connUd: pointer, sid: int64) {.cdecl.}
  OnStreamClose = proc(user, connUd: pointer, sid: int64, appErr: uint64) {.cdecl.}
  OnConnClose = proc(user, connUd: pointer) {.cdecl.}
  OnSend = proc(user: pointer, conn: ptr VqConn, data: ptr uint8, len: csize_t,
                peer: pointer, peerLen: csize_t): cint {.cdecl.}

  VqCallbacks {.importc, header: "vq_ngtcp2.h", bycopy.} = object
    on_accept: OnAccept
    on_headers: OnHeaders
    on_body: OnBody
    on_stream_end: OnStream
    on_stream_close: OnStreamClose
    on_stream_writable: OnStream
    on_conn_close: OnConnClose
    on_send: OnSend

  VqSniCert {.importc, header: "vq_ngtcp2.h", bycopy.} = object
    host: cstring
    cert_file: cstring
    key_file: cstring
    cert_pem: cstring
    key_pem: cstring
    key_password: cstring
    pkcs12_file: cstring
    pkcs12: ptr uint8
    pkcs12_len: csize_t

  VqConfig {.importc, header: "vq_ngtcp2.h", bycopy.} = object
    user: pointer
    cb: VqCallbacks
    cert_file: cstring
    key_file: cstring
    cert_pem: cstring
    key_pem: cstring
    key_password: cstring
    pkcs12_file: cstring
    pkcs12: ptr uint8
    pkcs12_len: csize_t
    max_body: uint64
    max_concurrent_streams: uint64
    max_connections: uint64
    max_reset_streams: uint64
    max_field_section_size: cint
    stream_recv_window: uint64
    conn_recv_window: uint64
    tls_cipher_suites: cstring
    max_tls_version: cint
    verify_client: cint
    client_ca_file: cstring
    client_ca_pem: cstring
    sni: ptr VqSniCert
    sni_len: csize_t
    max_idle_timeout_sec: uint64

  H3SniCert* = object
    ## Per-host certificate material for the QUIC SNI callback (#374). The same
    ## shape as settings.SniCertEntry; eventloop converts, which keeps this
    ## module free of the settings import like the rest of its parameters.
    host*: string
    certFile*, keyFile*: string
    certPem*, keyPem*: string
    pkcs12File*, pkcs12*: string
    keyPassword*: string

{.push header: "vq_ngtcp2.h", cdecl.}
proc vqEngineNew(cfg: ptr VqConfig): ptr VqEngine {.importc: "vq_engine_new".}
proc vqEngineFree(e: ptr VqEngine) {.importc: "vq_engine_free".}
proc vqEngineReloadCert(e: ptr VqEngine, certFile, keyFile: cstring,
  sni: ptr VqSniCert, sniLen: csize_t): cint {.importc: "vq_engine_reload_cert".}
proc vqEngineLastError(e: ptr VqEngine): cstring {.importc: "vq_engine_last_error".}
proc vqEngineRecv(e: ptr VqEngine, pkt: ptr uint8, len: csize_t, peer: pointer,
  peerLen: csize_t, local: pointer, localLen: csize_t, nowNs: uint64) {.importc: "vq_engine_recv".}
proc vqEnginePump(e: ptr VqEngine, nowNs: uint64) {.importc: "vq_engine_pump".}
proc vqEngineNextExpiry(e: ptr VqEngine, nowNs: uint64): uint64 {.importc: "vq_engine_next_expiry_ns".}
proc vqEngineHandleExpiry(e: ptr VqEngine, nowNs: uint64) {.importc: "vq_engine_handle_expiry".}
proc vqSubmitResponse(conn: ptr VqConn, sid: int64, status: cint, hdrs: ptr VqHeader,
  n: csize_t, body: ptr uint8, bodyLen: csize_t, fin: cint) {.importc: "vq_submit_response".}
proc vqSubmitHead(conn: ptr VqConn, sid: int64, status: cint, hdrs: ptr VqHeader, n: csize_t) {.importc: "vq_submit_head".}
proc vqStreamWrite(conn: ptr VqConn, sid: int64, data: ptr uint8, len: csize_t): csize_t {.importc: "vq_stream_write".}
proc vqSubmitTrailers(conn: ptr VqConn, sid: int64, hdrs: ptr VqHeader, n: csize_t) {.importc: "vq_submit_trailers".}
proc vqStreamFinish(conn: ptr VqConn, sid: int64) {.importc: "vq_stream_finish".}
proc vqStreamBacklog(conn: ptr VqConn, sid: int64): csize_t {.importc: "vq_stream_backlog".}
proc vqStreamReset(conn: ptr VqConn, sid: int64, appErr: uint64) {.importc: "vq_stream_reset".}
proc vqStreamConsume(conn: ptr VqConn, sid: int64, n: csize_t) {.importc: "vq_stream_consume".}
template vqConnConsume(conn: ptr VqConn, n: csize_t) =
  ## Connection-level (MAX_DATA) credit only; sid < 0 skips the per-stream window
  ## (see vq_stream_consume). For received body bytes with no stream to replenish.
  vqStreamConsume(conn, -1, n)
proc vqConnGoaway(conn: ptr VqConn) {.importc: "vq_conn_goaway".}
proc vqConnShutdown(conn: ptr VqConn) {.importc: "vq_conn_shutdown".}
proc vqConnClose(conn: ptr VqConn, appErr: uint64) {.importc: "vq_conn_close".}
proc vqConnCloseGraceful(conn: ptr VqConn, appErr: uint64) {.importc: "vq_conn_close_graceful".}
proc vqConnSsl(conn: ptr VqConn): pointer {.importc: "vq_conn_ssl".}
proc vqMaxRecvUdpPayload(): csize_t {.importc: "vq_max_recv_udp_payload".}
{.pop.}

# --- H3 state (codec-compatible surface) ------------------------------------
type
  H3Stream* = object
    id*: uint64
    headers*: seq[(string, string)]
    trailers*: seq[(string, string)]  ## request trailer fields (after the body)
    body*: string
    headersDone*: bool
    isHead*: bool
    isWsConnect*: bool
    ws*: RootRef
    rs*: RequestState        ## per-request state shared with h1/h2 (responded,
                             ## lazy caches, pathParams, streaming flags/callbacks)
    dispatched: bool
    finSeen: bool
    bodyManualAck: bool
    rejected: bool           ## the stream was reset for a malformed body length
                             ## but deliberately kept in the table so
                             ## cbStreamClose can return its flow-control
                             ## credit: it must never be dispatched (#237)
    contentLength: int64     ## declared content-length (-1 = absent); reconciled
                             ## against bodyReceived at stream end (#257)
    bodyReceived: int64      ## cumulative DATA payload bytes received
    respDeclaredLen: int64   ## Content-Length this streamed RESPONSE declared
                             ## (-1 = none); set by h3SendHead
    respBodyWritten: int64   ## response body bytes accepted by h3StreamWrite so
                             ## far; reconciled against respDeclaredLen at
                             ## h3StreamFinish (#345)
    uncredited: int          ## streaming body bytes received but not yet
                             ## credited to QUIC flow control
    bufferedCounted: int     ## bytes this un-dispatched buffered body currently
                             ## contributes to H3Conn.bufferedBytes (#254)

  H3Conn* = ref object of RootObj
    core*: ptr LoopCore
    ssl*: pointer            ## the shim's SSL* for this connection (it owns the
                             ## handle; borrowed here, nil once the connection
                             ## closes). Read-only: request.nim reads the peer
                             ## certificate through it (req.clientCertSubject
                             ## over h3, #351)
    remoteAddr*: string
    slot*: int
    vq: ptr VqConn
    streams*: Table[uint64, H3Stream]
    closing: bool
    bufferedBytes: int      ## total un-dispatched buffered (non-streaming) request
                            ## -body bytes across streams; the QUIC window credits
                            ## buffered bodies eagerly, so this independent
                            ## aggregate is what caps per-connection memory (#254)
    lastStreamId: uint64
    goneAway: bool          ## initial GOAWAY notice sent
    finalGoaway: bool       ## final GOAWAY (nghttp3_conn_shutdown) sent

# One engine + core + UDP fd per loop thread.
var
  gEngine {.threadvar.}: ptr VqEngine
  gCore {.threadvar.}: ptr LoopCore
  gUdpFd {.threadvar.}: cint
  gMaxBody {.threadvar.}: uint64             # buffered request-body cap (0 = none)
  gConnWindow {.threadvar.}: uint64          # h3 connection recv window (#254 cap)
  gLocalSa {.threadvar.}: array[128, byte]   # bound local sockaddr (for the QUIC path)
  gLocalLen {.threadvar.}: cuint
  gReady {.threadvar.}: seq[tuple[slot: int, gen: uint32, sid: uint64]]
  gRecvBuf {.threadvar.}: seq[uint8]         # ngReceive's datagram buffer, sized
                                             # from the max_udp_payload_size the
                                             # shim advertises (#380)

# NOT threadvars: the two numbers an operator (or a test) reads back off the
# MAIN thread, where a threadvar copy is always the main thread's own and so
# always zero. gRecvBufSize is the receive buffer size every loop thread
# settles on, stamped by ngSetup; gTruncDrops counts datagrams dropped for not
# fitting it, summed across the loops. Every loop writes gRecvBufSize the same
# number, computed from the one shim constant, but a plain shared global written
# from several threads is a data race whatever the values, so both are Atomics
# (relaxed: neither orders anything) (#380).
var
  gRecvBufSize: Atomic[int]
  gTruncDrops: Atomic[uint64]

proc ngNowNs*(): uint64 = getMonoTime().ticks.uint64
  ## The one clock this loop thread hands ngtcp2 -- every entry point (recv,
  ## pump, expiry, next-expiry) stamps its call with it, and ngtcp2 arms its idle,
  ## keep-alive and loss-detection timers against it.
  ##
  ## It is the raw monotonic clock, with nothing withheld from it, and it must
  ## stay that way: ngtcp2 checks on every entry that the stamp has not gone
  ## behind one it was already given (`conn->log.last_ts <= ts`) and aborts the
  ## process if it has. Crediting a loop-thread stall here -- subtracting the gap
  ## the thread spent descheduled, the h3 analogue of the loop's creditStall --
  ## does exactly that, and there is nowhere to put such a credit that does not:
  ## run() drives h3 *before* it ticks, so the drive that follows a stall has
  ## already handed ngtcp2 the full elapsed time before the loop has even measured
  ## the gap, and crediting it afterwards can only rewind the clock.
  ##
  ## A stall must not make ngtcp2 reap a blameless peer, but that is bought at the
  ## protocol level instead of by lying about the time: acceptConn advertises an
  ## idle window as wide as the h1/h2 keepAliveTimeout and arms ngtcp2's
  ## keep-alive PING at a third of it, so an ordinary stall fits inside the window
  ## and a live-but-quiet connection keeps both ends' timers fed.

proc h3ConnOf*(core: ptr LoopCore, fd: int32, gen: uint32): H3Conn =
  ## Resolve an h3 Request handle (fd = -(slot+2)); nil if gone.
  let idx = h3SlotOf(fd)
  if idx < 0 or idx >= core.h3slots.len: return nil
  if core.h3slots[idx].gen != gen or core.h3slots[idx].conn == nil: return nil
  H3Conn(core.h3slots[idx].conn)

proc h3StreamPtr*(conn: H3Conn, sid: uint64): ptr H3Stream =
  if sid in conn.streams: addr conn.streams[sid] else: nil

proc h3StreamAlive*(conn: H3Conn, sid: uint64): bool = sid in conn.streams
proc h3StreamRejected*(conn: H3Conn, sid: uint64): bool =
  ## True when this stream has been reset for a malformed request-body length but
  ## is still in the table (so cbStreamClose can return its flow-control credit).
  ## The dispatcher checks it before running a handler the ready list still
  ## carries from cbEndHeaders: the reset happens inside the engine pump, which
  ## finishes before the ready list is drained, so without this a request the
  ## server already rejected would still reach a streaming route (#237).
  sid in conn.streams and conn.streams[sid].rejected
proc h3StreamCount*(conn: H3Conn): int = conn.streams.len

# --- header validation (RFC 9114 pseudo-header rules; pure) -----------------
type H3HeaderKind* = enum h3hInvalid, h3hRequest, h3hWebSocket

proc classifyH3Headers*(headers: openArray[(string, string)]): H3HeaderKind =
  ## Validate the pseudo-header set and classify it as a normal request, an
  ## RFC 9220 Extended CONNECT websocket, or invalid. Delegates to the machine
  ## shared with the h2 codec (fieldrules.classifyRequestHead), so h3 enforces
  ## the same name/value byte rules itself rather than trusting nghttp3's
  ## wire-level checks. Pure (no live connection), so it is unit-testable.
  var meth, path, scheme, authority, protocol: string
  case classifyRequestHead(headers, meth, path, scheme, authority, protocol)
  of rhInvalid: h3hInvalid
  of rhRequest: h3hRequest
  of rhWebSocket: h3hWebSocket

# --- shim callbacks (all loop-thread) ---------------------------------------
proc cbAccept(user: pointer, conn: ptr VqConn, peerIp: cstring): pointer {.cdecl.} =
  let core = cast[ptr LoopCore](user)
  var idx = -1
  for i in 0 ..< core.h3slots.len:
    if core.h3slots[i].conn == nil and core.h3slots[i].totalPins == 0:
      idx = i; break
  if idx < 0:
    core.h3slots.add H3SlotEntry()
    idx = core.h3slots.len - 1
  let h3c = H3Conn(core: core, vq: conn, slot: idx,
                   ssl: vqConnSsl(conn),
                   remoteAddr: (if peerIp != nil: $peerIp else: ""))
  core.h3slots[idx].conn = h3c
  cast[pointer](h3c)

proc toStr(p: cstring, n: csize_t): string =
  result = newString(int(n))
  if n > 0: copyMem(addr result[0], p, int(n))

proc cbHeaders(user, connUd: pointer, sid: int64, hdrs: ptr VqHeader, n: csize_t) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid notin h3c.streams:
    h3c.streams[usid] = H3Stream(id: usid, contentLength: -1,
                                 respDeclaredLen: -1)
  template st: H3Stream = h3c.streams[usid]
  if st.headersDone:
    # A header block after the request head is the trailer section (RFC 9114
    # 4.1). Capture it for req.trailers, dropping pseudo-headers (not allowed
    # in trailers) rather than re-classifying it as a malformed request head.
    let tarr = cast[ptr UncheckedArray[VqHeader]](hdrs)
    for i in 0 ..< int(n):
      let name = toStr(tarr[i].name, tarr[i].name_len)
      let val = toStr(tarr[i].value, tarr[i].value_len)
      # RFC 9114 4.1/4.2: trailers are fields, so apply the same validity rules as
      # the head. QPACK does no byte validation, so a CR/LF/NUL value or non-token
      # name would inject via req.trailers; a pseudo-header or connection-specific
      # field is malformed. Reject the stream rather than store it (#257).
      # Shared rule (fieldrules.validTrailerField, also the h2 codec's).
      if not validTrailerField(name, val):
        vqStreamReset(h3c.vq, sid, 0x0105); h3c.streams.del(usid); return
      st.trailers.add (name, val)
    return
  let arr = cast[ptr UncheckedArray[VqHeader]](hdrs)
  for i in 0 ..< int(n):
    st.headers.add (toStr(arr[i].name, arr[i].name_len),
                    toStr(arr[i].value, arr[i].value_len))
  case classifyH3Headers(st.headers)
  of h3hInvalid:
    vqStreamReset(h3c.vq, sid, 0x0105)   # H3_MESSAGE_ERROR
    h3c.streams.del(usid)
    return
  of h3hWebSocket: st.isWsConnect = true
  of h3hRequest: discard
  for (name, val) in st.headers:
    if name == ":method": st.isHead = val == "HEAD"
    elif name == "content-length":
      # RFC 9110 8.6 grammar (1*DIGIT), non-negative, no duplicate-with-different
      # value; the Nim side owns this (nghttp3 may reconcile length but not the
      # digits-only grammar / duplicate rule) so a mis-parsed length can't smuggle
      # when the request is proxied (#257). Shared grammar (fieldrules, also h1/h2).
      var cl: int64
      case parseContentLength(val, st.contentLength, cl)
      of clOk: st.contentLength = cl
      else:
        vqStreamReset(h3c.vq, sid, 0x0105); h3c.streams.del(usid); return
  st.headersDone = true
  if usid > h3c.lastStreamId: h3c.lastStreamId = usid
  # Streaming route or ws-connect dispatch on headers; body flows via onBody.
  if not st.isWsConnect and hasStreamRoute(h3c.core) and
      callStreamRoute(h3c.core, h3SlotFd(h3c.slot),
                      h3c.core.h3slots[h3c.slot].gen, uint32(sid)):
    st.rs.reqStreaming = true
  if (st.isWsConnect or st.rs.reqStreaming) and not st.dispatched:
    st.dispatched = true
    gReady.add (h3c.slot, h3c.core.h3slots[h3c.slot].gen, usid)

proc deliverBody(h3c: H3Conn, usid: uint64, last: bool) =
  if usid notin h3c.streams: return
  template st: H3Stream = h3c.streams[usid]
  if st.rs.onBodyCb == nil: return
  if st.body.len > 0 or last:
    # The callback may res.send (deleting this stream from the table), so move
    # the buffer out and capture manualAck *before* the call, and touch nothing
    # on `st` afterwards -- re-check membership before crediting flow control.
    let cb = st.rs.onBodyCb
    let manualAck = st.bodyManualAck
    if last: st.rs.onBodyCb = nil   # single EOF: cbStreamClose must not re-fire (#256)
    var buf: string
    swap(buf, st.body)
    cb(buf.toOpenArray(0, buf.len - 1), last)
    if not manualAck and buf.len > 0 and h3c.vq != nil and usid in h3c.streams:
      # nghttp3_conn_read_stream does not credit DATA-frame payload to QUIC
      # flow control (only framing); replenish the consumed body bytes so the
      # peer's stream/connection window reopens. manualAck defers this to
      # req.ackBody so a slow consumer throttles the peer. Mirrors h2DeliverBody.
      vqStreamConsume(h3c.vq, int64(usid), csize_t(buf.len))
      h3c.streams[usid].uncredited -= buf.len

proc cbBody(user, connUd: pointer, sid: int64, data: ptr uint8, len: csize_t) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid notin h3c.streams: return
  template st: H3Stream = h3c.streams[usid]
  if st.rejected:
    # Reset for a content-length mismatch already; the stream only lingers in the
    # table so cbStreamClose can settle its flow-control credit. Keep counting
    # the bytes still in flight as uncredited so creditRemainder hands them back,
    # but never buffer them and never offer them to a sink (#237).
    if st.rs.reqStreaming: st.uncredited += int(len)
    return
  if st.ws != nil:
    # RFC 9220 tunnel: DATA payload is WebSocket framing.
    if len > 0 and h3c.vq != nil:
      # Credit the consumed tunnel bytes back to QUIC flow control. nghttp3 does
      # not credit DATA-frame payload (only framing), and unlike a request body
      # this stream is long-lived, so without crediting the CONNECT stream's
      # receive window never reopens: cumulative inbound ws bytes exhaust it
      # (1 MiB default), the peer goes flow-control-blocked and cannot send, the
      # tunnel stalls both ways, and the idle connection is torn down (QUIC code
      # 1). Credit before wsFeed (which may tear the stream down) so `sid` is
      # known-valid; mirrors the request-body paths below. No manualAck throttle:
      # wsFeed consumes each frame inline, so immediate credit is correct.
      vqStreamConsume(h3c.vq, sid, len)
    let arr = cast[ptr UncheckedArray[char]](data)
    wsFeed(h3c.core, nil, WsConn(st.ws), arr.toOpenArray(0, int(len) - 1))
    return
  if st.isWsConnect:
    # Same tunnel, before acceptance: the stream dispatched on headers, so DATA
    # coalesced with the Extended CONNECT handshake arrives while there is no
    # WsConn to feed. These are WebSocket bytes, not a request body, so bound
    # them by the ceiling wsFeed applies post-accept and leave them out of the
    # per-connection buffered-body aggregate: otherwise a client flooding
    # unaccepted CONNECT streams could park maxBodySize of framing each and pin
    # that aggregate, which is meant for request bodies (#263). h3WsAccept hands
    # the bytes to the WsConn (#259).
    let wsCap = h3c.core.config.maxWsMessage + 1024
    if st.body.len + int(len) > wsCap:
      # Over the WebSocket bound before acceptance: there is no WsConn yet to
      # carry the 1009 close wsFeed would send, so reject the handshake by
      # resetting the stream (the h3 twin of the h2 REFUSED_STREAM on this same
      # bound) rather than claiming a malformed request with H3_MESSAGE_ERROR.
      # Return the connection-window credit for the discarded bytes first, as
      # the oversize-body path below does, or the shared window leaks.
      if len > 0 and h3c.vq != nil: vqConnConsume(h3c.vq, len)
      if h3c.vq != nil: vqStreamReset(h3c.vq, sid, 0x010b)  # H3_REQUEST_REJECTED
      h3c.streams.del(usid)
      return
    if len > 0:
      let old = st.body.len
      st.body.setLen(old + int(len))
      copyMem(addr st.body[old], data, int(len))
      if h3c.vq != nil:
        # Credit as tunnel bytes, exactly as the accepted path above does: the
        # bound here (not the receive window) is what caps the memory held, and
        # the handover into inBuf does not credit again, so nothing is counted
        # twice across acceptance.
        vqStreamConsume(h3c.vq, sid, len)
    return
  if not st.rs.reqStreaming and gMaxBody > 0'u64 and
      uint64(st.body.len) + uint64(len) > gMaxBody:
    # Buffered request body over maxBodySize: reject with a stream reset rather
    # than buffering unboundedly (mirrors the h2 maxBody guard in codec.nim, which
    # is the 413 boundary). Return connection-level flow-control credit for these
    # received-but-discarded bytes first -- they counted against MAX_DATA, so
    # without it a client could leak the shared window with oversized requests --
    # then STOP_SENDING+RESET the stream.
    if len > 0 and h3c.vq != nil: vqConnConsume(h3c.vq, len)
    h3c.bufferedBytes -= st.bufferedCounted        # release its reservation (#254)
    if h3c.vq != nil: vqStreamReset(h3c.vq, sid, 0x0105)   # H3_MESSAGE_ERROR
    h3c.streams.del(usid)
    return
  let old = st.body.len
  st.body.setLen(old + int(len))
  if len > 0: copyMem(addr st.body[old], data, int(len))
  st.bodyReceived += int64(len)   # for content-length reconciliation (#257)
  if st.rs.reqStreaming:
    # Track received-but-uncredited body bytes so a stream that tears down with
    # bytes the handler never read (or a manualAck consumer stopped early)
    # returns them to the connection window at teardown (see creditRemainder);
    # deliverBody's auto-ack and h3AckBody decrement this as they credit.
    st.uncredited += int(len)
    if st.contentLength >= 0 and st.bodyReceived > st.contentLength:
      # Already past the declared content-length: malformed now, not only at
      # cbStreamEnd. A streaming route relays each chunk as it arrives, so an
      # end-of-stream-only check lets the excess bytes reach an h1 upstream
      # under the declared length before the reset (request smuggling), the h3
      # twin of the h2 guard in http2/codec.nim (#237). Reset and let
      # cbStreamClose clean up; creditRemainder returns these uncredited bytes
      # to the connection window, so nothing leaks.
      #
      # Mark the stream rejected so the dispatcher skips the entry cbEndHeaders
      # already queued on the ready list: head, body and FIN can all arrive in
      # one read batch, in which case this runs before the handler exists and
      # only the flag stops it running afterwards. Drop what was buffered too --
      # the sink does not exist yet on that path, so the bytes would otherwise
      # sit in st.body until cbStreamClose.
      st.rejected = true
      st.body.setLen(0)
      if h3c.vq != nil: vqStreamReset(h3c.vq, sid, 0x0105)  # H3_MESSAGE_ERROR
      return
    deliverBody(h3c, usid, false)
  elif len > 0 and h3c.vq != nil:
    # Buffered request body (#220): nghttp3_conn_read_stream does not credit
    # DATA-frame payload to QUIC flow control, so replenish it here as the body is
    # consumed into st.body. Both windows are credited (bounded by the maxBody
    # guard above, mirroring the h2 buffered path) so a body up to maxBodySize
    # flows and cumulative body bytes across requests do not exhaust the
    # connection's MAX_DATA window and stall the peer (QUIC code 1).
    vqStreamConsume(h3c.vq, sid, len)
    # The eager connection-window credit above means MAX_DATA does NOT bound
    # buffered memory; an independent per-connection aggregate does. cap >= maxBody
    # so any single upload fits; concurrent trickled bodies that together exceed it
    # get the offender H3_MESSAGE_ERROR reset rather than pinning maxBody x streams
    # of memory (#254).
    st.bufferedCounted += int(len)
    h3c.bufferedBytes += int(len)
    if gMaxBody > 0'u64 and
        h3c.bufferedBytes > max(int(gConnWindow), int(gMaxBody)):
      h3c.bufferedBytes -= st.bufferedCounted
      vqStreamReset(h3c.vq, sid, 0x0105)   # H3_MESSAGE_ERROR
      h3c.streams.del(usid)

proc cbStreamEnd(user, connUd: pointer, sid: int64) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid notin h3c.streams: return
  template st: H3Stream = h3c.streams[usid]
  st.finSeen = true
  if st.ws != nil:
    wsPeerClosed(h3c.core, nil, WsConn(st.ws))
  elif st.contentLength >= 0 and st.bodyReceived != st.contentLength:
    # Declared content-length disagrees with the DATA received: malformed request
    # (RFC 9110 8.6). Reset the stream; cbStreamClose delivers EOF to a suspended
    # handler and cleans up (#257). Do not dispatch/deliver a clean completion:
    # a streaming route was queued on the ready list back in cbEndHeaders and
    # the handler has not necessarily run yet (everything up to the FIN can
    # arrive in one read batch), so flag the stream and let the dispatcher drop
    # the queued entry (#237).
    st.rejected = true
    st.body.setLen(0)
    if h3c.vq != nil: vqStreamReset(h3c.vq, sid, 0x0105)   # H3_MESSAGE_ERROR
  elif st.rs.reqStreaming:
    deliverBody(h3c, usid, true)
  elif not st.dispatched and st.headersDone:
    # Dispatched: the buffered body leaves the un-dispatched aggregate (#254).
    h3c.bufferedBytes -= st.bufferedCounted
    st.bufferedCounted = 0
    st.dispatched = true
    gReady.add (h3c.slot, h3c.core.h3slots[h3c.slot].gen, usid)

proc creditRemainder(h3c: H3Conn, st: var H3Stream) =
  ## A streaming stream is going away with body bytes received but never
  ## credited (handler never read them, or a manualAck consumer stopped
  ## early). They counted against the connection's MAX_DATA, so return them
  ## there or the shared window leaks (QUIC code 1 eventually); the stream
  ## window needs nothing (the stream is gone). Mirrors the oversize path.
  ##
  ## Only in-order-received-but-app-uncredited bytes are tracked here. On a
  ## client RESET_STREAM ngtcp2 reclaims the connection window itself for both
  ## the unreceived gap up to final_size and any out-of-order buffered data
  ## (conn_recv_reset_stream -> ngtcp2_conn_extend_max_offset); those never
  ## enter this counter, so there is no double-credit.
  if st.uncredited > 0 and h3c.vq != nil:
    vqConnConsume(h3c.vq, csize_t(st.uncredited))
    st.uncredited = 0

proc cbStreamClose(user, connUd: pointer, sid: int64, appErr: uint64) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid notin h3c.streams: return
  template st: H3Stream = h3c.streams[usid]
  # Snapshot the WebSocket + parked callbacks and reconcile flow-control credit
  # BEFORE removing the stream, then fire the callbacks after -- so a callback
  # that responds (res.send/res.write) cannot invalidate the table access, and
  # BOTH onBodyCb(last=true) AND onRespDrain fire on every teardown (RST /
  # STOP_SENDING / abnormal close). Firing onBodyCb resumes a suspended
  # req.read(); firing onRespDrain resumes a producer parked in res.drained()
  # instead of stranding it forever (#232 analog, #250). Contain Exception (not
  # just CatchableError) so an unannotated user callback cannot unwind across the
  # C++ boundary.
  let w = if st.ws != nil: WsConn(st.ws) else: nil
  st.ws = nil
  let bodyCb = st.rs.onBodyCb
  st.rs.onBodyCb = nil
  let drainCb = st.rs.onRespDrain
  st.rs.onRespDrain = nil
  h3c.bufferedBytes -= st.bufferedCounted      # release any buffered reservation (#254)
  creditRemainder(h3c, h3c.streams[usid])
  h3c.streams.del(usid)
  if w != nil:
    try: wsStreamClosed(h3c.core, nil, w)
    except Exception: discard
  if bodyCb != nil:
    var empty: string
    try: bodyCb(toOpenArray(empty, 0, -1), true)
    except Exception: discard
  if drainCb != nil:
    try: drainCb(h3c.core, h3SlotFd(h3c.slot),
                 h3c.core.h3slots[h3c.slot].gen, uint32(usid))
    except Exception: discard

proc cbStreamWritable(user, connUd: pointer, sid: int64) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid in h3c.streams:
    template st: H3Stream = h3c.streams[usid]
    if st.rs.onRespDrain != nil and vqStreamBacklog(h3c.vq, sid) == 0:
      # One-shot: clear the callback before firing. nghttp3's acked_stream_data
      # can fire on_stream_writable more than once while the backlog is 0 (before
      # the drain callback has queued and written the next chunk); re-firing would
      # dispatch the next file read twice (two workers reading the same offset ->
      # duplicate bytes past Content-Length -> the client aborts the stream). The
      # drain re-registers itself per chunk (res.onDrain in applyFileChunk).
      let cb = st.rs.onRespDrain
      st.rs.onRespDrain = nil
      cb(h3c.core, h3SlotFd(h3c.slot),
         h3c.core.h3slots[h3c.slot].gen, uint32(usid))

proc cbConnClose(user, connUd: pointer) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  if h3c != nil:
    # The shim frees the VqConn immediately after this returns, so drop our
    # dangling pointers to it now: h3Free and the response procs must not touch
    # a freed VqConn (use-after-free otherwise), and the SSL handle borrowed
    # from it goes the same way (~Conn calls SSL_free), so a later
    # req.clientCertSubject reads nil instead of freed memory.
    h3c.vq = nil
    h3c.ssl = nil
    if h3c.slot >= 0 and h3c.slot < h3c.core.h3slots.len:
      h3c.core.h3slots[h3c.slot].closeReq = true

proc sendtoUdp(fd: cint, data: pointer, len: csize_t, flags: cint, peer: pointer,
               peerLen: cuint): int {.importc: "sendto", header: "<sys/socket.h>".}
proc recvfromUdp(fd: cint, buf: pointer, n: csize_t, flags: cint, peer: pointer,
                 peerLen: ptr cuint): int {.importc: "recvfrom", header: "<sys/socket.h>".}
proc getsocknameC(fd: cint, a: pointer, l: ptr cuint): cint {.importc: "getsockname", header: "<sys/socket.h>".}

when defined(linux):
  # MSG_TRUNC on a datagram socket makes recvfrom return the packet's REAL
  # length rather than how much it copied, which is the only way to notice a
  # truncated datagram. Hardcoded because std/posix exports it as an importc var
  # on some targets (same reasoning as sendFlags in eventloop.nim); the value is
  # uniform across Linux architectures. BSD/macOS recvfrom has no MSG_TRUNC
  # semantics, so there the larger buffer is the whole mitigation and an
  # oversize datagram stays indistinguishable from a full one (#380).
  const recvFlags = cint(0x20)
else:
  const recvFlags = cint(0)

proc ngMaxRecvUdpPayload*(): int =
  ## The max_udp_payload_size the shim advertises in its transport parameters,
  ## i.e. the largest datagram a conforming client may send us. ngReceive sizes
  ## its buffer from this same number, so the advertisement is honest by
  ## construction; exported so a test can pin the two together (#380).
  int(vqMaxRecvUdpPayload())

proc cbSend(user: pointer, conn: ptr VqConn, data: ptr uint8, len: csize_t,
            peer: pointer, peerLen: csize_t): cint {.cdecl.} =
  # Return < 0 on any send failure (notably EWOULDBLOCK, a full UDP socket
  # buffer) so writeConn stops this cycle instead of spinning out datagrams that
  # the kernel drops. QUIC loss recovery retransmits and the next pump retries
  # the drained socket -- swallowing the failure just wasted work (R15).
  if sendtoUdp(gUdpFd, data, len, cint(0), peer, cuint(peerLen)) < 0: cint(-1)
  else: cint(0)

proc toVqSni(sni: openArray[H3SniCert]): seq[VqSniCert] =
  ## Views into the caller's H3SniCert strings, valid as long as `sni` is: both
  ## call sites hand the result straight to a synchronous shim call, and the
  ## shim copies the material it keeps. Shared by ngSetup and ngReloadCert so
  ## the field list exists once.
  result = newSeq[VqSniCert](sni.len)
  for i in 0 ..< sni.len:
    result[i] = VqSniCert(
      host: sni[i].host.cstring,
      cert_file: sni[i].certFile.cstring, key_file: sni[i].keyFile.cstring,
      cert_pem: sni[i].certPem.cstring, key_pem: sni[i].keyPem.cstring,
      key_password: sni[i].keyPassword.cstring,
      pkcs12_file: sni[i].pkcs12File.cstring,
      pkcs12: (if sni[i].pkcs12.len > 0:
                 cast[ptr uint8](unsafeAddr sni[i].pkcs12[0]) else: nil),
      pkcs12_len: csize_t(sni[i].pkcs12.len))

# --- transport drive (called by eventloop's ngtcp2 h3Drive branch) ----------
proc ngSetup*(core: ptr LoopCore, udpFd: cint, certFile, keyFile: string,
              maxBody, maxStreams, maxFieldSection: int,
              certPem = "", keyPem = "", keyPassword = "",
              pkcs12File = "", pkcs12 = "",
              streamRecvWindow = 0, connRecvWindow = 0,
              maxConnections = 0, maxResetStreams = 0,
              tlsCipherSuites = "", maxTlsVersion = 0,
              verifyClient = 0, clientCaFile = "", clientCaPem = "",
              sni: openArray[H3SniCert] = [],
              maxIdleTimeout = 0): bool =
  ## Build this loop's QUIC engine. tlsCipherSuites / maxTlsVersion carry the
  ## operator's TLS policy onto the QUIC side (#359); maxTlsVersion is an
  ## OpenSSL version constant (0 = no cap) and anything below TLS 1.3 makes the
  ## engine refuse to start, since QUIC cannot negotiate below 1.3.
  ## verifyClient is the OpenSSL SSL_VERIFY_* bitmask for mTLS, enforced on h3
  ## exactly as on the TCP listener (#351). `sni` carries the per-host
  ## certificates, each getting its own QUIC context in the shim (#374).
  ## maxIdleTimeout is the max_idle_timeout we advertise, in seconds (0 = the
  ## shim default), which also caps the peer's idle timer and arms ngtcp2's
  ## keep-alive at a third of it.
  gCore = core
  gUdpFd = udpFd
  gMaxBody = uint64(maxBody)
  gConnWindow = uint64(connRecvWindow)
  var cfg: VqConfig
  cfg.user = core
  cfg.cb = VqCallbacks(on_accept: cbAccept, on_headers: cbHeaders, on_body: cbBody,
    on_stream_end: cbStreamEnd, on_stream_close: cbStreamClose,
    on_stream_writable: cbStreamWritable, on_conn_close: cbConnClose, on_send: cbSend)
  # The shim reads these only during vqEngineNew below (synchronous), so the
  # views into these parameters stay valid for the call. A PKCS#12 bundle takes
  # precedence, then in-memory PEM, then the file paths; key_password decrypts an
  # encrypted PEM key or the PKCS#12 bundle.
  cfg.cert_file = certFile.cstring
  cfg.key_file = keyFile.cstring
  cfg.cert_pem = certPem.cstring
  cfg.key_pem = keyPem.cstring
  cfg.key_password = keyPassword.cstring
  cfg.pkcs12_file = pkcs12File.cstring
  cfg.pkcs12 = (if pkcs12.len > 0: cast[ptr uint8](unsafeAddr pkcs12[0]) else: nil)
  cfg.pkcs12_len = csize_t(pkcs12.len)
  cfg.max_body = uint64(maxBody)
  cfg.max_concurrent_streams = uint64(maxStreams)
  cfg.max_connections = uint64(max(0, maxConnections))
  cfg.max_reset_streams = uint64(max(0, maxResetStreams))
  cfg.max_field_section_size = cint(maxFieldSection)
  cfg.stream_recv_window = uint64(streamRecvWindow)
  cfg.conn_recv_window = uint64(connRecvWindow)
  cfg.tls_cipher_suites = tlsCipherSuites.cstring
  cfg.max_tls_version = cint(maxTlsVersion)
  cfg.verify_client = cint(verifyClient)
  cfg.client_ca_file = clientCaFile.cstring
  cfg.client_ca_pem = clientCaPem.cstring
  var sniC = toVqSni(sni)
  cfg.sni = (if sniC.len > 0: addr sniC[0] else: nil)
  cfg.sni_len = csize_t(sniC.len)
  cfg.max_idle_timeout_sec = uint64(max(0, maxIdleTimeout))
  gEngine = vqEngineNew(addr cfg)
  if gEngine == nil: return false
  gLocalLen = cuint(sizeof(gLocalSa))
  discard getsocknameC(udpFd, addr gLocalSa[0], addr gLocalLen)
  # Size the receive buffer from the max_udp_payload_size the shim advertises,
  # here rather than lazily, so the two can never disagree while traffic flows
  # (#380). gRecvBufSize is the readable record of it.
  gRecvBuf = newSeq[uint8](ngMaxRecvUdpPayload())
  gRecvBufSize.store(gRecvBuf.len, moRelaxed)
  true

proc ngRecvBufSize*(): int =
  ## The ngReceive buffer size the loops settled on, 0 before any ngSetup. It
  ## must equal ngMaxRecvUdpPayload(): that equality IS the #380 fix, and it is
  ## what the regression test asserts.
  gRecvBufSize.load(moRelaxed)

proc ngTruncatedDrops*(): uint64 =
  ## Datagrams the loop threads dropped because they did not fit the receive
  ## buffer. It should never move: the buffer is 65527 bytes, the largest a UDP
  ## payload can be, so there is no datagram that can arrive truncated. The
  ## MSG_TRUNC branch it counts is a guard against a future smaller buffer, not
  ## a live path, and this is how a test asserts the guard stayed dormant. (It
  ## could only ever move on Linux anyway, where MSG_TRUNC reports the real
  ## datagram length; elsewhere a truncated datagram cannot be told from a full
  ## one and goes to the engine, which drops it when AEAD fails.)
  gTruncDrops.load(moRelaxed)

const ngRecvBudget* = 256
  ## Datagrams one ngReceive call will take off the UDP socket before handing the
  ## loop thread back: a per-drain budget, and the loop may drain up to four
  ## times per pass (h3Drive runs from processOutbox, the main drive, the tick's
  ## sweepWsIdle and the end-of-pass flush re-drive), so the true per-pass
  ## ceiling is four times this. Every datagram is decrypted and parsed
  ## synchronously (vq_engine_recv -> ngtcp2_conn_read_pkt -> nghttp3), so an
  ## unbounded drain
  ## let a UDP source at line rate keep the thread inside the receive loop and
  ## starve every HTTP/1.1 and HTTP/2 fd it owns: TLS handshakes stalled,
  ## responses did not flush, deadlines fired. Forging the datagrams is cheap
  ## because a QUIC server commits per-connection state before validating the
  ## peer's address (no Retry token yet; see acceptConn in the shim) (#381).
  ##
  ## 256 is a work quantum, not a rate limit: a legitimate burst is still fully
  ## received, just across drains of the loop, and the budget only bounds how
  ## long the TCP side waits between them. It is the shape of suspendAccept's
  ## accept-side backoff, except that there is nothing to back off from here --
  ## the next pass simply continues.

proc ngReceive*(): bool =
  ## Drain pending datagrams from the loop's (nonblocking) UDP socket into the
  ## engine, up to ngRecvBudget of them; the shim's callbacks populate
  ## connections and the ready list. Returns true when the budget ran out before
  ## the socket did, i.e. the caller should come back without waiting on the
  ## selector. (The UDP fd is level-triggered, so a plain return re-fires too,
  ## but the caller would first have blocked in select for up to a second.)
  ##
  ## The buffer is sized from the max_udp_payload_size we advertise, not from a
  ## path-MTU guess. A conforming client on a large-MTU path (a 9000-byte VPC
  ## MTU, 65536 on loopback) is entitled to fill that advertisement, and the old
  ## 2048-byte buffer had the kernel truncate those datagrams: header protection
  ## and AEAD then failed, ngtcp2 dropped the packet, the client retransmitted
  ## the same oversize datagram, and the connection died on the idle timer with
  ## nothing logged at either end. Clamping the advertisement down to the buffer
  ## instead would have capped every datagram the peer sends us and cost
  ## throughput on exactly those paths (#380). One heap buffer per loop thread:
  ## 64 KB of stack per call is not free.
  if gRecvBuf.len == 0: gRecvBuf = newSeq[uint8](ngMaxRecvUdpPayload())
  var peer: array[128, byte]
  var budget = ngRecvBudget
  while budget > 0:
    var plen = cuint(sizeof(peer))
    let n = recvfromUdp(gUdpFd, addr gRecvBuf[0], csize_t(gRecvBuf.len),
                        recvFlags, addr peer[0], addr plen)
    if n <= 0: return false            # socket drained: nothing left to come back for
    dec budget
    if n > gRecvBuf.len:
      # MSG_TRUNC: recvfrom reported a datagram larger than it copied. Feeding
      # the prefix to ngtcp2 would just fail AEAD and look like line corruption,
      # so drop it as the oversize datagram it is and count it.
      discard gTruncDrops.fetchAdd(1, moRelaxed)
      continue
    vqEngineRecv(gEngine, addr gRecvBuf[0], csize_t(n), addr peer[0], csize_t(plen),
                 addr gLocalSa[0], csize_t(gLocalLen), ngNowNs())
  true                                 # budget spent; the socket may hold more

proc ngPump*() = vqEnginePump(gEngine, ngNowNs())
proc ngHandleExpiry*() = vqEngineHandleExpiry(gEngine, ngNowNs())
proc ngTimeoutMs*(): int =
  let now = ngNowNs()
  let e = vqEngineNextExpiry(gEngine, now)
  if e == high(uint64): -1
  elif e <= now: 0
  else: int((e - now) div 1_000_000) + 1
proc ngReloadCert*(certFile, keyFile: string,
                   sni: openArray[H3SniCert] = []): bool =
  ## Rotate this loop's QUIC certificate from PEM file paths. Empty paths mean
  ## "rebuild from the configured material, re-reading any files" -- the bare
  ## reloadTls() form (#353). A non-empty `sni` replaces the per-host set
  ## wholesale, host names included, which is the reloadTls(sni = ...) override
  ## (#356); empty means "rebuild the configured per-host material". The shim
  ## builds the replacement contexts and installs them only if everything
  ## loaded, so false means nothing changed; ngLastError says why.
  if gEngine == nil: return false
  var sniC = toVqSni(sni)
  vqEngineReloadCert(gEngine, certFile.cstring, keyFile.cstring,
                     (if sniC.len > 0: addr sniC[0] else: nil),
                     csize_t(sniC.len)) == 0
proc ngLastError*(): string =
  ## Why this loop's last ngReloadCert was refused, or -- with no engine, i.e.
  ## after a failed ngSetup -- why the engine could not be built (#352). The
  ## shim owns the buffer, so copy it out before the next call.
  $vqEngineLastError(gEngine)
proc ngTakeReady*(): seq[tuple[slot: int, gen: uint32, sid: uint64]] =
  result = gReady
  gReady.setLen(0)
proc ngEngineFree*() =
  ## Release everything this loop thread's h3 state owns. The two threadvar
  ## seqs go with the engine: they are per-thread, so a process that starts and
  ## stops servers leaked gRecvBuf's 64 KiB (plus whatever gReady had grown to)
  ## per loop thread per cycle, which 25 cycles over 4 loops turned into 6 MiB
  ## with nothing to free it.
  if gEngine != nil: vqEngineFree(gEngine); gEngine = nil
  gRecvBuf = @[]
  gReady = @[]

# --- response emission (codec-compatible) -----------------------------------
proc toVq(hdrs: seq[(string, string)]): seq[VqHeader] =
  result = newSeq[VqHeader](hdrs.len)
  for i, (n, v) in hdrs:
    result[i] = VqHeader(name: n.cstring, name_len: csize_t(n.len),
                         value: v.cstring, value_len: csize_t(v.len))

proc buildRespHeaders(core: ptr LoopCore, code: int, contentType: string,
                      extra: openArray[(string, string)], bodyLen: int,
                      isHead, bodiless: bool,
                      secHeaders: openArray[(string, string)] = []):
                      seq[(string, string)] =
  result.add (":status", $code)
  if core.serverHeader.len > 0: result.add ("server", core.serverHeader)
  result.add ("date", core.dateStr)
  if contentType.len > 0 and not bodiless: result.add ("content-type", contentType)
  if not bodiless and bodyLen >= 0: result.add ("content-length", $bodyLen)
  for (name, val) in extra:
    let ln = name.toLowerAscii
    # RFC 9114 4.2: an h3 endpoint MUST NOT generate connection-specific fields;
    # drop them (and any stray handler pseudo-header) rather than QPACK-encode a
    # response a strict client would cancel (#257). Shared set (fieldrules), also h1/h2.
    if isForbiddenResponseField(ln): continue
    if ln.len == 0 or ln[0] != ':': result.add (ln, val)
  for (name, val) in secHeaders:               # OWASP baseline; app header wins
    var shadowed = false
    for (hn, _) in extra:
      if cmpIgnoreCase(hn, name) == 0: shadowed = true; break
    if shadowed: continue
    let ln = name.toLowerAscii
    if isForbiddenResponseField(ln): continue
    if ln.len == 0 or ln[0] != ':': result.add (ln, val)

proc h3Respond*(core: ptr LoopCore, conn: H3Conn, sid: uint64, code: int,
                contentType: string, extraHeaders: openArray[(string, string)],
                body: openArray[char],
                secHeaders: openArray[(string, string)] = []) =
  if conn.vq == nil or sid notin conn.streams or conn.streams[sid].rs.responded: return
  template st: H3Stream = conn.streams[sid]
  st.rs.responded = true
  let bodiless = bodilessStatus(code)
  let hdrs = buildRespHeaders(core, code, contentType, extraHeaders, body.len,
                              st.isHead, bodiless, secHeaders)
  var nv = toVq(hdrs)
  let sendBody = body.len > 0 and not st.isHead and not bodiless
  vqSubmitResponse(conn.vq, int64(sid), cint(code), addr nv[0], csize_t(nv.len),
    (if sendBody: cast[ptr uint8](unsafeAddr body[0]) else: nil),
    (if sendBody: csize_t(body.len) else: 0), 1)

proc h3SendHead*(core: ptr LoopCore, conn: H3Conn, sid: uint64, code: int,
                 contentType: string, extraHeaders: openArray[(string, string)],
                 contentLength: int64 = -1) =
  ## Send a streamed response's HEADERS and open the body. `contentLength` is the
  ## length the caller already declared in `extraHeaders` (-1 = none); it is not
  ## encoded here, only remembered, so h3StreamFinish can reconcile it against
  ## what the body actually wrote (#345).
  if conn.vq == nil or sid notin conn.streams or conn.streams[sid].rs.responded: return
  template st: H3Stream = conn.streams[sid]
  st.rs.responded = true
  st.rs.respStreaming = not st.isHead
  st.respDeclaredLen = contentLength
  st.respBodyWritten = 0
  let hdrs = buildRespHeaders(core, code, contentType, extraHeaders,
                              bodyLen = -1, st.isHead, bodiless = false)
  var nv = toVq(hdrs)
  vqSubmitHead(conn.vq, int64(sid), cint(code), addr nv[0], csize_t(nv.len))
  if st.isHead: vqStreamFinish(conn.vq, int64(sid))

proc h3StreamWrite*(conn: H3Conn, sid: uint64, data: openArray[char]): int =
  if conn.vq == nil or sid notin conn.streams or not conn.streams[sid].rs.respStreaming: return 0
  if data.len > 0:
    conn.streams[sid].respBodyWritten += data.len   # reconciled at finish (#345)
    return int(vqStreamWrite(conn.vq, int64(sid),
                             cast[ptr uint8](unsafeAddr data[0]), csize_t(data.len)))
  int(vqStreamBacklog(conn.vq, int64(sid)))

proc h3StreamAbort*(conn: H3Conn, sid: uint64) =
  if conn.vq == nil or sid notin conn.streams or not conn.streams[sid].rs.respStreaming: return
  conn.streams[sid].rs.respStreaming = false
  conn.streams[sid].rs.onRespDrain = nil
  vqStreamReset(conn.vq, int64(sid), 0x0102)   # H3_INTERNAL_ERROR

proc h3StreamFinish*(conn: H3Conn, sid: uint64,
                     trailers: openArray[(string, string)] = []) =
  ## Terminate a streamed response with the FIN (preceded by any trailer
  ## section). A body that came up short of (or ran past) a Content-Length the
  ## head already declared is RESET instead: a clean end at the wrong length is a
  ## well-formed lie the peer can only report as a protocol error, so the reset
  ## makes the truncation visible on our side too, as HTTP/1 forces the
  ## connection closed on the same mismatch (#248, #345).
  if conn.vq == nil or sid notin conn.streams or not conn.streams[sid].rs.respStreaming: return
  if conn.streams[sid].respDeclaredLen >= 0 and
      conn.streams[sid].respBodyWritten != conn.streams[sid].respDeclaredLen:
    h3StreamAbort(conn, sid)
    return
  conn.streams[sid].rs.respStreaming = false
  conn.streams[sid].rs.onRespDrain = nil
  # Submit any trailer fields before the FIN so nghttp3 keeps the stream open for
  # the trailing HEADERS (RFC 9114 4.1). Names must be lowercase on the wire.
  if trailers.len > 0:
    # Validate handler-supplied response trailers before submission: drop a
    # pseudo-header or non-token name, or a value with CR/LF/NUL, so a handler
    # concatenating untrusted data into a trailer can't split the response on an
    # h1 relay (#257). The forbidden set is the one h1's chunked trailer writer
    # and h2's trailing HEADERS share (fieldrules.forbiddenResponseTrailerField):
    # the connection-specific fields plus `te`, and content-length, which RFC
    # 9110 6.5.1 forbids generating in a trailer section (#238). Build the wire
    # list from only the accepted entries.
    var lower: seq[(string, string)]
    for (name, val) in trailers:
      let ln = name.toLowerAscii
      if ln.len == 0 or ln[0] == ':' or not validFieldName(ln) or
          not validFieldValue(val): continue
      if forbiddenResponseTrailerField(ln): continue
      lower.add (ln, val)
    if lower.len > 0:
      var tv = newSeq[VqHeader](lower.len)
      for i in 0 ..< lower.len:
        tv[i] = VqHeader(name: lower[i][0].cstring, name_len: csize_t(lower[i][0].len),
                         value: lower[i][1].cstring, value_len: csize_t(lower[i][1].len))
      vqSubmitTrailers(conn.vq, int64(sid), addr tv[0], csize_t(tv.len))
  vqStreamFinish(conn.vq, int64(sid))

proc h3StreamBacklog*(conn: H3Conn, sid: uint64): int =
  if conn.vq == nil or sid notin conn.streams: return 0
  int(vqStreamBacklog(conn.vq, int64(sid)))

proc h3RespComp*(conn: H3Conn, sid: uint64): RootRef =
  if sid in conn.streams: conn.streams[sid].rs.respComp else: nil
proc h3RespEnc*(conn: H3Conn, sid: uint64): string =
  if sid in conn.streams: conn.streams[sid].rs.respEnc else: ""
proc h3SetRespComp*(conn: H3Conn, sid: uint64, comp: RootRef, enc: string) =
  if sid in conn.streams:
    conn.streams[sid].rs.respComp = comp
    conn.streams[sid].rs.respEnc = enc

proc h3SetOnBody*(conn: H3Conn, sid: uint64, cb: BodyCb, manualAck = false) =
  if sid notin conn.streams: return
  conn.streams[sid].rs.onBodyCb = cb
  conn.streams[sid].bodyManualAck = manualAck
  deliverBody(conn, sid, conn.streams[sid].finSeen)

proc h3AckBody*(conn: H3Conn, sid: uint64, n: int) =
  ## Replenish `n` consumed request-body bytes of a streaming h3 stream by
  ## extending QUIC stream+connection flow control. nghttp3_conn_read_stream
  ## does not credit DATA-frame payload (RFC 9000 flow control is the app's to
  ## drive), so a manualAck consumer must ack what it reads or the peer stalls
  ## once the initial window fills. Mirrors h2AckBody's WINDOW_UPDATE; the
  ## auto-ack default replenishes in deliverBody instead.
  if conn.vq != nil and n > 0 and sid in conn.streams:
    vqStreamConsume(conn.vq, int64(sid), csize_t(n))
    conn.streams[sid].uncredited = max(0, conn.streams[sid].uncredited - n)

proc h3Goaway*(conn: H3Conn) =
  ## Initial GOAWAY notice (RFC 9114 5.2): "shutting down", max stream id.
  if conn.vq == nil or conn.goneAway: return
  conn.goneAway = true
  vqConnGoaway(conn.vq)

proc h3Shutdown*(conn: H3Conn) =
  ## Final GOAWAY (RFC 9114 5.2): the definitive last-accepted stream id. Sent
  ## after h3Goaway's notice, once the drain has given in-flight requests a
  ## chance to finish, so the peer learns the request boundary.
  if conn.vq == nil or conn.finalGoaway: return
  conn.finalGoaway = true
  vqConnShutdown(conn.vq)

proc h3GracefulClose*(conn: H3Conn) =
  ## Complete a clean shutdown of this connection: flush the final GOAWAY, then
  ## emit a QUIC CONNECTION_CLOSE(NO_ERROR) instead of going silent (which would
  ## force the peer to idle-time-out). Unlike h3Free this does NOT tear down the
  ## Nim H3Conn/streams: the shim keeps the connection alive until the frames are
  ## on the wire, then reaps it and fires on_conn_close -> cbConnClose, which
  ## drives h3FreeSlot. Idempotent (guarded by `closing`).
  if conn.vq == nil or conn.closing: return
  conn.closing = true
  vqConnCloseGraceful(conn.vq, 0)

proc h3Free*(conn: H3Conn) =
  # Snapshot ws + parked callbacks and detach them BEFORE firing any, so a
  # callback that responds cannot invalidate the mpairs iterator; then clear the
  # table and fire. Deliver onBodyCb(last=true) AND onRespDrain for every open
  # stream so a suspended req.read()/res.drained() resumes instead of stranding a
  # zombie coroutine when the whole connection dies (#250; matches h2NotifyClosed).
  var wss: seq[WsConn]
  var bodyCbs: seq[BodyCb]
  var drainCbs: seq[(uint32, RespDrainCb)]
  for sid, st in conn.streams.mpairs:
    if st.ws != nil:
      wss.add WsConn(st.ws); st.ws = nil
    if st.rs.onBodyCb != nil:
      bodyCbs.add st.rs.onBodyCb; st.rs.onBodyCb = nil
    if st.rs.onRespDrain != nil:
      drainCbs.add (uint32(sid), st.rs.onRespDrain); st.rs.onRespDrain = nil
  conn.streams.clear()
  var empty: string
  for w in wss:
    try: wsStreamClosed(conn.core, nil, w)
    except Exception: discard
  for cb in bodyCbs:
    try: cb(toOpenArray(empty, 0, -1), true)
    except Exception: discard
  for (sid, cb) in drainCbs:
    try: cb(conn.core, h3SlotFd(conn.slot), conn.core.h3slots[conn.slot].gen, sid)
    except Exception: discard
  if conn.vq != nil:
    vqConnClose(conn.vq, 0)
    conn.vq = nil

# --- WebSocket over HTTP/3 (RFC 9220 Extended CONNECT) ----------------------
proc wsFlushH3ng(core: ptr LoopCore, c: ptr Connection, w: WsConn) {.nimcall, gcsafe.} =
  ## WsConn.flush for HTTP/3: push produced frames as DATA (nghttp3 serves them),
  ## then finalize on close or fire onDrain when the backlog empties.
  let conn = H3Conn(w.h3conn)
  let sid = uint64(w.stream)
  if conn == nil or conn.vq == nil or sid notin conn.streams:
    w.outBuf.setLen 0
    return
  if w.outBuf.len > 0:
    discard vqStreamWrite(conn.vq, int64(sid),
                          cast[ptr uint8](addr w.outBuf[0]), csize_t(w.outBuf.len))
    w.outBuf.setLen 0
  let backlog = int(vqStreamBacklog(conn.vq, int64(sid)))
  w.h2Pending = backlog
  if backlog == 0:
    if w.wantClose:
      wsStreamClosed(core, nil, w)
      if sid in conn.streams: conn.streams[sid].ws = nil
      vqStreamFinish(conn.vq, int64(sid))
    elif w.backedUp:
      w.backedUp = false
      if w.onDrain != nil:
        w.onDrain(WebSocket(core: core, fd: w.fd, gen: w.gen, stream: w.stream))
  else:
    w.backedUp = true

proc h3WsAccept*(core: ptr LoopCore, conn: H3Conn, sid: uint64, fd: int32,
                 gen: uint32, maxMessage: int, extensionsOffer, protocolsOffer: string,
                 serverProtocols: openArray[string]): bool =
  ## Accept an Extended CONNECT WebSocket: 200 headers (no FIN, stream stays
  ## open) and attach a WsConn whose frames tunnel through h3 DATA.
  if sid notin conn.streams: return false
  template st: H3Stream = conn.streams[sid]
  if not st.isWsConnect or st.rs.responded or st.ws != nil: return false
  st.rs.responded = true
  let (w, proto, ext) = wsSetup(core, fd, gen, maxMessage, uint32(sid),
                                extensionsOffer, protocolsOffer, serverProtocols)
  w.flush = wsFlushH3ng
  w.h3conn = conn
  st.ws = w
  # Hand over any frames the client pipelined with the Extended CONNECT
  # handshake. An Extended-CONNECT stream dispatches on headers, so DATA that
  # arrived in the same packet burst landed in st.body while st.ws was nil; move
  # it into the WsConn instead of dropping it (#259). They are pumped once the
  # handler installs onMessage (see the post-accept pump in eventloop's h3Drive),
  # not here, so no message is dispatched into a nil callback. Mirrors h2WsAccept.
  if st.body.len > 0:
    w.inBuf.add st.body
    st.body.setLen(0)
  # The client may also have half-closed (FIN) the stream before the handler
  # accepted it: cbStreamEnd could not deliver the peer-close then (there was no
  # WsConn yet), so carry the FIN over for the post-accept pump to replay,
  # otherwise the application's onClose never fires and the handle lingers until
  # the idle sweep reaps it (#261). Twin of h2WsAccept's endStreamSeen.
  w.preAcceptFin = st.finSeen
  var hdrs: seq[(string, string)] = @[(":status", "200")]
  if core.serverHeader.len > 0: hdrs.add ("server", core.serverHeader)
  hdrs.add ("date", core.dateStr)
  if proto.len > 0: hdrs.add ("sec-websocket-protocol", proto)
  if ext.len > 0: hdrs.add ("sec-websocket-extensions", ext)
  var nv = toVq(hdrs)
  vqSubmitHead(conn.vq, int64(sid), cint(200), addr nv[0], csize_t(nv.len))
  true

proc h3WsLookup(corep: pointer, fd: int32, gen: uint32,
                stream: uint32): RootRef {.nimcall, gcsafe.} =
  let core = cast[ptr LoopCore](corep)
  let conn = h3ConnOf(core, fd, gen)
  if conn != nil and uint64(stream) in conn.streams:
    return conn.streams[uint64(stream)].ws
  nil

proc installH3WsHooks*(core: ptr LoopCore) =
  core.hooks.wsH3Lookup = h3WsLookup
