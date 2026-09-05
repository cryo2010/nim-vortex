"""Minimal aioquic-based HTTP/3 client for the stress soaks.

httpx has no HTTP/3, so the h3 cells drive the vortex QUIC listener with aioquic
(the reference Python QUIC/h3 stack, as conformance/h3websocket already uses).
`H3Session` exposes the same shape the httpx path uses - request / stream (a
generator whose first item is the status, then body chunks) / upload - so the
workloads are transport-agnostic. One QUIC connection multiplexes many streams.
"""
import asyncio, gzip, ssl
from contextlib import asynccontextmanager

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, StreamReset, ConnectionTerminated


class ProtocolPinError(Exception):
    """The negotiated wire protocol did not match the pinned VORTEX_PROTO. A
    stress run must measure exactly the protocol it names -- never a silent
    fallback (e.g. h2 -> h1, or an h3 dial that failed to negotiate h3)."""


def decode_body(data: bytes, enc):
    """Decode a response body by its content-encoding. httpx does this
    automatically for h1/h2; aioquic does not, so the h3 session must decode to
    match (vortex compresses large buffered responses like /echo)."""
    if not enc or enc == "identity":
        return data
    if enc == "gzip":
        return gzip.decompress(data)
    if enc == "br":
        import brotli; return brotli.decompress(data)
    if enc == "zstd":
        import io, zstandard
        return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
    raise ValueError(f"h3: unexpected content-encoding {enc!r}")

# Per-stream cap on the client's unacked upload buffer (aioquic
# stream.sender._buffer). Bounds client RAM to ~this x concurrent streams so a
# large STREAM_BYTES x high concurrency upload does not OOM the client; 256 KiB
# still keeps the localhost pipe full (well above the bandwidth-delay product).
_UPLOAD_BUF_CAP = 256 * 1024

# --- WebSocket-over-HTTP/3 (RFC 9220 Extended CONNECT) framing ---------------
OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x2, 0x8, 0x9, 0xA
_WS_MASK = b"\x21\x43\x65\x87"

def ws_frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    """A client-masked WebSocket frame (7-bit, 16-bit, or 64-bit length)."""
    out = bytearray([(0x80 if fin else 0) | opcode])
    n = len(payload)
    if n < 126:
        out.append(0x80 | n)
    elif n < 65536:
        out += bytes([0x80 | 126, (n >> 8) & 0xff, n & 0xff])
    else:
        out += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    out += _WS_MASK
    out += bytes(payload[i] ^ _WS_MASK[i % 4] for i in range(n))
    return bytes(out)

def parse_ws(buf: bytearray):
    """Return (frames, consumed): complete server (unmasked) frames as (op, payload)."""
    frames, pos = [], 0
    while pos + 2 <= len(buf):
        b0, b1 = buf[pos], buf[pos + 1]
        assert (b1 & 0x80) == 0, "server WebSocket frame must be unmasked"
        ln, hdr = b1 & 0x7f, 2
        if ln == 126:
            if pos + 4 > len(buf): break
            ln = (buf[pos + 2] << 8) | buf[pos + 3]; hdr = 4
        elif ln == 127:
            if pos + 10 > len(buf): break
            ln = int.from_bytes(bytes(buf[pos + 2:pos + 10]), "big"); hdr = 10
        if pos + hdr + ln > len(buf): break
        frames.append((b0 & 0x0f, bytes(buf[pos + hdr:pos + hdr + ln])))
        pos += hdr + ln
    return frames, pos


class H3Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._http = None
        self._queues = {}          # stream_id -> asyncio.Queue of (kind, value)
        self.authority = ""

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol.startswith("h3"):
            self._http = H3Connection(self._quic)
        # A stream reset / connection close yields no H3 terminal event, so a
        # consumer blocked on `q.get()` would hang forever (and the harness would
        # then wrongly downgrade the hang to a timeout). Enqueue an explicit error
        # terminal so the workload fails loud with the cause.
        if isinstance(event, StreamReset):
            q = self._queues.get(event.stream_id)
            if q is not None:
                q.put_nowait(("err", f"stream reset (code {event.error_code})"))
            return
        if isinstance(event, ConnectionTerminated):
            for q in self._queues.values():
                q.put_nowait(("err", f"connection closed (code {event.error_code})"))
            return
        if self._http is not None:
            for e in self._http.handle_event(event):
                self._on_h3(e)

    def _on_h3(self, e):
        q = self._queues.get(e.stream_id)
        if q is None:
            return
        if isinstance(e, HeadersReceived):
            status, enc = 0, None
            for k, v in e.headers:
                if k == b":status":
                    status = int(v)
                elif k == b"content-encoding":
                    enc = v.decode("ascii", "replace").strip().lower() or None
            q.put_nowait(("h", (status, enc)))
            if e.stream_ended:
                q.put_nowait(("end", None))
        elif isinstance(e, DataReceived):
            if e.data:
                q.put_nowait(("d", e.data))
            if e.stream_ended:
                q.put_nowait(("end", None))

    def _open(self, method, path, headers, end):
        sid = self._quic.get_next_available_stream_id()
        q = asyncio.Queue()
        self._queues[sid] = q
        h = [(b":method", method.encode()), (b":scheme", b"https"),
             (b":authority", self.authority.encode()), (b":path", path.encode())]
        h += [(k.lower().encode(), v.encode()) for k, v in headers.items()]
        self._http.send_headers(stream_id=sid, headers=h, end_stream=end)
        self.transmit()
        return sid, q


class H3Session:
    """httpx-shaped facade over one multiplexed H3 connection."""
    def __init__(self, client: H3Client):
        self.c = client

    async def request(self, method, path, headers=None, content=b""):
        sid, q = self.c._open(method, path, headers or {}, end=(not content))
        if content:
            self.c._http.send_data(sid, content, end_stream=True)
            self.c.transmit()
        status, enc, body = 0, None, bytearray()
        while True:
            kind, val = await q.get()
            if kind == "h": status, enc = val
            elif kind == "d": body += val
            elif kind == "err":
                self.c._queues.pop(sid, None); raise ConnectionError(val)
            else: break
        self.c._queues.pop(sid, None)
        # Decode content-encoding to match httpx's transparent h1/h2 behavior; the
        # requests workload sends accept-encoding, so /echo comes back compressed.
        return status, decode_body(bytes(body), enc)

    async def get(self, path, headers=None):
        return await self.request("GET", path, headers)

    async def stream(self, method, path, headers=None):
        """Async generator: first item is the status (int), then body chunks."""
        sid, q = self.c._open(method, path, headers or {}, end=True)
        try:
            while True:
                kind, val = await q.get()
                if kind == "h": yield val[0]        # (status, enc); enc unused --
                elif kind == "d": yield val         # streaming workloads send no
                elif kind == "err": raise ConnectionError(val)  # accept-encoding
                else: break
        finally:
            self.c._queues.pop(sid, None)

    async def upload(self, path, headers, body_agen):
        sid, q = self.c._open("POST", path, headers or {}, end=False)
        async for chunk in body_agen:
            self.c._http.send_data(sid, chunk, end_stream=False)
            self.c.transmit()
            # Backpressure. aioquic keeps written-but-unacked bytes in
            # stream.sender._buffer (acked data is dropped from the front). A bare
            # `sleep(0)` yields once but never waits, so the loop would pump the
            # whole body in and buffer up to STREAM_BYTES per stream -- which OOMs
            # the client at high concurrency (many x 1 GiB). Wait until this
            # stream's unacked buffer drains below the cap so only a bounded window
            # is held (like httpx pulling body chunks lazily on h1/h2); the event
            # loop processes incoming ACKs while we wait, shrinking the buffer.
            st = self.c._quic._streams.get(sid)
            while st is not None and len(st.sender._buffer) >= _UPLOAD_BUF_CAP:
                await asyncio.sleep(0.0005)
                self.c.transmit()
                st = self.c._quic._streams.get(sid)
        self.c._http.send_data(sid, b"", end_stream=True)
        self.c.transmit()
        status = 0
        while True:
            kind, val = await q.get()
            if kind == "h": status = val[0]         # (status, enc); enc unused
            elif kind == "err":
                self.c._queues.pop(sid, None); raise ConnectionError(val)
            elif kind == "end": break
        self.c._queues.pop(sid, None)
        return status

    async def ws_open(self, path="/ws", subprotocols=None):
        """Open an RFC 9220 Extended CONNECT WebSocket; returns an H3Ws tunnel."""
        sid = self.c._quic.get_next_available_stream_id()
        q = asyncio.Queue()
        self.c._queues[sid] = q
        h = [(b":method", b"CONNECT"), (b":scheme", b"https"),
             (b":authority", self.c.authority.encode()), (b":path", path.encode()),
             (b":protocol", b"websocket"), (b"sec-websocket-version", b"13")]
        if subprotocols:
            h.append((b"sec-websocket-protocol", ", ".join(subprotocols).encode()))
        self.c._http.send_headers(sid, h, end_stream=False)
        self.c.transmit()
        status = None
        while status is None:
            kind, val = await q.get()
            if kind == "h": status = val[0]         # (status, enc); enc unused
            elif kind == "err":
                self.c._queues.pop(sid, None); raise ConnectionError(val)
            elif kind == "end": raise ConnectionError("ws CONNECT stream ended")
        return H3Ws(self.c, sid, q, status)


class H3Ws:
    """A WebSocket tunnel over one Extended CONNECT h3 stream (client-masked)."""
    def __init__(self, client, sid, q, status):
        self.c, self.sid, self.q, self.status = client, sid, q, status
        self._buf = bytearray()

    def send(self, opcode, payload: bytes):
        self.c._http.send_data(self.sid, ws_frame(opcode, payload), end_stream=False)
        self.c.transmit()

    async def recv(self):
        """Return the next (opcode, payload) frame from the server."""
        while True:
            frames, consumed = parse_ws(self._buf)
            if frames:
                del self._buf[:consumed]
                return frames[0]
            kind, val = await self.q.get()
            if kind == "d": self._buf += val
            elif kind == "err": raise ConnectionError(val)
            elif kind == "end": raise ConnectionError("ws stream ended")

    def close(self):
        self.c._queues.pop(self.sid, None)


@asynccontextmanager
async def connect_h3(host: str, port: int):
    # ALPN is locked to h3 only: QUIC/h3 is a different transport from TCP h1/h2,
    # so there is no path to fall back to h2 here. We still assert h3 was actually
    # negotiated (H3Client builds `_http` only on an "h3" ProtocolNegotiated), so
    # a server that somehow completed the handshake without agreeing on h3 fails
    # loud instead of silently sending requests that never get a reply.
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE                # self-signed stress cert
    async with connect(host, port, configuration=cfg, create_protocol=H3Client) as client:
        await client.wait_connected()
        if client._http is None:
            raise ProtocolPinError("h3 was not negotiated (ALPN mismatch); "
                                   "no fallback allowed for VORTEX_PROTO=h3")
        client.authority = f"{host}:{port}"
        yield H3Session(client)
