"""Minimal aioquic-based HTTP/3 client for the stress soaks.

httpx has no HTTP/3, so the h3 cells drive the vortex QUIC listener with aioquic
(the reference Python QUIC/h3 stack, as conformance/h3websocket already uses).
`H3Session` exposes the same shape the httpx path uses - request / stream (a
generator whose first item is the status, then body chunks) / upload - so the
workloads are transport-agnostic. One QUIC connection multiplexes many streams.
"""
import asyncio, ssl
from contextlib import asynccontextmanager

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated


class H3Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._http = None
        self._queues = {}          # stream_id -> asyncio.Queue of (kind, value)
        self.authority = ""

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol.startswith("h3"):
            self._http = H3Connection(self._quic)
        if self._http is not None:
            for e in self._http.handle_event(event):
                self._on_h3(e)

    def _on_h3(self, e):
        q = self._queues.get(e.stream_id)
        if q is None:
            return
        if isinstance(e, HeadersReceived):
            status = 0
            for k, v in e.headers:
                if k == b":status":
                    status = int(v)
            q.put_nowait(("h", status))
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
        status, body = 0, bytearray()
        while True:
            kind, val = await q.get()
            if kind == "h": status = val
            elif kind == "d": body += val
            else: break
        self.c._queues.pop(sid, None)
        return status, bytes(body)

    async def get(self, path, headers=None):
        return await self.request("GET", path, headers)

    async def stream(self, method, path, headers=None):
        """Async generator: first item is the status (int), then body chunks."""
        sid, q = self.c._open(method, path, headers or {}, end=True)
        try:
            while True:
                kind, val = await q.get()
                if kind == "h": yield val
                elif kind == "d": yield val
                else: break
        finally:
            self.c._queues.pop(sid, None)

    async def upload(self, path, headers, body_agen):
        sid, q = self.c._open("POST", path, headers or {}, end=False)
        async for chunk in body_agen:
            self.c._http.send_data(sid, chunk, end_stream=False)
            self.c.transmit()
            await asyncio.sleep(0)             # let QUIC flush under flow control
        self.c._http.send_data(sid, b"", end_stream=True)
        self.c.transmit()
        status = 0
        while True:
            kind, val = await q.get()
            if kind == "h": status = val
            elif kind == "end": break
        self.c._queues.pop(sid, None)
        return status


@asynccontextmanager
async def connect_h3(host: str, port: int):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE                # self-signed stress cert
    async with connect(host, port, configuration=cfg, create_protocol=H3Client) as client:
        await client.wait_connected()
        client.authority = f"{host}:{port}"
        yield H3Session(client)
