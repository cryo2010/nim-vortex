"""RFC 9220 WebSocket-over-HTTP/3 conformance client for the vortex server.

Opens an Extended CONNECT WebSocket on a QUIC stream via aioquic's H3
connection, then exchanges WebSocket frames (hand-rolled framing, so the test
owns exactly what goes on the wire) and asserts the echo server's replies.
Exits 0 on success, non-zero on any mismatch or timeout.
"""

import argparse
import asyncio
import ssl
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x2, 0x8, 0x9, 0xA
MASK = b"\x21\x43\x65\x87"


def ws_frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    assert len(payload) < 126
    out = bytearray()
    out.append((0x80 if fin else 0) | opcode)
    out.append(0x80 | len(payload))                 # mask bit + 7-bit length
    out += MASK
    out += bytes(payload[i] ^ MASK[i % 4] for i in range(len(payload)))
    return bytes(out)


def parse_ws(buf: bytearray):
    """Return (frames, consumed): complete server (unmasked) WS frames."""
    frames = []
    pos = 0
    while pos + 2 <= len(buf):
        b0, b1 = buf[pos], buf[pos + 1]
        assert (b1 & 0x80) == 0, "server frame must be unmasked"
        ln, hdr = b1 & 0x7f, 2
        if ln == 126:
            if pos + 4 > len(buf):
                break
            ln = (buf[pos + 2] << 8) | buf[pos + 3]
            hdr = 4
        if pos + hdr + ln > len(buf):
            break
        frames.append((b0 & 0x0f, bytes(buf[pos + hdr:pos + hdr + ln])))
        pos += hdr + ln
    return frames, pos


class WsClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._sid = None
        self._status = None
        self._data = bytearray()
        self._got_headers = asyncio.Event()
        self._got_data = asyncio.Event()

    def quic_event_received(self, event):
        if self._http is None:
            self._http = H3Connection(self._quic)
        for e in self._http.handle_event(event):
            if isinstance(e, HeadersReceived) and e.stream_id == self._sid:
                for k, v in e.headers:
                    if k == b":status":
                        self._status = v.decode()
                self._got_headers.set()
            elif isinstance(e, DataReceived) and e.stream_id == self._sid:
                self._data += e.data
                self._got_data.set()

    async def open_ws(self, authority, path="/", subprotocols=None):
        if self._http is None:
            self._http = H3Connection(self._quic)
        self._sid = self._quic.get_next_available_stream_id()
        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
            (b":protocol", b"websocket"),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append(
                (b"sec-websocket-protocol", ", ".join(subprotocols).encode()))
        self._http.send_headers(self._sid, headers, end_stream=False)
        self.transmit()
        await asyncio.wait_for(self._got_headers.wait(), timeout=5)
        return self._status

    def send_raw(self, data: bytes):
        self._http.send_data(self._sid, data, end_stream=False)
        self.transmit()

    def send_ws(self, opcode, payload, fin=True):
        self.send_raw(ws_frame(opcode, payload, fin))

    async def recv_ws(self, want=1, timeout=5):
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            frames, consumed = parse_ws(self._data)
            if len(frames) >= want:
                del self._data[:consumed]
                return frames
            self._got_data.clear()
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError(f"recv_ws: got {len(frames)}/{want}")
            await asyncio.wait_for(self._got_data.wait(), timeout=remaining)


async def run(host, port):
    config = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
    config.verify_mode = ssl.CERT_NONE
    async with connect(host, port, configuration=config,
                       create_protocol=WsClient) as client:
        status = await client.open_ws("server", "/", ["chat", "json"])
        assert status == "200", f"handshake status {status!r}"
        print("handshake 200 OK")

        client.send_ws(OP_TEXT, b"hello")
        assert (await client.recv_ws())[0] == (OP_TEXT, b"hello"), "text echo"
        print("text echo OK")

        client.send_ws(OP_BINARY, b"\x00\x01\x02\xff")
        assert (await client.recv_ws())[0] == (OP_BINARY, b"\x00\x01\x02\xff"), \
            "binary echo"
        print("binary echo OK")

        client.send_ws(OP_PING, b"pingpayload")
        fr = (await client.recv_ws())[0]
        assert fr == (OP_PONG, b"pingpayload"), f"ping/pong: {fr}"
        print("ping/pong OK")

        client.send_ws(OP_TEXT, b"proto?")
        assert (await client.recv_ws())[0] == (OP_TEXT, b"chat"), "subprotocol"
        print("subprotocol OK")

        # fragmented text: "Hel" (fin=0) + continuation "lo!" (fin=1)
        client.send_raw(ws_frame(OP_TEXT, b"Hel", fin=False) +
                        ws_frame(0x0, b"lo!", fin=True))
        assert (await client.recv_ws())[0] == (OP_TEXT, b"Hello!"), "fragmented"
        print("fragmented message OK")

        client.send_ws(OP_CLOSE, b"\x03\xe8")           # close, code 1000
        fr = (await client.recv_ws())[0]
        assert fr[0] == OP_CLOSE, f"close echo: {fr}"
        print("close handshake OK")

    print("RESULT: all HTTP/3 WebSocket cases passed.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="server")
    ap.add_argument("--port", type=int, default=4433)
    args = ap.parse_args()
    try:
        asyncio.run(run(args.host, args.port))
    except Exception as exc:                            # noqa: BLE001
        print(f"RESULT: FAILED: {exc!r}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
