# aioquic (RFC 9220-capable) HTTP/3 WebSocket conformance client. Run by
# conformance/h3websocket/run.sh against the vortex echo server container.
FROM python:3.12-slim

RUN pip install --no-cache-dir "aioquic>=1.0.0"

WORKDIR /client
COPY conformance/h3websocket/client.py ./client.py

CMD ["python", "client.py", "--host", "server", "--port", "4433"]
