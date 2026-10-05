# Python load client for the vortex stress soaks (conformance/stress/run.sh).
# httpx drives h1/h2 (requests + streaming), websockets drives /ws, and aioquic
# drives HTTP/3; brotli/zstandard let httpx decode br/zstd responses and the
# client compress br/zstd request bodies. Built from the repository root.
FROM python:3.12-slim

# Pinned, not floating. A soak is a measurement, and an unpinned client silently
# changes the thing being measured: #390 was a teardown race inside
# httpcore/anyio that failed a cell roughly one run in three, and reproducing it
# at all meant knowing which versions the image had resolved to that day. These
# are what `pip install "httpx[http2]" websockets brotli zstandard
# "aioquic>=1.0.0"` resolved to on 2026-10-05; httpcore/anyio/h2 are pulled in by
# httpx but pinned here too, since they are the stack the race lives in. Bump
# them deliberately (and re-run the soaks), never by rebuilding.
RUN pip install --no-cache-dir \
      "httpx[http2]==0.28.1" \
      "httpcore==1.0.9" \
      "anyio==4.15.1" \
      "h2==4.4.1" \
      "websockets==17.2" \
      "brotli==1.2.0" \
      "zstandard==0.25.0" \
      "aioquic==1.3.0"

WORKDIR /client
COPY conformance/stress/client/transport.py ./transport.py
COPY conformance/stress/client/stress_client.py ./stress_client.py
COPY conformance/stress/client/h3.py ./h3.py
COPY conformance/stress/client/chaos.py ./chaos.py

CMD ["python", "stress_client.py"]
