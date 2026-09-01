# Python load client for the vortex perf benches (conformance/bench/run.sh).
# Same transport as the stress client (httpx h1/h2, websockets /ws, aioquic h3),
# reused via the shared transport module; only the workload/reporting differ
# (throughput + latency instead of correctness). Built from the repository root.
FROM python:3.12-slim

RUN pip install --no-cache-dir "httpx[http2]" websockets brotli zstandard "aioquic>=1.0.0"

WORKDIR /client
# Shared transport + h3 come from the stress client dir (single source of truth).
COPY conformance/stress/client/transport.py ./transport.py
COPY conformance/stress/client/h3.py ./h3.py
COPY conformance/bench/client/bench_client.py ./bench_client.py

CMD ["python", "bench_client.py"]
