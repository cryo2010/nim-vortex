# Python load client for the vortex stress soaks (conformance/stress/run.sh).
# httpx drives h1/h2 (requests + streaming), websockets drives /ws; brotli/
# zstandard let httpx decode br/zstd responses and the client compress br/zstd
# request bodies. Built from the repository root so it can COPY the client.
FROM python:3.12-slim

RUN pip install --no-cache-dir "httpx[http2]" websockets brotli zstandard

WORKDIR /client
COPY conformance/stress/client/stress_client.py ./stress_client.py

CMD ["python", "stress_client.py"]
