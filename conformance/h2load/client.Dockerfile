# h2load client image: nghttp2's load tester. Run by conformance/h2load/run.sh
# against the vortex server container over a private docker network.
FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends nghttp2-client && \
    rm -rf /var/lib/apt/lists/*
