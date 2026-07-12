# h1spec client image: dropseed/h1spec (an HTTP/1.1 conformance tester in
# the spirit of h2spec, RFC 9112/9110). Run by conformance/h1spec/run.sh
# against the vortex server container. Pinned to a commit for reproducibility.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

ARG H1SPEC_REF=d8f69184825d3eedd649843a545c957f3fccac06
RUN pip install --no-cache-dir \
      "h1spec @ git+https://github.com/dropseed/h1spec@${H1SPEC_REF}"

# Runs all sections including the hardening checks; h1spec exits non-zero on
# any failing case.
CMD ["h1spec", "server:8080"]
