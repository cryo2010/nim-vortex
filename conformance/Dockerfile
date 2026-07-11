# Runs the REDbot HTTP conformance check against vortex in a container,
# so you do not need Nim or a Python REDbot install on the host.
#
# Build from the repository root:
#   docker build -f conformance/Dockerfile -t vortex-redbot .
# On x86_64 hosts use the official Arch image instead of the arm64 one:
#   docker build -f conformance/Dockerfile -t vortex-redbot \
#     --build-arg BASE=archlinux:latest .
# Run (exits non-zero if REDbot reports a BAD-level finding):
#   docker run --rm vortex-redbot                # checks / and /json
#   docker run --rm vortex-redbot /json          # a specific path

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

# nim/gcc build the server under test; openssl is vortex's TLS/h2/h3
# dependency; curl is the readiness probe; python + git install REDbot.
# --disable-sandbox: pacman's Landlock sandbox cannot apply in a container.
RUN pacman -Syu --noconfirm --needed --disable-sandbox \
      nim gcc git curl openssl python && \
    pacman -Scc --noconfirm

# mnot's REDbot (the HTTP checker) from git into an isolated venv: the
# PyPI name `redbot` is a different project, and the venv gives run.sh
# both the `redbot` command and a `python3` (for the colour-forcing pty).
RUN python -m venv /opt/redbot && \
    /opt/redbot/bin/pip install --no-cache-dir \
      "git+https://github.com/mnot/redbot.git"
ENV PATH="/opt/redbot/bin:${PATH}"

WORKDIR /vortex
COPY src ./src
COPY conformance ./conformance

# Warm the Nim cache (and fail the build early on a compile error);
# run.sh rebuilds incrementally at runtime.
RUN nim c --mm:orc --threads:on -d:release \
      -o:conformance/redbot_server conformance/redbot_server.nim

ENTRYPOINT ["sh", "conformance/run.sh"]
