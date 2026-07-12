# Builds the vortex WebSocket echo server under test for the Autobahn
# conformance run. conformance/autobahn/run.sh (or `nimble autobahn`)
# starts this alongside the crossbario/autobahn-testsuite fuzzingclient on
# a private docker network.
#
# Built from the repository root by run.sh; the base defaults to arm64 and
# is overridden to archlinux:latest on x86_64 hosts.

ARG BASE=menci/archlinuxarm:latest
FROM ${BASE}

RUN pacman -Syu --noconfirm --needed --disable-sandbox \
      nim gcc openssl zlib && \
    pacman -Scc --noconfirm

WORKDIR /vortex
COPY src ./src
COPY conformance/autobahn/echo_server.nim ./echo_server.nim
# -d:wsDeflate + zlib so the permessage-deflate cases (12-13) are covered.
RUN nim c --mm:orc --threads:on -d:release -d:wsDeflate --passL:-lz -p:src \
      -o:echo_server echo_server.nim

EXPOSE 9001
CMD ["./echo_server"]
