# h3spec client image: the prebuilt Linux binary from kazu-yamamoto/h3spec.
# Run by conformance/h3spec/run.sh against the vortex HTTP/3 server container.
# Pinned to a release; the binary is x86_64, so the image is amd64 (native on
# x86 CI runners, emulated elsewhere).
FROM --platform=linux/amd64 debian:stable-slim

ARG H3SPEC_VERSION=v0.1.13
ADD https://github.com/kazu-yamamoto/h3spec/releases/download/${H3SPEC_VERSION}/h3spec-linux-x86_64 /usr/local/bin/h3spec
RUN chmod +x /usr/local/bin/h3spec

# Only the HTTP/3-server group is vortex's responsibility; the QUIC transport
# group is OpenSSL's QUIC stack. --no-validate: the server uses a self-signed
# cert.
CMD ["h3spec", "-n", "-m", "HTTP/3 servers", "server", "4433"]
