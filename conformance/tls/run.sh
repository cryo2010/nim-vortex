#!/usr/bin/env bash
# Build the per-configuration TLS harness once, then run each TLS configuration
# (each starts a real HTTPS server and makes a request). Used by the `tls` CI job
# (which builds once and runs one config per step) and runnable locally:
#
#   bash conformance/tls/run.sh                 # build + run all configs
#   bash conformance/tls/run.sh sni ocspFile    # only these
#   TLS_CONFIG=clientCaPem bash conformance/tls/run.sh   # a single config
#
# Needs curl + openssl on PATH. These are TCP/OpenSSL config checks; h3 material
# is covered by tests/test_tls_h3_material.nim.
set -uo pipefail

cd "$(dirname "$0")/../.."          # repo root
BIN=/tmp/tls_harness

# macOS: the TLS/QUIC deps live under Homebrew, which the compiler does not
# search by default. On Linux (CI) these dirs don't exist, so extra stays empty.
extra=()
if [ "$(uname -s)" = "Darwin" ]; then
  for inc in /opt/homebrew/include /usr/local/include; do
    [ -d "$inc" ] && extra+=("--passC:-I$inc")
  done
  for lib in /opt/homebrew/lib /usr/local/lib; do
    [ -d "$lib" ] && extra+=("--passL:-L$lib")
  done
  if ssl=$(brew --prefix openssl@3 2>/dev/null) && [ -d "$ssl" ]; then
    extra+=("--passC:-I$ssl/include" "--passL:-L$ssl/lib")
  fi
fi

if [ "${SKIP_BUILD:-}" != 1 ]; then
  echo "== building TLS config harness =="
  nim c --mm:orc --threads:on -p:src --hints:off \
    ${extra[@]+"${extra[@]}"} -o:"$BIN" conformance/tls/harness.nim
fi

# Which configs to run: $TLS_CONFIG, else CLI args, else all.
configs=(certFile certPem pkcs12File verifyClient clientCaFile clientCaPem sni
         minTlsVersion maxTlsVersion ocspFile ocspResponse tlsCipherSuites
         tlsCipherList hotReload)
if [ -n "${TLS_CONFIG:-}" ]; then
  configs=("$TLS_CONFIG")
elif [ "$#" -ge 1 ]; then
  configs=("$@")
fi

rc=0
for c in "${configs[@]}"; do
  if ! TLS_CONFIG="$c" "$BIN"; then
    echo "FAIL: $c"; rc=1
  fi
done
exit $rc
