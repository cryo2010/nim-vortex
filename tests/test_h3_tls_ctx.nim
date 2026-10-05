## White-box tests for the QUIC TLS context the ngtcp2 shim builds.
##
## These cover invariants no HTTP/3 client can observe: how many times the
## ngtcp2 ossl backend was initialized (#357). The harness
## tests/vq_h3_tls_ctx.cpp compiles the shim's own translation unit to reach its
## internals, so this suite must NOT import the vortex h3 backend -- the shim's
## extern "C" ABI is linked exactly once here.

import std/[unittest, os]

when not defined(plainHttp):
  {.passC: "-I" & currentSourcePath().parentDir.parentDir /
           "src/vortex/http3/ngtcp2".}
  {.passL: "-lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto -lstdc++".}
  {.compile: "vq_h3_tls_ctx.cpp".}

  proc vqTestOsslInitRuns(): cint {.importc: "vq_test_ossl_init_runs", cdecl.}
  proc vqTestOsslInitOk(): cint {.importc: "vq_test_ossl_init_ok", cdecl.}

  suite "ngtcp2 ossl backend initialization (#357)":
    test "the backend initializes successfully":
      check vqTestOsslInitOk() == 1

    test "concurrent engine creation initializes the backend exactly once":
      # ngtcp2_crypto_ossl_init allocates an OpenSSL ex_data index into a
      # library global and is not thread safe, but vq_engine_new runs on every
      # loop thread. Calling it per engine leaked an index per extra loop and
      # left a window where a session configured under one index was read back
      # under another: a null crypto context and a failed handshake, only at
      # startup and only under a thread race. There is no way to provoke that
      # race from a client, so the invariant itself is what is pinned here.
      check vqTestOsslInitRuns() == 1
