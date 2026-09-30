## Regression test for #362: an HTTP/3 connection error must be terminal for
## nghttp3 before control returns to ngtcp2.
##
## nghttp3 documents that once nghttp3_conn_read_stream returns a negative code
## the connection is in error and "calling nghttp3 API other than
## nghttp3_conn_del causes undefined behavior". The shim used to only schedule a
## CONNECTION_CLOSE and return 0, so ngtcp2 kept decoding the rest of the
## datagram and every further STREAM frame, stream close, ack and window update
## re-entered the poisoned nghttp3_conn: a remotely triggerable crash of the
## whole loop thread from one hostile datagram.
##
## A real client cannot drive this (curl will not emit a malformed HTTP/3 frame
## sequence, and the aioquic harnesses in conformance/ need docker), so the two
## STREAM frames of the hostile datagram are replayed straight into the shim's
## recv_stream_data callback by tests/vq_h3_malformed.cpp, which compiles the
## shim's translation unit to reach its internals. This suite does NOT import
## the vortex h3 backend, so that TU is linked exactly once here.

import std/[unittest, os]

when not defined(plainHttp):
  {.passC: "-I" & currentSourcePath().parentDir.parentDir /
           "src/vortex/http3/ngtcp2".}
  {.passL: "-lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto -lstdc++".}
  {.compile: "vq_h3_malformed.cpp".}

  proc vqTestMalformedH3(): cint {.importc: "vq_test_malformed_h3", cdecl.}

  # Bits reported by the harness.
  const
    bitReported = 1      ## the callback told ngtcp2 the read failed
    bitCallbackFail = 2  ## ... specifically with NGTCP2_ERR_CALLBACK_FAILURE
    bitH3Deleted = 4     ## the nghttp3_conn was deleted (the fix)
    bitWantClose = 8     ## a CONNECTION_CLOSE was scheduled
    bitAppError = 16     ## ... carrying the HTTP/3 application error code
    bitSecondNoop = 32   ## the next STREAM frame of the datagram was a no-op

  suite "HTTP/3 malformed frame sequence (#362)":
    let rv = vqTestMalformedH3()

    test "the harness set up an nghttp3 connection":
      check rv >= 0

    test "a malformed request stream is reported to ngtcp2 as a failure":
      # Returning 0 (the old behaviour) let ngtcp2_conn_read_pkt keep decoding
      # the remaining frames of the same packet and the packets coalesced behind
      # it, all of them calling back into nghttp3.
      check (rv and bitReported) != 0
      check (rv and bitCallbackFail) != 0

    test "the poisoned nghttp3 connection is deleted, not left reachable":
      check (rv and bitH3Deleted) != 0

    test "the connection still closes with the HTTP/3 error code":
      check (rv and bitWantClose) != 0
      check (rv and bitAppError) != 0

    test "a second STREAM frame in the same datagram is a no-op":
      check (rv and bitSecondNoop) != 0
