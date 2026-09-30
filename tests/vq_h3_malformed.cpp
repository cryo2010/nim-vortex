// Test harness for #362: a connection error from nghttp3 must be terminal.
//
// There is no in-process QUIC client in the tree (the aioquic harnesses in
// conformance/ need docker), and a malformed HTTP/3 frame sequence cannot be
// produced with curl, so this drives the shim's own recv_stream_data callback
// instead of a real datagram. That is exactly the path the bug lives on:
// cbRecvStreamData needs no ngtcp2_conn on the error path (it only touches
// c->h3 and, on success, the flow-control extends), so the two STREAM frames of
// one hostile datagram can be replayed as two back-to-back callback calls.
//
// Including the shim's translation unit gives access to its internals (the
// anonymous namespace). This file is compiled ONLY by tests/test_http3_malformed
// .nim, which does not import the vortex h3 backend, so the shim's extern "C"
// ABI is defined exactly once in that binary.
#include "vq_ngtcp2.cpp"   // NOLINT: deliberate, see above

namespace {

// A request stream that opens with DATA (type 0x00, length 5, "hello") instead
// of HEADERS: RFC 9114 4.1 requires HEADERS first, so nghttp3 fails the
// CONNECTION with H3_FRAME_UNEXPECTED.
const uint8_t kDataBeforeHeaders[] = {0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};

}  // namespace

extern "C" {

// Returns a bitmask of observations (see tests/test_http3_malformed.nim), or a
// negative value if the harness itself could not be set up.
int vq_test_malformed_h3(void) {
  Engine e;
  Conn c;
  c.engine = &e;

  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  static const nghttp3_callbacks cbs{};   // no callbacks: nothing to deliver
  if (nghttp3_conn_server_new(&c.h3, &cbs, &settings, nullptr, &c) != 0)
    return -1;

  int result = 0;

  // Frame 1: the malformed request stream. cbRecvStreamData must report the
  // failure to ngtcp2 so it stops parsing the datagram.
  int rv = cbRecvStreamData(nullptr, 0, 0, 0, kDataBeforeHeaders,
                            sizeof kDataBeforeHeaders, &c, nullptr);
  if (rv != 0) result |= 1;
  if (rv == NGTCP2_ERR_CALLBACK_FAILURE) result |= 2;
  if (c.h3 == nullptr) result |= 4;                 // the fix for #362
  if (c.wantClose) result |= 8;
  if (c.ccerr.type == NGTCP2_CCERR_TYPE_APPLICATION &&
      c.ccerr.error_code == NGHTTP3_H3_FRAME_UNEXPECTED)
    result |= 16;

  // Frame 2 of the same datagram, on another stream. Before the fix this
  // re-entered nghttp3_conn_read_stream on the poisoned connection (undefined
  // behavior); it must now be a no-op.
  const uint8_t more[] = {'x'};
  int rv2 = cbRecvStreamData(nullptr, 0, 4, 0, more, sizeof more, &c, nullptr);
  if (rv2 == 0 && c.h3 == nullptr) result |= 32;

  return result;   // ~Conn tolerates h3 == nullptr (no double nghttp3_conn_del)
}

}  // extern "C"
