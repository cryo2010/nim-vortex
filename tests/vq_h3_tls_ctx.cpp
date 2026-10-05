// Test harness for the shim's TLS-context plumbing: the once-per-process
// ngtcp2 ossl initializer (#357).
//
// None of this is reachable through a QUIC client: the initializer runs before
// the first engine exists. Including the shim's translation unit gives access
// to its internals, the same trick tests/vq_h3_malformed.cpp uses. This file is
// compiled ONLY by tests/test_h3_tls_ctx.nim, which does not import the vortex
// h3 backend, so the shim's extern "C" ABI is defined exactly once in that
// binary.
#include "vq_ngtcp2.cpp"   // NOLINT: deliberate, see above

#include <thread>
#include <vector>

extern "C" {

// Hammer osslInitOnce from several threads at once (what newLoop does on a
// numThreads > 1 server) and report how many times the underlying
// ngtcp2_crypto_ossl_init actually ran. Must be 1.
int vq_test_ossl_init_runs(void) {
  std::vector<std::thread> t;
  for (int i = 0; i < 8; i++) t.emplace_back([] { (void)osslInitOnce(); });
  for (auto &x : t) x.join();
  return gOsslInitRuns;
}

// Whether the shared initializer succeeded (so a 0-run count can be told apart
// from a backend that refused to initialize at all).
int vq_test_ossl_init_ok(void) { return osslInitOnce() ? 1 : 0; }

}  // extern "C"
