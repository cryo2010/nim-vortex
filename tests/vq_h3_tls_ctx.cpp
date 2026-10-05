// Test harness for the shim's TLS-context plumbing: the once-per-process
// ngtcp2 ossl initializer (#357) and the certificate chain a reload installs
// (#354).
//
// None of this is reachable through a QUIC client: the initializer runs before
// the first engine exists, and the served chain length is not something curl
// reports. Including the shim's translation unit gives access to its internals,
// the same trick tests/vq_h3_malformed.cpp uses. This file is compiled ONLY by
// tests/test_h3_tls_ctx.nim, which does not import the vortex h3 backend, so
// the shim's extern "C" ABI is defined exactly once in that binary.
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

// --- #354: the chain a repeated load leaves behind -------------------------
//
// Load `pem` (leaf + intermediates) into one context `times` times, as an
// in-place certificate reload used to, and report how many chain certificates
// the context ends up sending. Returns -1 if a load failed.

static int chainLen(SSL_CTX *ctx) {
  STACK_OF(X509) *chain = nullptr;
  if (SSL_CTX_get0_chain_certs(ctx, &chain) != 1) return -1;
  return chain ? sk_X509_num(chain) : 0;
}

int vq_test_chain_len_after_loads(const char *pem, int times) {
  SslCtxPtr ctx(SSL_CTX_new(TLS_server_method()));
  if (!ctx) return -1;
  for (int i = 0; i < times; i++)
    if (!loadCertChain(ctx.get(), pem)) return -1;
  return chainLen(ctx.get());
}

// Same for a PKCS#12 bundle, whose CA certificates go in through
// SSL_CTX_add1_chain_cert and accumulated the same way.
int vq_test_p12_chain_len_after_loads(const uint8_t *der, size_t len,
                                     const char *pw, int times) {
  SslCtxPtr ctx(SSL_CTX_new(TLS_server_method()));
  if (!ctx) return -1;
  for (int i = 0; i < times; i++)
    if (!loadPkcs12(ctx.get(), der, len, nullptr, pw)) return -1;
  return chainLen(ctx.get());
}

}  // extern "C"
