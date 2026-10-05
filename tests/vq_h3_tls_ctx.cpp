// Test harness for the shim's TLS-context plumbing: the once-per-process
// ngtcp2 ossl initializer (#357), the certificate chain a reload installs
// (#354) and what a refused reload leaves the engine serving (#352).
//
// None of this is reachable through a QUIC client: the initializer runs before
// the first engine exists, the served chain length is not something curl
// reports, and the reloads that fail on the QUIC side alone are the ones the
// TCP-side validation in server.reloadTls rejects before it ever signals the
// loops. Including the shim's translation unit gives access to its internals,
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

// --- #352 / #353: what a reload installs, and what a refused one leaves ---
//
// An engine built from any of the material sources VqConfig accepts, with an
// optional single per-host (SNI) certificate read from files so the per-host
// rebuild can be driven too. The caller then reloads it through the real
// vq_engine_reload_cert ABI and asks what the engine is left with.

VqEngine *vq_test_engine_new(const char *cert_file, const char *key_file,
                             const char *cert_pem, const char *key_pem,
                             const char *pkcs12_file, const char *key_password,
                             const char *host, const char *host_cert_file,
                             const char *host_key_file) {
  VqConfig cfg{};
  cfg.cert_file = cert_file;
  cfg.key_file = key_file;
  cfg.cert_pem = cert_pem;
  cfg.key_pem = key_pem;
  cfg.pkcs12_file = pkcs12_file;
  cfg.key_password = key_password;
  VqSniCert sc{};
  if (host && host[0]) {
    sc.host = host;
    sc.cert_file = host_cert_file;
    sc.key_file = host_key_file;
    cfg.sni = &sc;
    cfg.sni_len = 1;
  }
  return vq_engine_new(&cfg);
}

// 1 when the engine's default context holds a certificate AND a private key
// that matches it, i.e. when an h3 handshake on this loop can still succeed.
// The pre-#352 in-place reload left this at 0 for good after one bad reload.
int vq_test_engine_usable(VqEngine *eng) {
  auto *e = reinterpret_cast<Engine *>(eng);
  const int ok = SSL_CTX_check_private_key(e->ssl_ctx.get()) == 1 ? 1 : 0;
  ERR_clear_error();
  return ok;
}

static void subjectOf(SSL_CTX *ctx, char *buf, size_t len) {
  X509 *x = ctx ? SSL_CTX_get0_certificate(ctx) : nullptr;
  if (!x) { snprintf(buf, len, "(none)"); return; }
  buf[0] = '\0';
  X509_NAME_oneline(X509_get_subject_name(x), buf, static_cast<int>(len));
}

// The subject of the certificate the default context currently serves.
void vq_test_engine_subject(VqEngine *eng, char *buf, size_t len) {
  subjectOf(reinterpret_cast<Engine *>(eng)->ssl_ctx.get(), buf, len);
}

// ... and of the first per-host context, "(none)" if there is none.
void vq_test_engine_host_subject(VqEngine *eng, char *buf, size_t len) {
  auto *e = reinterpret_cast<Engine *>(eng);
  subjectOf(e->sni_ctx.empty() ? nullptr : e->sni_ctx[0].get(), buf, len);
}

}  // extern "C"
