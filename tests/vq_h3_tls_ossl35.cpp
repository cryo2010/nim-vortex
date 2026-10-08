// Regression harness for #398: the ngtcp2 shim has to compile, and still apply
// server cipher preference, against OpenSSL 3.5-shaped headers.
//
// The shim reads the option name SSL_OP_SERVER_PREFERENCE out of
// <openssl/ssl.h>. That name arrived in OpenSSL 3.6.0; 3.5, which README.md,
// HARDENING.md and CONTRIBUTING.md all give as the project minimum, defines
// only SSL_OP_CIPHER_SERVER_PREFERENCE for the same SSL_OP_BIT(22). So this
// translation unit did not build on the documented minimum at all, which is a
// failure nobody saw locally: vortex's own Arch-based images carry a newer
// OpenSSL, and nim-navi's stress image had to paper over it with
// `--passC:-DSSL_OP_SERVER_PREFERENCE=SSL_OP_CIPHER_SERVER_PREFERENCE`.
//
// There is no 3.5 header on a CI runner that has 3.6, so this suite makes the
// headers look like 3.5's below and then compiles the shim against them. The
// shim's own fallback define is what makes that work, so reverting it turns
// this file into a compile error naming SSL_OP_SERVER_PREFERENCE.
//
// Including the shim's translation unit also defines its extern "C" ABI, so
// this is a SEPARATE binary from tests/test_h3_tls_ctx.nim: two TUs including
// the shim in one link would be duplicate symbols.
#include <openssl/ssl.h>

// OpenSSL 3.5's <openssl/ssl.h> offers exactly one spelling of the bit:
//
//   #define SSL_OP_CIPHER_SERVER_PREFERENCE SSL_OP_BIT(22)
//
// 3.6 instead defines the new name to SSL_OP_BIT(22) and the old name to the
// new one, so undefining only the new name would leave the old one expanding
// to an identifier that no longer exists. Both have to go, and the old one is
// then written back the way 3.5 writes it.
#undef SSL_OP_SERVER_PREFERENCE
#undef SSL_OP_CIPHER_SERVER_PREFERENCE
#define SSL_OP_CIPHER_SERVER_PREFERENCE SSL_OP_BIT(22)

#include "vq_ngtcp2.cpp"   // NOLINT: deliberate, see above

// Whatever name the shim's fallback picked up, it has to be the same bit. The
// value is spelled out rather than taken from a macro so this still means
// something if a later OpenSSL renames the option again.
static_assert(SSL_OP_SERVER_PREFERENCE == 0x00400000ULL,
              "SSL_OP_SERVER_PREFERENCE must be SSL_OP_BIT(22)");

extern "C" {

// Build the shim's QUIC server context from in-memory PEM material, the way
// makeCtx does for a real engine, and report whether the option word it ends up
// with carries SSL_OP_BIT(22): 1 yes, 0 no, -1 if the context could not be
// built at all (so a bad fixture is not read as a lost option).
//
// Compiling is half of the regression; this is the other half. A fallback that
// resolved to the wrong bit, or an #ifndef placed where the shim never sees it,
// would still compile and would still leave QUIC following the client's
// ciphersuite order (#375).
int vq_test_ossl35_server_pref(const char *cert_pem, const char *key_pem) {
  VqConfig cfg{};
  cfg.cert_pem = cert_pem;
  cfg.key_pem = key_pem;
  std::string err;
  SslCtxPtr ctx = makeCtx(&cfg, &err);
  if (!ctx) return -1;
  return (SSL_CTX_get_options(ctx.get()) & 0x00400000ULL) ? 1 : 0;
}

}   // extern "C"
