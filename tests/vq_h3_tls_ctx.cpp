// Test harness for the shim's TLS-context plumbing: the once-per-process
// ngtcp2 ossl initializer (#357), the certificate chain a reload installs
// (#354), what a refused reload leaves the engine serving (#352, #353, #379)
// and the process-wide session-ticket key (#382).
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

// --- #356: a reload that REPLACES the per-host set -------------------------
//
// reloadTls(sni = ...) reached the TCP listener alone: the loops were signalled
// with the cert/key paths only and rebuilt their host contexts from the
// material vq_engine_new was given, so a host added through the override was
// served the DEFAULT certificate over h3 (the #374 bug again, for any host
// configured after startup) and one removed from it kept being served over h3
// for the life of the process.
//
// `h1` comes from files, `h2` from in-memory PEM, so both material sources in a
// replacement set are driven. An empty host skips that entry; no entries at all
// means "keep the configured material". Returns the real ABI's return code.
int vq_test_reload_with_sni(VqEngine *eng, const char *cert_file,
                            const char *key_file, const char *h1,
                            const char *c1, const char *k1, const char *h2,
                            const char *p2, const char *pk2) {
  VqSniCert sc[2]{};
  size_t n = 0;
  if (h1 && h1[0]) {
    sc[n].host = h1;
    sc[n].cert_file = c1;
    sc[n].key_file = k1;
    ++n;
  }
  if (h2 && h2[0]) {
    sc[n].host = h2;
    sc[n].cert_pem = p2;
    sc[n].key_pem = pk2;
    ++n;
  }
  return vq_engine_reload_cert(eng, cert_file, key_file, n ? sc : nullptr, n);
}

// How many per-host contexts the engine holds.
int vq_test_engine_host_count(VqEngine *eng) {
  return static_cast<int>(reinterpret_cast<Engine *>(eng)->sni.size());
}

// The subject the engine serves for the SNI name `name`, chosen exactly as
// servernameCb chooses it: the per-host context whose host matches (exact over
// wildcard), else the default one. The white-box view of what an h3 client
// asking for that name is handed.
void vq_test_sni_subject(VqEngine *eng, const char *name, char *buf,
                         size_t len) {
  auto *e = reinterpret_cast<Engine *>(eng);
  SSL_CTX *sel = e->ssl_ctx.get();
  const size_t n = e->sni_ctx.size();
  size_t idx = n;
  for (size_t i = 0; i < n; i++)
    if (hostEq(name, e->sni[i].host)) { idx = i; break; }
  if (idx == n)
    for (size_t i = 0; i < n; i++)
      if (hostWildMatch(name, e->sni[i].host)) { idx = i; break; }
  if (idx < n) sel = e->sni_ctx[idx].get();
  subjectOf(sel, buf, len);
}

// --- #382: one session-ticket key across engines, with rotation -----------
//
// Drives the ticket-key callback exactly as OpenSSL does, so the sharing and
// the rotation are observable without a resuming QUIC client (curl cannot
// easily be made to resume over h3).

// The process-wide key name the encrypt side would stamp, as lowercase hex.
// Building another engine must not change it: pre-fix every SSL_CTX carried its
// own OpenSSL-generated key, so a ticket issued on one loop was undecryptable
// on all the others.
void vq_test_ticket_key_name(char *buf, size_t len) {
  std::lock_guard<std::mutex> lock(gTicketMu);
  size_t n = 0;
  for (size_t i = 0; i < kTicketKeyNameLen && n + 3 <= len; i++)
    n += static_cast<size_t>(snprintf(buf + n, len - n, "%02x",
                                      gTicketCur.name[i]));
}

// Non-zero if this engine's default context would suppress tickets.
int vq_test_engine_no_ticket(VqEngine *eng) {
  auto *e = reinterpret_cast<Engine *>(eng);
  return (SSL_CTX_get_options(e->ssl_ctx.get()) & SSL_OP_NO_TICKET) ? 1 : 0;
}

// Bits:
//   1   the encrypt side succeeded
//   2   the name it stamped decrypts (rv 1)
//   4   an unknown key name is refused with 0: a full handshake, not an error
//   8   once the lifetime has elapsed the encrypt side stamps a NEW name
//   16  ... and the retired name still decrypts, asking for a reissue (rv 2)
//   32  ... while a name two lifetimes old is refused
int vq_test_ticket_key_cycle(void) {
  if (!osslInitOnce()) return -1;
  EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  if (!mac) return -1;
  unsigned char name1[kTicketKeyNameLen], name2[kTicketKeyNameLen];
  unsigned char name3[kTicketKeyNameLen], bogus[kTicketKeyNameLen];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  auto call = [&](unsigned char *nm, int enc) {
    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
    const int rv =
        (cctx && mctx) ? ticketKeyCb(nullptr, nm, iv, cctx, mctx, enc) : -1;
    EVP_MAC_CTX_free(mctx);
    EVP_CIPHER_CTX_free(cctx);
    return rv;
  };
  auto age = [] {
    std::lock_guard<std::mutex> lock(gTicketMu);
    gTicketBorn -= std::chrono::seconds(
        static_cast<long long>(kTicketKeyLifetimeSec));
  };

  int result = 0;
  if (call(name1, 1) == 1) result |= 1;
  if (call(name1, 0) == 1) result |= 2;
  memcpy(bogus, name1, kTicketKeyNameLen);
  bogus[0] = static_cast<unsigned char>(bogus[0] ^ 0xff);
  if (call(bogus, 0) == 0) result |= 4;

  age();
  if (call(name2, 1) == 1 && memcmp(name1, name2, kTicketKeyNameLen) != 0)
    result |= 8;
  if (call(name1, 0) == 2) result |= 16;

  age();
  if (call(name3, 1) == 1 && call(name1, 0) == 0) result |= 32;

  EVP_MAC_free(mac);
  return result;
}

// --- #382: the callback as OpenSSL sees it ---------------------------------
//
// Everything above drives ticketKeyCb directly, which proves the key is shared
// and rotates but says nothing about whether makeCtx ever INSTALLED the
// callback: delete the SSL_CTX_set_tlsext_ticket_key_evp_cb line and those
// cases still pass, while every context falls back to its own OpenSSL-generated
// key and the cross-loop resumption #382 is about stops working. So run real
// TLS 1.3 handshakes over a BIO pair against the engines' own contexts: first
// one against engine A to mint a ticket, then one against a DIFFERENT engine B
// that resumes it. Only a shared, installed key can make the second succeed.

static SSL_SESSION *gSavedSession = nullptr;

// SSL_CTX_sess_set_new_cb: returning 1 takes ownership of `sess`.
static int captureSessionCb(SSL *, SSL_SESSION *sess) {
  if (gSavedSession) SSL_SESSION_free(gSavedSession);
  gSavedSession = sess;
  return 1;
}

// A TLS 1.3 client context that the shim's alpnSelect will accept (it offers h3
// alone and alerts on anything else) and that hands its tickets to the callback
// above rather than an internal cache we cannot see into.
static SSL_CTX *ticketClientCtx(void) {
  SSL_CTX *c = SSL_CTX_new(TLS_client_method());
  if (!c) return nullptr;
  SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION);
  SSL_CTX_set_verify(c, SSL_VERIFY_NONE, nullptr);   // self-signed fixtures
  static const unsigned char kAlpn[] = {2, 'h', '3'};
  if (SSL_CTX_set_alpn_protos(c, kAlpn, sizeof kAlpn) != 0) {
    SSL_CTX_free(c);
    return nullptr;
  }
  SSL_CTX_set_session_cache_mode(
      c, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  SSL_CTX_sess_set_new_cb(c, captureSessionCb);
  return c;
}

// One handshake between `cctx` (client, resuming `resume` if given) and `sctx`
// (the engine's server context) over a BIO pair, followed by a record each way
// so the client processes the server's NewSessionTicket: TLS 1.3 sends it after
// the handshake, and nothing reaches captureSessionCb until the client reads.
// Returns 1 when both ends finished, with *reused set from SSL_session_reused.
static int ticketHandshake(SSL_CTX *sctx, SSL_CTX *cctx, SSL_SESSION *resume,
                           int *reused) {
  *reused = 0;
  BIO *cb = nullptr, *sb = nullptr;
  if (BIO_new_bio_pair(&cb, 0, &sb, 0) != 1) return 0;
  SSL *c = SSL_new(cctx);
  SSL *s = SSL_new(sctx);
  int ok = 0;
  if (c && s) {
    SSL_set_bio(c, cb, cb);   // SSL_free releases its end of the pair
    SSL_set_bio(s, sb, sb);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    if (resume) (void)SSL_set_session(c, resume);
    for (int i = 0; i < 64; i++) {
      const int cr = SSL_do_handshake(c);
      const int sr = SSL_do_handshake(s);
      if (cr == 1 && sr == 1) break;
      // WANT_READ/WANT_WRITE on either side just means the other has to run.
      if (cr <= 0 && SSL_get_error(c, cr) != SSL_ERROR_WANT_READ &&
          SSL_get_error(c, cr) != SSL_ERROR_WANT_WRITE)
        break;
      if (sr <= 0 && SSL_get_error(s, sr) != SSL_ERROR_WANT_READ &&
          SSL_get_error(s, sr) != SSL_ERROR_WANT_WRITE)
        break;
    }
    if (SSL_is_init_finished(c) && SSL_is_init_finished(s)) {
      ok = 1;
      *reused = SSL_session_reused(c) ? 1 : 0;
      unsigned char buf[64];
      (void)SSL_write(s, "x", 1);
      for (int i = 0; i < 8 && !gSavedSession; i++)
        (void)SSL_read(c, buf, sizeof buf);
      // Close cleanly. Without a sent close_notify, SSL_free below runs
      // ssl_clear_bad_session, which calls SSL_CTX_remove_session on the
      // client's session and that sets not_resumable on it -- so the ticket we
      // just captured would be unusable and the resuming pass below would
      // silently fall back to a full handshake.
      (void)SSL_shutdown(c);
      (void)SSL_shutdown(s);
    }
  }
  if (c) SSL_free(c);
  if (s) SSL_free(s);
  ERR_clear_error();
  return ok;
}

static uint64_t ticketRuns(bool enc) {
  std::lock_guard<std::mutex> lock(gTicketMu);
  return enc ? gTicketEncRuns : gTicketDecRuns;
}

// Bits:
//   1   a TLS 1.3 handshake against engine A's own context completed
//   2   OpenSSL invoked the shim's ticket-key callback to ENCRYPT a ticket,
//       i.e. makeCtx actually installed it
//   4   the client received a session ticket
//   8   a second handshake, against engine B's context, RESUMED that session
//  16   ... and OpenSSL invoked the callback to decrypt the ticket
int vq_test_ticket_handshake(VqEngine *ea, VqEngine *eb) {
  auto *a = reinterpret_cast<Engine *>(ea);
  auto *b = reinterpret_cast<Engine *>(eb);
  SSL_CTX *cc = ticketClientCtx();
  if (!cc) return -1;
  if (gSavedSession) {
    SSL_SESSION_free(gSavedSession);
    gSavedSession = nullptr;
  }
  int result = 0;
  int reused = 0;
  const uint64_t enc0 = ticketRuns(true);
  if (ticketHandshake(a->ssl_ctx.get(), cc, nullptr, &reused)) result |= 1;
  if (ticketRuns(true) > enc0) result |= 2;
  if (gSavedSession) {
    result |= 4;
    SSL_SESSION *sess = gSavedSession;
    gSavedSession = nullptr;          // so the resumed pass can capture its own
    const uint64_t dec0 = ticketRuns(false);
    if (ticketHandshake(b->ssl_ctx.get(), cc, sess, &reused) && reused)
      result |= 8;
    if (ticketRuns(false) > dec0) result |= 16;
    SSL_SESSION_free(sess);
    if (gSavedSession) {
      SSL_SESSION_free(gSavedSession);
      gSavedSession = nullptr;
    }
  }
  SSL_CTX_free(cc);
  ERR_clear_error();
  return result;
}

}  // extern "C"
