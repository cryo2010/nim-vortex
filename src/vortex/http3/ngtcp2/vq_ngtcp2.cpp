// vq_ngtcp2 -- ngtcp2 (QUIC) + nghttp3 (HTTP/3) server glue for vortex.
// See vq_ngtcp2.h for the C ABI and threading contract. C++20; one VqEngine per
// loop thread, single-threaded (no locking).

#include "vq_ngtcp2.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/pemerr.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

// SSL_OP_SERVER_PREFERENCE is the name OpenSSL 3.6.0 introduced for the option
// bit it had always called SSL_OP_CIPHER_SERVER_PREFERENCE; both spellings are
// SSL_OP_BIT(22) and 3.6's <openssl/ssl.h> keeps the old one as an alias for
// the new. OpenSSL 3.5, this project's documented minimum, defines only the
// old name, so taking the new one straight from the header stopped this
// translation unit compiling there (#398). Nothing else in vortex reads the
// name out of a header -- transport/tls.nim declares the bit itself -- so one
// fallback here covers the whole build.
#ifndef SSL_OP_SERVER_PREFERENCE
#define SSL_OP_SERVER_PREFERENCE SSL_OP_CIPHER_SERVER_PREFERENCE
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef VQ_FRAME_LOG
// Only the test-only frame observation hook below needs these (#347); the
// production build does not pull them in.
#include <atomic>
#include <cstdarg>
#endif

namespace {

constexpr size_t kMaxUdpPayload = 1452;   // conservative IPv4 path MTU
// The largest datagram we are willing to *receive*, advertised to the peer as
// max_udp_payload_size (RFC 9000 18.2) and exported via
// vq_max_recv_udp_payload so the Nim side can size its recvfrom buffer from
// this one number. 65527 is the largest a UDP payload can be and is also
// ngtcp2's NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE, so the value the peer
// sees is unchanged -- what changes is that the receive buffer now actually
// holds it (#380). Keeping the advertisement honest matters more than keeping
// it small: clamping it to a 2 KB buffer would also cap every datagram the
// peer sends us, costing throughput on a large-MTU path.
constexpr size_t kMaxRecvUdpPayload = 65527;
constexpr size_t kScidLen = 18;           // our connection-id length

// unique_ptr deleters for the C OpenSSL handles the shim owns. Scoped locals
// (loadKey/loadCertChain/makeCtx) then free on every path, and the Engine's
// SSL_CTX is released by RAII instead of a manual SSL_CTX_free.
struct SslCtxDeleter  { void operator()(SSL_CTX *p) const noexcept { SSL_CTX_free(p); } };
struct BioDeleter     { void operator()(BIO *p) const noexcept { BIO_free(p); } };
struct X509Deleter    { void operator()(X509 *p) const noexcept { X509_free(p); } };
struct EvpPkeyDeleter { void operator()(EVP_PKEY *p) const noexcept { EVP_PKEY_free(p); } };
using SslCtxPtr  = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using BioPtr     = std::unique_ptr<BIO, BioDeleter>;
using X509Ptr    = std::unique_ptr<X509, X509Deleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

// A response body: a FIFO of chunks with absolute offsets. nghttp3 borrows the
// buffers we hand it via read_data until they are acknowledged, so chunk storage
// must stay put until acked -- a deque of separately-allocated std::strings is
// pointer-stable across pop_front (unlike a compacting std::string).
struct Body {
  std::deque<std::string> q;
  uint64_t base = 0;    // absolute offset of q.front()[0]
  uint64_t handed = 0;  // absolute offset already handed to nghttp3
  uint64_t end = 0;     // absolute offset just past the last enqueued byte
  bool fin = false;     // no more chunks will be added

  void push(const uint8_t *d, size_t n) {
    if (n) q.emplace_back(reinterpret_cast<const char *>(d), n);
    end += n;
  }
  // Point v at the next un-handed run; false if nothing new is buffered.
  bool next(nghttp3_vec *v) {
    if (handed >= end) return false;
    uint64_t off = base;
    for (auto &c : q) {
      if (handed < off + c.size()) {
        size_t within = static_cast<size_t>(handed - off);
        v->base = reinterpret_cast<uint8_t *>(&c[0]) + within;
        v->len = c.size() - within;
        handed = off + c.size();
        return true;
      }
      off += c.size();
    }
    return false;
  }
  void ack(uint64_t nAbs) {  // nAbs = cumulative acked byte offset
    while (!q.empty() && base + q.front().size() <= nAbs) {
      base += q.front().size();
      q.pop_front();
    }
  }
  size_t backlog() const { return static_cast<size_t>(end - handed); }
};

struct Stream {
  int64_t id = -1;
  Body body;
  uint64_t acked = 0;         // cumulative acked body bytes (for Body::ack)
  bool headSubmitted = false; // submit_response/submit_head issued
  bool hasTrailers = false;   // trailers submitted: keep the stream open past body EOF
  bool everBlocked = false;   // nghttp3 stream currently blocked in ngtcp2
  // request header accumulation (owned copies; borrowed to on_headers)
  std::vector<std::string> hdrStore;
  std::vector<VqHeader> hdrs;
  void *conn_ud = nullptr;    // vortex per-conn context (cached for callbacks)
};

struct Engine;

struct Conn {
  ngtcp2_crypto_conn_ref conn_ref{};  // must be first for SSL app-data get_conn
  Engine *engine = nullptr;
  ngtcp2_conn *conn = nullptr;
  nghttp3_conn *h3 = nullptr;
  SSL *ssl = nullptr;
  ngtcp2_crypto_ossl_ctx *ossl = nullptr;
  void *conn_ud = nullptr;            // vortex h3-slot handle (from on_accept)
  std::string peer_ip;
  std::vector<uint8_t> peer_sa;       // sockaddr copy for on_send addressing
  std::vector<uint8_t> local_sa;
  std::unordered_map<int64_t, std::unique_ptr<Stream>> streams;
  bool closed = false;                // scheduled for reaping
  bool draining = false;
  bool wantClose = false;             // emit CONNECTION_CLOSE(ccerr) then close
  bool wantGracefulClose = false;     // flush pending h3 frames (final GOAWAY)
                                      // first, THEN emit CONNECTION_CLOSE(ccerr)
  uint64_t reset_count = 0;           // client request streams closed via reset
                                      // (rapid-reset budget, #251)
  ngtcp2_ccerr ccerr{};               // application error for the close

  Stream *stream(int64_t id) {
    auto it = streams.find(id);
    return it == streams.end() ? nullptr : it->second.get();
  }

  // Free the ngtcp2/nghttp3/OpenSSL resources this Conn owns, in the same order
  // the reap path used (h3, conn, ossl, ssl). A destructor (RAII) means every
  // exit unwinds them -- including acceptConn's early returns, which previously
  // leaked c->ssl/c->ossl because Conn had no destructor (R7). Member
  // destructors (streams etc.) run afterwards, as before.
  ~Conn() {
    if (h3) nghttp3_conn_del(h3);
    if (conn) ngtcp2_conn_del(conn);
    if (ossl) ngtcp2_crypto_ossl_ctx_del(ossl);
    if (ssl) {
      // ngtcp2's ossl backend requires the SSL's app data to be cleared before
      // SSL_free whenever the ngtcp2_conn does not outlive the SSL (which it
      // does not here: it is deleted two lines up). SSL_free can still invoke
      // the QUIC record-layer callbacks -- release_rcd for crypto data OpenSSL
      // never consumed, which is exactly what a handshake rejected for a
      // missing client certificate leaves behind -- and those resolve the
      // conn_ref in app data to reach the ngtcp2_conn and its ossl ctx. With a
      // stale conn_ref that is a use-after-free (it aborted in
      // crypto_ossl_ctx_release_crypto_data); nulling it makes the callbacks
      // return without touching anything, as the backend documents.
      SSL_set_app_data(ssl, nullptr);
      SSL_free(ssl);
    }
  }
};

// An owned copy of one certificate's material. The caller's VqConfig /
// VqSniCert strings are borrowed for the vq_engine_new call only, and a per-host
// context must stay rebuildable on a certificate reload, so the engine keeps its
// own copies. Same sources and precedence as VqConfig's default cert fields.
struct Material {
  std::string host;   // "" for the default certificate
  std::string cert_file, key_file, cert_pem, key_pem, key_password, pkcs12_file;
  std::string pkcs12;  // PKCS#12 DER bytes
};

struct Engine {
  VqConfig cfg{};
  SslCtxPtr ssl_ctx;                   // RAII: freed when the Engine is deleted
  std::string last_error;  // why the last certificate reload was refused (#352)
  std::string key_pw;   // owns the passphrase (cfg.key_password char* may dangle)
  std::string cipher_suites;  // ditto for the TLS 1.3 suite list (#359)
  std::string client_ca_file, client_ca_pem;   // ... and the mTLS CA (#351)
  // Per-host certificates (SNI, #374): the material and the contexts built from
  // it, parallel arrays. The contexts are freed with the Engine; a connection
  // that already switched to one keeps it alive through its own reference.
  std::vector<Material> sni;
  std::vector<SslCtxPtr> sni_ctx;
  // The DEFAULT certificate's material, kept for the same reason (#353): a
  // reload with no paths means "re-read what was configured", which needs the
  // configured sources, not just the bytes they produced at startup.
  Material def_material;
  // Every CID that routes to a conn (our SCIDs + the client's original DCID).
  std::unordered_map<std::string, Conn *> byCid;
  std::vector<std::unique_ptr<Conn>> conns;
  // Scratch set on entry to vq_engine_recv so on_send/accept can address replies.
  const void *cur_peer = nullptr; size_t cur_peer_len = 0;
  const void *cur_local = nullptr; size_t cur_local_len = 0;
};

std::string cidKey(const uint8_t *d, size_t n) {
  return std::string(reinterpret_cast<const char *>(d), n);
}

ngtcp2_conn *getConnFromRef(ngtcp2_crypto_conn_ref *ref) {
  return static_cast<Conn *>(ref->user_data)->conn;
}

// Terminal handling for a connection error reported by nghttp3: delete the
// poisoned nghttp3_conn, then schedule an HTTP/3/QPACK CONNECTION_CLOSE carrying
// the app error code inferred from the nghttp3 error (so h3spec sees the right
// code); the close itself is emitted by writeConn.
//
// Deleting c->h3 here is what makes the failure terminal (#362). nghttp3
// documents that once nghttp3_conn_read_stream or nghttp3_conn_writev_stream
// return a negative code the connection is in error and "calling nghttp3 API
// other than nghttp3_conn_del causes undefined behavior" -- yet the rest of the
// datagram ngtcp2_conn_read_pkt is already parsing (further STREAM frames,
// stream closes, acks, window updates) would keep calling into it, as would a
// response submitted from the Nim side before the next pump reaps the conn.
// Every nghttp3 call site is guarded by `if (c->h3)`, so a null h3 turns them
// all into no-ops, and ~Conn skips the (already done) nghttp3_conn_del.
void failConn(Conn *c, int nghttp3_rv) {
  if (c->h3) {
    nghttp3_conn_del(c->h3);
    c->h3 = nullptr;
  }
  if (c->wantClose || c->closed) return;
  ngtcp2_ccerr_set_application_error(
      &c->ccerr, nghttp3_err_infer_quic_app_error_code(nghttp3_rv), nullptr, 0);
  c->wantClose = true;
}

// --- ngtcp2 non-crypto callbacks -------------------------------------------

void cbRand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *) {
  RAND_bytes(dest, static_cast<int>(destlen));
}

int cbGetNewCid(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                size_t cidlen, void *user_data) {
  auto *c = static_cast<Conn *>(user_data);
  if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1) return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = cidlen;
  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) return NGTCP2_ERR_CALLBACK_FAILURE;
  c->engine->byCid[cidKey(cid->data, cid->datalen)] = c;
  return 0;
}

int cbRemoveCid(ngtcp2_conn *, const ngtcp2_cid *cid, void *user_data) {
  auto *c = static_cast<Conn *>(user_data);
  c->engine->byCid.erase(cidKey(cid->data, cid->datalen));
  return 0;
}

int cbHandshakeCompleted(ngtcp2_conn *, void *user_data);
int cbRecvStreamData(ngtcp2_conn *, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data);
int cbStreamClose(ngtcp2_conn *, uint32_t flags, int64_t stream_id,
                  uint64_t app_error_code, void *user_data,
                  void *stream_user_data);
int cbAckedStreamDataOffset(ngtcp2_conn *, int64_t stream_id, uint64_t offset,
                            uint64_t datalen, void *user_data,
                            void *stream_user_data);
int cbStreamOpen(ngtcp2_conn *, int64_t stream_id, void *user_data);

// --- nghttp3 callbacks ------------------------------------------------------

int h3BeginHeaders(nghttp3_conn *, int64_t stream_id, void *cud, void *sud) {
  auto *c = static_cast<Conn *>(cud);
  if (Stream *s = c->stream(stream_id)) {
    s->hdrStore.clear();
    s->hdrs.clear();
  }
  return 0;
}

int h3RecvHeader(nghttp3_conn *, int64_t stream_id, int32_t, nghttp3_rcbuf *name,
                 nghttp3_rcbuf *value, uint8_t, void *cud, void *) {
  auto *c = static_cast<Conn *>(cud);
  Stream *s = c->stream(stream_id);
  if (!s) return 0;
  nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
  s->hdrStore.emplace_back(reinterpret_cast<char *>(n.base), n.len);
  s->hdrStore.emplace_back(reinterpret_cast<char *>(v.base), v.len);
  return 0;
}

int h3EndHeaders(nghttp3_conn *, int64_t stream_id, int, void *cud, void *) {
  auto *c = static_cast<Conn *>(cud);
  Stream *s = c->stream(stream_id);
  if (!s) return 0;
  // hdrStore holds [name,value,...]; build the borrowed VqHeader view now that
  // the backing strings will not move (no further push during the callback).
  s->hdrs.clear();
  for (size_t i = 0; i + 1 < s->hdrStore.size(); i += 2) {
    s->hdrs.push_back(VqHeader{s->hdrStore[i].data(), s->hdrStore[i].size(),
                               s->hdrStore[i + 1].data(),
                               s->hdrStore[i + 1].size()});
  }
  auto &cb = c->engine->cfg.cb;
  if (cb.on_headers)
    cb.on_headers(c->engine->cfg.user, c->conn_ud, stream_id,
                  s->hdrs.data(), s->hdrs.size());
  return 0;
}

int h3RecvData(nghttp3_conn *, int64_t stream_id, const uint8_t *data,
               size_t datalen, void *cud, void *) {
  auto *c = static_cast<Conn *>(cud);
  auto &cb = c->engine->cfg.cb;
  if (cb.on_body)
    cb.on_body(c->engine->cfg.user, c->conn_ud, stream_id,
               const_cast<uint8_t *>(data), datalen);
  return 0;
}

int h3EndStream(nghttp3_conn *, int64_t stream_id, void *cud, void *) {
  auto *c = static_cast<Conn *>(cud);
  auto &cb = c->engine->cfg.cb;
  if (cb.on_stream_end)
    cb.on_stream_end(c->engine->cfg.user, c->conn_ud, stream_id);
  return 0;
}

int h3StreamClose(nghttp3_conn *, int64_t stream_id, uint64_t app_error_code,
                  void *cud, void *) {
  auto *c = static_cast<Conn *>(cud);
  auto &cb = c->engine->cfg.cb;
  if (cb.on_stream_close)
    cb.on_stream_close(c->engine->cfg.user, c->conn_ud, stream_id,
                       app_error_code);
  c->streams.erase(stream_id);
  return 0;
}

int h3DeferredConsume(nghttp3_conn *, int64_t stream_id, size_t consumed,
                      void *cud, void *) {
  auto *c = static_cast<Conn *>(cud);
  if (c->conn) {
    ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, consumed);
    ngtcp2_conn_extend_max_offset(c->conn, consumed);
  }
  return 0;
}

int h3AckedStreamData(nghttp3_conn *, int64_t stream_id, uint64_t datalen,
                      void *cud, void *) {
  auto *c = static_cast<Conn *>(cud);
  if (Stream *s = c->stream(stream_id)) {
    s->acked += datalen;
    s->body.ack(s->acked);
    auto &cb = c->engine->cfg.cb;
    if (cb.on_stream_writable)
      cb.on_stream_writable(c->engine->cfg.user, c->conn_ud, stream_id);
  }
  return 0;
}

// nghttp3 response body source: hand the next un-handed run, EOF at fin.
nghttp3_ssize h3ReadData(nghttp3_conn *, int64_t stream_id, nghttp3_vec *vec,
                         size_t, uint32_t *pflags, void *cud, void *) {
  auto *c = static_cast<Conn *>(cud);
  Stream *s = c->stream(stream_id);
  // At body EOF, NO_END_STREAM keeps the stream open so the already-submitted
  // trailer HEADERS can follow (RFC 9114 4.1); otherwise EOF ends the stream.
  const uint32_t eof = s && s->hasTrailers
      ? (NGHTTP3_DATA_FLAG_EOF | NGHTTP3_DATA_FLAG_NO_END_STREAM)
      : NGHTTP3_DATA_FLAG_EOF;
  if (!s) { *pflags |= NGHTTP3_DATA_FLAG_EOF; return 0; }
  if (s->body.next(vec)) {
    if (s->body.fin && s->body.handed >= s->body.end)
      *pflags |= eof;
    return 1;
  }
  if (s->body.fin) { *pflags |= eof; return 0; }
  return NGHTTP3_ERR_WOULDBLOCK;  // streaming: resumed by vq_stream_write/finish
}

// --- nghttp3 setup ----------------------------------------------------------

int setupHttpConn(Conn *c) {
  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  settings.qpack_blocked_streams = 0;
  settings.qpack_max_dtable_capacity = 4096;
  settings.enable_connect_protocol = 1;   // RFC 9220 WebSockets over HTTP/3
  // Advertise the configured header-section limit (#253). Without this nghttp3
  // leaves it unlimited, so the operator's max_field_section_size is silently
  // ignored and a client can send an oversized header section (bounded only by
  // the stream flow-control window).
  if (c->engine->cfg.max_field_section_size > 0)
    settings.max_field_section_size =
        (uint64_t)c->engine->cfg.max_field_section_size;

  static const nghttp3_callbacks cbs = {
      h3AckedStreamData,   // acked_stream_data
      h3StreamClose,       // stream_close
      h3RecvData,          // recv_data
      h3DeferredConsume,   // deferred_consume
      h3BeginHeaders,      // begin_headers
      h3RecvHeader,        // recv_header
      h3EndHeaders,        // end_headers
      // A request's trailer section reuses the header callbacks (same
      // signatures): begin clears the field store, recv appends, end delivers
      // via on_headers. vortex's cbHeaders routes a post-head block into
      // req.trailers (it keys off headersDone), so request trailers over h3 are
      // surfaced like h1/h2 -- without these nghttp3 would drop them.
      h3BeginHeaders,      // begin_trailers
      h3RecvHeader,        // recv_trailer
      h3EndHeaders,        // end_trailers
      nullptr,             // stop_sending
      h3EndStream,         // end_stream
      nullptr,             // reset_stream
      nullptr,             // shutdown
      nullptr,             // recv_settings
      nullptr,             // recv_origin
      nullptr,             // end_origin
      nullptr,             // rand
  };

  const ngtcp2_transport_params *params =
      ngtcp2_conn_get_local_transport_params(c->conn);
  // The server's control + QPACK encoder/decoder unidirectional streams need 3
  // uni streams; ngtcp2 grants them via the peer's initial_max_streams_uni.
  if (nghttp3_conn_server_new(&c->h3, &cbs, &settings, nullptr, c) != 0)
    return -1;

  int64_t ctrl = -1, enc = -1, dec = -1;
  if (ngtcp2_conn_open_uni_stream(c->conn, &ctrl, nullptr) != 0) return -1;
  if (ngtcp2_conn_open_uni_stream(c->conn, &enc, nullptr) != 0) return -1;
  if (ngtcp2_conn_open_uni_stream(c->conn, &dec, nullptr) != 0) return -1;
  if (nghttp3_conn_bind_control_stream(c->h3, ctrl) != 0) return -1;
  if (nghttp3_conn_bind_qpack_streams(c->h3, enc, dec) != 0) return -1;
  (void)params;
  return 0;
}

int cbHandshakeCompleted(ngtcp2_conn *, void *user_data) {
  auto *c = static_cast<Conn *>(user_data);
  // A connection whose nghttp3_conn failConn already deleted must never get a
  // fresh one: a null h3 with a close scheduled means HTTP/3 is over for this
  // connection (#362).
  if (c->wantClose || c->closed) return 0;
  if (!c->h3 && setupHttpConn(c) != 0) return NGTCP2_ERR_CALLBACK_FAILURE;
  return 0;
}

int cbStreamOpen(ngtcp2_conn *, int64_t stream_id, void *user_data) {
  auto *c = static_cast<Conn *>(user_data);
  // Only track client-initiated bidi streams (request streams). Uni/h3-internal
  // streams are owned by nghttp3.
  if ((stream_id & 0x03) == 0) {  // client bidi
    auto s = std::make_unique<Stream>();
    s->id = stream_id;
    s->conn_ud = c->conn_ud;
    c->streams[stream_id] = std::move(s);
    // h3 can be absent here: a stream may open before the handshake completes,
    // or after failConn deleted the nghttp3_conn (#362).
    if (c->h3)
      nghttp3_conn_set_stream_user_data(c->h3, stream_id,
                                        c->streams[stream_id].get());
  }
  return 0;
}

int cbRecvStreamData(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t, const uint8_t *data, size_t datalen,
                     void *user_data, void *) {
  auto *c = static_cast<Conn *>(user_data);
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
  if (!c->h3) return 0;
  nghttp3_ssize n =
      nghttp3_conn_read_stream(c->h3, stream_id, data, datalen, fin);
  if (n < 0) {
    // nghttp3 detected an HTTP/3/QPACK protocol error: close the connection
    // with the corresponding application error code (RFC 9114/9204), not a
    // generic transport failure. failConn deletes the now-poisoned
    // nghttp3_conn, and returning CALLBACK_FAILURE (instead of 0) makes
    // ngtcp2_conn_read_pkt abandon the remaining frames of this packet and the
    // packets coalesced behind it, rather than driving more callbacks from the
    // same datagram (#362). vq_engine_recv turns that error into the terminal
    // CONNECTION_CLOSE, keeping the h3 ccerr failConn just set.
    failConn(c, static_cast<int>(n));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  // nghttp3 tells us via deferred_consume how much QPACK-blocked data it kept;
  // the bytes it did consume are extended here.
  ngtcp2_conn_extend_max_stream_offset(conn, stream_id, static_cast<uint64_t>(n));
  ngtcp2_conn_extend_max_offset(conn, static_cast<uint64_t>(n));
  return 0;
}

int cbStreamClose(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                  uint64_t app_error_code, void *user_data, void *) {
  auto *c = static_cast<Conn *>(user_data);
  if (c->h3) nghttp3_conn_close_stream(c->h3, stream_id, app_error_code);
  // Grant the client one more bidi stream to replace the finished request one,
  // via a MAX_STREAMS frame. Without this the peer is capped forever at the
  // initial budget (each request is a fresh bidi stream) and stalls after it.
  if ((stream_id & 0x03) == 0)
    ngtcp2_conn_extend_max_streams_bidi(conn, 1);
  // Rapid-reset budget (CVE-2023-44487, #251). Because the concurrency credit is
  // replenished above on every close, a client can open a request stream (making
  // us QPACK-decode HEADERS + dispatch), then RESET_STREAM it, churning work at
  // line rate. Count reset-class closes -- an app error code was set, i.e. the
  // stream did not complete cleanly -- on client bidi streams, and tear the
  // connection down with H3_EXCESSIVE_LOAD (0x0107) once they exceed the budget.
  if (c->engine->cfg.max_reset_streams > 0 && (stream_id & 0x03) == 0 &&
      (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
    if (++c->reset_count > c->engine->cfg.max_reset_streams &&
        !c->wantClose && !c->closed) {
      ngtcp2_ccerr_set_application_error(&c->ccerr, 0x0107 /*H3_EXCESSIVE_LOAD*/,
                                         nullptr, 0);
      c->wantClose = true;
    }
  }
  return 0;
}

int cbAckedStreamDataOffset(ngtcp2_conn *, int64_t stream_id, uint64_t,
                            uint64_t datalen, void *user_data, void *) {
  auto *c = static_cast<Conn *>(user_data);
  if (c->h3) nghttp3_conn_add_ack_offset(c->h3, stream_id, datalen);
  return 0;
}

// The peer extended this stream's flow-control window. writeConn blocks a stream
// in nghttp3 (nghttp3_conn_block_stream) when ngtcp2 reports
// STREAM_DATA_BLOCKED; without a matching unblock the stream stays parked in
// nghttp3 forever and a response larger than the peer's per-stream window stalls
// permanently (R6). Unblock it so the next writev offers it again.
int cbExtendMaxStreamData(ngtcp2_conn *, int64_t stream_id, uint64_t,
                          void *user_data, void *) {
  auto *c = static_cast<Conn *>(user_data);
  if (c->h3 && nghttp3_conn_unblock_stream(c->h3, stream_id) != 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  return 0;
}

// --- test-only frame observation (VQ_FRAME_LOG) -----------------------------

#ifdef VQ_FRAME_LOG
// Count the keep-alive PING frames this process TRANSMITS, so a test can pin
// that the keep-alive armed in acceptConn actually puts packets on the wire --
// not merely that the idle window reached the transport parameters, which is
// all a black-box h3 test can see when the client (curl) sends keep-alive
// PINGs of its own and refreshes our idle timer for us (#347).
//
// ngtcp2's only per-frame hook is its logger: ngtcp2_settings.log_printf, a
// printf-style callback it calls for every frame it reads and writes, on the
// thread that owns the conn (for us the loop thread). (1.23.0 deprecates it for
// log_write, which hands over the rendered line instead; log_printf is the one
// that exists in every 1.x, and a test hook has no business pinning the build
// to a minimum ngtcp2.) The lines this cares about are fixed-position (as
// observed on ngtcp2 1.25.0):
//
//   I00001337 0x5f3a..  pkt tx pkn=3 dcid=0x37b4.. type=1RTT k=0
//   I00001337 0x5f3a..  pkt read packet 1200 left 0
//   I00001337 0x5f3a..  frm tx 3 1RTT PING(0x1)
//   I00001337 0x5f3a..  frm tx 3 1RTT ACK(0x2) largest_ack=5 ...
//
// that is, `<ts> <scid> <category> <dir> <pkn> <type> <NAME>(0x..)`, so the
// frame test below is positional: token 2 == "frm", token 3 == "tx", token 6
// starting "PING(" or "ACK(". Positional rather than a substring search on
// purpose: a peer-controlled CONNECTION_CLOSE reason string is logged
// verbatim (`reason=[..]`) and could otherwise spell any of those tokens. A
// PING we *received* is the same line with `rx` in place of `tx`, and never
// counts, which is what excludes the client's own keep-alives.
//
// A transmitted PING is still not the same thing as a keep-alive, because
// ngtcp2 writes one in three places (lib/ngtcp2_conn.c, conn_write_pkt):
//
//   (a) it appends a PING to a packet that would otherwise be non-ack-eliciting
//       (a run of pure ACKs) and is older than the smoothed RTT, so the run
//       still gets acknowledged and keeps yielding RTT samples. Answering the
//       client's own keep-alive is such a run: it produced two PINGs per quiet
//       gap here with the server's arming removed;
//   (b) the keep-alive expiry, the one under test. It is written alone (PING +
//       PADDING, no ACK: there was nothing to acknowledge, which is why the
//       timer fired) -- unless an ACK happens to be pending, in which case it
//       rides with it and looks exactly like (a);
//   (c) a PTO probe (RFC 9002 6.2.4), also ACK-less, and two to a burst.
//
// So the rule is "a tx PING in a packet with no ACK frame in it", which rejects
// (a) exactly and keeps (b) and (c). gPingTx is therefore a LOWER bound on
// keep-alives -- one that rode with a pending ACK is not in it -- and an UPPER
// bound once PTO probes are counted in; the suite's scope paragraph sets its
// thresholds from both. gPingTxWithAck counts the other shape, so a run that
// undercounted can be told from one with no keep-alive at all. Path-MTU
// probes are padded PINGs too, and the define switches PMTUD off rather than
// lean on any distinction there.
//
// Per-packet state is thread_local: the logger is called synchronously from the
// engine that owns the connection, one packet at a time, on the loop thread.
// Within a packet ngtcp2 logs a PING it appends after that packet's ACK frames
// (conn_write_pkt writes the ACK first), and a `pkt` line always precedes its
// own frames, so the one-pass "has an ACK been seen in this packet" flag is
// enough -- across 784 logged lines of 4 connections no PING was ever logged
// before its packet's ACK. Both counters only ever increase, so a test can
// subtract two readings.
//
// Compiled only under -DVQ_FRAME_LOG (Nim: -d:vortexH3FrameLog). In a normal
// build nothing here exists, no callback is installed, and ngtcp2's logging
// stays off -- the field is left NULL, which is how it ships.
std::atomic<uint64_t> gPingTx{0};         // ACK-less transmitted PINGs
std::atomic<uint64_t> gPingTxWithAck{0};  // transmitted PINGs riding an ACK
thread_local bool tlPktHasAck = false;    // this tx packet carries an ACK

struct LogTok {
  const char *p;
  size_t n;
};

// Split `s` into at most `max` whitespace-delimited tokens and return how many
// were filled. Nothing is copied: each token points into `s`.
size_t logTokens(const char *s, LogTok *out, size_t max) {
  size_t cnt = 0;
  const char *p = s;
  while (*p && cnt < max) {
    while (*p == ' ' || *p == '\t') ++p;
    if (!*p) break;
    const char *start = p;
    while (*p && *p != ' ' && *p != '\t') ++p;
    out[cnt].p = start;
    out[cnt].n = static_cast<size_t>(p - start);
    ++cnt;
  }
  return cnt;
}

bool tokIs(const LogTok &t, const char *lit) {
  const size_t n = std::strlen(lit);
  return t.n == n && std::strncmp(t.p, lit, n) == 0;
}

bool tokStartsWith(const LogTok &t, const char *lit) {
  const size_t n = std::strlen(lit);
  return t.n >= n && std::strncmp(t.p, lit, n) == 0;
}

// ngtcp2_printf: void (*)(void *user_data, const char *fmt, ...) with ngtcp2's
// own format strings, so the text has to be rendered before it can be read.
// Most of what ngtcp2 logs is neither a packet header nor a frame, so the cheap
// substring reject runs FIRST and only what survives it is tokenized.
void frameLogPrintf(void *, const char *fmt, ...) {
  char line[512];
  va_list ap;
  va_start(ap, fmt);
  const int n = vsnprintf(line, sizeof line, fmt, ap);
  va_end(ap);
  if (n <= 0) return;
  if (std::strstr(line, " pkt ") == nullptr &&
      std::strstr(line, " frm ") == nullptr)
    return;

  LogTok t[7];
  const size_t nt = logTokens(line, t, 7);
  if (nt < 4) return;
  // A `pkt` line ends the previous packet's frame list: both the header shape
  // (`pkt tx pkn=..` / `pkt rx pkn=..`) and the `pkt read packet 1200 left 0`
  // shape count, and no such line ever appears between the frames of one
  // packet.
  if (tokIs(t[2], "pkt")) {
    tlPktHasAck = false;
    return;
  }
  if (nt < 7 || !tokIs(t[2], "frm") || !tokIs(t[3], "tx")) return;
  if (tokStartsWith(t[6], "ACK(")) {
    // ngtcp2 logs a line per ACK range after the frame's own line, so this is
    // often already set: it is a flag, not a count.
    tlPktHasAck = true;
    return;
  }
  // PING(0x1) in one ngtcp2 and PING(0x01) in another, hence the prefix.
  if (!tokStartsWith(t[6], "PING(")) return;
  if (tlPktHasAck)
    gPingTxWithAck.fetch_add(1, std::memory_order_relaxed);
  else
    gPingTx.fetch_add(1, std::memory_order_relaxed);
}
#endif

// --- connection creation ----------------------------------------------------

Conn *acceptConn(Engine *e, const uint8_t *pkt, size_t pktlen,
                 const ngtcp2_version_cid *vc, uint64_t now_ns) {
  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, pkt, pktlen) != 0) return nullptr;

  // Bound concurrent QUIC connections so a flood of Initial packets can't grow
  // unbounded per-connection state (each Conn is an ngtcp2_conn + SSL + h3 slot).
  // 0 = unlimited. A spoofed-address flood is still cheap here because we do not
  // yet issue a Retry token (address validation) before committing state: every
  // Initial that gets this far allocates an ngtcp2_conn + SSL + h3 slot. What
  // bounds the damage today is max_connections (above) plus the per-pass
  // datagram budget on the Nim side (ngRecvBudget, #381), which keeps the flood
  // from monopolising the loop thread; a Retry token would stop the state being
  // committed at all and is the real fix, still outstanding.
  if (e->cfg.max_connections != 0 && e->conns.size() >= e->cfg.max_connections)
    return nullptr;

  auto owned = std::make_unique<Conn>();
  Conn *c = owned.get();
  c->engine = e;
  c->conn_ref.get_conn = getConnFromRef;
  c->conn_ref.user_data = c;
  if (e->cur_peer) c->peer_sa.assign(static_cast<const uint8_t *>(e->cur_peer),
                                     static_cast<const uint8_t *>(e->cur_peer) + e->cur_peer_len);
  if (e->cur_local) c->local_sa.assign(static_cast<const uint8_t *>(e->cur_local),
                                       static_cast<const uint8_t *>(e->cur_local) + e->cur_local_len);
  { char host[64] = {0};
    // best-effort numeric peer IP from the sockaddr
    const auto *sa = reinterpret_cast<const sockaddr *>(c->peer_sa.data());
    if (!c->peer_sa.empty()) {
      void *ap = nullptr;
      if (sa->sa_family == AF_INET) ap = &((sockaddr_in *)sa)->sin_addr;
      else if (sa->sa_family == AF_INET6) ap = &((sockaddr_in6 *)sa)->sin6_addr;
      if (ap && inet_ntop(sa->sa_family, ap, host, sizeof host)) c->peer_ip = host;
    }
  }

  // TLS per-connection state (ossl crypto backend).
  c->ssl = SSL_new(e->ssl_ctx.get());
  if (!c->ssl) return nullptr;
  SSL_set_app_data(c->ssl, &c->conn_ref);
  SSL_set_accept_state(c->ssl);
  if (ngtcp2_crypto_ossl_configure_server_session(c->ssl) != 0) return nullptr;
  if (ngtcp2_crypto_ossl_ctx_new(&c->ossl, c->ssl) != 0) return nullptr;

  ngtcp2_cid scid;
  scid.datalen = kScidLen;
  if (RAND_bytes(scid.data, kScidLen) != 1) return nullptr;

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_init(&ps,
      reinterpret_cast<sockaddr *>(c->local_sa.data()),
      static_cast<socklen_t>(c->local_sa.size()),
      reinterpret_cast<sockaddr *>(c->peer_sa.data()),
      static_cast<socklen_t>(c->peer_sa.size()), nullptr);

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.initial_ts = now_ns;
#ifdef VQ_FRAME_LOG
  // Test-only observation of the frames we transmit (see frameLogPrintf). Path
  // MTU discovery goes with it: ngtcp2 probes the path by sending a PING padded
  // to the candidate size, which is a transmitted PING that has nothing to do
  // with the keep-alive, arrives on every connection, and would make the
  // keep-alive count unreadable. Both are confined to this define (#347) -- the
  // flip side being that the suite runs against a transport config the shipped
  // server never has, so nothing it observes pins a PMTUD interaction.
  settings.log_printf = frameLogPrintf;
  settings.no_pmtud = 1;
#endif

  ngtcp2_transport_params tp;
  ngtcp2_transport_params_default(&tp);
  // The idle timeout we advertise. QUIC gives each endpoint min(local, peer)
  // (RFC 9000 10.1), so this number caps the *client's* idle timer as much as
  // ours -- and the client is the one that reports "Idle timeout" when a loop
  // thread goes away. It must therefore be at least as generous as the h1/h2
  // idle budget (keepAliveTimeout, which the loop already credits back for a
  // stall) and wider than the drain grace, or an h3 connection is reaped where
  // an h1/h2 one on the same listener survives.
  const uint64_t idle_sec =
      e->cfg.max_idle_timeout_sec ? e->cfg.max_idle_timeout_sec : 30ULL;
  tp.max_idle_timeout = idle_sec * NGTCP2_SECONDS;
  // Receive flow-control windows (configurable via VortexConfig; 0 = default).
  // bidi_remote is the request-body upload window (client-opened streams) and
  // initial_max_data is the connection aggregate -- both extended on consumption
  // (vq_stream_consume) so they cap un-consumed upload buffer, the h3 analog of
  // h2's stream/connection receive windows. uni streams carry only the HTTP/3
  // control and QPACK encoder/decoder streams, so they keep a fixed window
  // independent of the upload knob (a tiny knob must not starve QPACK).
  uint64_t stream_win = e->cfg.stream_recv_window
                            ? e->cfg.stream_recv_window : 1024 * 1024;
  tp.initial_max_data = e->cfg.conn_recv_window
                            ? e->cfg.conn_recv_window : 4 * 1024 * 1024;
  tp.initial_max_stream_data_bidi_remote = stream_win;
  tp.initial_max_stream_data_bidi_local = stream_win;
  tp.initial_max_stream_data_uni = 1024 * 1024;
  tp.initial_max_streams_bidi = e->cfg.max_concurrent_streams
                                    ? e->cfg.max_concurrent_streams : 100;
  tp.initial_max_streams_uni = 3;
  // What we advertise as the biggest datagram we can take. ngtcp2's default is
  // the same number, but set it explicitly from the constant the receive buffer
  // is sized from: the two must agree or a conforming client on a jumbo-frame
  // path (a 9000-byte VPC MTU, 65536 on loopback) takes us at our word, sends a
  // datagram we then truncate in recvfrom, and every packet fails AEAD until
  // the connection dies on the idle timer with nothing logged at either end
  // (#380).
  tp.max_udp_payload_size = kMaxRecvUdpPayload;
  tp.original_dcid = hd.dcid;
  tp.original_dcid_present = 1;

  ngtcp2_callbacks cbs{};
  cbs.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  cbs.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  cbs.encrypt = ngtcp2_crypto_encrypt_cb;
  cbs.decrypt = ngtcp2_crypto_decrypt_cb;
  cbs.hp_mask = ngtcp2_crypto_hp_mask_cb;
  cbs.update_key = ngtcp2_crypto_update_key_cb;
  cbs.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  cbs.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  cbs.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
  cbs.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  cbs.handshake_completed = cbHandshakeCompleted;
  cbs.recv_stream_data = cbRecvStreamData;
  cbs.acked_stream_data_offset = cbAckedStreamDataOffset;
  cbs.extend_max_stream_data = cbExtendMaxStreamData;
  cbs.stream_open = cbStreamOpen;
  cbs.stream_close = cbStreamClose;
  cbs.rand = cbRand;
  cbs.get_new_connection_id = cbGetNewCid;
  cbs.remove_connection_id = cbRemoveCid;

  if (ngtcp2_conn_server_new(&c->conn, &hd.scid, &scid, &ps.path, hd.version,
                             &cbs, &settings, &tp, nullptr, c) != 0)
    return nullptr;

  ngtcp2_conn_set_tls_native_handle(c->conn, c->ossl);

  // Keep a live connection's idle timers fed. Nothing else does: an h3
  // connection sends packets only when the application has bytes to move, and
  // RFC 9000 10.1 restarts an endpoint's idle timer on a *received* packet (a
  // peer that only sends, like a WebSocket client waiting for its echo, does not
  // refresh its own). So any gap in application data -- a loop thread
  // descheduled on an oversubscribed host, a slow handler, the drain pause --
  // goes entirely silent, and whichever peer notices first closes the
  // connection with "Idle timeout" against a server that is perfectly healthy.
  // ngtcp2's keep-alive turns that gap into a PING, which is ack-eliciting and
  // so restarts the timer at both ends; a third of the window leaves room for
  // two lost PINGs before the peer gives up.
  ngtcp2_conn_set_keep_alive_timeout(c->conn,
                                     idle_sec * NGTCP2_SECONDS / 3);

  // Route the client's original DCID and our SCID to this conn.
  e->byCid[cidKey(vc->dcid, vc->dcidlen)] = c;
  e->byCid[cidKey(scid.data, scid.datalen)] = c;

  if (e->cfg.cb.on_accept)
    c->conn_ud = e->cfg.cb.on_accept(e->cfg.user, reinterpret_cast<VqConn *>(c),
                                     const_cast<char *>(c->peer_ip.c_str()));

  // on_accept returning NULL rejects the connection (per the header contract).
  // Without honoring it the conn would handshake and drive callbacks with a nil
  // conn_ud, which the Nim side dereferences (#255). Emit CONNECTION_CLOSE and do
  // not admit it. (Latent today: cbAccept never returns nil, but the contract is
  // now enforced for any future admission policy.)
  if (e->cfg.cb.on_accept && c->conn_ud == nullptr) {
    c->wantClose = true;
    e->conns.push_back(std::move(owned));   // reaped on the next pump after CLOSE
    return c;
  }

  e->conns.push_back(std::move(owned));
  return c;
}

// --- egress -----------------------------------------------------------------

// Emit the pending CONNECTION_CLOSE(ccerr) and mark the conn for reaping: the
// terminal packet ngtcp2 documents for every error path other than DRAINING,
// DROP_CONN and an idle close.
void sendConnClose(Conn *c, uint64_t now_ns) {
  uint8_t buf[kMaxUdpPayload];
  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi{};
  ngtcp2_ssize nw = ngtcp2_conn_write_connection_close(
      c->conn, &ps.path, &pi, buf, sizeof buf, &c->ccerr, now_ns);
  auto &send = c->engine->cfg.cb.on_send;
  if (nw > 0 && send)
    send(c->engine->cfg.user, reinterpret_cast<VqConn *>(c), buf,
         static_cast<size_t>(nw), ps.path.remote.addr, ps.path.remote.addrlen);
  c->closed = true;
}

void writeConn(Conn *c, uint64_t now_ns) {
  if (!c->conn || c->closed) return;
  uint8_t buf[kMaxUdpPayload];
  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi{};
  auto &send = c->engine->cfg.cb.on_send;

  // A pending HTTP/3/QPACK error: emit one CONNECTION_CLOSE with the app error
  // code, then reap the connection.
  if (c->wantClose) {
    sendConnClose(c, now_ns);
    return;
  }

  for (;;) {
    int64_t sid = -1;
    int fin = 0;
    nghttp3_vec vec[16];
    nghttp3_ssize vcnt = 0;
    if (c->h3 && ngtcp2_conn_get_max_data_left(c->conn)) {
      vcnt = nghttp3_conn_writev_stream(c->h3, &sid, &fin, vec, 16);
      if (vcnt < 0) {
        // Same nghttp3 contract as the read path: the connection is in error
        // and only nghttp3_conn_del may still be called. Dropping the Conn
        // silently (the old behaviour) left c->h3 alive and reachable from
        // vq_stream_write / vq_submit_response until the next pump reaped it
        // (#362). failConn deletes it and sets the h3 error code; emit the
        // terminal CONNECTION_CLOSE instead of going silent (R15).
        failConn(c, static_cast<int>(vcnt));
        sendConnClose(c, now_ns);
        return;
      }
    }
    ngtcp2_ssize ndatalen = 0;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    ngtcp2_ssize nw = ngtcp2_conn_writev_stream(
        c->conn, &ps.path, &pi, buf, sizeof buf, &ndatalen, flags, sid,
        reinterpret_cast<const ngtcp2_vec *>(vec),
        static_cast<size_t>(vcnt < 0 ? 0 : vcnt), now_ns);
    if (nw < 0) {
      switch (nw) {
      case NGTCP2_ERR_WRITE_MORE:
        if (c->h3 && sid >= 0)
          nghttp3_conn_add_write_offset(c->h3, sid, static_cast<size_t>(ndatalen));
        continue;
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
        if (c->h3 && sid >= 0) nghttp3_conn_block_stream(c->h3, sid);
        continue;
      case NGTCP2_ERR_DRAINING:
        c->draining = true; return;
      default:
        c->closed = true; return;
      }
    }
    if (ndatalen >= 0 && c->h3 && sid >= 0)
      nghttp3_conn_add_write_offset(c->h3, sid, static_cast<size_t>(ndatalen));
    if (nw == 0) {
      // Nothing left to send. For a graceful close (vq_conn_close): the queued
      // h3 control frames -- notably the final GOAWAY submitted by
      // vq_conn_shutdown -- have now been serialized, so emit the
      // CONNECTION_CLOSE(ccerr) that completes the clean shutdown instead of
      // going silent and forcing the peer to wait out its idle timeout (R15).
      if (c->wantGracefulClose && !c->closed) {
        ngtcp2_ssize cw = ngtcp2_conn_write_connection_close(
            c->conn, &ps.path, &pi, buf, sizeof buf, &c->ccerr, now_ns);
        if (cw > 0 && send)
          send(c->engine->cfg.user, reinterpret_cast<VqConn *>(c), buf,
               static_cast<size_t>(cw), ps.path.remote.addr,
               ps.path.remote.addrlen);
        c->closed = true;
      }
      return;   // congestion-limited or nothing left to send
    }
    if (send && send(c->engine->cfg.user, reinterpret_cast<VqConn *>(c), buf,
                     static_cast<size_t>(nw), ps.path.remote.addr,
                     ps.path.remote.addrlen) < 0)
      return;
  }
}

}  // namespace

// ===========================================================================
// C ABI
// ===========================================================================

extern "C" {

static int alpnSelect(SSL *, const unsigned char **out, unsigned char *outlen,
                      const unsigned char *in, unsigned int inlen, void *) {
  // Offer h3 only.
  static const unsigned char h3[] = {2, 'h', '3'};
  if (SSL_select_next_proto((unsigned char **)out, outlen, h3, sizeof h3, in,
                            inlen) != OPENSSL_NPN_NEGOTIATED)
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  return SSL_TLSEXT_ERR_OK;
}

// Passphrase callback for encrypted PEM keys. `u` is the NUL-terminated
// passphrase (or null). Passing this explicitly to every PEM_read_bio_PrivateKey
// keeps OpenSSL from falling back to its built-in callback, which prompts on the
// controlling tty (blocking) when a key is encrypted and no callback is given.
static int vqPasswdCb(char *buf, int size, int /*rwflag*/, void *u) {
  if (!u) return 0;
  const char *pw = static_cast<const char *>(u);
  int n = static_cast<int>(strlen(pw));
  if (n > size) n = size;
  memcpy(buf, pw, static_cast<size_t>(n));
  return n;
}

// Load a private key into `ctx` from a PEM blob (`pem`) or, if that is empty, a
// PEM file (`file`), decrypting with `pw` if set. Never prompts (see vqPasswdCb).
static bool loadKey(SSL_CTX *ctx, const char *pem, const char *file,
                    const char *pw) {
  BioPtr b((pem && pem[0])   ? BIO_new_mem_buf(pem, -1)
           : (file && file[0]) ? BIO_new_file(file, "r")
                               : nullptr);
  if (!b) return false;
  EvpPkeyPtr k(PEM_read_bio_PrivateKey(b.get(), nullptr, vqPasswdCb,
                                       const_cast<char *>(pw)));
  // The error queue is deliberately left alone: makeCtx reads the reason out of
  // it so a refused reload can tell the operator what was wrong (#352).
  if (!k) return false;
  return SSL_CTX_use_PrivateKey(ctx, k.get()) == 1;
}

// Load the leaf cert (+ any following chain certs) into `ctx` from a PEM blob.
// A chain that does not parse in full is rejected: PEM_read_bio_X509 returns
// null for every failure, not only end-of-data, so the error queue is what
// distinguishes a clean EOF (PEM's benign "no start line") from a mangled or
// truncated block. Clearing it unconditionally would install a silently
// truncated, leaf-only chain. Mirrors OpenSSL's own
// SSL_CTX_use_certificate_chain_file and the TCP path's loadCertChainMem.
static bool loadCertChain(SSL_CTX *ctx, const char *pem) {
  BioPtr b(BIO_new_mem_buf(pem, -1));
  if (!b) return false;
  // Drop whatever chain the ctx already holds before appending this one.
  // SSL_CTX_use_certificate does NOT touch the chain (unlike
  // SSL_CTX_use_certificate_chain_file, which clears it first), so loading into
  // a context that already had a certificate left the previous leaf's
  // intermediates in place and stacked the new ones on top: after a CA rotated
  // its intermediate, h3 clients were handed the new leaf together with the
  // old, no-longer-valid intermediates, and the chain grew with every reload
  // (#354). Harmless on a fresh context, which is the only caller left now that
  // a reload builds one (#352), but the function has to be correct on its own.
  // Note that SSL_CTX_clear_chain_certs clears the chain of the currently
  // selected key slot only, not every slot the ctx may hold. That is exactly
  // right here: every live reload builds a fresh context and loads one leaf
  // into it, so there is never a second slot to leave behind.
  (void)SSL_CTX_clear_chain_certs(ctx);
  ERR_clear_error();   // so the peek below sees only our own errors
  X509Ptr leaf(PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr));
  bool ok = leaf && SSL_CTX_use_certificate(ctx, leaf.get()) == 1;
  while (ok) {
    X509Ptr x(PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr));
    if (!x) {
      const unsigned long e = ERR_peek_last_error();
      if (ERR_GET_LIB(e) == ERR_LIB_PEM &&
          ERR_GET_REASON(e) == PEM_R_NO_START_LINE)
        ERR_clear_error();               // end of PEM data
      else
        ok = false;                      // a real parse error: reject
      break;
    }
    // add0 takes ownership on success, so release; on failure the unique_ptr frees.
    if (SSL_CTX_add0_chain_cert(ctx, x.get()) != 1) ok = false;
    else (void)x.release();
  }
  return ok;
}

// Load cert + key (+ any bundled CA chain) into `ctx` from a PKCS#12 bundle:
// DER bytes (`data`/`len`) or, if empty, a .pfx/.p12 file (`file`). `pw` is the
// bundle passphrase (may be empty). Mirrors the TCP path's loadPkcs12.
static bool loadPkcs12(SSL_CTX *ctx, const uint8_t *data, size_t len,
                       const char *file, const char *pw) {
  BioPtr b(len ? BIO_new_mem_buf(data, static_cast<int>(len))
           : (file && file[0]) ? BIO_new_file(file, "rb")
                               : nullptr);
  if (!b) return false;
  (void)SSL_CTX_clear_chain_certs(ctx);   // same accumulation as loadCertChain
                                          // (add1_chain_cert appends), #354;
                                          // the selected key slot's chain, all
                                          // a fresh context ever has
  PKCS12 *p12 = d2i_PKCS12_bio(b.get(), nullptr);
  if (!p12) return false;   // reason left queued for makeCtx (#352)
  EVP_PKEY *pkey = nullptr;
  X509 *cert = nullptr;
  STACK_OF(X509) *ca = nullptr;
  bool ok = PKCS12_parse(p12, pw ? pw : "", &pkey, &cert, &ca) == 1;
  PKCS12_free(p12);
  if (ok) {
    // use_certificate / use_PrivateKey up-ref; add1_chain_cert up-refs each CA,
    // so our references below are freed uniformly regardless of success.
    ok = cert && pkey && SSL_CTX_use_certificate(ctx, cert) == 1 &&
         SSL_CTX_use_PrivateKey(ctx, pkey) == 1;
    if (ok && ca)
      for (int i = 0; i < sk_X509_num(ca); i++)
        if (SSL_CTX_add1_chain_cert(ctx, sk_X509_value(ca, i)) != 1) {
          ok = false;
          break;
        }
  }
  if (cert) X509_free(cert);
  if (pkey) EVP_PKEY_free(pkey);
  if (ca) sk_X509_pop_free(ca, X509_free);
  return ok;
}

// Add PEM CA certificate(s) from memory to the ctx's trust store: the anchors
// for client-certificate verification. Mirrors the TCP path's loadCaMem,
// including its error-queue discipline (#368): a null from PEM_read_bio_X509 is
// clean end of data only when the queue's last reason is PEM_R_NO_START_LINE.
// Any other reason (a truncated or damaged bundle) must fail the configuration
// rather than install a partial trust store, which would reject every client
// issued by a CA past the damage with nothing logged.
static bool loadCaMem(SSL_CTX *ctx, const char *pem) {
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  if (!store || !pem || !pem[0]) return false;
  BioPtr b(BIO_new_mem_buf(pem, -1));
  if (!b) return false;
  int added = 0;
  for (;;) {
    X509Ptr x(PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr));
    if (!x) {
      const bool eof =
          ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE;
      ERR_clear_error();
      if (!eof) return false;
      break;
    }
    if (X509_STORE_add_cert(store, x.get()) != 1) return false;  // up-refs x
    ++added;
  }
  return added > 0;
}

// Configure mTLS: load the client-cert CA (if any) and set the verify mode.
// Same shape and precedence as the TCP path's applyClientVerify, so a
// verifyClient policy means the same thing on QUIC (#351).
static bool applyClientVerify(SSL_CTX *ctx, const VqConfig *cfg) {
  if (cfg->verify_client == 0) return true;   // SSL_VERIFY_NONE
  if (cfg->client_ca_pem && cfg->client_ca_pem[0]) {
    if (!loadCaMem(ctx, cfg->client_ca_pem)) return false;
  } else if (cfg->client_ca_file && cfg->client_ca_file[0]) {
    if (SSL_CTX_load_verify_locations(ctx, cfg->client_ca_file, nullptr) != 1)
      return false;
  }
  SSL_CTX_set_verify(ctx, cfg->verify_client, nullptr);  // null cb: default check
  return true;
}

// Drain the OpenSSL error queue into a readable reason (its oldest entry, which
// ERR_get_error pops and is the one closest to the root cause), leaving the
// queue empty. The loaders above report a bare bool, so the reason has to be
// collected by the step that failed or it is lost -- which is why every refused
// QUIC reload used to reach the operator as the same generic log line (#352).
static std::string sslErrStr() {
  const unsigned long e = ERR_get_error();
  if (e == 0) return "";
  char buf[256];
  ERR_error_string_n(e, buf, sizeof buf);
  ERR_clear_error();
  return std::string(buf);
}

// Why `path` cannot be opened for reading, or "" when it can (and "" for an
// empty path, which means the material comes from elsewhere). A missing or
// unreadable certificate/key FILE leaves nothing useful in OpenSSL's error
// queue: the rejection reached the operator as "cannot load TLS
// certificate/key: error:80000002:system library::No such file or directory",
// naming neither the path nor which half of the pair failed. Mirrors the TCP
// path's readMaterialFile, which prefixes the path and the OS reason (#377).
static std::string fileOpenError(const char *path) {
  if (!path || !path[0]) return "";
  FILE *f = fopen(path, "rb");
  if (!f) return std::string(strerror(errno));
  fclose(f);
  return "";
}

// --- process-wide TLS 1.3 session-ticket keys (#382) -----------------------
//
// Every loop thread builds its own QUIC SSL_CTX, and OpenSSL generates a fresh
// random ticket key per context, so a ticket issued on one loop could only be
// decrypted on that loop -- while which loop receives a returning client's
// first datagram is decided by the kernel's SO_REUSEPORT hash over its NEW
// 4-tuple, which has no relationship to the issuing loop. On an N-loop server
// roughly (N-1)/N of resumption attempts therefore fell back to a full
// handshake, invisibly: the connection succeeded, just a round trip slower,
// every time. The contexts stay per-loop (the per-loop reload is built on
// that); the ticket key is shared instead, which is the sharing the TCP path
// gets for free from its single ctx.
//
// The keys rotate: the current key encrypts, the previous one still decrypts
// for one more lifetime and the callback returns 2 so OpenSSL reissues the
// ticket under the current key, and any older name is refused (0), which costs
// that client one full handshake. Without rotation a memory disclosure would
// compromise every session resumed since startup, which is why nginx and envoy
// both rotate. The callback runs on every loop thread, so the state is behind a
// mutex; it is touched once per ticket, not per packet.
//
// 0-RTT early data is NOT offered anywhere in the shim (nothing enables early
// data on the SSL or sets an early-data context), so this is about session
// resumption only and does not change what a client may send on its first
// flight.

constexpr uint64_t kTicketKeyLifetimeSec = 3600;
constexpr size_t kTicketKeyNameLen = 16;
constexpr size_t kTicketAesIvLen = 16;    // AES-256-CBC

struct TicketKey {
  unsigned char name[kTicketKeyNameLen]{};
  unsigned char aes[32]{};    // AES-256-CBC key
  unsigned char hmac[32]{};   // HMAC-SHA256 key
  bool valid = false;
};

static std::mutex gTicketMu;
static TicketKey gTicketCur;
static TicketKey gTicketPrev;
static std::chrono::steady_clock::time_point gTicketBorn;
// How many times OpenSSL has invoked the callback below, per direction.
// Diagnostics only, and the only way a test can observe that the callback is
// installed on an engine's SSL_CTX at all: driving ticketKeyCb directly proves
// the key is shared and rotates, but passes just as happily with the
// SSL_CTX_set_tlsext_ticket_key_evp_cb line deleted from makeCtx
// (tests/vq_h3_tls_ctx.cpp runs real handshakes against these).
static uint64_t gTicketEncRuns = 0;
static uint64_t gTicketDecRuns = 0;

static bool genTicketKey(TicketKey *k) {
  if (RAND_bytes(k->name, sizeof k->name) != 1 ||
      RAND_bytes(k->aes, sizeof k->aes) != 1 ||
      RAND_bytes(k->hmac, sizeof k->hmac) != 1) {
    ERR_clear_error();
    return false;
  }
  k->valid = true;
  return true;
}

// Caller holds gTicketMu.
static void rotateTicketKeyIfDue() {
  const auto age = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::steady_clock::now() - gTicketBorn)
                       .count();
  if (age < static_cast<long long>(kTicketKeyLifetimeSec)) return;
  TicketKey next;
  if (!genTicketKey(&next)) return;   // RNG trouble: keep the current key
  gTicketPrev = gTicketCur;
  gTicketCur = next;
  gTicketBorn = std::chrono::steady_clock::now();
}

// Rotate on the clock, not only on ticket traffic. Rotation used to be driven
// from the `enc` branch of the callback alone, so the hourly bound held only
// while tickets were being issued: on a server that went quiet, a ticket minted
// at t=0 was still accepted at t=10h, and "a disclosed key exposes at most two
// hours of resumed sessions" was not true of an idle deployment (#382). The
// loops call this once per engine tick (at least once a second), which is one
// steady_clock read under the mutex.
static void ticketKeyTick() {
  std::lock_guard<std::mutex> lock(gTicketMu);
  if (gTicketCur.valid) rotateTicketKeyIfDue();
}

static bool ticketMacInit(EVP_MAC_CTX *hctx, const unsigned char *key,
                          size_t len) {
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_utf8_string(
      OSSL_MAC_PARAM_DIGEST, const_cast<char *>(SN_sha256), 0);
  params[1] = OSSL_PARAM_construct_end();
  return EVP_MAC_init(hctx, key, len, params) == 1;
}

static int ticketKeyCb(SSL * /*ssl*/, unsigned char key_name[16],
                       unsigned char iv[EVP_MAX_IV_LENGTH],
                       EVP_CIPHER_CTX *ctx, EVP_MAC_CTX *hctx, int enc) {
  std::lock_guard<std::mutex> lock(gTicketMu);
  // Normally seeded by osslInitOnce before any engine exists; self-heal rather
  // than fail a handshake if a context somehow got here first.
  if (!gTicketCur.valid) {
    if (!genTicketKey(&gTicketCur)) return -1;
    gTicketBorn = std::chrono::steady_clock::now();
  }
  if (enc) {
    ++gTicketEncRuns;
    rotateTicketKeyIfDue();
    if (RAND_bytes(iv, static_cast<int>(kTicketAesIvLen)) != 1) {
      ERR_clear_error();
      return -1;
    }
    memcpy(key_name, gTicketCur.name, kTicketKeyNameLen);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, gTicketCur.aes,
                           iv) != 1)
      return -1;
    return ticketMacInit(hctx, gTicketCur.hmac, sizeof gTicketCur.hmac) ? 1
                                                                        : -1;
  }
  ++gTicketDecRuns;
  const TicketKey *k = nullptr;
  int rv = 1;
  if (memcmp(key_name, gTicketCur.name, kTicketKeyNameLen) == 0) {
    k = &gTicketCur;
  } else if (gTicketPrev.valid &&
             memcmp(key_name, gTicketPrev.name, kTicketKeyNameLen) == 0) {
    k = &gTicketPrev;
    rv = 2;   // accept, and reissue the ticket under the current key
  }
  if (!k) return 0;   // retired or foreign key name: a full handshake
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, k->aes, iv) != 1)
    return -1;
  return ticketMacInit(hctx, k->hmac, sizeof k->hmac) ? rv : -1;
}

// A readable rendering of an ASN1_TIME ("Jan  2 00:00:00 2020 GMT"), or "" if
// OpenSSL will not print it.
static std::string asn1TimeStr(const ASN1_TIME *t) {
  BioPtr b(BIO_new(BIO_s_mem()));
  if (!b || ASN1_TIME_print(b.get(), t) != 1) {
    ERR_clear_error();
    return "";
  }
  char buf[64];
  const int n = BIO_read(b.get(), buf, static_cast<int>(sizeof buf) - 1);
  if (n <= 0) { ERR_clear_error(); return ""; }
  return std::string(buf, static_cast<size_t>(n));
}

// Why the context's leaf certificate must not be installed, or "" when it is
// inside its validity window. Nothing checked notBefore/notAfter on either
// transport, so an expired certificate loaded cleanly and a reload pointed at
// an archived copy (or racing a certbot symlink swap) reported success while
// every new client failed with certificate_expired (#379). Hard failure, with
// no clock-skew allowance: serving an expired certificate is never intentional,
// and refusing it at load time keeps the running certificate on a reload.
static std::string certValidityError(SSL_CTX *ctx) {
  X509 *x = SSL_CTX_get0_certificate(ctx);
  if (!x) return "no certificate";
  // X509_cmp_current_time returns < 0 for a time in the past, > 0 for one in
  // the future, and 0 only when it cannot parse the field. A field that will
  // not parse is a rejection too, not a pass: treating it as valid let a
  // certificate whose notAfter OpenSSL cannot read install as if it were
  // in-window, which is the one case where we know nothing about the window at
  // all. The TCP side rejects it identically.
  ASN1_TIME *notAfter = X509_getm_notAfter(x);
  if (!notAfter) return "certificate has no notAfter";
  const int after = X509_cmp_current_time(notAfter);
  if (after < 0) return "certificate expired at " + asn1TimeStr(notAfter);
  if (after == 0) return "certificate validity time could not be parsed";
  ASN1_TIME *notBefore = X509_getm_notBefore(x);
  if (!notBefore) return "certificate has no notBefore";
  const int before = X509_cmp_current_time(notBefore);
  if (before > 0)
    return "certificate not valid until " + asn1TimeStr(notBefore);
  if (before == 0) return "certificate validity time could not be parsed";
  return "";
}

// `err`, when given, is filled with the step that failed plus whatever OpenSSL
// queued about it, so vq_engine_reload_cert / vq_engine_new can report a cause
// instead of a bare failure.
static SslCtxPtr makeCtx(const VqConfig *cfg, std::string *err = nullptr) {
  auto fail = [err](const char *what) -> SslCtxPtr {
    if (err) {
      const std::string reason = sslErrStr();
      *err = reason.empty() ? std::string(what)
                            : std::string(what) + ": " + reason;
    }
    ERR_clear_error();
    return nullptr;
  };
  // For a reason that does not come out of OpenSSL's queue (an unreadable file,
  // a validity window), so it is reported verbatim instead of being glued to
  // whatever happened to be queued.
  auto failWith = [err](const std::string &why) -> SslCtxPtr {
    if (err) *err = why;
    ERR_clear_error();
    return nullptr;
  };
  // "" when `path` can be read, else the message naming it and the OS reason:
  // a material file diagnosed before OpenSSL loses the reason (#377).
  auto unreadable = [](const char *path, const char *what) {
    const std::string why = fileOpenError(path);
    return why.empty() ? std::string()
                       : "cannot read " + std::string(what) + " " +
                             std::string(path) + ": " + why;
  };
  SslCtxPtr ctx(SSL_CTX_new(TLS_server_method()));
  if (!ctx) return fail("SSL_CTX_new failed");
  // Protocol versions. QUIC mandates TLS 1.3 (RFC 9001 4.2), so both ends stay
  // pinned there: that clamps a configured minTlsVersion of TLS 1.2 up instead
  // of honoring it. A configured maxTlsVersion *below* 1.3 cannot be honored at
  // all, so it is refused: returning nullptr fails vq_engine_new, which leaves
  // h3 off and unadvertised rather than negotiating outside the operator's
  // policy. That combination is also rejected at config time (#359); this is
  // the fail-closed backstop.
  if (cfg->max_tls_version != 0 && cfg->max_tls_version < TLS1_3_VERSION)
    return fail("maxTlsVersion below TLS 1.3 cannot apply to QUIC");
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
  // TLS 1.3 cipher suites: the operator's list, or OpenSSL's default when
  // unset. The TLS <= 1.2 cipher list has no counterpart here (no QUIC
  // connection ever negotiates TLS 1.2), so it is not applied.
  if (cfg->tls_cipher_suites && cfg->tls_cipher_suites[0] &&
      SSL_CTX_set_ciphersuites(ctx.get(), cfg->tls_cipher_suites) != 1)
    return fail("invalid TLS 1.3 cipher suites");
  // That list is a preference order, not a set. Without
  // SSL_OP_SERVER_PREFERENCE (the name OpenSSL 3.6.0 introduced for the bit
  // that 3.5, this project's minimum, spells only
  // SSL_OP_CIPHER_SERVER_PREFERENCE; see the fallback define at the top of this
  // file) OpenSSL walks the CLIENT's ciphersuite list and takes the first entry
  // we also allow, so tlsCipherSuites would be an unordered allow-set here and
  // an ordered preference on TCP: the same configuration, two answers,
  // depending only on which transport the client picked (#375).
  // SSL_OP_NO_RENEGOTIATION has no counterpart to add -- QUIC is
  // TLS 1.3 only and TLS 1.3 has no renegotiation. Nor is there a counterpart to
  // the TCP side's RFC 7540 Appendix A screen of tlsCipherList: QUIC never
  // negotiates TLS 1.2, and every TLS 1.3 ciphersuite is AEAD, so a QUIC
  // handshake cannot land on a suite HTTP/2 (or HTTP/3) refuses.
  //
  // The bit is wider than ciphers. OpenSSL 3.5, this project's minimum, already
  // extended it to cover server-side TLS 1.3 key exchange group selection, and
  // 3.6 documents the whole scope: "when choosing a cipher, signature, (TLS
  // 1.2) curve or (TLS 1.3) group, use the server's preferences". So ECDH group
  // and signature-algorithm selection follow our order too. That is the policy
  // we want (the server decides) and it costs no round trip: the group list
  // here is OpenSSL's default, and OpenSSL still picks a group the client sent
  // a key share for when that group is in our list, so no HelloRetryRequest
  // appears.
  //
  // SSL_OP_PRIORITIZE_CHACHA keeps our order except for a client whose own first
  // choice is ChaCha20-Poly1305, which in practice means a client with no AES
  // hardware. With tls_cipher_suites unset the operator stated no policy -- the
  // order we would be enforcing is just OpenSSL's built-in one -- so the
  // courtesy is granted, matching Go's crypto/tls and the BoringSSL-based
  // servers. A configured list IS a policy statement, so it is withheld there.
  // The TCP side keys the same decision off both lists being empty; QUIC has
  // only this one, so an operator who sets tlsCipherList alone gets strict
  // server order on TCP for both TLS versions while QUIC, which has no TLS 1.2
  // to order, keeps the ChaCha courtesy.
  uint64_t opts = SSL_OP_SERVER_PREFERENCE;
  if (!cfg->tls_cipher_suites || !cfg->tls_cipher_suites[0])
    opts |= SSL_OP_PRIORITIZE_CHACHA;
  SSL_CTX_set_options(ctx.get(), opts);
  // Every per-host (SNI) context is built by this same function via ctxConfig,
  // so they carry these options too. That is defence in depth, not what makes
  // an SNI connection ordered: SSL_set_SSL_CTX in servernameCb does not re-read
  // options, and a connection's option word is the copy SSL_new took from the
  // context it was created on, which is always the default one. The per-host bit
  // is inert at runtime; it is here so that a future refactor creating the SSL
  // from a host context cannot silently drop the policy.
  // The ossl backend has no CTX-level configure; per-connection setup happens in
  // ngtcp2_crypto_ossl_configure_server_session(ssl) at accept time.
  SSL_CTX_set_alpn_select_cb(ctx.get(), alpnSelect, nullptr);
  // Session resumption. Tickets are issued by default (SSL_OP_NO_TICKET is
  // never set, and the ngtcp2 ossl backend does not change that: it only
  // registers the QUIC record-layer callbacks on the SSL, so the TLS stack
  // builds and encrypts tickets as usual and they travel in CRYPTO frames).
  // The key is process-wide so a returning client resumes on whichever loop the
  // kernel's SO_REUSEPORT hash hands it, instead of only on the loop that
  // issued the ticket (#382). An explicit session-id context goes with it, like
  // the TCP path's: under client-cert auth OpenSSL refuses to resume a session
  // that has none.
  SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx.get(), ticketKeyCb);
  static const unsigned char kSidCtx[] = "vortex-h3/1";
  SSL_CTX_set_session_id_context(ctx.get(), kSidCtx, sizeof kSidCtx - 1);
  bool ok;
  if ((cfg->pkcs12 && cfg->pkcs12_len) ||
      (cfg->pkcs12_file && cfg->pkcs12_file[0])) {
    // PKCS#12 bundle carries both cert and key (matches the TCP path's order).
    if (!(cfg->pkcs12 && cfg->pkcs12_len)) {
      const std::string why = unreadable(cfg->pkcs12_file, "PKCS#12 bundle");
      if (!why.empty()) return failWith(why);
    }
    ok = loadPkcs12(ctx.get(), cfg->pkcs12, cfg->pkcs12_len, cfg->pkcs12_file,
                    cfg->key_password);
  } else {
    // Cert: in-memory PEM takes precedence over the file (matches the TCP path).
    ok = true;
    if (cfg->cert_pem && cfg->cert_pem[0]) {
      ok = loadCertChain(ctx.get(), cfg->cert_pem);
    } else if (cfg->cert_file && cfg->cert_file[0]) {
      const std::string why = unreadable(cfg->cert_file, "certificate");
      if (!why.empty()) return failWith(why);
      ok = SSL_CTX_use_certificate_chain_file(ctx.get(), cfg->cert_file) == 1;
    }
    // Key: PEM blob or file, decrypted with key_password, never prompting.
    if (ok && cfg->key_pem && cfg->key_pem[0]) {
      ok = loadKey(ctx.get(), cfg->key_pem, cfg->key_file, cfg->key_password);
    } else if (ok && cfg->key_file && cfg->key_file[0]) {
      const std::string why = unreadable(cfg->key_file, "private key");
      if (!why.empty()) return failWith(why);
      ok = loadKey(ctx.get(), cfg->key_pem, cfg->key_file, cfg->key_password);
    }
  }
  // Fail closed: require a certificate AND a matching private key. Without this
  // a config that loaded neither (e.g. PKCS#12-only before this was wired, or an
  // empty/half TLS config) would yield a keyless SSL_CTX that vq_engine_new
  // accepts, so h3 would be advertised via Alt-Svc yet every handshake would
  // fail. check_private_key returns 1 only when both are set and they match.
  if (!ok) return fail("cannot load TLS certificate/key");
  if (SSL_CTX_check_private_key(ctx.get()) != 1)
    return fail("certificate/key mismatch");
  // Validity last among the material checks, so a mismatch is still reported as
  // a mismatch. No OpenSSL error is queued for this one, so it does not go
  // through fail().
  const std::string invalid = certValidityError(ctx.get());
  if (!invalid.empty()) {
    if (err) *err = invalid;
    ERR_clear_error();
    return nullptr;
  }
  // Client-certificate policy last, like the TCP path's buildTlsCtx. Fail
  // closed: a verifyClient config whose CA material will not load must not
  // yield an engine that accepts unauthenticated connections (#351).
  if (!applyClientVerify(ctx.get(), cfg))
    return fail("cannot configure client verification / load client CA");
  return ctx;   // unique_ptr frees the ctx on every failure path above
}

// --- SNI: one context per host, switched by the servername callback (#374) ---

static Material materialOf(const VqSniCert *s) {
  auto str = [](const char *p) { return std::string(p ? p : ""); };
  Material m;
  m.host = str(s->host);
  m.cert_file = str(s->cert_file);
  m.key_file = str(s->key_file);
  m.cert_pem = str(s->cert_pem);
  m.key_pem = str(s->key_pem);
  m.key_password = str(s->key_password);
  m.pkcs12_file = str(s->pkcs12_file);
  if (s->pkcs12 && s->pkcs12_len)
    m.pkcs12.assign(reinterpret_cast<const char *>(s->pkcs12), s->pkcs12_len);
  return m;
}

// Same, for the default certificate's material in a VqConfig.
static Material materialOfConfig(const VqConfig *c) {
  auto str = [](const char *p) { return std::string(p ? p : ""); };
  Material m;
  m.cert_file = str(c->cert_file);
  m.key_file = str(c->key_file);
  m.cert_pem = str(c->cert_pem);
  m.key_pem = str(c->key_pem);
  m.key_password = str(c->key_password);
  m.pkcs12_file = str(c->pkcs12_file);
  if (c->pkcs12 && c->pkcs12_len)
    m.pkcs12.assign(reinterpret_cast<const char *>(c->pkcs12), c->pkcs12_len);
  return m;
}

// A VqConfig view over the engine's retained TLS policy plus `m`'s certificate
// material: what makeCtx needs to build a per-host context, or rebuild one after
// the caller's pointers are gone. Going through makeCtx is the point -- a host
// context inherits the client verification, cipher suites and TLS 1.3 pinning of
// the default one instead of drifting from it.
static VqConfig ctxConfig(const Engine *e, const Material &m) {
  VqConfig c = e->cfg;    // policy fields (its string pointers were cleared)
  c.tls_cipher_suites = e->cipher_suites.c_str();
  c.client_ca_file = e->client_ca_file.c_str();
  c.client_ca_pem = e->client_ca_pem.c_str();
  c.cert_file = m.cert_file.c_str();
  c.key_file = m.key_file.c_str();
  c.cert_pem = m.cert_pem.c_str();
  c.key_pem = m.key_pem.c_str();
  c.key_password = m.key_password.c_str();
  c.pkcs12_file = m.pkcs12_file.c_str();
  c.pkcs12 = m.pkcs12.empty()
                 ? nullptr
                 : reinterpret_cast<const uint8_t *>(m.pkcs12.data());
  c.pkcs12_len = m.pkcs12.size();
  c.sni = nullptr;
  c.sni_len = 0;
  return c;
}

// (Re)build a per-host context for every entry in `mats` into `out`. All or
// nothing: nothing is written unless every host built, so a broken per-host
// certificate cannot quietly drop that host back to the default certificate.
// Writing into a caller-supplied vector is what lets a reload stage the
// per-host contexts alongside the new default one and publish both together
// (#352), and taking the material as a parameter is what lets it stage a
// REPLACEMENT host set the same way (#356).
static bool buildSniCtxs(Engine *e, const std::vector<Material> &mats,
                         std::vector<SslCtxPtr> &out,
                         std::string *err = nullptr) {
  std::vector<SslCtxPtr> built;
  built.reserve(mats.size());
  for (const auto &m : mats) {
    VqConfig c = ctxConfig(e, m);
    std::string why;
    SslCtxPtr hc = makeCtx(&c, &why);
    if (!hc) {
      if (err) *err = "per-host certificate for \"" + m.host + "\": " + why;
      return false;
    }
    built.push_back(std::move(hc));
  }
  out = std::move(built);
  return true;
}

static inline char lcAscii(char c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Compare a NUL-terminated SNI name to a configured host, case-insensitively:
// DNS names are case-insensitive and a client may send any casing (RFC 6066).
// The TCP path matches the same way, so a client sending API.Example.com gets
// the same certificate on either transport (#358).
static bool hostEq(const char *name, const std::string &host) {
  size_t i = 0;
  for (; i < host.size(); i++)
    if (name[i] == '\0' || lcAscii(name[i]) != lcAscii(host[i])) return false;
  return name[i] == '\0';
}

// `*.example.com` matches exactly one leading label: foo.example.com yes,
// example.com no, a.b.example.com no. Mirrors the TCP path's wildMatch.
static bool hostWildMatch(const char *name, const std::string &pat) {
  if (pat.size() < 3 || pat[0] != '*' || pat[1] != '.') return false;
  size_t dot = 0;
  while (name[dot] != '\0' && name[dot] != '.') ++dot;
  if (dot == 0 || name[dot] != '.') return false;   // need a label then a dot
  size_t i = dot, j = 1;                            // both include the dot
  for (; j < pat.size(); ++i, ++j)
    if (name[i] == '\0' || lcAscii(name[i]) != lcAscii(pat[j])) return false;
  return name[i] == '\0';
}

// Switch the connection to the context whose host matches the requested server
// name (an exact match wins over a wildcard); no match keeps the default
// context. SSL_set_SSL_CTX replaces the certificate and the context-level
// settings only: the QUIC record-layer callbacks and transport parameters
// ngtcp2_crypto_ossl_configure_server_session installed live on the SSL, so
// they survive the switch.
static int servernameCb(SSL *ssl, int * /*al*/, void *arg) {
  auto *e = static_cast<Engine *>(arg);
  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (name) {
    size_t n = e->sni_ctx.size();
    size_t idx = n;
    for (size_t i = 0; i < n; i++)
      if (hostEq(name, e->sni[i].host)) { idx = i; break; }
    if (idx == n)
      for (size_t i = 0; i < n; i++)
        if (hostWildMatch(name, e->sni[i].host)) { idx = i; break; }
    if (idx < n) SSL_set_SSL_CTX(ssl, e->sni_ctx[idx].get());
  }
  return SSL_TLSEXT_ERR_OK;
}

// ngtcp2_crypto_ossl_init is a once-per-process initializer: it allocates an
// OpenSSL ex_data index and parks it in a library-level global, and it is not
// thread safe. vq_engine_new runs once per loop thread, concurrently, so
// calling it there directly raced -- N-1 indices leaked, and a session
// configured under index i could be read back under index j, which yields a
// null crypto context and a failed handshake (#357). Run it exactly once and
// hand every engine the same verdict, so a failure fails them all instead of
// leaving some threads on a half-initialized backend.
static std::once_flag gOsslInitOnce;
static int gOsslInitRv = -1;
static int gOsslInitRuns = 0;   // how many times the initializer actually ran
                                // (the #357 invariant; see tests/vq_h3_tls_ctx.cpp)

// Why the last vq_engine_new on this thread failed. The engine does not exist
// on that path, so the reason cannot live on it, and one slot per loop thread
// is enough: each thread builds exactly one engine (#352).
static thread_local std::string gEngineError;

static bool osslInitOnce() {
  std::call_once(gOsslInitOnce, [] {
    gOsslInitRv = ngtcp2_crypto_ossl_init();
    // The first process-wide ticket key is generated here too, once, before any
    // loop thread can build a context (#382). A broken RNG fails the engine:
    // nothing about TLS works without it.
    if (gOsslInitRv == 0) {
      std::lock_guard<std::mutex> lock(gTicketMu);
      if (!genTicketKey(&gTicketCur)) gOsslInitRv = -1;
      else gTicketBorn = std::chrono::steady_clock::now();
    }
    ++gOsslInitRuns;
  });
  return gOsslInitRv == 0;
}

VqEngine *vq_engine_new(const VqConfig *cfg) {
  gEngineError.clear();
  if (!osslInitOnce()) {
    gEngineError = "ngtcp2 ossl backend initialization failed";
    return nullptr;
  }
  auto e = std::make_unique<Engine>();
  e->cfg = *cfg;
  e->key_pw = cfg->key_password ? cfg->key_password : "";
  // Don't retain the caller's (possibly transient) TLS-material pointers.
  e->cfg.cert_pem = e->cfg.key_pem = e->cfg.key_password = nullptr;
  e->cfg.cert_file = e->cfg.key_file = nullptr;
  e->cfg.pkcs12_file = nullptr;
  e->cfg.pkcs12 = nullptr;
  e->cfg.pkcs12_len = 0;
  // Same for the TLS policy strings: makeCtx below reads the caller's copies.
  e->cipher_suites = cfg->tls_cipher_suites ? cfg->tls_cipher_suites : "";
  e->client_ca_file = cfg->client_ca_file ? cfg->client_ca_file : "";
  e->client_ca_pem = cfg->client_ca_pem ? cfg->client_ca_pem : "";
  e->cfg.tls_cipher_suites = nullptr;
  e->cfg.client_ca_file = e->cfg.client_ca_pem = nullptr;
  e->def_material = materialOfConfig(cfg);
  for (size_t i = 0; i < cfg->sni_len; i++)
    e->sni.push_back(materialOf(&cfg->sni[i]));
  e->cfg.sni = nullptr;
  e->cfg.sni_len = 0;
  e->ssl_ctx = makeCtx(cfg, &gEngineError);
  if (!e->ssl_ctx) return nullptr;   // unique_ptr frees the Engine on this path
  // Per-host certificates: a context each, selected by the servername callback
  // on the default context. Without this the QUIC side had one context and one
  // certificate per engine, so a client asking for an SNI host over h3 was
  // served the default certificate and aborted, while the same request over TCP
  // got the right one (#374).
  if (!e->sni.empty()) {
    if (!buildSniCtxs(e.get(), e->sni, e->sni_ctx, &gEngineError))
      return nullptr;
    SSL_CTX_set_tlsext_servername_callback(e->ssl_ctx.get(), servernameCb);
    SSL_CTX_set_tlsext_servername_arg(e->ssl_ctx.get(), e.get());
  }
  return reinterpret_cast<VqEngine *>(e.release());
}

void vq_engine_free(VqEngine *eng) {
  if (!eng) return;
  // delete runs ~Engine: the SSL_CTX (unique_ptr member) and every connection's
  // h3/conn/ossl/ssl (~Conn via the conns vector) are freed as it unwinds.
  delete reinterpret_cast<Engine *>(eng);
}

const char *vq_engine_last_error(VqEngine *eng) {
  // No engine: the reason the last vq_engine_new on this thread failed.
  if (!eng) return gEngineError.c_str();
  return reinterpret_cast<Engine *>(eng)->last_error.c_str();
}

int vq_engine_reload_cert(VqEngine *eng, const char *cert_file,
                          const char *key_file, const VqSniCert *sni,
                          size_t sni_len) {
  auto *e = reinterpret_cast<Engine *>(eng);
  e->last_error.clear();
  // Build a complete replacement context and publish it only once every piece
  // of material loaded and the key matches the certificate. The reload used to
  // write into the LIVE ctx, certificate first then key, with no validation and
  // no rollback: OpenSSL's ssl_set_cert silently frees the existing private key
  // when the new leaf does not match it, and ssl_set_pkey silently frees the
  // existing certificate when the new key does not match, so an unreadable,
  // missing or mismatched key left the engine holding a certificate with no
  // private key. Every later h3 handshake on that loop then failed, for good,
  // while the caller was told the old certificate was still serving (#352).
  //
  // Empty paths mean "rebuild from the configured material, re-reading any
  // files", which is what a bare reloadTls() asks for and what the TCP path has
  // always done. Before this the loop resolved nothing: applyQuicReload did
  // readFile("") and the reload failed, so the certbot pattern the project
  // documents (renew in place, then srv.reloadTls()) rotated HTTP/1.1 and
  // HTTP/2 and left HTTP/3 on the certificate loaded at startup until it
  // expired, at which point h3 broke on its own while the other protocols
  // stayed healthy (#353). For material configured as PEM bytes or PKCS#12
  // *bytes* there is nothing to re-read, so the rebuild is a no-op for the
  // default certificate (a configured pkcs12_file IS re-read) and still picks
  // up per-host files replaced on disk.
  const bool haveCert = cert_file && cert_file[0];
  const bool haveKey = key_file && key_file[0];
  Material m = e->def_material;
  // Explicit paths replace whatever the material was sourced from, with the
  // same rules as the TCP path's reloadTlsConfig: a certificate path clears the
  // in-memory PEM and the bundle, and a key-only rotation against a
  // PKCS#12-sourced certificate is refused rather than silently rebuilding the
  // old pair (the bundle carries both halves and takes precedence, so the new
  // key would never be opened).
  const bool p12Sourced = !m.pkcs12.empty() || !m.pkcs12_file.empty();
  if (haveCert && !haveKey && p12Sourced) {
    // The mirror image of the key-only rejection below, and refused for the
    // same reason: clearing the bundle leaves the key half with nothing to
    // load, so makeCtx would report a bare "certificate/key mismatch" (or, on
    // an engine with no key file at all, a certificate with no private key)
    // instead of naming the one thing the operator has to change. Same wording
    // as the TCP path's reloadTlsConfig.
    e->last_error =
        "a certificate-only reload cannot replace a PKCS#12 bundle; rotate "
        "certFile and keyFile together";
    return -1;
  }
  if (haveCert) {
    m.cert_file = cert_file;
    m.cert_pem.clear();
    m.pkcs12.clear();
    m.pkcs12_file.clear();
  }
  if (haveKey) {
    if (!haveCert && p12Sourced) {
      e->last_error = "a key-only reload cannot replace a PKCS#12 certificate";
      return -1;
    }
    m.key_file = key_file;
    m.key_pem.clear();
    m.pkcs12.clear();
    m.pkcs12_file.clear();
  }
  // A hot cert/key swap keeps the passphrase the engine was built with, and
  // ctxConfig carries over the verify policy, cipher suites, version pinning
  // and client CA, so the replacement is the same context with new material.
  m.key_password = e->key_pw;
  VqConfig c = ctxConfig(e, m);
  SslCtxPtr fresh = makeCtx(&c, &e->last_error);
  if (!fresh) return -1;
  // The per-host rebuild joins the same transaction: a per-host certificate
  // rotated on disk by the same renewal is picked up with the default one
  // (#374), and a failure anywhere leaves EVERY context untouched.
  //
  // A non-empty `sni` REPLACES the per-host set wholesale, host names
  // included, which is the override reloadTlsConfig takes on the TCP side.
  // Before this it reached the TCP listener alone: the loops were signalled
  // with the cert/key paths only and rebuilt their host contexts from the
  // material vq_engine_new was given, so a host added through the override was
  // served the DEFAULT certificate over h3 and every client that followed
  // Alt-Svc failed on a name mismatch, while a host removed from it kept being
  // served over h3 for the life of the process (#356, the #374 bug for any
  // host configured after startup). An empty set still means "rebuild the
  // configured per-host material, re-reading its files"; there is deliberately
  // no spelling for "drop every host", matching the TCP path.
  const std::vector<Material> sniM = [&] {
    if (!sni_len) return e->sni;
    std::vector<Material> v;
    v.reserve(sni_len);
    for (size_t i = 0; i < sni_len; i++) v.push_back(materialOf(&sni[i]));
    return v;
  }();
  std::vector<SslCtxPtr> freshSni;
  if (!sniM.empty()) {
    if (!buildSniCtxs(e, sniM, freshSni, &e->last_error)) return -1;
    SSL_CTX_set_tlsext_servername_callback(fresh.get(), servernameCb);
    SSL_CTX_set_tlsext_servername_arg(fresh.get(), e);
  }
  // Past this point nothing can fail, so the swap is atomic from the loop's
  // point of view. Releasing the engine's reference to the old context right
  // away is safe: SSL_new up-refs the SSL_CTX, so an in-flight connection holds
  // a reference of its own and keeps the certificate it handshook with until
  // its SSL is freed. The same goes for a per-host context a connection already
  // switched to: SSL_set_SSL_CTX up-refs what it is handed, so a host dropped
  // by the override here cannot pull the context out from under it.
  if (!sniM.empty()) {
    e->sni = sniM;
    e->sni_ctx = std::move(freshSni);
  }
  e->ssl_ctx = std::move(fresh);
  // Remember what was actually loaded, so the NEXT bare reload re-reads these
  // paths rather than the ones configured at startup. Nothing is persisted on a
  // rejection, matching reloadTlsConfig.
  e->def_material = m;
  return 0;
}

void vq_engine_recv(VqEngine *eng, const uint8_t *pkt, size_t len,
                    const void *peer, size_t peer_len, const void *local,
                    size_t local_len, uint64_t now_ns) {
  auto *e = reinterpret_cast<Engine *>(eng);
  e->cur_peer = peer; e->cur_peer_len = peer_len;
  e->cur_local = local; e->cur_local_len = local_len;

  ngtcp2_version_cid vc;
  int rv = ngtcp2_pkt_decode_version_cid(&vc, pkt, len, kScidLen);
  if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
    // The client offered a QUIC version we don't support: reply with a Version
    // Negotiation packet listing our supported versions (RFC 9000 6.1) so it can
    // retry immediately, instead of dropping the datagram and forcing a timeout.
    // The VN packet echoes the CIDs swapped (its DCID = the client's SCID).
    uint8_t vnbuf[kMaxUdpPayload];
    uint8_t rnd = 0;
    RAND_bytes(&rnd, 1);
    const uint32_t sv[] = {NGTCP2_PROTO_VER_V1};
    ngtcp2_ssize nw = ngtcp2_pkt_write_version_negotiation(
        vnbuf, sizeof vnbuf, rnd, vc.scid, vc.scidlen, vc.dcid, vc.dcidlen,
        sv, sizeof(sv) / sizeof(sv[0]));
    if (nw > 0 && e->cfg.cb.on_send)
      e->cfg.cb.on_send(e->cfg.user, nullptr, vnbuf, static_cast<size_t>(nw),
                        const_cast<void *>(peer), peer_len);
    return;
  }
  if (rv < 0) return;

  Conn *c = nullptr;
  auto it = e->byCid.find(cidKey(vc.dcid, vc.dcidlen));
  if (it != e->byCid.end()) c = it->second;
  if (!c) {
    c = acceptConn(e, pkt, len, &vc, now_ns);
    if (!c) return;
  }
  if (c->wantClose || c->closed) return;   // closing: don't feed more packets

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_init(&ps,
      reinterpret_cast<sockaddr *>(c->local_sa.data()),
      static_cast<socklen_t>(c->local_sa.size()),
      const_cast<sockaddr *>(reinterpret_cast<const sockaddr *>(peer)),
      static_cast<socklen_t>(peer_len), nullptr);
  ngtcp2_pkt_info pi{};
  int r = ngtcp2_conn_read_pkt(c->conn, &ps.path, &pi, pkt, len, now_ns);
  if (r != 0) {
    switch (r) {
    case NGTCP2_ERR_DRAINING:
      c->draining = true;              // peer is closing: enter the drain period
      break;
    case NGTCP2_ERR_DROP_CONN:
      c->closed = true;                // unrecoverable: drop without a close
      break;
    case NGTCP2_ERR_CRYPTO:
      // TLS handshake failure: close with the TLS alert as the reason so the
      // peer learns why instead of idle-timing-out (R15).
      if (!c->wantClose) {
        ngtcp2_ccerr_set_tls_alert(&c->ccerr,
            ngtcp2_conn_get_tls_alert(c->conn), nullptr, 0);
        c->wantClose = true;
      }
      break;
    default:
      // Any other transport error: emit a CONNECTION_CLOSE carrying the mapped
      // transport error code on the next writeConn, instead of going silent and
      // forcing the peer to wait out its idle timeout (R15).
      if (!c->wantClose) {
        ngtcp2_ccerr_set_liberr(&c->ccerr, r, nullptr, 0);
        c->wantClose = true;
      }
      break;
    }
  }
}

void vq_engine_pump(VqEngine *eng, uint64_t now_ns) {
  auto *e = reinterpret_cast<Engine *>(eng);
  for (auto &c : e->conns) writeConn(c.get(), now_ns);

  // Reap closed/draining connections.
  for (auto i = e->conns.begin(); i != e->conns.end();) {
    Conn *c = i->get();
    // Reap a connection in the DRAINING period too (peer sent CONNECTION_CLOSE):
    // in_closing_period is true only when WE sent the close, so without this a
    // peer-initiated close left the Conn/ngtcp2/nghttp3/SSL alive until the full
    // idle timeout -- a slow leak / slot exhaustion (#252).
    bool dead = c->closed || c->draining ||
                (c->conn && (ngtcp2_conn_in_closing_period(c->conn) ||
                             ngtcp2_conn_in_draining_period(c->conn)));
    if (dead) {
      if (e->cfg.cb.on_conn_close && c->conn_ud)
        e->cfg.cb.on_conn_close(e->cfg.user, c->conn_ud);
      for (auto it = e->byCid.begin(); it != e->byCid.end();)
        it = (it->second == c) ? e->byCid.erase(it) : std::next(it);
      i = e->conns.erase(i);   // ~Conn frees h3/conn/ossl/ssl in order
    } else {
      ++i;
    }
  }
}

uint64_t vq_engine_next_expiry_ns(VqEngine *eng, uint64_t) {
  auto *e = reinterpret_cast<Engine *>(eng);
  uint64_t m = UINT64_MAX;
  for (auto &c : e->conns)
    if (c->conn) { uint64_t t = ngtcp2_conn_get_expiry(c->conn); if (t < m) m = t; }
  return m;
}

void vq_engine_handle_expiry(VqEngine *eng, uint64_t now_ns) {
  auto *e = reinterpret_cast<Engine *>(eng);
  // The loops run this on every pass (at least once a second), which is where
  // the session-ticket key's hourly rotation is driven from: see ticketKeyTick.
  ticketKeyTick();
  for (auto &c : e->conns)
    if (c->conn && ngtcp2_conn_get_expiry(c->conn) <= now_ns)
      if (ngtcp2_conn_handle_expiry(c->conn, now_ns) != 0) c->closed = true;
}

// --- response submission ----------------------------------------------------

static std::vector<nghttp3_nv> toNv(const VqHeader *hdrs, size_t n) {
  std::vector<nghttp3_nv> nva;
  nva.reserve(n);
  for (size_t i = 0; i < n; i++)
    nva.push_back(nghttp3_nv{
        (uint8_t *)hdrs[i].name, (uint8_t *)hdrs[i].value,
        hdrs[i].name_len, hdrs[i].value_len, NGHTTP3_NV_FLAG_NONE});
  return nva;
}

void vq_submit_response(VqConn *conn, int64_t stream_id, int /*status*/,
                        const VqHeader *hdrs, size_t n, const uint8_t *body,
                        size_t body_len, int fin) {
  auto *c = reinterpret_cast<Conn *>(conn);
  Stream *s = c->stream(stream_id);
  if (!s || s->headSubmitted || !c->h3) return;
  s->headSubmitted = true;
  if (body && body_len) s->body.push(body, body_len);
  s->body.fin = fin != 0;
  auto nva = toNv(hdrs, n);
  nghttp3_data_reader dr{h3ReadData};
  nghttp3_conn_submit_response(c->h3, stream_id, nva.data(), nva.size(), &dr);
}

void vq_submit_head(VqConn *conn, int64_t stream_id, int /*status*/,
                    const VqHeader *hdrs, size_t n) {
  auto *c = reinterpret_cast<Conn *>(conn);
  Stream *s = c->stream(stream_id);
  if (!s || s->headSubmitted || !c->h3) return;
  s->headSubmitted = true;
  auto nva = toNv(hdrs, n);
  nghttp3_data_reader dr{h3ReadData};
  nghttp3_conn_submit_response(c->h3, stream_id, nva.data(), nva.size(), &dr);
}

size_t vq_stream_write(VqConn *conn, int64_t stream_id, const uint8_t *data,
                       size_t len) {
  auto *c = reinterpret_cast<Conn *>(conn);
  Stream *s = c->stream(stream_id);
  if (!s || !c->h3) return 0;
  if (data && len) s->body.push(data, len);
  nghttp3_conn_resume_stream(c->h3, stream_id);
  return s->body.backlog();
}

void vq_submit_trailers(VqConn *conn, int64_t stream_id, const VqHeader *hdrs,
                        size_t n) {
  auto *c = reinterpret_cast<Conn *>(conn);
  Stream *s = c->stream(stream_id);
  if (!s || !c->h3 || !s->headSubmitted || n == 0) return;
  // nghttp3 copies the field data during submit (like submit_response), so the
  // borrowed VqHeader buffers need only outlive this call. Setting hasTrailers
  // makes h3ReadData flag NO_END_STREAM at body EOF so these HEADERS can follow.
  auto nva = toNv(hdrs, n);
  if (nghttp3_conn_submit_trailers(c->h3, stream_id, nva.data(), nva.size()) == 0)
    s->hasTrailers = true;
}

void vq_stream_finish(VqConn *conn, int64_t stream_id) {
  auto *c = reinterpret_cast<Conn *>(conn);
  Stream *s = c->stream(stream_id);
  if (!s || !c->h3) return;
  s->body.fin = true;
  nghttp3_conn_resume_stream(c->h3, stream_id);
}

size_t vq_stream_backlog(VqConn *conn, int64_t stream_id) {
  auto *c = reinterpret_cast<Conn *>(conn);
  Stream *s = c->stream(stream_id);
  return s ? s->body.backlog() : 0;
}

void vq_stream_reset(VqConn *conn, int64_t stream_id, uint64_t app_error) {
  auto *c = reinterpret_cast<Conn *>(conn);
  if (c->conn) ngtcp2_conn_shutdown_stream(c->conn, 0, stream_id, app_error);
}

void vq_stream_consume(VqConn *conn, int64_t stream_id, size_t n) {
  auto *c = reinterpret_cast<Conn *>(conn);
  if (c->conn) {
    // stream_id < 0 credits the connection window (MAX_DATA) only, e.g. for
    // buffered-body bytes that were discarded (an over-limit request whose stream
    // is being reset): there is no stream window worth replenishing.
    if (stream_id >= 0)
      ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, n);
    ngtcp2_conn_extend_max_offset(c->conn, n);
  }
}

void vq_conn_goaway(VqConn *conn) {
  auto *c = reinterpret_cast<Conn *>(conn);
  if (c->h3) { nghttp3_conn_submit_shutdown_notice(c->h3); }
}

void vq_conn_shutdown(VqConn *conn) {
  // Final GOAWAY: narrows the range to the last stream the server will process
  // (nghttp3 uses the highest processed client-initiated bidi id). Sent after
  // vq_conn_goaway's notice to complete the RFC 9114 5.2 two-step drain, so a
  // draining client learns which in-flight requests were accepted vs refused.
  auto *c = reinterpret_cast<Conn *>(conn);
  if (c->h3) { nghttp3_conn_shutdown(c->h3); }
}

void vq_conn_close(VqConn *conn, uint64_t app_error) {
  auto *c = reinterpret_cast<Conn *>(conn);
  // Abrupt teardown: the Nim H3Conn (our conn_ud) is being freed right now
  // (h3Free), so drop conn_ud first -- the reap must NOT fire on_conn_close on
  // the freed H3Conn (heap-use-after-free). Then schedule a CONNECTION_CLOSE so
  // the peer learns the connection is gone instead of idle-timing-out (R15);
  // the next pump's writeConn emits it and reaps. (Best-effort: if the loop
  // tears the engine down before the next pump, no packet is sent, which is
  // acceptable on this hard-close path.)
  c->conn_ud = nullptr;
  if (!c->wantClose && !c->closed) {
    ngtcp2_ccerr_set_application_error(&c->ccerr, app_error, nullptr, 0);
    c->wantClose = true;
  }
}

void vq_conn_close_graceful(VqConn *conn, uint64_t app_error) {
  auto *c = reinterpret_cast<Conn *>(conn);
  // Clean shutdown: keep conn_ud valid and the Conn alive so writeConn first
  // flushes the queued final GOAWAY (vq_conn_shutdown) and only then emits a
  // CONNECTION_CLOSE(app_error) (see writeConn's nw==0 branch). When the Conn is
  // reaped afterward it fires on_conn_close -> the Nim slot is released. This is
  // the RFC 9114 5.2 two-step drain completed with a real close, the h3 analog
  // of the h2 graceful GOAWAY+close.
  if (c->wantClose || c->wantGracefulClose || c->closed) return;
  ngtcp2_ccerr_set_application_error(&c->ccerr, app_error, nullptr, 0);
  c->wantGracefulClose = true;
}

const char *vq_conn_peer_ip(VqConn *conn) {
  auto *c = reinterpret_cast<Conn *>(conn);
  return c->peer_ip.c_str();
}

void *vq_conn_ssl(VqConn *conn) {
  auto *c = reinterpret_cast<Conn *>(conn);
  return c->ssl;
}

size_t vq_max_recv_udp_payload(void) { return kMaxRecvUdpPayload; }

uint64_t vq_ping_tx_count(void) {
#ifdef VQ_FRAME_LOG
  return gPingTx.load(std::memory_order_relaxed);
#else
  return 0;
#endif
}

uint64_t vq_ping_tx_with_ack_count(void) {
#ifdef VQ_FRAME_LOG
  return gPingTxWithAck.load(std::memory_order_relaxed);
#else
  return 0;
#endif
}

}  // extern "C"
