// vq_ngtcp2 -- ngtcp2 (QUIC) + nghttp3 (HTTP/3) server glue for vortex.
// See vq_ngtcp2.h for the C ABI and threading contract. C++20; one VqEngine per
// loop thread, single-threaded (no locking).

#include "vq_ngtcp2.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr size_t kMaxUdpPayload = 1452;   // conservative IPv4 path MTU
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
    if (ssl) SSL_free(ssl);
  }
};

struct Engine {
  VqConfig cfg{};
  SslCtxPtr ssl_ctx;                   // RAII: freed when the Engine is deleted
  std::string key_pw;   // owns the passphrase (cfg.key_password char* may dangle)
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

// Schedule an HTTP/3/QPACK CONNECTION_CLOSE carrying the app error code inferred
// from an nghttp3 error (so h3spec sees the right code); emitted by writeConn.
void failConn(Conn *c, int nghttp3_rv) {
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
    // generic transport failure.
    failConn(c, static_cast<int>(n));
    return 0;
  }
  // nghttp3 tells us via deferred_consume how much QPACK-blocked data it kept;
  // the bytes it did consume are extended here.
  ngtcp2_conn_extend_max_stream_offset(conn, stream_id, static_cast<uint64_t>(n));
  ngtcp2_conn_extend_max_offset(conn, static_cast<uint64_t>(n));
  return 0;
}

int cbStreamClose(ngtcp2_conn *conn, uint32_t, int64_t stream_id,
                  uint64_t app_error_code, void *user_data, void *) {
  auto *c = static_cast<Conn *>(user_data);
  if (c->h3) nghttp3_conn_close_stream(c->h3, stream_id, app_error_code);
  // Grant the client one more bidi stream to replace the finished request one,
  // via a MAX_STREAMS frame. Without this the peer is capped forever at the
  // initial budget (each request is a fresh bidi stream) and stalls after it.
  if ((stream_id & 0x03) == 0)
    ngtcp2_conn_extend_max_streams_bidi(conn, 1);
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

// --- connection creation ----------------------------------------------------

Conn *acceptConn(Engine *e, const uint8_t *pkt, size_t pktlen,
                 const ngtcp2_version_cid *vc, uint64_t now_ns) {
  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, pkt, pktlen) != 0) return nullptr;

  // Bound concurrent QUIC connections so a flood of Initial packets can't grow
  // unbounded per-connection state (each Conn is an ngtcp2_conn + SSL + h3 slot).
  // 0 = unlimited. A spoofed-address flood is still cheap here because we do not
  // yet issue a Retry token (address validation) before committing state.
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

  ngtcp2_transport_params tp;
  ngtcp2_transport_params_default(&tp);
  tp.max_idle_timeout = 30ULL * NGTCP2_SECONDS;
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

  // Route the client's original DCID and our SCID to this conn.
  e->byCid[cidKey(vc->dcid, vc->dcidlen)] = c;
  e->byCid[cidKey(scid.data, scid.datalen)] = c;

  if (e->cfg.cb.on_accept)
    c->conn_ud = e->cfg.cb.on_accept(e->cfg.user, reinterpret_cast<VqConn *>(c),
                                     const_cast<char *>(c->peer_ip.c_str()));

  e->conns.push_back(std::move(owned));
  return c;
}

// --- egress -----------------------------------------------------------------

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
    ngtcp2_ssize nw = ngtcp2_conn_write_connection_close(
        c->conn, &ps.path, &pi, buf, sizeof buf, &c->ccerr, now_ns);
    if (nw > 0 && send)
      send(c->engine->cfg.user, reinterpret_cast<VqConn *>(c), buf,
           static_cast<size_t>(nw), ps.path.remote.addr, ps.path.remote.addrlen);
    c->closed = true;
    return;
  }

  for (;;) {
    int64_t sid = -1;
    int fin = 0;
    nghttp3_vec vec[16];
    nghttp3_ssize vcnt = 0;
    if (c->h3 && ngtcp2_conn_get_max_data_left(c->conn)) {
      vcnt = nghttp3_conn_writev_stream(c->h3, &sid, &fin, vec, 16);
      if (vcnt < 0) { c->closed = true; return; }
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
  if (!k) { ERR_clear_error(); return false; }
  return SSL_CTX_use_PrivateKey(ctx, k.get()) == 1;
}

// Load the leaf cert (+ any following chain certs) into `ctx` from a PEM blob.
static bool loadCertChain(SSL_CTX *ctx, const char *pem) {
  BioPtr b(BIO_new_mem_buf(pem, -1));
  if (!b) return false;
  X509Ptr leaf(PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr));
  bool ok = leaf && SSL_CTX_use_certificate(ctx, leaf.get()) == 1;
  while (ok) {
    X509Ptr x(PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr));
    if (!x) { ERR_clear_error(); break; }   // expected: end of PEM data
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
  PKCS12 *p12 = d2i_PKCS12_bio(b.get(), nullptr);
  if (!p12) { ERR_clear_error(); return false; }
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

static SslCtxPtr makeCtx(const VqConfig *cfg) {
  SslCtxPtr ctx(SSL_CTX_new(TLS_server_method()));
  if (!ctx) return nullptr;
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
  // The ossl backend has no CTX-level configure; per-connection setup happens in
  // ngtcp2_crypto_ossl_configure_server_session(ssl) at accept time.
  SSL_CTX_set_alpn_select_cb(ctx.get(), alpnSelect, nullptr);
  bool ok;
  if ((cfg->pkcs12 && cfg->pkcs12_len) ||
      (cfg->pkcs12_file && cfg->pkcs12_file[0])) {
    // PKCS#12 bundle carries both cert and key (matches the TCP path's order).
    ok = loadPkcs12(ctx.get(), cfg->pkcs12, cfg->pkcs12_len, cfg->pkcs12_file,
                    cfg->key_password);
  } else {
    // Cert: in-memory PEM takes precedence over the file (matches the TCP path).
    ok = true;
    if (cfg->cert_pem && cfg->cert_pem[0])
      ok = loadCertChain(ctx.get(), cfg->cert_pem);
    else if (cfg->cert_file && cfg->cert_file[0])
      ok = SSL_CTX_use_certificate_chain_file(ctx.get(), cfg->cert_file) == 1;
    // Key: PEM blob or file, decrypted with key_password, never prompting.
    if (ok && ((cfg->key_pem && cfg->key_pem[0]) ||
               (cfg->key_file && cfg->key_file[0])))
      ok = loadKey(ctx.get(), cfg->key_pem, cfg->key_file, cfg->key_password);
  }
  // Fail closed: require a certificate AND a matching private key. Without this
  // a config that loaded neither (e.g. PKCS#12-only before this was wired, or an
  // empty/half TLS config) would yield a keyless SSL_CTX that vq_engine_new
  // accepts, so h3 would be advertised via Alt-Svc yet every handshake would
  // fail. check_private_key returns 1 only when both are set and they match.
  if (ok) ok = SSL_CTX_check_private_key(ctx.get()) == 1;
  if (!ok) { ERR_clear_error(); return nullptr; }  // unique_ptr frees the ctx
  return ctx;
}

VqEngine *vq_engine_new(const VqConfig *cfg) {
  if (ngtcp2_crypto_ossl_init() != 0) return nullptr;
  auto e = std::make_unique<Engine>();
  e->cfg = *cfg;
  e->key_pw = cfg->key_password ? cfg->key_password : "";
  // Don't retain the caller's (possibly transient) TLS-material pointers.
  e->cfg.cert_pem = e->cfg.key_pem = e->cfg.key_password = nullptr;
  e->cfg.cert_file = e->cfg.key_file = nullptr;
  e->cfg.pkcs12_file = nullptr;
  e->cfg.pkcs12 = nullptr;
  e->cfg.pkcs12_len = 0;
  e->ssl_ctx = makeCtx(cfg);
  if (!e->ssl_ctx) return nullptr;   // unique_ptr frees the Engine on this path
  return reinterpret_cast<VqEngine *>(e.release());
}

void vq_engine_free(VqEngine *eng) {
  if (!eng) return;
  // delete runs ~Engine: the SSL_CTX (unique_ptr member) and every connection's
  // h3/conn/ossl/ssl (~Conn via the conns vector) are freed as it unwinds.
  delete reinterpret_cast<Engine *>(eng);
}

int vq_engine_reload_cert(VqEngine *eng, const char *cert_pem,
                          const char *key_pem) {
  auto *e = reinterpret_cast<Engine *>(eng);
  bool ok = true;
  if (cert_pem && cert_pem[0])
    ok = ok && loadCertChain(e->ssl_ctx.get(), cert_pem);
  // Reuse the passphrase from engine construction: a hot cert/key swap keeps the
  // same encryption passphrase. loadKey never prompts on an encrypted key.
  if (ok && key_pem && key_pem[0])
    ok = ok && loadKey(e->ssl_ctx.get(), key_pem, nullptr, e->key_pw.c_str());
  return ok ? 0 : -1;
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
    bool dead = c->closed || (c->conn && ngtcp2_conn_in_closing_period(c->conn));
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

}  // extern "C"
