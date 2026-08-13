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
  ngtcp2_ccerr ccerr{};               // application error for the close

  Stream *stream(int64_t id) {
    auto it = streams.find(id);
    return it == streams.end() ? nullptr : it->second.get();
  }
};

struct Engine {
  VqConfig cfg{};
  SSL_CTX *ssl_ctx = nullptr;
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
  if (!s) { *pflags |= NGHTTP3_DATA_FLAG_EOF; return 0; }
  if (s->body.next(vec)) {
    if (s->body.fin && s->body.handed >= s->body.end)
      *pflags |= NGHTTP3_DATA_FLAG_EOF;
    return 1;
  }
  if (s->body.fin) { *pflags |= NGHTTP3_DATA_FLAG_EOF; return 0; }
  return NGHTTP3_ERR_WOULDBLOCK;  // streaming: resumed by vq_stream_write/finish
}

// --- nghttp3 setup ----------------------------------------------------------

int setupHttpConn(Conn *c) {
  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  settings.qpack_blocked_streams = 0;
  settings.qpack_max_dtable_capacity = 4096;

  static const nghttp3_callbacks cbs = {
      h3AckedStreamData,   // acked_stream_data
      h3StreamClose,       // stream_close
      h3RecvData,          // recv_data
      h3DeferredConsume,   // deferred_consume
      h3BeginHeaders,      // begin_headers
      h3RecvHeader,        // recv_header
      h3EndHeaders,        // end_headers
      nullptr,             // begin_trailers
      nullptr,             // recv_trailer
      nullptr,             // end_trailers
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

// --- connection creation ----------------------------------------------------

Conn *acceptConn(Engine *e, const uint8_t *pkt, size_t pktlen,
                 const ngtcp2_version_cid *vc, uint64_t now_ns) {
  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, pkt, pktlen) != 0) return nullptr;

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
  c->ssl = SSL_new(e->ssl_ctx);
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
  tp.initial_max_data = 4 * 1024 * 1024;
  tp.initial_max_stream_data_bidi_remote = 1024 * 1024;
  tp.initial_max_stream_data_bidi_local = 1024 * 1024;
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
    if (nw == 0) return;   // congestion-limited or nothing left to send
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

static SSL_CTX *makeCtx(const VqConfig *cfg) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) return nullptr;
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  // The ossl backend has no CTX-level configure; per-connection setup happens in
  // ngtcp2_crypto_ossl_configure_server_session(ssl) at accept time.
  SSL_CTX_set_alpn_select_cb(ctx, alpnSelect, nullptr);
  bool ok = true;
  if (cfg->cert_file && cfg->cert_file[0])
    ok = ok && SSL_CTX_use_certificate_chain_file(ctx, cfg->cert_file) == 1;
  if (cfg->key_file && cfg->key_file[0])
    ok = ok && SSL_CTX_use_PrivateKey_file(ctx, cfg->key_file,
                                           SSL_FILETYPE_PEM) == 1;
  if (!ok) { SSL_CTX_free(ctx); return nullptr; }
  return ctx;
}

VqEngine *vq_engine_new(const VqConfig *cfg) {
  if (ngtcp2_crypto_ossl_init() != 0) return nullptr;
  auto *e = new Engine();
  e->cfg = *cfg;
  e->ssl_ctx = makeCtx(cfg);
  if (!e->ssl_ctx) { delete e; return nullptr; }
  return reinterpret_cast<VqEngine *>(e);
}

void vq_engine_free(VqEngine *eng) {
  if (!eng) return;
  auto *e = reinterpret_cast<Engine *>(eng);
  for (auto &c : e->conns) {
    if (c->h3) nghttp3_conn_del(c->h3);
    if (c->conn) ngtcp2_conn_del(c->conn);
    if (c->ossl) ngtcp2_crypto_ossl_ctx_del(c->ossl);
    if (c->ssl) SSL_free(c->ssl);
  }
  if (e->ssl_ctx) SSL_CTX_free(e->ssl_ctx);
  delete e;
}

int vq_engine_reload_cert(VqEngine *eng, const char *cert_pem,
                          const char *key_pem) {
  auto *e = reinterpret_cast<Engine *>(eng);
  bool ok = true;
  if (cert_pem && cert_pem[0]) {
    BIO *b = BIO_new_mem_buf(cert_pem, -1);
    X509 *x = b ? PEM_read_bio_X509(b, nullptr, nullptr, nullptr) : nullptr;
    ok = ok && x && SSL_CTX_use_certificate(e->ssl_ctx, x) == 1;
    if (x) X509_free(x);
    if (b) BIO_free(b);
  }
  if (key_pem && key_pem[0]) {
    BIO *b = BIO_new_mem_buf(key_pem, -1);
    EVP_PKEY *k = b ? PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr) : nullptr;
    ok = ok && k && SSL_CTX_use_PrivateKey(e->ssl_ctx, k) == 1;
    if (k) EVP_PKEY_free(k);
    if (b) BIO_free(b);
  }
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
    if (r == NGTCP2_ERR_DRAINING) c->draining = true;
    else c->closed = true;
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
      if (c->h3) nghttp3_conn_del(c->h3);
      if (c->conn) ngtcp2_conn_del(c->conn);
      if (c->ossl) ngtcp2_crypto_ossl_ctx_del(c->ossl);
      if (c->ssl) SSL_free(c->ssl);
      i = e->conns.erase(i);
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

void vq_conn_close(VqConn *conn, uint64_t app_error) {
  auto *c = reinterpret_cast<Conn *>(conn);
  (void)app_error;
  c->closed = true;
}

const char *vq_conn_peer_ip(VqConn *conn) {
  auto *c = reinterpret_cast<Conn *>(conn);
  return c->peer_ip.c_str();
}

}  // extern "C"
