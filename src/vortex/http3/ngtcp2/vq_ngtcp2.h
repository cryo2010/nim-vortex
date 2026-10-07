/* vq_ngtcp2 -- C ABI over ngtcp2 (QUIC transport) + nghttp3 (HTTP/3) for vortex.
 *
 * One VqEngine per loop thread; single-threaded (the loop thread owns it), so
 * nothing here locks. vortex owns the UDP socket, event loop, timers, worker
 * pool, routing and Request/Response model; this shim owns only the
 * ngtcp2_conn + nghttp3_conn objects, their ~40 callbacks, and the OpenSSL
 * SSL_CTX/SSL for the TLS handshake (ngtcp2 `ossl` crypto backend, OpenSSL>=3.5).
 *
 * Data flow:
 *   ingress: vortex recvmmsg -> vq_engine_recv(pkt) -> ngtcp2_conn_read_pkt ->
 *            nghttp3_conn_read_stream -> the on_* event callbacks fire (below).
 *   egress:  vq_engine_pump() -> ngtcp2_conn_writev_stream -> the send callback
 *            hands each datagram back to vortex, which batches with sendmmsg.
 *   timers:  vq_engine_next_expiry_ns() folds into the selector timeout;
 *            vq_engine_handle_expiry() on fire.
 *
 * All on_* callbacks fire on the loop thread, synchronously inside recv/pump/
 * expiry. They must be plain functions (Nim {.nimcall.}): no closures, no
 * exceptions crossing the boundary. Buffers passed to callbacks are borrowed
 * (valid only for the call); the callee copies what it needs.
 *
 * The implementation is C++20 (vq_ngtcp2.cpp); this header is plain C so Nim's
 * {.importc, header.} can consume it.
 */
#ifndef VQ_NGTCP2_H
#define VQ_NGTCP2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VqEngine VqEngine;

/* Opaque per-connection handle. Its lifetime is the QUIC connection; vortex
 * stores it in the h3 slot and passes it back to submit responses. */
typedef struct VqConn VqConn;

/* A single header name/value (borrowed, not NUL-terminated). */
typedef struct {
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
} VqHeader;

/* ---- callbacks into vortex (registered once in vq_engine_new) --------------
 * user is the engine-level context vortex passed at creation (the loop core).
 * conn_ud is the per-connection context vortex returned from on_accept. */
typedef struct {
  /* A new QUIC connection finished its handshake. Return an opaque per-conn
   * context (vortex's h3 slot handle); returning NULL rejects the connection.
   * peer_ip is a numeric string (no port), valid for the call only. */
  void *(*on_accept)(void *user, VqConn *conn, char *peer_ip);

  /* HTTP/3 request headers for a stream, delivered once complete. hdrs points
   * to n contiguous VqHeader (pseudo-headers first), borrowed for the call.
   * (Params are non-const so Nim {.nimcall.} callback types match exactly; the
   * callee must still treat the buffers as read-only and copy what it keeps.) */
  void (*on_headers)(void *user, void *conn_ud, int64_t stream_id,
                     VqHeader *hdrs, size_t n);

  /* A DATA chunk (request body). data borrowed for the call. */
  void (*on_body)(void *user, void *conn_ud, int64_t stream_id,
                  uint8_t *data, size_t len);

  /* The request stream is fully received (peer FIN after headers/body). */
  void (*on_stream_end)(void *user, void *conn_ud, int64_t stream_id);

  /* The stream was closed/reset by the peer or transport (app_error is the
   * HTTP/3/QUIC application error code, 0 if none). Fires at most once/stream. */
  void (*on_stream_close)(void *user, void *conn_ud, int64_t stream_id,
                          uint64_t app_error);

  /* Flow control opened up on a streamed response: vortex may resume writing
   * (mirrors the current onDrain). */
  void (*on_stream_writable)(void *user, void *conn_ud, int64_t stream_id);

  /* The QUIC connection is gone; vortex must free its slot and stop using
   * conn_ud / the VqConn after this returns. */
  void (*on_conn_close)(void *user, void *conn_ud);

  /* Emit one outbound UDP datagram. peer is the destination sockaddr (the
   * packet's path remote), valid for the call only. Return 0 on success, <0 to
   * signal a send error. */
  int (*on_send)(void *user, VqConn *conn, uint8_t *data, size_t len,
                 void *peer, size_t peer_len);
} VqCallbacks;

/* ---- engine config -------------------------------------------------------- */

/* One per-hostname certificate for SNI (#374). The material comes from the same
 * sources, with the same precedence, as the default cert/key fields of VqConfig:
 * a PKCS#12 bundle wins, then in-memory PEM, then PEM files. */
typedef struct {
  const char *host;           /* exact host, or "*.example.com" (one label) */
  const char *cert_file;
  const char *key_file;
  const char *cert_pem;
  const char *key_pem;
  const char *key_password;
  const char *pkcs12_file;
  const uint8_t *pkcs12;
  size_t pkcs12_len;
} VqSniCert;

typedef struct {
  void *user;                 /* engine context (loop core) passed to callbacks */
  VqCallbacks cb;
  /* TLS material for the ossl SSL_CTX. A PKCS#12 bundle (file path or DER
   * bytes) takes precedence; otherwise in-memory PEM, otherwise PEM files. */
  const char *cert_file;
  const char *key_file;
  const char *cert_pem;       /* used when *_file are NULL/empty */
  const char *key_pem;
  const char *key_password;   /* may be NULL; also the PKCS#12 passphrase */
  const char *pkcs12_file;    /* PKCS#12 (.pfx/.p12) path; used if non-empty */
  const uint8_t *pkcs12;      /* PKCS#12 DER bytes; used if pkcs12_len > 0 */
  size_t pkcs12_len;
  /* Limits mirrored from VortexConfig. */
  uint64_t max_body;
  uint64_t max_concurrent_streams;
  uint64_t max_connections;   /* cap on concurrent QUIC conns (0 = unlimited) */
  uint64_t max_reset_streams; /* rapid-reset budget per connection (0 = off) */
  int max_field_section_size;
  /* QUIC receive flow-control windows (0 = shim default). stream_recv_window is
   * initial_max_stream_data for client-opened bidi streams (request-body upload
   * window); conn_recv_window is initial_max_data (connection aggregate). */
  uint64_t stream_recv_window;
  uint64_t conn_recv_window;
  /* TLS policy mirrored from the TCP listener, so an operator's configuration is
   * in force on QUIC too (#359). tls_cipher_suites is the TLS 1.3 suite list
   * (SSL_CTX_set_ciphersuites format); NULL/empty keeps OpenSSL's default.
   * max_tls_version is an OpenSSL version constant (0 = no cap): below TLS 1.3
   * it makes vq_engine_new fail rather than negotiate outside the policy, since
   * QUIC mandates TLS 1.3 (RFC 9001 4.2). The configured *minimum* needs no
   * field: that same mandate clamps it up to TLS 1.3 unconditionally. Nor does
   * the TLS <= 1.2 cipher *list*, which can never apply to a QUIC handshake. */
  const char *tls_cipher_suites;
  int max_tls_version;
  /* Client-certificate verification (mTLS), mirrored from the TCP listener so a
   * verifyClient policy is not bypassable by taking the Alt-Svc h3 upgrade
   * (#351). verify_client is the OpenSSL SSL_VERIFY_* bitmask (0 = off, 1 =
   * PEER, 3 = PEER | FAIL_IF_NO_PEER_CERT). The client CA comes from
   * client_ca_pem (in-memory PEM, preferred) or client_ca_file, matching the
   * TCP path's precedence; neither is required, in which case OpenSSL's default
   * trust store applies. */
  int verify_client;
  const char *client_ca_file;
  const char *client_ca_pem;
  /* Per-host certificates selected by SNI (#374): sni_len entries, each getting
   * its own SSL_CTX built like the default one (so the verify mode, cipher
   * suites and version pinning above apply to them too). Borrowed for the
   * vq_engine_new call only; the shim copies what it keeps. */
  const VqSniCert *sni;
  size_t sni_len;
  /* max_idle_timeout we advertise, in seconds (0 = shim default). QUIC gives
   * each endpoint min(local, peer), so this also caps the *client's* idle timer:
   * advertise less than the h1/h2 keep-alive budget and h3 connections are
   * reaped where h1/h2 ones survive. The shim arms ngtcp2's keep-alive at a
   * third of it so a live-but-quiet connection keeps both timers fed. */
  uint64_t max_idle_timeout_sec;
} VqConfig;

/* Create/destroy the per-loop engine. Returns NULL on failure (bad cert etc.).*/
VqEngine *vq_engine_new(const VqConfig *cfg);
void      vq_engine_free(VqEngine *e);

/* Hot-reload the TLS certificate/key from PEM file paths. 0 on success, -1 on
 * failure. A fresh SSL_CTX is built from the new material plus the engine's
 * retained TLS policy (passphrase, verify mode, cipher suites, version pinning,
 * client CA) and installed only once the certificate and key both loaded and
 * match, so a refused reload leaves the engine serving exactly what it was
 * serving before. Any per-host (SNI) contexts are rebuilt in the same
 * transaction, from `sni` when one is given and otherwise from the material
 * they were configured with, so a rotation of on-disk per-host certificates is
 * picked up with the default one and a failure anywhere leaves every context as
 * it was.
 *
 * NULL/empty paths mean "rebuild from the material this engine was configured
 * with, re-reading any files": the bare-reloadTls() form. Material configured
 * as in-memory PEM or PKCS#12 *bytes* has nothing to re-read, so that is a
 * no-op for the default certificate (a configured pkcs12_file is re-read) and
 * still refreshes the per-host files. Explicit paths replace whatever the
 * material was sourced from, with the TCP path's rules: a certificate path
 * clears the in-memory PEM and the bundle, and a one-sided reload against a
 * PKCS#12-sourced certificate (cert without key, or key without cert) is
 * refused, since the bundle carries both halves. What loads successfully
 * becomes the material the next bare reload re-reads.
 *
 * `sni`/`sni_len`, when non-empty, REPLACE the per-host set wholesale, host
 * names included: the reloadTls(sni = ...) override, which reached the TCP
 * listener alone before this (a host added through it was served the DEFAULT
 * certificate over h3, and a host removed from it kept being served over h3 for
 * the life of the process). The entries are borrowed for the call; the shim
 * copies what it keeps, and keeps nothing unless the whole reload succeeded. An
 * empty set rebuilds the configured per-host material instead; there is no
 * spelling for "drop every host", matching the TCP path.
 *
 * In-flight connections keep the certificate they handshook with: SSL_new
 * up-refs the SSL_CTX, so releasing the engine's reference here is a decrement
 * and the old context lives as long as the sessions created on it. The same
 * holds for a per-host context a connection already switched to, which
 * SSL_set_SSL_CTX up-ref'd for it. */
int vq_engine_reload_cert(VqEngine *e, const char *cert_file,
                          const char *key_file, const VqSniCert *sni,
                          size_t sni_len);

/* Why the last vq_engine_reload_cert on `e` failed (empty if it succeeded), or,
 * with e == NULL, why the last vq_engine_new on THIS thread failed. The string
 * is owned by the shim; copy it before the next call on the same engine. */
const char *vq_engine_last_error(VqEngine *e);

/* Feed one received datagram. peer/local are sockaddr pointers (the shim copies
 * peer so on_send can address replies); now_ns is a monotonic timestamp. */
void vq_engine_recv(VqEngine *e, const uint8_t *pkt, size_t len,
                    const void *peer, size_t peer_len,
                    const void *local, size_t local_len, uint64_t now_ns);

/* Produce and emit all pending outbound datagrams (via on_send) for every
 * connection with work to do, and reap connections that have closed. */
void vq_engine_pump(VqEngine *e, uint64_t now_ns);

/* Nanoseconds until the earliest ngtcp2 timer across all connections, or
 * UINT64_MAX if none pending (fold into the selector timeout). */
uint64_t vq_engine_next_expiry_ns(VqEngine *e, uint64_t now_ns);

/* Fire expired ngtcp2 timers (loss detection, idle, etc.). */
void vq_engine_handle_expiry(VqEngine *e, uint64_t now_ns);

/* ---- response submission (from the loop thread) --------------------------- */
/* One-shot response: status + headers (+ optional body), FIN if fin!=0. */
void vq_submit_response(VqConn *conn, int64_t stream_id, int status,
                        const VqHeader *hdrs, size_t n,
                        const uint8_t *body, size_t body_len, int fin);

/* Streaming response: head (no body/FIN), then write chunks, then finish. */
void vq_submit_head(VqConn *conn, int64_t stream_id, int status,
                    const VqHeader *hdrs, size_t n);
/* Append a body chunk to a streamed response; returns unsent backlog bytes
 * (for backpressure). Buffered in the shim, drained via nghttp3 read_data. */
size_t vq_stream_write(VqConn *conn, int64_t stream_id,
                       const uint8_t *data, size_t len);
/* Submit a trailer field section, emitted after the body (RFC 9114 4.1). Call
 * before vq_stream_finish so the stream stays open for the trailing HEADERS. */
void   vq_submit_trailers(VqConn *conn, int64_t stream_id,
                          const VqHeader *hdrs, size_t n);
void   vq_stream_finish(VqConn *conn, int64_t stream_id);       /* FIN */
size_t vq_stream_backlog(VqConn *conn, int64_t stream_id);

/* Abort a single stream with an HTTP/3 application error (RESET_STREAM). */
void vq_stream_reset(VqConn *conn, int64_t stream_id, uint64_t app_error);

/* Ack n consumed request-body bytes: extend the peer's flow-control window
 * (mirrors req.ackBody backpressure). stream_id < 0 extends the CONNECTION-level
 * window (MAX_DATA) only, leaving the per-stream window untouched -- used for
 * buffered-body bytes with no stream to replenish (e.g. an over-limit request
 * whose stream is being reset). */
void vq_stream_consume(VqConn *conn, int64_t stream_id, size_t n);

/* Connection-level graceful shutdown (RFC 9114 5.2, two-step GOAWAY):
 *   vq_conn_goaway   -- initial GOAWAY notice (max stream id: "shutting down").
 *   vq_conn_shutdown -- final GOAWAY (last-accepted stream id: the boundary).
 * and CONNECTION_CLOSE. */
void vq_conn_goaway(VqConn *conn);
void vq_conn_shutdown(VqConn *conn);
void vq_conn_close(VqConn *conn, uint64_t app_error);
/* Clean close: flush the final GOAWAY, then emit CONNECTION_CLOSE(app_error)
 * and reap (fires on_conn_close). Keeps conn_ud valid; shim-driven teardown. */
void vq_conn_close_graceful(VqConn *conn, uint64_t app_error);

/* Peer IP (numeric, no port) of a connection; empty string if unavailable.
 * Returned pointer is owned by the shim and valid until the conn closes. */
const char *vq_conn_peer_ip(VqConn *conn);

/* The connection's OpenSSL SSL object (as void*, so this header stays plain C
 * with no openssl dependency for the Nim importer), or NULL if there is none.
 * Owned by the shim and valid until on_conn_close fires. vortex reads the peer
 * (client) certificate through it for req.clientCertSubject over h3 (#351). */
void *vq_conn_ssl(VqConn *conn);

/* The max_udp_payload_size this shim advertises to peers (RFC 9000 18.2), i.e.
 * the largest datagram a client may send us. The caller owns the receive socket
 * and must size its buffer to at least this, or oversize datagrams are silently
 * truncated and dropped (#380). */
size_t vq_max_recv_udp_payload(void);

/* ACK-less PING frames this process has TRANSMITTED, across every engine
 * (every loop thread) since start, or 0 in a normal build. Monotonically
 * increasing: nothing ever decrements it, so two readings can be subtracted.
 *
 * A test-only observation hook: the counter is fed by an ngtcp2 frame-log
 * callback that the shim installs ONLY when compiled with -DVQ_FRAME_LOG (Nim:
 * -d:vortexH3FrameLog). It counts a transmitted PING only when the packet
 * carrying it has no ACK in it, which is what separates the keep-alive from the
 * PING ngtcp2 appends to an otherwise non-ack-eliciting packet; that build also
 * disables path-MTU discovery, whose probes are padded PINGs. So this is a
 * LOWER bound on keep-alives (one that fires while an ACK is pending rides in
 * that packet and is not counted) and an UPPER bound once PTO probes -- also
 * ACK-less -- are included. Without the define no callback is installed,
 * nothing counts, and this returns 0: a pin for the keep-alive the shim arms
 * per connection, not a production metric (#347). */
uint64_t vq_ping_tx_count(void);

/* The other half of the same hook: transmitted PINGs that rode in a packet
 * which also carried an ACK, and so were NOT counted by vq_ping_tx_count. Most
 * are the PING ngtcp2 appends to an otherwise non-ack-eliciting packet, but a
 * keep-alive that fired with an ACK pending lands here too, which is why a test
 * prints it -- it tells an undercounted run from a run with no keep-alive at
 * all. Same build rules, same monotonicity, 0 in a normal build (#347). */
uint64_t vq_ping_tx_with_ack_count(void);

#ifdef __cplusplus
}
#endif

#endif /* VQ_NGTCP2_H */
