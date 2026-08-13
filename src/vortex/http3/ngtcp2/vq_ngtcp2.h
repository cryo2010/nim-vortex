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
  void *(*on_accept)(void *user, VqConn *conn, const char *peer_ip);

  /* HTTP/3 request headers for a stream, delivered once complete. hdrs points
   * to n contiguous VqHeader (pseudo-headers first), borrowed for the call. */
  void (*on_headers)(void *user, void *conn_ud, int64_t stream_id,
                     const VqHeader *hdrs, size_t n);

  /* A DATA chunk (request body). data borrowed for the call. */
  void (*on_body)(void *user, void *conn_ud, int64_t stream_id,
                  const uint8_t *data, size_t len);

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

  /* Emit one outbound UDP datagram to peer (an opaque sockaddr pointer the shim
   * captured on ingress). Return 0 on success, <0 to signal a send error. */
  int (*on_send)(void *user, VqConn *conn, const uint8_t *data, size_t len);
} VqCallbacks;

/* ---- engine config -------------------------------------------------------- */
typedef struct {
  void *user;                 /* engine context (loop core) passed to callbacks */
  VqCallbacks cb;
  /* TLS material for the ossl SSL_CTX. Either file paths or PEM blobs. */
  const char *cert_file;
  const char *key_file;
  const char *cert_pem;       /* used when *_file are NULL/empty */
  const char *key_pem;
  const char *key_password;   /* may be NULL */
  /* Limits mirrored from VortexConfig. */
  uint64_t max_body;
  uint64_t max_concurrent_streams;
  int max_field_section_size;
} VqConfig;

/* Create/destroy the per-loop engine. Returns NULL on failure (bad cert etc.).*/
VqEngine *vq_engine_new(const VqConfig *cfg);
void      vq_engine_free(VqEngine *e);

/* Swap the TLS certificate/key in place (hot reload; PEM blobs). 0 on success. */
int vq_engine_reload_cert(VqEngine *e, const char *cert_pem, const char *key_pem);

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
void   vq_stream_finish(VqConn *conn, int64_t stream_id);       /* FIN */
size_t vq_stream_backlog(VqConn *conn, int64_t stream_id);

/* Abort a single stream with an HTTP/3 application error (RESET_STREAM). */
void vq_stream_reset(VqConn *conn, int64_t stream_id, uint64_t app_error);

/* Ack n consumed request-body bytes: extend the peer's flow-control window
 * (mirrors req.ackBody backpressure). */
void vq_stream_consume(VqConn *conn, int64_t stream_id, size_t n);

/* Connection-level: GOAWAY (graceful drain) and CONNECTION_CLOSE. */
void vq_conn_goaway(VqConn *conn);
void vq_conn_close(VqConn *conn, uint64_t app_error);

/* Peer IP (numeric, no port) of a connection; empty string if unavailable.
 * Returned pointer is owned by the shim and valid until the conn closes. */
const char *vq_conn_peer_ip(VqConn *conn);

#ifdef __cplusplus
}
#endif

#endif /* VQ_NGTCP2_H */
