#ifndef HEADER_fd_src_waltz_tlsrec_fd_tlsrec_h
#define HEADER_fd_src_waltz_tlsrec_fd_tlsrec_h

/* fd_tlsrec.h provides the TLS 1.3 record layer, as used in TLS over
   TCP (RFC 8446).  The record layer provides a mechanism to transfer
   handshake messages, alerts, and user data over a reliable stream.
   It also implements data authentication and encryption.

   This implementation provides the simplest way to secure individual
   TCP connections.  It is not designed for high-performance use.  It
   should not be used in servers that handle many concurrent connections
   due to high memory footprint.

   ### Middlebox Compatibility Mode

   fd_tlsrec ignores incoming compatibility messages as described in
   RFC 8446, Appendix D.4.  It does not generate compatibility messages.

   ### Cryptography

   Each decryption step happens after a record has been fully received
   to allow for vectorized decryption.

   fd_tlsrec does not randomly pad records.  It thus leaks the exact
   size of every outgoing record.  Be careful when using with plaintexts
   where the size can be used as a side channel (see CVE-2019-4929).

   ### Integration

   fd_tlsrec offers a backend-agnostic non-blocking API.  It is usually
   used with sockets (e.g. for HTTPS snapshot downloading). */

#include "fd_tlsrec_frag.h"
#include "../tls/fd_tls.h"
#include "../tls/fd_tls_estate.h"
#include "../../ballet/aes/fd_aes_gcm.h"
#include <stddef.h>

/* fd_tlsrec_conn drives a TLS 1.3 connection over a reliable byte
   stream.  The conn footprint is ~100 kB order of magnitude. */

struct fd_tlsrec_conn;
typedef struct fd_tlsrec_conn fd_tlsrec_conn_t;

/* FD_TLSREC_{SUCCESS,ERR_{...}} indicate error values returned by
   most API functions. */

#define FD_TLSREC_SUCCESS     (0)
#define FD_TLSREC_ERR_OOM     (1)  /* out of memory (forgot to poll?) */
#define FD_TLSREC_ERR_PROTO   (2)  /* protocol error */
#define FD_TLSREC_ERR_STATE   (3)  /* unexpected state */
#define FD_TLSREC_ERR_CRYPTO  (4)  /* crypto error */

/* FD_TLSREC_KEY_UPDATE_SEQ is the number of records encrypted under one
   application write key before fd_tlsrec_conn_tx rotates it with a
   KeyUpdate.  RFC 8446 Section 5.5 bounds AES-GCM at ~2^24.5 full-size
   records per key. */

#define FD_TLSREC_KEY_UPDATE_SEQ (1UL<<24)

/* fd_tlsrec_keys holds symmetric keys for a given encryption layer. */

struct __attribute__((aligned(FD_AES_GCM_ALIGN))) fd_tlsrec_keys {
  /* rebuilt on key change */
  fd_aes_gcm_t read_gcm;
  fd_aes_gcm_t write_gcm;

  uchar read_secret [ 32 ];
  uchar write_secret[ 32 ];
  uchar read_key    [ 16 ];
  uchar read_iv     [ 12 ];
  uchar write_key   [ 16 ];
  uchar write_iv    [ 12 ];
};

typedef struct fd_tlsrec_keys fd_tlsrec_keys_t;

/* FD_TLSREC_HS_MSG_CAP is the max supported handshake message size. */

#define FD_TLSREC_HS_MSG_CAP (0x10000UL)

/* fd_tlsrec_hs_rbuf reassembles incoming handshakes messages one at a
   time.  (private API) */

struct fd_tlsrec_hs_rbuf {
  uchar buf[ FD_TLSREC_HS_MSG_CAP ];
  ulong sz;
};

typedef struct fd_tlsrec_hs_rbuf fd_tlsrec_hs_rbuf_t;

/* fd_tlsrec_buf_t defragments incoming TLS record data (private API) */

struct __attribute__((aligned(16UL))) fd_tlsrec_buf {
  uchar buf[ FD_TLSREC_CAP ];
  ulong sz;
};

typedef struct fd_tlsrec_buf fd_tlsrec_buf_t;

struct fd_tlsrec_conn {
  fd_tls_t tls;  /* TODO dedup across conns for better memory use */
  fd_tls_secrets_fn_t secrets_fn;  /* optional key-log observer */

  fd_tlsrec_keys_t keys[2]; /* 0=handshake 1=app */
  fd_tls_estate_t  hs;

  fd_tlsrec_buf_t     rec_buf; /* reassembly of TLS records */
  fd_tlsrec_hs_rbuf_t hs_rbuf; /* reassembly of TLS handshake messages */

  ulong read_seq;  /* Incoming encrypted record counter */
  ulong write_seq; /* Outgoing encrypted record counter */

  uchar rx_closed; /* 1 if peer sent close_notify: no more plaintext is
                      delivered (RFC 8446 Section 6.1), tx still works */
  uchar key_update_pending; /* 1 if the peer requested a KeyUpdate that
                               has not been answered yet */
  uchar tx_level;  /* FD_TLS_LEVEL_{INITIAL,HANDSHAKE,APPLICATION}: the
                      encryption level an alert sent now would use */
  uchar tx_closed; /* 1 once a fatal alert or close_notify went out: no
                      more records are sent */
};

/* TLS v1.3 record content types */

#define FD_TLS_REC_CHANGE_CIPHER_SPEC ((uchar)20)
#define FD_TLS_REC_ALERT              ((uchar)21)
#define FD_TLS_REC_HANDSHAKE          ((uchar)22)
#define FD_TLS_REC_APPLICATION_DATA   ((uchar)23)

/* fd_tlsrec_hdr_t is the TLS v1.3 record header. */

struct __attribute__((packed)) fd_tlsrec_hdr {
  uchar  content_type;           /* FD_TLS_REC_{...} */
  ushort legacy_record_version;  /* sent as 0x0303, ignored on receive */
  ushort length;
};

typedef struct fd_tlsrec_hdr fd_tlsrec_hdr_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE char const *
fd_tlsrec_strerror( int err );

static inline void
fd_tlsrec_hdr_bswap( fd_tlsrec_hdr_t * hdr ) {
  hdr->legacy_record_version = fd_ushort_bswap( hdr->legacy_record_version );
  hdr->length                = fd_ushort_bswap( hdr->length );
}

/* fd_tlsrec_conn_init initializes a connection object.  tls points to
   the TLS instance parameters.  tls->secrets_fn, if non-NULL, observes
   generated traffic secrets after fd_tlsrec installs them.  The
   tls->sendmsg_fn callback is ignored.  is_server is 1 if conn operates
   in server mode. */

fd_tlsrec_conn_t *
fd_tlsrec_conn_init( fd_tlsrec_conn_t * conn,
                     fd_tls_t const *   tls,
                     int                is_server );

FD_FN_PURE int
fd_tlsrec_conn_is_server( fd_tlsrec_conn_t const * conn );

FD_FN_PURE int
fd_tlsrec_conn_is_ready( fd_tlsrec_conn_t const * conn );

FD_FN_PURE int
fd_tlsrec_conn_is_failed( fd_tlsrec_conn_t const * conn );

/* fd_tlsrec_conn_rx consumes ciphertext from tcp_rx (may be NULL;
   any fragment size is fine), writes ciphertext to send to the peer
   into tcp_tx, and decrypted app data into app_rx.  The size pointers
   are capacity in, bytes written out.  Call once with tcp_rx==NULL on
   a fresh client conn to emit the ClientHello.  Any non-zero return is
   fatal (including ERR_OOM).  On a protocol error tcp_tx holds the
   fatal alert record for the peer (unless it did not fit), and the size
   is reported as usual: send it before closing the connection.  Once
   the peer's close_notify has been received, remaining tcp_rx bytes are
   consumed and discarded and the call returns SUCCESS with no
   plaintext; check conn->rx_closed.

   Post-handshake, one call writes at most one 27 byte record to tcp_tx:
   a single KeyUpdate answering however many the peer requested (RFC
   8446 Section 4.6.3).  If tcp_tx lacks room for it the reply waits
   for the next fd_tlsrec_conn_rx or fd_tlsrec_conn_tx call.

   app_rx is also used as decrypt scratch, so bytes past the returned
   size are clobbered.  One call produces at most tcp_rx bytes consumed
   plus FD_TLSREC_CAP bytes of plaintext. */

int
fd_tlsrec_conn_rx( fd_tlsrec_conn_t *  conn,
                   fd_tlsrec_slice_t * tcp_rx,
                   uchar *             tcp_tx,
                   ulong *             tcp_tx_sz_p,
                   uchar *             app_rx,
                   ulong *             app_rx_sz_p );

/* fd_tlsrec_conn_tx encrypts outgoing application data into TLS records.
   Returns ERR_STATE before the handshake completes and after
   fd_tlsrec_conn_close. */

int
fd_tlsrec_conn_tx( fd_tlsrec_conn_t *  conn,
                   uchar *             tcp_tx,
                   ulong *             tcp_tx_sz_p,
                   fd_tlsrec_slice_t * app_tx );

/* fd_tlsrec_conn_close writes a close_notify alert record (24 bytes)
   into tcp_tx and closes the write side (RFC 8446 Section 6.1): no
   further records are sent, receiving still works.  Returns ERR_STATE
   if the handshake has not completed or the write side is closed
   already, ERR_OOM if tcp_tx is too small. */

int
fd_tlsrec_conn_close( fd_tlsrec_conn_t * conn,
                      uchar *            tcp_tx,
                      ulong *            tcp_tx_sz_p );

/* fd_tlsrec_conn_key_update sends a TLS 1.3 KeyUpdate message and
   rotates the write traffic key.  request_peer_update must be 0 or 1. */

int
fd_tlsrec_conn_key_update( fd_tlsrec_conn_t * conn,
                           uchar *            tcp_tx,
                           ulong *            tcp_tx_sz_p,
                           int                request_peer_update );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_tlsrec_fd_tlsrec_h */
