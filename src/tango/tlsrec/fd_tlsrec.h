#ifndef HEADER_fd_src_tango_tlsrec_fd_tlsrec_h
#define HEADER_fd_src_tango_tlsrec_fd_tlsrec_h

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

   fd_tlsrec only supports the AES-128-GCM-SHA-256 cipher suite.
   Each decryption step happens after a record has been fully received
   to allow for vectorized decryption.

   fd_tlsrec does not randomly pad records.  It thus leaks the exact
   size of every outgoing record.  Be careful when using with plaintexts
   where the size can be used as a side channel (see CVE-2019-4929).

   ### Integration

   fd_tlsrec offers a backend-agnostic non-blocking API.  It is usually
   used with sockets (see fd_tlscat). */

#include "fd_tlsrec_frag.h"
#include "../tls/fd_tls.h"
#include "../tls/fd_tls_estate.h"
#include <stddef.h>

/* fd_tlsrec_conn drives a TLS 1.3 connection over a reliable byte
   stream.  The conn footprint is ~100 kB order of magnitude.

                                            TLS records
              App Data                      (handshake
     ┌─────┐    FIN     ┌────────────────┐   messages,  ┌─────────┐
     │     ├────────────►                │   app data,  │   TCP   │
     │ App │            │ fd_tlsrec_conn │   alerts)    │         │
     │     ◄────────────┤                ◄──────────────► Backend │
     └─────┘  App Data  └────────────────┘              └─────────┘
                FIN
               Alert

   At a high level, fd_tlsrec_conn turns a reliable stream of app data
   into a reliable stream of TCP fragments, and vice versa.  Various
   TLS protocol messages are multiplexed into the TCP stream as needed.

   The fd_tlsrec_conn object is not relocatable nor thread-safe.

   ### Usage

   Each fd_tlsrec_conn object may only be used with a single TCP
   connection.  On initialization, the fd_tlsrec_conn is in a non-ready
   state and first needs to complete a handshake.  This is done via
   repeated calls to fd_tlsrec_conn_rx until the conn indicates
   readiness (via fd_tlsrec_conn_is_ready) or an error (via
   fd_tlsrec_conn_is_failed). */

struct fd_tlsrec_conn;
typedef struct fd_tlsrec_conn fd_tlsrec_conn_t;

/* FD_TLS_REC_{SUCCESS,ERR_{...}} indicate error values returned by
   most API functions. */

#define FD_TLSREC_SUCCESS     (0)
#define FD_TLSREC_ERR_OOM     (1)  /* out of memory (forgot to poll?) */
#define FD_TLSREC_ERR_PROTO   (2)  /* protocol error */
#define FD_TLSREC_ERR_STATE   (3)  /* unexpected state */
#define FD_TLSREC_ERR_CRYPTO  (4)  /* crypto error */

/* fd_tlsrec_keys holds symmetric keys for a given encryption layer. */

struct __attribute__((aligned(16UL))) fd_tlsrec_keys {
  uchar recv_key[ 16 ];
  uchar recv_iv [ 12 ];
  uchar _pad1c  [  4 ];
  uchar send_key[ 16 ];
  uchar send_iv [ 12 ];
  uchar _pad3c  [  4 ];
};

typedef struct fd_tlsrec_keys fd_tlsrec_keys_t;

/* FD_TLSREC_HS_MSG_CAP is the max supported handshake message size. */

#define FD_TLSREC_HS_MSG_CAP (4096UL)

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

  fd_tlsrec_keys_t keys[2];  /* 0=handshake 1=app */
  fd_tls_estate_t  hs;

  fd_tlsrec_buf_t     rec_buf;   /* reassembly of TLS records */
  fd_tlsrec_hs_rbuf_t hs_rbuf;   /* reassembly of TLS handshake messages */

  ulong rx_seq;  /* Incoming encrypted record counter */
  ulong tx_seq;  /* Outgoing encrypted record counter */
};

/* TLS v1.3 record content types */

#define FD_TLS_REC_CHANGE_CIPHER_SPEC ((uchar)20)
#define FD_TLS_REC_ALERT              ((uchar)21)
#define FD_TLS_REC_HANDSHAKE          ((uchar)22)
#define FD_TLS_REC_APP_DATA           ((uchar)23)

/* fd_tlsrec_hdr_t is the TLS v1.3 record header. */

struct __attribute__((packed)) fd_tlsrec_hdr {
  uchar  content_type;           /* FD_TLS_REC_{...} */
  ushort legacy_record_version;  /* ==0x0303 */
  ushort length;
};

typedef struct fd_tlsrec_hdr fd_tlsrec_hdr_t;

FD_PROTOTYPES_BEGIN

/* fd_tlsrec_strerror returns a cstr containign a short human readable
   error description given an error code in FD_TLS_REC_{SUCCESS,ERR_{...}}. */

FD_FN_PURE char const *
fd_tlsrec_strerror( int err );

static inline void
fd_tlsrec_hdr_bswap( fd_tlsrec_hdr_t * hdr ) {
  hdr->legacy_record_version = fd_ushort_bswap( hdr->legacy_record_version );
  hdr->length                = fd_ushort_bswap( hdr->length );
}

/* fd_tlsrec_conn_init initializes a connection object.  tls points to
   the TLS instance parameters.  The tls->{secrets,sendmsg} callbacks
   are ignored.  is_server is 1 if conn operates in server mode. */

fd_tlsrec_conn_t *
fd_tlsrec_conn_init( fd_tlsrec_conn_t * conn,
                     fd_tls_t const *   tls,
                     int                is_server );

/* fd_tlsrec_conn_is_server returns 1 if local role is server, and 0
   if local role is client. */

FD_FN_PURE int
fd_tlsrec_conn_is_server( fd_tlsrec_conn_t const * conn );

/* fd_tlsrec_conn_is_ready returns 1 if the local connection state
   indicates readiness to send and receive application data. */

FD_FN_PURE int
fd_tlsrec_conn_is_ready( fd_tlsrec_conn_t const * conn );

/* fd_tlsrec_conn_is_failed returns 1 if the object has entered an
   irrecoverable state (e.g. protocol error).  Otherwise, returns 0. */

FD_FN_PURE int
fd_tlsrec_conn_is_failed( fd_tlsrec_conn_t const * conn );

/* fd_tlsrec_conn_rx processes an incoming stream fragment, delivers
   decrypted app data, and responds TLS internal messages to the peer.
   Typically, this is called for each TCP payload. Fragments must be
   delivered in order and without gaps.  In rare cases (e.g. during
   initial handshake), may require response TCP stream data back to
   sender.

   conn points to an initialized connection object.

   tcp_rx points to a slice of incoming encrypted TCP data.  On return,
   tcp_rx->data is advanced to the first byte not yet consumed
   (==tcp->data_end) if all data has been consumed.

   tcp_tx points to a buffer to be filled with outgoing TCP stream data.
   The caller sets *tcp_tx_sz_p to the capacity of this buffer (should
   be at least FD_TLSREC_CAP bytes).  On return, *tcp_tx_sz_p is set to
   the number of bytes written to the buffer.

   app_rx points to a buffer to be filled with decrypted app data.  The
   caller sets *app_rx_sz_p to the capacity of this buffer (should be at
   least FD_TLSREC_CAP bytes).  On return, *app_rx_sz_p is set to the
   number of bytes written to the buffer.

   Note: TLS clients should call this function with a NULL tcp_rx to
   initiate the TLS handshake.

   Return value is in FD_TLSREC_{SUCCESS,ERR_{...}}. */

int
fd_tlsrec_conn_rx( fd_tlsrec_conn_t *  conn,
                   fd_tlsrec_slice_t * tcp_rx,
                   uchar *             tcp_tx,
                   ulong *             tcp_tx_sz_p,
                   uchar *             app_rx,
                   ulong *             app_rx_sz_p );

/* fd_tlsrec_conn_tx attempts to create an outgoing stream fragment,
   packaging as much app data as possible.

   conn points to an initialized connection object.

   tcp_tx points to a buffer to be filled with outgoing TCP stream data.
   The caller sets *tcp_tx_sz_p to the capacity of this buffer (should
   be at least FD_TLSREC_CAP bytes).  On return, *tcp_tx_sz_p is set to
   the number of bytes written to the buffer.

   app_tx points to a slice of outgoing app data.  On return,
   app_tx->data is advanced to the first byte not yet consumed
   (==app_tx->data_end) if all data has been consumed.

   Return value is in FD_TLSREC_{SUCCESS,ERR_{...}}. */

int
fd_tlsrec_conn_tx( fd_tlsrec_conn_t *  conn,
                   uchar *             tcp_tx,
                   ulong *             tcp_tx_sz_p,
                   fd_tlsrec_slice_t * app_tx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_tls_fd_tlsrec_h */
