#ifndef HEADER_fd_src_tango_quic_tls_fd_quic_tls_h
#define HEADER_fd_src_tango_quic_tls_fd_quic_tls_h

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <stdlib.h>
#include <stdio.h>

#include "../fd_quic_common.h"

/* QUIC-TLS

   This defines an API for QUIC-TLS

   Currently, this uses a fork of openssl found here:
     https://github.com/quictls/openssl.git

   General operation:
     // set up a quic-tls config object
     fd_quic_tls_cfg_t quic_tls_cfg = {
       .client_hello_cb       = my_client_hello_cb,  // client_hello receives a callback
                                                     // to determine whether a handshake
                                                     // should be accepted

       .alert_cb              = my_alert_cb,         // callback for quic-tls to alert of
                                                     // handshake errors

       .secret_cb             = my_secret_cb,        // callback for communicating secrets

       .handshake_complete_cb = my_hs_complete,      // called when handshake is complete

       .max_concur_handshakes = 1234,                // number of handshakes this object can
                                                     // manage concurrently

       .alpns                 = "\x02solana-tpu",    // ALPN
       .alpns_sz              = 11                   // number of bytes of ALPN - see spec
       };

     // create a quic-tls object to manage handshakes:
     fd_quic_tls_t * quic_tls = fd_quic_tls_new( quic_tls_cfg );

     // delete a quic-tls object when it's not needed anymore
     fd_quic_delete( quic_tls );

     // create a client or a server handshake object
     //   call upon a new connection to manage the connection TLS handshake
     // hostname may be null for servers
     fd_quic_tls_hs_t * hs = fd_quic_tls_hs_new( quic_tls, conn_id, conn_id_sz, is_server, hostname );

     // if an error occurs, hs will be null
     //   TODO how to report errors?
     //   via quic_tls?  fd_quic_tls_get_error( quic_tls )?

     // delete a handshake object
     //   NULL is allowed here
     fd_quic_tls_hs_delete( hs );

     // call fd_quic_tls_process whenever the state changes
     //   clients should call immediately to get a blob to frame
     //   and send to the server
     //   clients and servers should call after calling
     //     fd_quic_tls_provide_data

*/

/* each TLS handshake requires a number of hf_quic_tls_hs_data structures */
#define FD_QUIC_TLS_HS_DATA_CNT 16u

/* alignment of hs_data
   must be a power of 2 */
#define FD_QUIC_TLS_HS_DATA_ALIGN 32u

/* number of bytes allocated for queued handshake data
   must be a multiple of FD_QUIC_TLS_HS_DATA_ALIGN */
#define FD_QUIC_TLS_HS_DATA_SZ  (1u<<14u)

/* callback function prototypes */
typedef int
(* fd_quic_tls_cb_client_hello_t)( fd_quic_tls_hs_t * hs,
                                   void *             context );

typedef void
(* fd_quic_tls_cb_alert_t)( fd_quic_tls_hs_t * hs,
                            void *             context,
                            int                alert );

typedef void
(* fd_quic_tls_cb_secret_t)( fd_quic_tls_hs_t *           hs,
                             void *                       context,
                             fd_quic_tls_secret_t const * secret );

typedef void
(* fd_quic_tls_cb_handshake_complete_t)( fd_quic_tls_hs_t * hs,
                                         void *             context  );

typedef void
(* fd_quic_tls_cb_keylog_t)( fd_quic_tls_hs_t * hs,
                             char const *       line );

struct fd_quic_tls_secret {
  OSSL_ENCRYPTION_LEVEL enc_level;
  uchar const *         read_secret;
  uchar const *         write_secret;
  uint                  suite_id;
  ulong                 secret_len;
};

struct fd_quic_tls_cfg {
  // callbacks ../crypto/fd_quic_crypto_suites
  fd_quic_tls_cb_client_hello_t        client_hello_cb;
  fd_quic_tls_cb_alert_t               alert_cb;
  fd_quic_tls_cb_secret_t              secret_cb;
  fd_quic_tls_cb_handshake_complete_t  handshake_complete_cb;
  fd_quic_tls_cb_keylog_t              keylog_cb;

  ulong          max_concur_handshakes;

  /* Certificate and key */
  EVP_PKEY * cert_key;
  X509 *     cert;

  /* keylog_fd == 0 indicates no keylogger file */
  int            keylog_fd;             /* keylogger file */

  uchar const *  alpns;                 /* ALPNs */
  uint           alpns_sz;              /* number of bytes... see ALPN spec */
};

/* structure for organising handshake data */
struct fd_quic_tls_hs_data {
  uchar const *            data;
  uint                     data_sz;
  uint                     free_data_sz; /* internal use */
  uint                     offset;
  OSSL_ENCRYPTION_LEVEL    enc_level;

  /* internal use */
  ushort      next_idx; /* next in linked list, ~0 for end */
};

struct fd_quic_tls {
  uchar const *                        transport_params;
  ulong                                transport_params_sz;

  /* callbacks */
  fd_quic_tls_cb_client_hello_t        client_hello_cb;
  fd_quic_tls_cb_alert_t               alert_cb;
  fd_quic_tls_cb_secret_t              secret_cb;
  fd_quic_tls_cb_handshake_complete_t  handshake_complete_cb;
  fd_quic_tls_cb_keylog_t              keylog_cb;

  ulong                                max_concur_handshakes;

  /* array of (max_concur_handshakes) pre-allocated handshakes */
  fd_quic_tls_hs_t *                   handshakes;
  uchar *                              used_handshakes;

  /* ssl related */
  SSL_CTX *                            ssl_ctx;

  /* Regular file descriptor for key logging.
     Owned by fd_quic. */
  int keylog_fd;

  /* ALPNs in OpenSSL length-prefixed list format */
  uchar const * alpns;
  uint          alpns_sz;
};

#define FD_QUIC_TLS_HS_DATA_UNUSED ((ushort)~0u)

struct fd_quic_tls_hs {
  fd_quic_tls_t * quic_tls;

  SSL *           ssl;

  int             is_server;
  int             is_flush;
  int             is_hs_complete;
  int             state;
# define FD_QUIC_TLS_HS_STATE_DEAD         0
# define FD_QUIC_TLS_HS_STATE_NEED_INPUT   1
# define FD_QUIC_TLS_HS_STATE_NEED_SERVICE 2
# define FD_QUIC_TLS_HS_STATE_COMPLETE     3

  /* user defined context supplied in callbacks */
  void *          context;

  /* handshake data
     this is data that must be sent to the peer
     it consists of an arbitrary list of tuples of:
       < "encryption level", array of bytes >
     these will be encapsulated and sent in order */
  fd_quic_tls_hs_data_t hs_data[ FD_QUIC_TLS_HS_DATA_CNT ];

  /* head of handshake data free list */
  ushort hs_data_free_idx;

  /* head of handshake data pending (to be sent) */
  ushort hs_data_pend_idx[4];
  ushort hs_data_pend_end_idx[4];

  /* handshake data buffer
     allocated in arbitrary chunks in a circular queue manner */
  uchar  hs_data_buf[ FD_QUIC_TLS_HS_DATA_SZ ];

  /* head and tail of unused hs_data_buf data
       head % buf_sz is first used byte
       tail % buf_sz is first unused byte
       invariants
         0 <= head < 2 * buf_sz
         0 <= tail <     buf_sz
         head >= tail
         head <  tail + buf_sz
         head -  tail == unused size */

  /* buffer space is shared between encryption levels */
  uint  hs_data_buf_head;
  uint  hs_data_buf_tail;
  uint  hs_data_offset[ 4 ]; /* one offset per encoding level */

  /* TLS alert code */
  uint  alert;

  /* error condition */
  int   err_ssl_rc;
  int   err_ssl_err;
  int   err_line;
};

ulong
fd_quic_tls_align( void );

ulong
fd_quic_tls_footprint( ulong handshake_cnt );

/* fd_quic_tls_new formats an unused memory region for use as an
   fd_quic_tls_t object and joins the caller to it */

fd_quic_tls_t *
fd_quic_tls_new( void *              mem,
                 fd_quic_tls_cfg_t * cfg );

/* fd_quic_delete unformats a memory region used as an fd_quic_tls_t.
   Returns the given pointer on success and NULL if used obviously in error.
   Frees any OpenSSL resources. */

void *
fd_quic_tls_delete( fd_quic_tls_t * self );

/* create a quic-tls handshake object for managing
   the handshakes for a single connection */
fd_quic_tls_hs_t *
fd_quic_tls_hs_new( fd_quic_tls_t * quic_tls,
                    void *          context,
                    int             is_server,
                    char const *    hostname,
                    uchar const *   transport_params_raw,
                    ulong           transport_params_raw_sz );

/* delete a handshake object and free resources */
void
fd_quic_tls_hs_delete( fd_quic_tls_hs_t * self );

/* provide data
   called when the user gets data from the peer to forward it
   to this management object

   In the case of a failure, errors will be stored in the fd_quic_tls_t object

   args
     hs             the fd_quic_tls_hs_t object to operate on
     enc_level      the encryption level specified in the quic packet
     data           the data from the quic CRYPT frame
     data_sz        the length of the data from the quic CRYPT frame

   returns
     FD_QUIC_TLS_SUCCESS
     FD_QUIC_TLS_FAILED
   */
int
fd_quic_tls_provide_data( fd_quic_tls_hs_t *    self,
                          OSSL_ENCRYPTION_LEVEL enc_level,
                          uchar const *         data,
                          ulong                 data_sz );


/* fd_quic_tls_get_hs_data

   get oldest queued handshake data from the queue of pending data to sent to peer

   returns
     NULL    there is no data available
     hd_data   a pointer to the fd_quic_tls_hs_data_t structure at the head of the queue

   the hd_data and data therein are invalidated by the following
     fd_quic_tls_pop_hs_data
     fd_quic_tls_delete
     fd_quic_tls_hs_delete

   args
     self        the handshake in question
     enc_level   a pointer for receiving the encryption level
     data        a pointer for receiving the pointer to the data buffer
     data_sz     a pointer for receiving the data size */
fd_quic_tls_hs_data_t *
fd_quic_tls_get_hs_data( fd_quic_tls_hs_t *  self, int enc_level );


/* fd_quic_tls_get_next_hs_data

   get the next unit of handshake data from the queue

   returns NULL if no more available */
fd_quic_tls_hs_data_t *
fd_quic_tls_get_next_hs_data( fd_quic_tls_hs_t * self, fd_quic_tls_hs_data_t * hs );


/* fd_quic_tls_pop_hs_data

   remove handshake data from head of queue and free associated resources */
void
fd_quic_tls_pop_hs_data( fd_quic_tls_hs_t * self, int enc_level );


/* process a handshake
   parses and handles incoming data (delivered via fd_quic_tls_provide_data)
   generates new data to send to peer
   makes callbacks for notification of the following:
       client_hello_cb        initial handshake. May be used to accept or reject
       alert_cb               a tls alert has occurred and the handshake has failed
       secret_cb              a secret is available
       handshake_complete_cb  the handshake is complete - stream handling can begin */
int
fd_quic_tls_process( fd_quic_tls_hs_t * self );


/* get peer transport params

   retrieves the peer transport params

   args
     self                 the fd_quic_tls_hs_t to query
     transport_params     pointer to pointer to the transport params in question
     transport_params_sz  pointer to the length in bytes of the transport params */
void
fd_quic_tls_get_peer_transport_params( fd_quic_tls_hs_t * self,
                                       uchar const **     transport_params,
                                       ulong *            transport_params_sz );

#endif /* HEADER_fd_src_tango_quic_tls_fd_quic_tls_h */

