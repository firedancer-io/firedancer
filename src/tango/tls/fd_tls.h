#ifndef HEADER_fd_src_tango_tls_fd_tls_h
#define HEADER_fd_src_tango_tls_fd_tls_h

#include "fd_tls_proto.h"
#include "fd_tls_estate_srv.h"
#include "fd_tls_estate_cli.h"

struct fd_tls {
  fd_tls_rand_t       rand;
  fd_tls_secrets_fn_t secrets_fn;
  fd_tls_sendmsg_fn_t sendmsg_fn;

  uchar kex_private_key[ 32 ];
  uchar kex_public_key [ 32 ];

  uchar cert_private_key[ 32 ];
  uchar cert_public_key [ 32 ];

  /* Buffers storing the Certificate record.  This is not a simple copy
     of the cert but also contains TLS headers/footers.  Do not set
     directly. */
  uchar cert_x509[ FD_TLS_SERVER_CERT_MSG_SZ_MAX ];  /* set using fd_tls_server_set_x509 */
  ulong cert_x509_sz;

  uchar alpn[ 32 ];

  /* Advertised QUIC transport parameters */
  uchar  quic_tp[ FD_TLS_EXT_QUIC_PARAMS_SZ_MAX ];
  ushort quic_tp_sz;
};

typedef struct fd_tls fd_tls_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_tls_align( void );

FD_FN_CONST ulong
fd_tls_footprint( void );

/* TODO document new/join/leave/delete */

void *
fd_tls_new( void * mem );

fd_tls_t *
fd_tls_join( void * );

void *
fd_tls_leave( fd_tls_t * );

void *
fd_tls_delete( void * );

/* fd_tls_server_set_x509 sets the server certificate.  cert points to
   the first byte of the DER serialized X.509 certificate.  cert_sz is
   the serialized size.  Returns 1 on success and 0 on failure.  Reasons
   for failure include oversz cert. */

static inline int
fd_tls_set_x509( fd_tls_t * server,
                 void const *      cert,
                 ulong             cert_sz ) {

  long res = fd_tls_encode_server_cert_x509( cert, cert_sz, server->cert_x509, FD_TLS_SERVER_CERT_MSG_SZ_MAX );
  if( FD_UNLIKELY( res<0 ) ) return 0;
  server->cert_x509_sz = (ulong)res;
  return 1;
}

/* fd_tls_server_handshake ingests a TLS record from the client.
   Dispatches an asynchronous task entry to process the record.
   Returns 0L on success.  On failure, returns negated TLS alert code. */

long
fd_tls_server_handshake( fd_tls_t const *      tls,
                         fd_tls_estate_srv_t * handshake,
                         void const *          record,
                         ulong                 record_sz,
                         int                   encryption_level );


long
fd_tls_client_handshake( fd_tls_t const *      client,
                         fd_tls_estate_cli_t * handshake,
                         void *                record,
                         ulong                 record_sz,
                         int                   encryption_level );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_tls_fd_tls_h */
