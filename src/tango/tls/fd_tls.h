#ifndef HEADER_fd_src_tango_tls_fd_tls_h
#define HEADER_fd_src_tango_tls_fd_tls_h

#include "fd_tls_base.h"
#include "fd_tls_proto.h"
#include "fd_tls_estate.h"

struct fd_tls {
  fd_tls_rand_t       rand;
  fd_tls_secrets_fn_t secrets_fn;
  fd_tls_sendmsg_fn_t sendmsg_fn;

  /* QUIC specific callbacks -- Only called if quic flag is set.
     TODO: Will optional function pointers stall the pipeline? */
  fd_tls_quic_tp_self_fn_t quic_tp_self_fn;
  fd_tls_quic_tp_peer_fn_t quic_tp_peer_fn;

  /* key_{private,public}_key is an X25519 key pair.  During the TLS
     handshake, it is used to establish symmetric encryption keys.
     kex_private_key is an arbitrary 32 byte vector.  It is recommended
     to generate a new X25519 key on startup from cryptographically
     secure randomness. kex_public_key is the corresponding public key
     curve point derived via fd_x25519_public.

     Security notes:
     - May not be changed while conns are active.
     - Using a public key that is not derived from the private key may
       reveal the private key (!!!) */
  uchar kex_private_key[ 32 ];
  uchar kex_public_key [ 32 ];

  /* cert_{private,public}_key is the Ed25519 key pair that identifies
     the server. During TLS handshakes, used to sign a transcript of the
     handshake to prove to the peer that we are in possession of this
     key. cert_private_key is an arbitrary 32 byte vector.  (Currently,
     equal to the Solana node identity key.)  cert_public_key is the
     corresponding public key curve point derived via
     fd_ed25519_public_from_private.

     Security notes:
     - May not be changed while conns are active.
     - Using a public key that is not derived from the private key may
       reveal the private key (!!!) */
  uchar cert_private_key[ 32 ];
  uchar cert_public_key [ 32 ];

  /* Buffers storing the Certificate handshake message.  This is not a
     simple copy of the cert but also contains TLS headers/footers.
     Written by fd_tls_server_set_x509.  Do not write directly. */
  uchar cert_x509[ FD_TLS_SERVER_CERT_MSG_SZ_MAX ];  /* set using  */
  ulong cert_x509_sz;

  /* ALPN protocol identifier.  Written by fd_tls_server_set_alpn.
     Format: <1 byte length prefix> <ASCII chars>.
     Is not NUL delimited. */
  uchar alpn[ 32 ];

  /* Flags */
  ulong quic            :  1;
  ulong _flags_reserved : 63;
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
   Synchronously processes the record (API may become async in the
   future).  Record must be complete (does not defragment).  Returns 0L
   on success.  On failure, returns negated TLS alert code. */

long
fd_tls_server_handshake( fd_tls_t const *      tls,
                         fd_tls_estate_srv_t * handshake,
                         void const *          record,
                         ulong                 record_sz,
                         uint                  encryption_level );

/* fd_tls_client_handshake is the client-side equivalent of
   fd_tls_server_handshake.  Must not be called with records sent after
   the handshake was completed (such as NewSessionTicket). */

long
fd_tls_client_handshake( fd_tls_t const *      client,
                         fd_tls_estate_cli_t * handshake,
                         void *                record,
                         ulong                 record_sz,
                         uint                  encryption_level );

static inline long
fd_tls_handshake( fd_tls_t const *  tls,
                  fd_tls_estate_t * handshake,
                  void *            record,
                  ulong             record_sz,
                  uint              encryption_level ) {
  if( handshake->base.server )
    return fd_tls_server_handshake( tls, &handshake->srv, record, record_sz, encryption_level );
  else
    return fd_tls_client_handshake( tls, &handshake->cli, record, record_sz, encryption_level );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_tls_fd_tls_h */
