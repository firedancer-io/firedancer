#ifndef HEADER_fd_src_tango_tls_fd_tls_estate_cli_h
#define HEADER_fd_src_tango_tls_fd_tls_estate_cli_h

#include "fd_tls.h"

/* fd_tls_estate_cli contains TLS client handshake state while waiting
   for the server to send a message.

   TLS client side handshake state is considerably more complex than
   the server-side state.  Thus, estate_cli memory requirements are
   larger than for estate_srv.

   However, clients are not vulnerable to handshake packet floods:
   - The packet count per handshake is limited
   - Peers cannot initiate connections to clients (clients will simply
     drop unsolicited packets)

   Thus, estate_cli is not optimized for memory use. */

struct fd_tls_estate_cli {
  uchar server_pubkey[ 32 ];

  char  state;

  uchar server_cert_raw : 1;  /* 0=X.509 1=RPK */
  uchar client_cert_raw : 1;  /* 0=X.509 1=RPK */
  uchar client_cert     : 1;  /* 0=anon  1=client auth */

  fd_sha256_t transcript;
};

typedef struct fd_tls_estate_cli fd_tls_estate_cli_t;

FD_PROTOTYPES_BEGIN

fd_tls_estate_cli_t *
fd_tls_estate_cli_new( void * mem );

static inline void *
fd_tls_estate_cli_delete( fd_tls_estate_cli_t * estate ) {
  return (void *)estate;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_tls_fd_tls_estate_cli_h */
