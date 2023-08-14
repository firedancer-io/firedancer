#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_h

#include "../types/fd_types.h"

/* fd_gossip_credentials holds the node's gossip private credentials. */

struct fd_gossip_credentials {
  /* TODO refactor out to external signer */
  uchar private_key[ 32 ];
  uchar public_key [ 32 ];
};

typedef struct fd_gossip_credentials fd_gossip_credentials_t;

/* fd_gossip_handle_ping_request generates a pong response given an
   incoming ping request.  Involves a hash and an Ed25519 sign op. */

void
fd_gossip_handle_ping_request( fd_gossip_ping_t        const * ping,
                               fd_gossip_ping_t              * pong,
                               fd_gossip_credentials_t const * creds );

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_ping_server_h */
