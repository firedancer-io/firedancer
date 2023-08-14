#include "fd_gossip.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"

void
fd_gossip_handle_ping_request( fd_gossip_ping_t        const * ping,
                               fd_gossip_ping_t              * pong,
                               fd_gossip_credentials_t const * creds ) {

  memcpy( pong->from.uc, creds->public_key, 32UL );

  /* Generate response hash token */
  fd_sha256_t sha[1];
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, ping->token.uc,     32UL );
  fd_sha256_fini( sha, pong->token.uc );

  /* Sign */
  fd_sha512_t sha2[1];
  fd_ed25519_sign( /* sig */ pong->signature.uc,
                   /* msg */ ping->token.uc,
                   /* sz  */ 32UL,
                   /* public_key  */ creds->public_key,
                   /* private_key */ creds->private_key,
                   sha2 );
}
