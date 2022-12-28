#include "fd_poh.h"

fd_poh_state_t *
fd_poh_append( fd_poh_state_t * poh,
               ulong            n ) {
  fd_sha256_t sha;
  while( n-- ) {
    fd_sha256_init( &sha );
    fd_sha256_append( &sha, poh->state, FD_SHA256_HASH_SZ );
    fd_sha256_fini( &sha, poh->state );
  }
  return poh;
}

fd_poh_state_t *
fd_poh_mixin( fd_poh_state_t * FD_RESTRICT poh,
              uchar const *    FD_RESTRICT mixin ) {
  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, poh->state, FD_SHA256_HASH_SZ );
  fd_sha256_append( &sha, mixin,      FD_SHA256_HASH_SZ );
  fd_sha256_fini( &sha, poh->state );
  return poh;
}
