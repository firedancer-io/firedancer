#include "fd_poh.h"

fd_hash_t *
fd_poh_append( fd_hash_t * poh,
               ulong       n ) {
  fd_sha256_t sha;
  while( n-- ) {
    fd_sha256_init( &sha );
    fd_sha256_append( &sha, poh, FD_SHA256_HASH_SZ );
    fd_sha256_fini( &sha, poh );
  }
  return poh;
}

fd_hash_t *
fd_poh_mixin( fd_hash_t *   FD_RESTRICT poh,
              uchar const * FD_RESTRICT mixin ) {
  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, poh, FD_SHA256_HASH_SZ );
  fd_sha256_append( &sha, mixin, FD_SHA256_HASH_SZ );
  fd_sha256_fini( &sha, poh );
  return poh;
}
