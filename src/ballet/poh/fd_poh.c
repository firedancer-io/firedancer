#include "fd_poh.h"

void *
fd_poh_append( void * poh,
               ulong  n ) {
  while( n-- ) {
    fd_sha256_hash_32( poh, poh );
  }
  return poh;
}

void *
fd_poh_mixin( void *        FD_RESTRICT poh,
              uchar const * FD_RESTRICT mixin ) {
  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, poh,   FD_SHA256_HASH_SZ );
  fd_sha256_append( &sha, mixin, FD_SHA256_HASH_SZ );
  fd_sha256_fini( &sha, poh );
  return poh;
}
