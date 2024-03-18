#include "../fd_f25519.h"

/* fd_f25519_rng generates a random fd_f25519_t element.
   Note: insecure, for tests only. */
fd_f25519_t *
fd_f25519_rng_unsafe( fd_f25519_t * r,
                      fd_rng_t *    rng ) {
  uchar buf[32];
  for( int j=0; j<32; j++ ) {
    buf[j] = fd_rng_uchar( rng );
  }
  return fd_f25519_frombytes( r, buf );
}
