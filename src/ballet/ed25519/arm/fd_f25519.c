#include "../fd_f25519.h"

fd_f25519_t *
fd_f25519_rng_unsafe( fd_f25519_t * r,
                      fd_rng_t *    rng ) {
  r->el[0] = fd_rng_ulong( rng );
  r->el[1] = fd_rng_ulong( rng );
  r->el[2] = fd_rng_ulong( rng );
  r->el[3] = fd_rng_ulong( rng );
  bignum_mod_p25519_4( r->el, r->el );
  return r;
}
