/* falcon_ref.c - thin shim that exposes the NIST round 3 reference
 *                implementation (T. Pornin et al.) under the namespaced
 *                symbol `falcon_ref_crypto_sign_open`.
 *
 * The vendored reference, in
 *   vendor/falcon-round3/Reference_Implementation/falcon512/falcon512int,
 * already exports the NIST API as `crypto_sign_open`.  This file does
 * nothing more than rename it to avoid colliding with anything else
 * that might also export `crypto_sign_open`.  We also adjust the
 * integer types of `mlen`/`smlen` from `unsigned long long` to
 * `size_t`, which is what the rest of this directory uses.
 *
 * Public domain. */

#include "falcon.h"

/* Forward declaration of the vendored reference's NIST entry point.  Its
 * default symbol prefix is `crypto_sign_*` (no namespace), so we simply
 * declare and forward to it. */
int crypto_sign_open( unsigned char *m, unsigned long long *mlen,
                      const unsigned char *sm, unsigned long long smlen,
                      const unsigned char *pk );

int
falcon_ref_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                             uint8_t const * sm, size_t   smlen,
                             uint8_t const * pk ) {
  unsigned long long ull = 0;
  int r = crypto_sign_open( m, &ull, sm, (unsigned long long)smlen, pk );
  if( mlen ) *mlen = (size_t)ull;
  return r;
}
