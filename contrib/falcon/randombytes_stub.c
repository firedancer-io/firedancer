/* randombytes_stub.c - stub `randombytes` for the verify-only build.
 *
 * The Pornin reference implementation in vendor/falcon-round3 declares
 *   extern int randombytes(unsigned char *x, unsigned long long xlen);
 * and calls it from `crypto_sign_keypair` and `crypto_sign`.  We never
 * exercise those paths in this benchmark; the stub provided here aborts
 * if called so a misuse cannot silently produce non-random output.
 *
 * PQClean ships its own `PQCLEAN_randombytes` (selected via a macro in
 * its `randombytes.h`); we use the upstream randombytes.c for the
 * PQClean wrapper.  The Pornin code does not include that header and so
 * resolves to the symbol below. */

#include <stdlib.h>

int
randombytes( unsigned char * x, unsigned long long xlen ) {
  (void)x; (void)xlen;
  abort();
}
