#include <stdint.h>
#include <s2n-bignum.h>

/* s2n-bignum implementation of Keccak-f1600.  sha3_keccak_f1600 is a
   formally-verified hand-written x86-64/AArch64 assembly routine from
   https://github.com/awslabs/s2n-bignum (Apache-2.0 / ISC / MIT-0).
   It takes the 25-element state in-place and the 24 round constants. */

static inline void
fd_keccak256_core( ulong * state ) {
  sha3_keccak_f1600( (uint64_t *)state, (const uint64_t *)fd_keccak256_rc );
}
