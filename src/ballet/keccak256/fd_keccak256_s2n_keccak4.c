#include "../fd_ballet_base.h"
#include <stdint.h>
#include <s2n-bignum.h>

extern ulong const fd_keccak256_rc[24];

/* Wraps s2n-bignum sha3_keccak4_f1600: four independent 25×uint64 Keccak
   states packed as state[0..24], [25..49], [50..74], [75..99]. */

void
fd_s2n_sha3_keccak4_f1600( ulong state[ static 100 ] ) {
  sha3_keccak4_f1600( (uint64_t *)state, (uint64_t const *)fd_keccak256_rc );
}
