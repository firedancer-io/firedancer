#ifndef HEADER_fd_src_ballet_keccak256_fd_keccak256_avx512_keccak4a_asm_h
#define HEADER_fd_src_ballet_keccak256_fd_keccak256_avx512_keccak4a_asm_h

/* AVX-512 mechanical lift of s2n-bignum sha3_keccak4_f1600.

   The asm body lives in `fd_keccak256_avx512_keccak4a.inc` as a GAS
   macro produced by `gen_keccak4a_inc_from_s2n.py`.  Same instruction
   order, same register allocation, same stack layout (slots widened
   from 32 B to 64 B) as the s2n source.  Round body uses zmm registers
   exclusively; boundary transposes stay ymm-encoded (VEX zero-extension
   keeps the upper 256 bits of the underlying zmm at zero throughout).

   The top 4 lanes of every zmm ride along as wasted-zero work.  Useful
   solely for line-by-line comparison against s2n keccak4 and against
   the keccak8a / keccak8b variants.

   Match arity / semantics with the s2n entry point:
     extern void sha3_keccak4_f1600( ulong state[100], ulong const rc[24] ); */

#include "../fd_ballet_base.h"

#if FD_HAS_X86 && FD_HAS_AVX512
__asm__( ".include \"src/ballet/keccak256/fd_keccak256_avx512_keccak4a.inc\"" );

static inline __attribute__((always_inline)) void
fd_keccak256_avx512_keccak4a_f1600_asm( ulong *       state,
                                        ulong const * rc ) {
  register ulong *       _s  __asm__("rdi") = state;
  register ulong const * _rc __asm__("rsi") = rc;
  __asm__ __volatile__ (
    "_fd_keccak256_avx512_keccak4a_f1600"
    : [s]"+r"(_s), [rc]"+r"(_rc)
    :
    : "rax", "rcx", "cc", "memory",
      "zmm0", "zmm1", "zmm2",  "zmm3",  "zmm4",  "zmm5",  "zmm6",  "zmm7",
      "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15"
  );
}

#endif /* FD_HAS_X86 && FD_HAS_AVX512 */

#endif /* HEADER_... */
