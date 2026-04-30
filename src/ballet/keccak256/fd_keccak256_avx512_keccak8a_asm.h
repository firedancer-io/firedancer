#ifndef HEADER_fd_src_ballet_keccak256_fd_keccak256_avx512_keccak8a_asm_h
#define HEADER_fd_src_ballet_keccak256_fd_keccak256_avx512_keccak8a_asm_h

/* AVX-512 Keccak-f[1600] x8, hand-edited from keccak4a (round body
   verbatim, boundary widened from 4 to 8 states via two s2n-style 4x4
   ymm transposes joined by vinserti64x4).  Same shift+or rotate and
   andn+xor chi as keccak4a — no vprolq, no vpternlogq.

   Boundary uses: 6 lane-groups of 4 (each: 2x s2n 4x4 transpose +
   vinserti64x4) + 1 special handling for lane 24.

   Entry point matches the s2n calling convention extended to 8 states:
     extern void fd_keccak256_avx512_keccak8a_f1600( ulong state[200],
                                                    ulong const rc[24] ); */

#include "../fd_ballet_base.h"

#if FD_HAS_X86 && FD_HAS_AVX512
__asm__( ".include \"src/ballet/keccak256/fd_keccak256_avx512_keccak8a.inc\"" );

static inline __attribute__((always_inline)) void
fd_keccak256_avx512_keccak8a_f1600_asm( ulong *       state,
                                        ulong const * rc ) {
  register ulong *       _s  __asm__("rdi") = state;
  register ulong const * _rc __asm__("rsi") = rc;
  __asm__ __volatile__ (
    "_fd_keccak256_avx512_keccak8a_f1600"
    : [s]"+r"(_s), [rc]"+r"(_rc)
    :
    : "rax", "rcx", "cc", "memory",
      "zmm0", "zmm1", "zmm2",  "zmm3",  "zmm4",  "zmm5",  "zmm6",  "zmm7",
      "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15"
  );
}

#endif /* FD_HAS_X86 && FD_HAS_AVX512 */

#endif /* HEADER_... */
