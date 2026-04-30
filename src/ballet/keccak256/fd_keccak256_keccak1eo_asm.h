#ifndef HEADER_fd_src_ballet_keccak256_fd_keccak256_keccak1eo_asm_h
#define HEADER_fd_src_ballet_keccak256_fd_keccak256_keccak1eo_asm_h

/* Scalar Keccak-f[1600] for ONE state with EVEN/ODD bit-interleaved limbs.

   Mirrors fd_keccak256_avx2_keccak8_eo_asm.h structure, but the .inc body is
   scalar (32-bit GP ops) — every ymm op in keccak8 maps to a 32-bit GP op
   here.  Same data flow, 1/8 the SIMD width.  Used as the proof target for
   phase 2 (HOL Light correctness), so phase 3 (keccak8 verification) can
   bridge from this scalar reference.

   State layout: 50 uint32 (200 bytes, 32-byte alignment recommended):
     state[ 0..24]  E limb of each Keccak lane (E_bit_k = w[2k])
     state[25..49]  O limb of each Keccak lane (O_bit_k = w[2k+1])
*/

#if FD_HAS_X86 && defined(__BMI__)
__asm__( ".include \"src/ballet/keccak256/fd_keccak256_keccak1eo.inc\"" );

static inline __attribute__((always_inline)) void
fd_keccak256_keccak1eo_f1600_raw_asm( void *       state_eo,
                                      uint const * rc_eo ) {
  register void *       _s  __asm__("rdi") = state_eo;
  register uint const * _rc __asm__("rsi") = rc_eo;
  __asm__ __volatile__ (
    "_fd_keccak256_keccak1eo_f1600_raw %[s], %[rc]"
    : [s]"+r"(_s), [rc]"+r"(_rc)
    :
    : "rax", "rcx", "rdx", "cc", "memory",
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
  );
}

#endif /* FD_HAS_X86 && __BMI__ */

#endif /* HEADER_... */
