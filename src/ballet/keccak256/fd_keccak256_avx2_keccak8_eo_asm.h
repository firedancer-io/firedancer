#ifndef HEADER_fd_src_ballet_keccak256_fd_keccak256_avx2_keccak8_eo_asm_h
#define HEADER_fd_src_ballet_keccak256_fd_keccak256_avx2_keccak8_eo_asm_h

/* Hand-written-style asm for fd_keccak256_avx2_keccak8_eo_f1600_raw.

   Pattern follows fd_uint256_mul.h: the heavy code lives in a .inc file
   as a GAS macro; this header includes it and provides a C inline wrapper
   that pins arguments to specific registers and emits the macro inline.
   No function-call overhead at the call site.

   Match arity / semantics with the C version
   (fd_keccak256_avx2_keccak8_eo_f1600_raw): operates on state already in
   (E,O) SoA form across 8 instances, using a pre-deinterleaved RC table.

   The asm itself uses ymm0..ymm15, rax, rcx, rbp, rsp, and 1920 bytes of
   stack scratch.  rbp is push/pop'd. */

#if FD_HAS_X86 && FD_HAS_AVX
__asm__( ".include \"src/ballet/keccak256/fd_keccak256_avx2_keccak8_eo.inc\"" );

static inline __attribute__((always_inline)) void
fd_keccak256_avx2_keccak8_eo_f1600_raw_asm( void *       state_eo,
                                            uint const * rc_eo ) {
  /* Pin state_eo to %rdi (gcc body uses it as the ae base) and rc_eo to %rdx
     (gcc body's rc cursor).  The macro computes ao = state + 800 into %rsi
     and clobbers it. */
  register void *       _s  __asm__("rdi") = state_eo;
  register uint const * _rc __asm__("rdx") = rc_eo;
  __asm__ __volatile__ (
    "_fd_keccak256_avx2_keccak8_eo_f1600_raw %[s], %[rc]"
    : [s]"+r"(_s), [rc]"+r"(_rc)
    :
    : "rax", "rcx", "rsi", "cc", "memory",
      "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
      "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15"
  );
}

#endif /* FD_HAS_X86 && FD_HAS_AVX */

#endif /* HEADER_... */
