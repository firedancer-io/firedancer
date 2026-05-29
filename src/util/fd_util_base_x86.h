#ifndef HEADER_fd_src_util_fd_util_base_h
#error "Do not include this directly; use fd_util_base.h"
#endif

/* FD_HAS_X86:  If the build target supports x86 specific features and
   can benefit from x86 specific optimizations, define FD_HAS_X86.  Code
   needing more specific target features (Intel / AMD / SSE / AVX2 /
   AVX512 / etc) can specialize further as necessary with even more
   precise capabilities (that in turn imply FD_HAS_X86). */

#ifndef FD_HAS_X86
#define FD_HAS_X86 0
#endif

/* These allow even more precise targeting for X86. */

/* FD_HAS_SSE indicates the target supports Intel SSE4 style SIMD
   (basically do the 128-bit wide parts of "x86intrin.h" work).
   Recommend using the simd/fd_sse.h APIs instead of raw Intel
   intrinsics for readability and to facilitate portability to non-x86
   platforms.  Implies FD_HAS_X86. */

#ifndef FD_HAS_SSE
#define FD_HAS_SSE 0
#endif

/* FD_HAS_AVX indicates the target supports Intel AVX2 style SIMD
   (basically do the 256-bit wide parts of "x86intrin.h" work).
   Recommend using the simd/fd_avx.h APIs instead of raw Intel
   intrinsics for readability and to facilitate portability to non-x86
   platforms.  Implies FD_HAS_SSE. */

#ifndef FD_HAS_AVX
#define FD_HAS_AVX 0
#endif

/* FD_HAS_AVX512 indicates the target supports Intel AVX-512 style SIMD
   (basically do the 512-bit wide parts of "x86intrin.h" work).
   Recommend using the simd/fd_avx512.h APIs instead of raw Intel
   intrinsics for readability and to facilitate portability to non-x86
   platforms.  Implies FD_HAS_AVX. */

#ifndef FD_HAS_AVX512
#define FD_HAS_AVX512 0
#endif

/* FD_HAS_SHANI indicates that the target supports Intel SHA extensions
   which accelerate SHA-1 and SHA-256 computation.  This extension is
   also called SHA-NI or SHA_NI (Secure Hash Algorithm New
   Instructions).  Although proposed in 2013, they're only supported on
   Intel Ice Lake and AMD Zen CPUs and newer.  Implies FD_HAS_AVX. */

#ifndef FD_HAS_SHANI
#define FD_HAS_SHANI 0
#endif

/* FD_HAS_GFNI indicates that the target supports Intel Galois Field
   extensions, which accelerate operations over binary extension fields,
   especially GF(2^8).  These instructions are supported on Intel Ice
   Lake and newer and AMD Zen4 and newer CPUs.  Implies FD_HAS_AVX. */

#ifndef FD_HAS_GFNI
#define FD_HAS_GFNI 0
#endif

/* FD_HAS_AESNI indicates that the target supports AES-NI extensions,
   which accelerate AES encryption and decryption.  While AVX predates
   the original AES-NI extension, the combination of AES-NI+AVX adds
   additional opcodes (such as vaesenc, a more flexible variant of
   aesenc).  Thus, implies FD_HAS_AVX.  A conservative estimate for
   minimum platform support is Intel Haswell or AMD Zen. */

#ifndef FD_HAS_AESNI
#define FD_HAS_AESNI 0
#endif

#if FD_HAS_X86

#define FD_HW_MFENCE()    __asm__ __volatile__( "lock addl $0, (%%rsp)" ::: "memory", "cc" )
#define FD_HW_MFENCE_LD() FD_COMPILER_MFENCE()
#define FD_HW_MFENCE_ST() FD_COMPILER_MFENCE()

#define fd_tickcount() ((long)__builtin_ia32_rdtsc())

#define FD_SPIN_PAUSE() __builtin_ia32_pause()

#if FD_HAS_ATOMIC && !__cplusplus
#define FD_ATOMIC_XCHG(p,v) __sync_lock_test_and_set( (p), (v) )
#endif

#if FD_USE_ARCH_MEMCPY && !defined(CBMC) && !FD_HAS_DEEPASAN && !FD_HAS_MSAN
static inline void *
fd_memcpy_arch( void       * FD_RESTRICT d,
                void const * FD_RESTRICT s,
                ulong                    sz ) {
  void * p = d;
  __asm__ __volatile__( "rep movsb" : "+D" (p), "+S" (s), "+c" (sz) :: "memory" );
  return d;
}
#endif

#if FD_USE_ARCH_MEMSET && !defined(CBMC) && !FD_HAS_DEEPASAN && !FD_HAS_MSAN
static inline void *
fd_memset_arch( void  * d,
                int     c,
                ulong   sz ) {
  void * p = d;
  __asm__ __volatile__( "rep stosb" : "+D" (p), "+c" (sz) : "a" (c) : "memory" );
  return d;
}
#endif

#endif
