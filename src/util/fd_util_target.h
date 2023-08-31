#ifndef HEADER_fd_src_util_fd_util_target_h
#define HEADER_fd_src_util_fd_util_target_h

/* Build target capabilities ******************************************/

/* Different build targets often have different levels of support for
   various language and hardware features.  The presence of various
   features can be tested at preprocessor, compile, or run time via the
   below capability macros.

   Code that does not exploit any of these capabilities written within
   the base development environment should be broadly portable across a
   range of build targets ranging from on-chain virtual machines to
   commodity hosts to custom hardware.

   As such, highly portable yet high performance code is possible by
   writing generic implementations that do not exploit any of the below
   capabilities as a portable fallback along with build target specific
   optimized implementations that are invoked when the build target
   supports the appropriate capabilities.

   The base development itself provide lots of functionality to help
   with implementing portable fallbacks while making very minimal
   assumptions about the build targets and zero use of 3rd party
   libraries (these might make unknown additional assumptions about the
   build target, including availability of a quality implementation of
   the library on the build target). */

/* FD_HAS_HOSTED:  If the build target is hosted (e.g. resides on a host
   with a POSIX-ish environment ... practically speaking, stdio.h,
   stdlib.h, unistd.h, et al more or less behave normally ...
   pedantically XOPEN_SOURCE=700), FD_HAS_HOSTED will be 1.  It will be
   zero otherwise. */

#ifndef FD_HAS_HOSTED
#define FD_HAS_HOSTED 0
#endif

/* FD_HAS_ATOMIC:  If the build target supports atomic operations
   between threads accessing a common memory region (include threads
   that reside in different processes on a host communicating via a
   shared memory region with potentially different local virtual
   mappings).  Practically speaking, does atomic compare-and-swap et al
   work? */

#ifndef FD_HAS_ATOMIC
#define FD_HAS_ATOMIC 0
#endif

/* FD_HAS_THREADS:  If the build target supports a POSIX-ish notion of
   threads (e.g. practically speaking, global variables declared within
   a compile unit are visible to more than one thread of execution,
   pthreads.h / threading parts of C standard, the atomics parts of the
   C standard, ... more or less work normally), FD_HAS_THREADS will be
   1.  It will be zero otherwise.  FD_HAS_THREADS implies FD_HAS_HOSTED
   and FD_HAS_ATOMIC. */

#ifndef FD_HAS_THREADS
#define FD_HAS_THREADS 0
#endif

/* FD_HAS_INT128:  If the build target supports reasonably efficient
   128-bit wide integer operations, define FD_HAS_INT128 to 1 to enable
   use of them in implementations. */

#ifndef FD_HAS_INT128
#define FD_HAS_INT128 0
#endif

/* FD_HAS_DOUBLE:  If the build target supports reasonably efficient
   IEEE 754 64-bit wide double precision floating point options, define
   FD_HAS_DOUBLE to 1 to enable use of them in implementations.  Note
   that even if the build target does not, va_args handling in the C /
   C++ language requires promotion of a float in an va_arg list to a
   double.  Thus, C / C++ language that support IEEE 754 float also
   implies a minimum level of support for double (though not necessarily
   efficient or IEEE 754).  That is, even if a target does not have
   FD_HAS_DOUBLE, there might still be limited use of double in va_arg
   list handling. */

#ifndef FD_HAS_DOUBLE
#define FD_HAS_DOUBLE 0
#endif

/* FD_HAS_ALLOCA:  If the build target supports fast alloca-style
   dynamic stack memory allocation (e.g. alloca.h / __builtin_alloca
   more or less work normally), define FD_HAS_ALLOCA to 1 to enable use
   of it in implementations. */

#ifndef FD_HAS_ALLOCA
#define FD_HAS_ALLOCA 0
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

#if defined(__x86_64__) && defined(__SSE4_2__)
#define FD_HAS_SSE 1
#else
#define FD_HAS_SSE 0
#endif

/* FD_HAS_AVX indicates the target supports Intel AVX2 style SIMD
   (basically do the 256-bit wide parts of "x86intrin.h" work).
   Recommend using the simd/fd_avx.h APIs instead of raw Intel
   intrinsics for readability and to facilitate portability to non-x86
   platforms.  Implies FD_HAS_SSE. */

#if defined(__x86_64__) && defined(__AVX2__)
#define FD_HAS_AVX 1
#else
#define FD_HAS_AVX 0
#endif

/* FD_HAS_SHANI indicates that the target supports Intel SHA extensions
   which accelerate SHA-1 and SHA-256 computation.  This extension is
   also called SHA-NI or SHA_NI (Secure Hash Algorithm New
   Instructiosn).  Although proposed in 2013, they're only supported on
   Intel Ice Lake and AMD Zen CPUs and newer.  Implies FD_HAS_AVX. */

#if defined(__x86_64__) && defined(__SHA__)
#define FD_HAS_SHANI 1
#else
#define FD_HAS_SHANI 0
#endif

/* FD_HAS_GFNI indicates that the target supports Intel Galois Field
 * extensions, which accelerate operations over binary extension fields,
 * especially GF(2^8).  These instructions are supported on Intel Ice
 * Lake and newer and AMD Zen4 and newer CPUs.  Implies FD_HAS_AVX. */

#if defined(__x86_64__) && defined(__GFNI__)
#define FD_HAS_GFNI 1
#else
#define FD_HAS_GFNI 0
#endif

/* FD_HAS_ASAN indicates that the build target is using ASAN. */
#define FD_HAS_ASAN 0
#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    undef FD_HAS_ASAN
#    define FD_HAS_ASAN 1
#  endif
#endif

/* FD_HAS_UBSAN indicates that the build target is using UBSAN. */
#ifndef FD_HAS_UBSAN
#define FD_HAS_UBSAN 0
#endif

#endif /* HEADER_fd_src_util_fd_util_target_h */
