#ifndef HEADER_fd_src_util_simd_fd_avx512_h
#define HEADER_fd_src_util_simd_fd_avx512_h

#if FD_HAS_AVX512

/* An API for writing vectorized C/C++ code using 16-wide 32-bit ints,
   16-wide 32-bit uints, 16-wide 32-bit floats, 8-wide 64-bit doubles,
   8-wide 64-bit longs, 8-wide 64-bit ulongs and 16- or 8-wide logicals
   assuming a platform with AVX512 support.

   Essentially, all the usual C/C++ operations you can do on an int,
   uint, float, double, long, ulong or logical has a fast O(1)
   vectorized equivalent here.  Most operations boil down to a single
   assembly instruction in most cases and the macros are robust.

   Further operations commonly used to transition from scalar/vector to
   vector/scalar code, to do cross lane data motion, etc are also
   provided to make it much easier to convert scalar implementations
   into highly optimized vectorized implementations.

   That is, this is a thin wrapper around Intel's AVX512 intrinsics to
   give it a sane type system and robust semantics for writing mixed
   type and mixed width vectorized code (including branching).  This
   includes a lot of non-obvious tricks, fixes for the ultra high
   density of irregularities in their intrinsics, implementations of
   missing intrinsics and lots of workarounds to get Intel AVX512 to
   behave sanely.

   A side effect is that this API also makes it easy to port code
   vectorized for AVX512 to non-Intel architectures.  Just make
   implementations of these wrappers for the target platform and then,
   magically, code written in terms of this API has been ported.  (This
   is similar to how CUDA works under the hood.  Developers don't write
   GPU code ... they write CUDA code that is then adapted for the target
   architecture by the CUDA tooling at compile- or run-time.)

   Much like the fd_util_base.h primitive types, APIs in here generally
   aren't prefixed with fd_ given how aggressively they get used in
   writing compute intensive code.  This is unlikely to matter
   practically given this API is both optional and limited to particular
   build targets (i.e. namespace collisions highly unlikely to occur
   accidentally). */

#include "../bits/fd_bits.h"
#include <x86intrin.h> /* Include the intrinsics we are going to patch up */

/* Some useful constants */

#define WW_WIDTH        (16) /* Vector width / element count / lanes (32-bit elements) */
#define WW_FOOTPRINT    (64) /* Vector byte size */
#define WW_ALIGN        (64) /* Vector byte alignment required for aligned operations */
#define WW_LG_WIDTH      (4) /* log_2 WW_WIDTH */
#define WW_LG_FOOTPRINT  (6) /* log_2 WW_FOOTPRINT */
#define WW_LG_ALIGN      (6) /* log_2 WW_ALIGN */
#define WW_ATTR         __attribute__((aligned(WW_ALIGN)))

/* Include all the APIs */

/* TODO: ADD EXTRA APIS AS NECESSARY */
//#include "fd_avx512_wwc.h" /* Vector conditional support */
//#include "fd_avx512_wwf.h" /* Vector float support */
//#include "fd_avx512_wwi.h" /* Vector int support */
//#include "fd_avx512_wwu.h" /* Vector uint support */
//#include "fd_avx512_wwd.h" /* Vector double support */
#include "fd_avx512_wwl.h" /* Vector long support */
#include "fd_avx512_wwv.h" /* Vector ulong support */
//#include "fd_avx512_wwb.h" /* Vector uchar (byte) support */

#else
#error "Build target does not support AVX512 wrappers"
#endif

#endif /* HEADER_fd_src_util_simd_fd_avx512_h */
