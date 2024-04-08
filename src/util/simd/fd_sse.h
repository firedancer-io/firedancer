#ifndef HEADER_fd_src_util_simd_fd_sse_h
#define HEADER_fd_src_util_simd_fd_sse_h

#if FD_HAS_SSE

/* An API for writing vectorized C/C++ code using 4-wide 32-bit ints,
   4-wide 32-bit uints, 4-wide 32-bit floats, 2-wide 64-bit doubles,
   2-wide 64-bit longs, 2-wide 64-bit ulongs and 4- or 2-wide logicals
   assuming a platform with SSE support.

   Essentially, all the usual C/C++ operations you can do on an int,
   uint, float, double, long, ulong or logical has a fast O(1)
   vectorized equivalent here.  Most operations boil down to a single
   assembly instruction in most cases and the macros are robust.

   Further operations commonly used to transition from scalar/vector to
   vector/scalar code, to do cross lane data motion, etc are also
   provided to make it much easier to convert scalar implementations
   into highly optimized vectorized implementations.

   That is, this is a thin wrapper around Intel's SSE intrinsics to give
   it a sane type system and robust semantics for writing mixed type and
   mixed width vectorized code (including branching).  This includes a
   lot of non-obvious tricks, fixes for ultra high density of
   irregularities in their intrinsics, implementations of missing
   intrinsics and lots of workarounds to get Intel AVX to behave sanely.

   A side effect is that this API also makes it easy to port code
   vectorized for SSE to non-Intel architectures.  Just make
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

#define V_WIDTH         (4) /* Vector width / element count / lanes */
#define V_FOOTPRINT    (16) /* Vector byte size */
#define V_ALIGN        (16) /* Vector byte alignment required for aligned operations */
#define V_LG_WIDTH      (4) /* log_2 V_WIDTH */
#define V_LG_FOOTPRINT  (4) /* log_2 V_FOOTPRINT */
#define V_LG_ALIGN      (4) /* log_2 V_ALIGN */
#define V_ATTR         __attribute__((aligned(V_ALIGN)))

/* Include all the APIs */

#include "fd_sse_vc.h" /* Vector conditional support */
#include "fd_sse_vf.h" /* Vector float support */
#include "fd_sse_vi.h" /* Vector int support */
#include "fd_sse_vu.h" /* Vector uint support */
#include "fd_sse_vd.h" /* Vector double support */
#include "fd_sse_vl.h" /* Vector long support */
#include "fd_sse_vv.h" /* Vector ulong support */
#include "fd_sse_vb.h" /* Vector uchar (byte) support */

#else
#error "Build target does not support SSE wrappers"
#endif

#endif /* HEADER_fd_src_util_simd_fd_sse_h */

