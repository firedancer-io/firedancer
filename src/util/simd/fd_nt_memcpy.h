#ifndef HEADER_fd_src_util_simd_fd_nt_memcpy_h
#define HEADER_fd_src_util_simd_fd_nt_memcpy_h

#if FD_HAS_SSE || FD_HAS_AVX || FD_HAS_AVX512

/* Unlike the other headers in this directory, this one does not contain
   a vector API.  Instead, it includes files for vector accelerated
   non-temporal memcpy.  In x86, using non-temporal store requires
   either assembly or the emmintrin.h header, but really the best way to
   use them is via SIMD instructions, which is why the functions are
   here.

   Crash course on non-temporal memory hints and write combining memory:

   When we think about normal memory that an application uses, what
   we're typically thinking of is memory classified as Write Back (WB)
   type memory.  WB memory is cacheable and provides total store
   ordering.  Modern x86 CPUs, however, support other types of memory,
   which is normally used for memory-mapped I/O and frame-buffer memory
   for a graphics system.  (The OS configures these memory types using
   the Memory Type Range Registers or the Page Attribute Table.)

   The Write Combining (WC) memory type, unlike WB, on the other hand,
   does not allow caching, but it does allow the CPU to delay, reorder,
   and combine writes to the same 64 byte cache line.  That is, writes
   to a cache line of WC memory are initially staged in a special WC
   buffer instead of the normal cache.  As long as that data remains in
   the WC buffer, additional writes to it are "combined" in the WC
   buffer; at this point, none of the writes are visible to other
   processors, since the WC buffer does not listen to snooping.  At some
   point, the WC buffer is evicted, and the 64-byte chunk of data is
   written back to main memory.  AMD's optimization guides mention
   that, at least for Zen 4 and Zen 5, writing all 64 bytes is enough to
   trigger evicting the WC buffer.  Intel's manual makes no such
   promise.  Executing an SFENCE or MFENCE instruction is always
   sufficient to evict all WC buffers, however.

   This is relevant because using a non-temporal write causes the
   processor to treat WB memory as if it were WC.  In order to do this,
   the processor must first make sure the memory is not in the normal
   cache (evicting it if so).  The written data then goes to the WC
   buffer, bypassing the cache.  It is eventually written back to main
   memory, at which point it becomes visible to other cores.  In all of
   these steps, it never touches the normal cache, which means it won't
   pollute anything there.

   On completely the other hand, the SIMD non-temporal loads are
   documented to do nothing special when writing to WB memory.  That
   means if we want non-temporal-like behavior, we need to implement it
   another way.  Currently, the least polluting way is to pre-fetch the
   data with the non-temporal hint (PREFETCHNTA) and then demote it to
   L3 afterwards (CLDEMOTE).  It may still evict data on the way in, and
   Intel's manual isn't as descriptive about what this actually does,
   but it should reduce the amount of cache pollution. */



/* fd_memcpy_{nn,nt,tn,tt} copies `sz` bytes from the source (`_s`) to
   the destination (`_d`), where either the source is loaded with the
   non-temporal memory hint, the destination is stored with the
   non-temporal memory hint, or both.  `sz` need not be a multiple of
   64.  `s` and `d` must not overlap.  Returns `d`.

   The first letter of the function suffix indicates how the destination
   is stored, and the second letter of the suffix indicates how the
   source is loaded.  n means non-temporal while t means temporal
   (regular load/store).  fd_memcpy_tt is basically just normal memcpy
   and is only included for completeness; the compiler may even replace
   a call to it with memcpy.

   WARNING: the writes to memory that this function issues may become
   visible to another core in a surprising order.  This is a normal part
   of the memcpy contract, but is especially true when using
   non-temporal stores.  This function includes the appropriate fencing
   so that stores issued by this function will become visible before any
   stores following the function call.

   WARNING: on many CPUs, a normal store following a non-temporal store
   to the same cache line causes a SEVERE performance degradation
   (approx 500-1000 cycles).  See the crash course for the background on
   why.  This function will not trigger these stalls, even when `_d` and
   `sz` are not multiples of 64, but it's up to the caller not to touch
   the memory pointed to by _d after this function returns. */

#include "../fd_util_base.h"
#include <immintrin.h>

#define FD_EMIT_TEMPORAL_MEMCPY( suffix, needs_sfence )                                               \
static void *                                                                                         \
fd_memcpy_##suffix( void       * FD_RESTRICT _d,                                                      \
                    void const * FD_RESTRICT _s,                                                      \
                    ulong                    sz ) {                                                   \
  ulong                     rem = sz;                                                                 \
  uchar *       FD_RESTRICT d   = (uchar       *)_d;                                                  \
  uchar const * FD_RESTRICT s   = (uchar const *)_s;                                                  \
  ulong align = fd_ulong_min( rem, fd_ulong_align_up( (ulong)d, 64UL ) - (ulong)d );                  \
  if( FD_UNLIKELY( align ) ) { memcpy( d, s, align ); rem -= align; d += align; s += align; }         \
  for( ; rem>63UL; rem-=64UL, d += 64UL, s += 64UL ) copy64_##suffix( d, s );                         \
  if( needs_sfence         ) _mm_sfence();                                                            \
  if( FD_UNLIKELY( rem   ) ) memcpy( d, s, rem );                                                     \
  return _d;                                                                                          \
}


#if FD_HAS_AVX512

#if defined(__CLDEMOTE__) && 0
/* cldemote is only supported on Sapphire Rapids and newer.  Some
   experiments on Emerald Rapids showed that it does reduce cache
   pollution, but it dramatically reduces the speed of the copy.  For
   now, we'll just disable it globally.  Maybe it will make sense on a
   future CPU. */
#define FD_CLDEMOTE( s )  _cldemote( (void *)(s) )
#else
#define FD_CLDEMOTE( s ) do { } while( 0 )
#endif

# define copy64_nn( d, s ) do { _mm_prefetch( (s)+384UL, _MM_HINT_NTA ); _mm512_stream_si512( (void *)(d), _mm512_loadu_si512( (void const *)(s) ) ); FD_CLDEMOTE( s ); } while( 0 )
# define copy64_nt( d, s ) do {                                          _mm512_stream_si512( (void *)(d), _mm512_loadu_si512( (void const *)(s) ) );                   } while( 0 )
# define copy64_tn( d, s ) do { _mm_prefetch( (s)+384UL, _MM_HINT_NTA ); _mm512_storeu_si512( (void *)(d), _mm512_loadu_si512( (void const *)(s) ) ); FD_CLDEMOTE( s ); } while( 0 )
# define copy64_tt( d, s ) do {                                          _mm512_storeu_si512( (void *)(d), _mm512_loadu_si512( (void const *)(s) ) );                   } while( 0 )

#elif FD_HAS_AVX

# define copy64_nn( d, s ) do { _mm_prefetch( (s)+384UL, _MM_HINT_NTA ); _mm256_stream_si256( (void *)(d     ), _mm256_loadu_si256( (void const *)(s     ) ) );              \
                                                                         _mm256_stream_si256( (void *)(d+32UL), _mm256_loadu_si256( (void const *)(s+32UL) ) ); } while( 0 )
# define copy64_nt( d, s ) do {                                          _mm256_stream_si256( (void *)(d     ), _mm256_loadu_si256( (void const *)(s     ) ) );              \
                                                                         _mm256_stream_si256( (void *)(d+32UL), _mm256_loadu_si256( (void const *)(s+32UL) ) ); } while( 0 )
# define copy64_tn( d, s ) do { _mm_prefetch( (s)+384UL, _MM_HINT_NTA ); _mm256_storeu_si256( (void *)(d     ), _mm256_loadu_si256( (void const *)(s     ) ) );              \
                                                                         _mm256_storeu_si256( (void *)(d+32UL), _mm256_loadu_si256( (void const *)(s+32UL) ) ); } while( 0 )
# define copy64_tt( d, s ) do {                                          _mm256_storeu_si256( (void *)(d     ), _mm256_loadu_si256( (void const *)(s     ) ) );              \
                                                                         _mm256_storeu_si256( (void *)(d+32UL), _mm256_loadu_si256( (void const *)(s+32UL) ) ); } while( 0 )

#elif FD_HAS_SSE

# define copy64_nn( d, s ) do { _mm_prefetch( (s)+384UL, _MM_HINT_NTA ); _mm_stream_si128( (void *)(d     ), _mm_loadu_si128( (void const *)(s     ) ) );              \
                                                                         _mm_stream_si128( (void *)(d+16UL), _mm_loadu_si128( (void const *)(s+16UL) ) );              \
                                                                         _mm_stream_si128( (void *)(d+32UL), _mm_loadu_si128( (void const *)(s+32UL) ) );              \
                                                                         _mm_stream_si128( (void *)(d+48UL), _mm_loadu_si128( (void const *)(s+48UL) ) ); } while( 0 )
# define copy64_nt( d, s ) do {                                          _mm_stream_si128( (void *)(d     ), _mm_loadu_si128( (void const *)(s     ) ) );              \
                                                                         _mm_stream_si128( (void *)(d+16UL), _mm_loadu_si128( (void const *)(s+16UL) ) );              \
                                                                         _mm_stream_si128( (void *)(d+32UL), _mm_loadu_si128( (void const *)(s+32UL) ) );              \
                                                                         _mm_stream_si128( (void *)(d+48UL), _mm_loadu_si128( (void const *)(s+48UL) ) ); } while( 0 )
# define copy64_tn( d, s ) do { _mm_prefetch( (s)+384UL, _MM_HINT_NTA ); _mm_storeu_si128( (void *)(d     ), _mm_loadu_si128( (void const *)(s     ) ) );              \
                                                                         _mm_storeu_si128( (void *)(d+16UL), _mm_loadu_si128( (void const *)(s+16UL) ) );              \
                                                                         _mm_storeu_si128( (void *)(d+32UL), _mm_loadu_si128( (void const *)(s+32UL) ) );              \
                                                                         _mm_storeu_si128( (void *)(d+48UL), _mm_loadu_si128( (void const *)(s+48UL) ) ); } while( 0 )
# define copy64_tt( d, s ) do {                                          _mm_storeu_si128( (void *)(d     ), _mm_loadu_si128( (void const *)(s     ) ) );              \
                                                                         _mm_storeu_si128( (void *)(d+16UL), _mm_loadu_si128( (void const *)(s+16UL) ) );              \
                                                                         _mm_storeu_si128( (void *)(d+32UL), _mm_loadu_si128( (void const *)(s+32UL) ) );              \
                                                                         _mm_storeu_si128( (void *)(d+48UL), _mm_loadu_si128( (void const *)(s+48UL) ) ); } while( 0 )

#else
# error "fd_nt_memcpy requires SSE, AVX or AVX512"
#endif


FD_EMIT_TEMPORAL_MEMCPY( nn, 1 )
FD_EMIT_TEMPORAL_MEMCPY( nt, 1 )
FD_EMIT_TEMPORAL_MEMCPY( tn, 0 )
FD_EMIT_TEMPORAL_MEMCPY( tt, 0 )

#undef FD_EMIT_TEMPORAL_MEMCPY

#else
#error "Build target does not support non-temporal memcpy"
#endif

#endif /* HEADER_fd_src_util_simd_fd_nt_memcpy_h */
