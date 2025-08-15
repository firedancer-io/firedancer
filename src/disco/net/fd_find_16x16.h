#ifndef HEADER_fd_src_disco_net_fd_find_16x16_h
#define HEADER_fd_src_disco_net_fd_find_16x16_h

/* fd_find_16x16() provides an API to find an element in ushort[ 16 ].

   If multiple elements match, returns the one at the lowest index.
   If no element matched, returns 16. */

#include "../../util/fd_util_base.h"

#if FD_HAS_AVX

#include "../../util/simd/fd_avx.h"

static inline uint
fd_find_16x16_avx( wu_t const ymm,
                   ushort     x ) {
  wc_t cmp_res  = wh_eq( ymm, wh_bcast( x ) );
  uint mask     = (uint)_mm256_movemask_epi8( cmp_res );
#if defined(__LZNCT__)
  int  lane_idx = _lzcnt_u32( mask ); /* lane_idx==32 if mask==0 */
#else
  int  lane_idx = fd_uint_find_lsb_w_default( mask, 32 );
#endif
  return ((uint)lane_idx)>>1;
}

#endif

static inline uint
fd_find_16x16_generic( ushort const ele[ 16 ],
                       ushort       x ) {
  /* Generates surprisingly bad code on GCC 15 and Clang 20 */
  uint i;
  for( i=0; i<16; i++ ) {
    if( ele[ i ]==x ) break;
  }
  return i;
}

#if FD_HAS_AVX
static inline uint fd_find_16x16( ushort const ele[ 16 ], ushort x ) { return fd_find_16x16_avx( wu_ldu( ele ),x ); }
#else
#define fd_find_16x16 fd_find_16x16_generic
#endif

#endif /* HEADER_fd_src_disco_net_fd_find_16x16_h */
