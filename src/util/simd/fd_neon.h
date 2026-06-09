#ifndef HEADER_fd_src_util_simd_fd_neon_h
#define HEADER_fd_src_util_simd_fd_neon_h

#include "../bits/fd_bits.h"

#if FD_HAS_NEON

#include <arm_neon.h>

typedef uint32x4_t fd_neon_u32x4_t;
typedef uint8x16_t fd_neon_u8x16_t;

FD_FN_CONST static inline fd_neon_u32x4_t
fd_neon_u32x4_bcast( uint x ) {
  return vdupq_n_u32( x );
}

static inline fd_neon_u32x4_t
fd_neon_u32x4( uint x0, uint x1, uint x2, uint x3 ) {
  uint const lane[ 4 ] = { x0, x1, x2, x3 };
  return vld1q_u32( lane );
}

FD_FN_CONST static inline fd_neon_u32x4_t
fd_neon_u32x4_rotl( fd_neon_u32x4_t x, int n ) {
  switch( n ) {
  case  7: return vorrq_u32( vshlq_n_u32( x,  7 ), vshrq_n_u32( x, 25 ) );
  case  8: return vorrq_u32( vshlq_n_u32( x,  8 ), vshrq_n_u32( x, 24 ) );
  case 12: return vorrq_u32( vshlq_n_u32( x, 12 ), vshrq_n_u32( x, 20 ) );
  case 16: return vorrq_u32( vshlq_n_u32( x, 16 ), vshrq_n_u32( x, 16 ) );
  default: return vorrq_u32( vshlq_u32( x, vdupq_n_s32( n ) ), vshlq_u32( x, vdupq_n_s32( n-32 ) ) );
  }
}

FD_FN_CONST static inline fd_neon_u32x4_t
fd_neon_u32x4_rev32( fd_neon_u32x4_t x ) {
  return vreinterpretq_u32_u8( vrev32q_u8( vreinterpretq_u8_u32( x ) ) );
}

static inline fd_neon_u32x4_t
fd_neon_u32x4_load( void const * p ) {
  return vld1q_u32( (uint const *)p );
}

static inline void
fd_neon_u32x4_store( void * p, fd_neon_u32x4_t x ) {
  vst1q_u32( (uint *)p, x );
}

static inline fd_neon_u8x16_t
fd_neon_u8x16_load( void const * p ) {
  return vld1q_u8( (uchar const *)p );
}

static inline void
fd_neon_u8x16_store( void * p, fd_neon_u8x16_t x ) {
  vst1q_u8( (uchar *)p, x );
}

#endif /* FD_HAS_NEON */

#endif /* HEADER_fd_src_util_simd_fd_neon_h */
