#ifndef HEADER_fd_src_ballet_bigint_uint256_h
#define HEADER_fd_src_ballet_bigint_uint256_h

/* Implementation of uint256. */

#include "../fd_ballet_base.h"

/* Align at most at 32 bytes.
   This way a struct containing multiple fd_uint256_t doesn't waste space
   (e.g., on avx512 FD_ALIGNED would be 64, causing each fd_uint256_t to
   consume 64 bytes instead of 32).
   Note: FD_ALIGNED implies FD_UINT256_ALIGNED, so a struct containing 1+
   fd_uint256_t can be simply defined as FD_ALIGNED, and it's also implicitly
   FD_UINT256_ALIGNED. */
#if FD_ALIGN > 32
#define FD_UINT256_ALIGNED __attribute__((aligned(32)))
#else
#define FD_UINT256_ALIGNED FD_ALIGNED
#endif

/* fd_uint256_t represents a uint256 as a buffer of 32 bytes,
   or equivalently (on little endian platforms) an array of 4 ulong. */
union FD_UINT256_ALIGNED fd_uint256 {
  ulong limbs[4];
  uchar buf[32];
};
typedef union fd_uint256 fd_uint256_t;

/* fd_uint256_bswap swaps 32 bytes. Useful to convert from/to
   little and big endian. */
static inline fd_uint256_t *
fd_uint256_bswap( fd_uint256_t *       r,
                  fd_uint256_t const * a ) {
  ulong r3 = fd_ulong_bswap( a->limbs[0] );
  ulong r2 = fd_ulong_bswap( a->limbs[1] );
  ulong r1 = fd_ulong_bswap( a->limbs[2] );
  ulong r0 = fd_ulong_bswap( a->limbs[3] );
  r->limbs[3] = r3;
  r->limbs[2] = r2;
  r->limbs[1] = r1;
  r->limbs[0] = r0;
  return r;
}

/* fd_uint256_eq returns 1 is a == b, 0 otherwise. */
static inline int
fd_uint256_eq( fd_uint256_t const * a,
               fd_uint256_t const * b ) {
  return ( a->limbs[0] == b->limbs[0] )
      && ( a->limbs[1] == b->limbs[1] )
      && ( a->limbs[2] == b->limbs[2] )
      && ( a->limbs[3] == b->limbs[3] );
}

/* fd_uint256_cmp returns 0 is a == b, -1 if a < b, 1 if a > b. */
static inline int
fd_uint256_cmp( fd_uint256_t const * a,
                fd_uint256_t const * b ) {
  for( int i=3; i>=0; i-- ) {
    if( a->limbs[i] != b->limbs[i] ) {
      return a->limbs[i] > b->limbs[i] ? 1 : -1;
    }
  }
  return 0;
}

/* fd_uint256_bit returns the i-th bit of a.
   Important: the return value is 0, non-zero, it's NOT 0, 1. */
static inline ulong
fd_uint256_bit( fd_uint256_t const * a,
                int                  i ) {
  return a->limbs[i / 64] & (1UL << (i % 64));
}

#include "./fd_uint256_mul.h"

#endif /* HEADER_fd_src_ballet_bigint_uint256_h */
