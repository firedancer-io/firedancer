#ifndef HEADER_fd_src_ballet_bigint_fd_uint384_h
#define HEADER_fd_src_ballet_bigint_fd_uint384_h

/* Implementation of uint384. */

#include "../fd_ballet_base.h"

/* Kept at the natural alignment, as our usecases like P-384 require that
   the limbs have no padding in between them. */
union fd_uint384 {
  ulong limbs[6];
  uchar buf[48];
};
typedef union fd_uint384 fd_uint384_t;

static inline fd_uint384_t *
fd_uint384_bswap( fd_uint384_t *       r,
                  fd_uint384_t const * a ) {
  ulong r5 = fd_ulong_bswap( a->limbs[0] );
  ulong r4 = fd_ulong_bswap( a->limbs[1] );
  ulong r3 = fd_ulong_bswap( a->limbs[2] );
  ulong r2 = fd_ulong_bswap( a->limbs[3] );
  ulong r1 = fd_ulong_bswap( a->limbs[4] );
  ulong r0 = fd_ulong_bswap( a->limbs[5] );
  r->limbs[5] = r5;
  r->limbs[4] = r4;
  r->limbs[3] = r3;
  r->limbs[2] = r2;
  r->limbs[1] = r1;
  r->limbs[0] = r0;
  return r;
}

/* fd_uint384_eq returns 1 if a == b, 0 otherwise. */
static inline int
fd_uint384_eq( fd_uint384_t const * a,
               fd_uint384_t const * b ) {
  return ( a->limbs[0] == b->limbs[0] )
      && ( a->limbs[1] == b->limbs[1] )
      && ( a->limbs[2] == b->limbs[2] )
      && ( a->limbs[3] == b->limbs[3] )
      && ( a->limbs[4] == b->limbs[4] )
      && ( a->limbs[5] == b->limbs[5] );
}

/* fd_uint384_is_zero returns 1 if a == 0, 0 otherwise. */
static inline int
fd_uint384_is_zero( fd_uint384_t const * a ) {
  return !( a->limbs[0] | a->limbs[1] | a->limbs[2] |
            a->limbs[3] | a->limbs[4] | a->limbs[5] );
}

/* fd_uint384_cmp returns 0 if a == b, -1 if a < b, 1 if a > b. */
static inline int
fd_uint384_cmp( fd_uint384_t const * a,
                fd_uint384_t const * b ) {
  for( int i=5; i>=0; i-- ) {
    if( a->limbs[i] != b->limbs[i] ) {
      return a->limbs[i] > b->limbs[i] ? 1 : -1;
    }
  }
  return 0;
}

#endif /* HEADER_fd_src_ballet_bigint_fd_uint384_h */
