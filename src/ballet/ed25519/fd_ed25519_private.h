#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h
#define HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h

#include "fd_ed25519.h"

/* Field element API **************************************************/

#ifndef FD_ED25519_FE_IMPL
#if FD_HAS_AVX
#define FD_ED25519_FE_IMPL 1
#else
#define FD_ED25519_FE_IMPL 0
#endif
#endif

#if FD_ED25519_FE_IMPL==0
#include "ref/fd_ed25519_fe.h"
#elif FD_ED25519_FE_IMPL==1
#include "avx/fd_ed25519_fe.h"
#else
#error "Unsupported FD_ED25519_FE_IMPL"
#endif

/* Constants used in multiple functions.
   Currently the same no matter the backend (ref or avx).
 */
#include "fd_ed25519_private_const.h"

/* Group element API **************************************************/

/* A fd_ed25519_ge_*_t stores an ed25519 group element.  Here the group
   is the set of pairs (x,y) of field elements satisfying
     -x^2 + y^2 = 1 + d x^2y^2
   where d = -121665/121666.  Useful representations include:

     p2 (projective): (X:Y:Z)   satisfying x=X/Z, y=Y/Z
     p3 (extended):   (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT */

struct fd_ed25519_ge_p2_private {
  fd_ed25519_fe_t X[1];
  fd_ed25519_fe_t Y[1];
  fd_ed25519_fe_t Z[1];
};

typedef struct fd_ed25519_ge_p2_private fd_ed25519_ge_p2_t;

struct fd_ed25519_ge_p3_private {
  fd_ed25519_fe_t X[1];
  fd_ed25519_fe_t Y[1];
  fd_ed25519_fe_t Z[1];
  fd_ed25519_fe_t T[1];
};

typedef struct fd_ed25519_ge_p3_private fd_ed25519_ge_p3_t;

static const uchar fd_ed25519_scalar_zero[ 32 ] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static const uchar fd_ed25519_scalar_one[ 32 ] = {
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* l   = 2^252 + 27742317777372353535851937790883648493
       = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
   l-1 = 0x10...ec */
static const uchar fd_ed25519_scalar_minus_one[ 32 ] = {
  0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

FD_PROTOTYPES_BEGIN

/* FIXME: DOCUMENT THESE */

uchar *
fd_ed25519_ge_tobytes( uchar *                    s,   /* 32 */
                       fd_ed25519_ge_p2_t const * h );

uchar *
fd_ed25519_ge_p3_tobytes( uchar *                    s,   /* 32 */
                          fd_ed25519_ge_p3_t const * h );

int
fd_ed25519_ge_frombytes_vartime( fd_ed25519_ge_p3_t * h,
                                 uchar const *        s ); /* 32 */

int
fd_ed25519_ge_frombytes_vartime_2( fd_ed25519_ge_p3_t * h0, uchar const * s0,   /* 32 */
                                   fd_ed25519_ge_p3_t * h1, uchar const * s1 ); /* 32 */

int fd_ed25519_ge_p3_is_small_order(fd_ed25519_ge_p3_t * const p);

static inline fd_ed25519_ge_p2_t *
fd_ed25519_ge_p2_0( fd_ed25519_ge_p2_t * h ) {
  fd_ed25519_fe_0( h->X );
  fd_ed25519_fe_1( h->Y );
  fd_ed25519_fe_1( h->Z );
  return h;
}

static inline fd_ed25519_ge_p3_t *
fd_ed25519_ge_p3_0( fd_ed25519_ge_p3_t * h ) {
  fd_ed25519_fe_0( h->X );
  fd_ed25519_fe_1( h->Y );
  fd_ed25519_fe_1( h->Z );
  fd_ed25519_fe_0( h->T );
  return h;
}

static inline int
fd_ed25519_ge_eq( fd_ed25519_ge_p3_t * const p,
                  fd_ed25519_ge_p3_t * const q ) {
  fd_ed25519_fe_t cmp[2];
  fd_ed25519_fe_mul( &cmp[ 0 ], p->X, q->Z );
  fd_ed25519_fe_mul( &cmp[ 1 ], q->X, p->Z );
  int x = fd_ed25519_fe_eq( &cmp[ 0 ], &cmp[ 1 ] );

  fd_ed25519_fe_mul( &cmp[ 0 ], p->Y, q->Z );
  fd_ed25519_fe_mul( &cmp[ 1 ], q->Y, p->Z );
  int y = fd_ed25519_fe_eq( &cmp[ 0 ], &cmp[ 1 ] );

  return x & y;
}

fd_ed25519_ge_p3_t *
fd_ed25519_ge_scalarmult_base( fd_ed25519_ge_p3_t * h,
                               uchar const *        a );

fd_ed25519_ge_p2_t *
fd_ed25519_ge_double_scalarmult_vartime( fd_ed25519_ge_p2_t *       r,
                                         uchar const *              a,
                                         fd_ed25519_ge_p3_t const * A,
                                         uchar const *              b );

/* User APIs **********************************************************/

/* fd_ed25519_sc_reduce computes s mod l where s is a 512-bit value.  s
   is stored in 64-byte little endian form and in points to the first
   byte of s.  l is:

     2^252 + 27742317777372353535851937790883648493.

   The result can be represented as a 256-bit value and stored in a
   32-byte little endian form.  out points to where to store the result.

   Does no input argument checking.  The caller takes a write interest
   in out and a read interest in in for the duration of the call.
   Returns out and, on return, out will be populated with the 256-bit
   result.  In-place operation fine. */

uchar *
fd_ed25519_sc_reduce( uchar       out[ static 32 ],
                      uchar const in [ static 64 ] );

/* fd_ed25519_sc_muladd computes s = (a*b+c) mod l where a, b and c
   are 256-bit values.  a is stored in 32-byte little endian form and a
   points to the first byte of a.  Similarly for b and c.  l is:

     2^252 + 27742317777372353535851937790883648493.

   The result can be represented as a 256-bit value and stored in a
   32-byte little endian form.  s points to where to store the result.

   Does no input argument checking.  The caller takes a write interest
   in s and a read interest in a, b and c for the duration of the call.
   Returns s and, on return, s will be populated with the 256-bit
   result.  In-place operation fine. */

uchar *
fd_ed25519_sc_muladd( uchar *       s,
                      uchar const * a,
                      uchar const * b,
                      uchar const * c );

static inline uchar *
fd_ed25519_sc_mul   ( uchar *       s,
                      uchar const * a,
                      uchar const * b ) {
  return fd_ed25519_sc_muladd( s, a, b, fd_ed25519_scalar_zero );
}

static inline uchar *
fd_ed25519_sc_add   ( uchar *       s,
                      uchar const * a,
                      uchar const * b ) {
  return fd_ed25519_sc_muladd( s, a, fd_ed25519_scalar_one, b );
}

static inline uchar *
fd_ed25519_sc_sub   ( uchar *       s,
                      uchar const * a,
                      uchar const * b ) {
  //TODO implement dedicated neg/sub
  return fd_ed25519_sc_muladd( s, fd_ed25519_scalar_minus_one, b, a );
}

static inline uchar *
fd_ed25519_sc_neg   ( uchar *       s,
                      uchar const * a ) {
  //TODO implement dedicated neg/sub
  return fd_ed25519_sc_muladd( s, fd_ed25519_scalar_minus_one, a, fd_ed25519_scalar_zero );
}

static inline uchar *
fd_ed25519_sc_inv( uchar *       s,
                   uchar const * a ) {
  uchar t[ 32 ];
  // TODO: use mul chain to save ~12% https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion
  /* the bits of -2 are the same as -1, except the first few (that we skip):
     -1 = 0xEC ... = b 1110 1100 ...
     -2 = 0xEB ... = b 1110 1011 ...
                       ^ bit 7 ^ bit 0
   */
  /* bit 0 == 1 */
  fd_memcpy( t, a, 32 );
  fd_memcpy( s, a, 32 );
  /* bit 1 == 1 */
  fd_ed25519_sc_mul( t, t, t );
  fd_ed25519_sc_mul( s, s, t );
  /* bit 2 == 0 */
  fd_ed25519_sc_mul( t, t, t );
  /* from bit 3 on, use -1 bits */
  for( ulong i=3; i<=252; i++ ) {
    fd_ed25519_sc_mul( t, t, t );
    if( (fd_ed25519_scalar_minus_one[ i/8 ] & (1 << (i % 8))) ) {
      fd_ed25519_sc_mul( s, s, t );
    }
  }
  return s;
}

static inline void
fd_ed25519_sc_batch_inv( uchar       s     [ static 32 ], /* sz scalars */
                         uchar       allinv[ static 32 ], /* 1 scalar */
                         uchar const a     [ static 32 ], /* sz scalars */
                         ulong       sz ) {
  uchar acc[ 32 ];
  fd_memcpy( acc, fd_ed25519_scalar_one, 32 );
  for( ulong i=0; i<sz; i++ ) {
    fd_memcpy( &s[ i*32 ], acc, 32 );
    fd_ed25519_sc_mul( acc, acc, &a[ i*32 ] );
  }

  fd_ed25519_sc_inv( acc, acc );
  fd_memcpy( allinv, acc, 32 );

  for( int i=(int)sz-1; i>=0; i-- ) {
    fd_ed25519_sc_mul( &s[ i*32 ], &s[ i*32 ], acc );
    fd_ed25519_sc_mul( acc, acc, &a[ i*32 ] );
  }
}


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h */
