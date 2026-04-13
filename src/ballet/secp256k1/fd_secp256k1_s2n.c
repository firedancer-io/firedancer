#include <stdint.h>
#include <s2n-bignum.h>

/* On CPUs without ADX (mulx/adcx/adox), redirect the ADX-optimized
   s2n-bignum symbols to their _alt equivalents, which use only base
   x86-64 instructions and are functionally identical. */
#ifndef __ADX__
#define bignum_mul_p256k1      bignum_mul_p256k1_alt
#define bignum_sqr_p256k1      bignum_sqr_p256k1_alt
#define secp256k1_jadd         secp256k1_jadd_alt
#define secp256k1_jdouble      secp256k1_jdouble_alt
#define secp256k1_jmixadd      secp256k1_jmixadd_alt
#endif

#include "fd_secp256k1_base_table.c"

/* Scalars */

static inline int
fd_secp256k1_scalar_is_zero( fd_secp256k1_scalar_t const *r ) {
  return fd_uint256_eq( r, fd_secp256k1_const_zero );
}

/* Returns the scalar in NON Montgomery form. */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_frombytes( fd_secp256k1_scalar_t * r,
                               uchar const             input[ 32 ] ) {
  memcpy( r, input, 32 );
  fd_uint256_bswap( r, r );

  /*
    The verifier SHALL check that 0 < r' < q and 0 < s' < q.
    The r' element is parsed as a scalar, and checked against r' < n.
    Later it is re-used as fp_t, however n < p, so we do not need to
    perform any additional checks after this.
  */
  if( FD_UNLIKELY( fd_uint256_cmp( r, fd_secp256k1_const_n ) >= 0 ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( fd_secp256k1_scalar_is_zero( r ) ) ) {
    return NULL;
  }
  return r;
}

/* r = 1 / a
   Operates on scalars NOT in the montgomery domain.
   a MUST not be 0. */
fd_secp256k1_scalar_t *
fd_secp256k1_scalar_invert( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  ulong t[ 12 ];
  bignum_modinv( 4, r->limbs, (ulong *)a->limbs, (ulong *)fd_secp256k1_const_n[ 0 ].limbs, t );
  return r;
}

/* None of the arguments may alias. */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_mul( fd_secp256k1_scalar_t *       restrict r,
                         fd_secp256k1_scalar_t const * restrict a,
                         fd_secp256k1_scalar_t const * restrict b ) {
  bignum_montmul( 4, r->limbs, (ulong *)a->limbs, (ulong *)b->limbs, (ulong *)fd_secp256k1_const_n[0].limbs );
  return r;
}

/* r = -a */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_negate( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  /* We cannot use bignum_modsub() as it requires a < n /\ b < n.

     The best way to implement it using the current API is to use
     bignum_sub(n, a), getting a result bounded within [0, n+1). Then
     we perform a second reduction from [0, n+1) to [0, n) with
     bignum_mod_n256k1_4(). */

  /* t \in [0, n + 1). There is no carry-out, as a < n. */
  ulong t[4];
  bignum_sub( 4, t, 4, (ulong *)fd_secp256k1_const_n[ 0 ].limbs, 4, (ulong *)a->limbs );
  bignum_mod_n256k1_4( r->limbs, t );
  return r;
}

static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_tomont( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  /* bignum_montmul has an undocumented restriction
     that the input and outputs may not alias. */
  ulong t[4];
  memcpy( t, a->limbs, 32 );
  bignum_montmul( 4, r->limbs, t, (ulong *)fd_secp256k1_const_scalar_rr_mont, (ulong *)fd_secp256k1_const_n[ 0 ].limbs );
  return r;
}

static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_demont( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  bignum_demont( 4, r->limbs, (ulong *)a->limbs, (ulong *)fd_secp256k1_const_n[ 0 ].limbs );
  return r;
}

/* Field */

static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_set( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a ) {
  r->limbs[ 0 ] = a->limbs[ 0 ];
  r->limbs[ 1 ] = a->limbs[ 1 ];
  r->limbs[ 2 ] = a->limbs[ 2 ];
  r->limbs[ 3 ] = a->limbs[ 3 ];
  return r;
}

/* r = (a == b) */
static inline int
fd_secp256k1_fp_eq( fd_secp256k1_fp_t const * a,
                    fd_secp256k1_fp_t const * b ) {
  return fd_uint256_eq( a, b );
}

/* r = a * b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_mul( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  bignum_mul_p256k1( r->limbs, (ulong *)a->limbs, (ulong *)b->limbs );
  return r;
}

/* r = a^2 */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_sqr( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a ) {
  bignum_sqr_p256k1( r->limbs, (ulong *)a->limbs );
  return r;
}

/* r = a + b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_add( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  bignum_add_p256k1( r->limbs, (ulong *)a->limbs, (ulong *)b->limbs );
  return r;
}

/* r = -a */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_negate( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  bignum_neg_p256k1( r->limbs, (ulong *)a->limbs );
  return r;
}

static inline int
fd_secp256k1_fp_is_odd( fd_secp256k1_fp_t const *r ) {
  return r->limbs[ 0 ] & 1;
}

/* r = 1 / a
   a MUST not be 0. */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_invert( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  ulong t[ 12 ];
  bignum_modinv( 4, r->limbs, (ulong *)a->limbs, (ulong *)fd_secp256k1_const_p[0].limbs, t );
  return r;
}

static inline uchar *
fd_secp256k1_fp_tobytes( uchar                    r[ 32 ],
                         fd_secp256k1_fp_t const *a ) {
  fd_secp256k1_fp_t swapped[1];
  fd_secp256k1_fp_set( swapped, a );
  fd_uint256_bswap( swapped, swapped );
  memcpy( r, swapped->buf, 32 );
  return r;
}

/*
  Returns NULL if a is not a square.
  r may NOT alias a

  r = a^((p + 1) / 4) mod p

  We know that a^((p-1)/2) = 1 when a is a quadratic residue.
  So for a valid square, we can show that re-squaring recovers a with:
    (a^((p+1)/4))^2 = a^((p+1)/1)
                    = a * a^((p-1)/2)
                    = a (if a is a square)

  We use a more optimal addition-chain which takes advantage that quite
  a few of the powers consist of all 1s when in binary form. We build up:
    x2    = a^3
    x3    = a^7
    x6    = a^63
    x9    = a^511
    x11   = a^2047
    x22   = a^(2^22 - 1)
    x44   = a^(2^44 - 1)
    x88   = a^(2^88 - 1)
    x176  = a^(2^176 - 1)
    x220  = a^(2^220 - 1)
    x223  = a^(2^223 - 1)

  These "all 1s" exponents are convenient because:
    (2^k - 1)*(2^m)+(2^m - 1) = 2^(k+m) - 1
  Allowing us to quickly build them.

  If a is NOT a square, then
    a^((p-1)/2) = -1
  and the result will fail the final verification.
*/
fd_secp256k1_fp_t *
fd_secp256k1_fp_sqrt( fd_secp256k1_fp_t *       restrict r,
                      fd_secp256k1_fp_t const * restrict a ) {
  fd_secp256k1_fp_t x2;
  fd_secp256k1_fp_t x3;

  fd_secp256k1_fp_sqr( &x2, a );
  fd_secp256k1_fp_mul( &x2, &x2, a );

  fd_secp256k1_fp_sqr( &x3, &x2 );
  fd_secp256k1_fp_mul( &x3, &x3, a );

  fd_secp256k1_fp_t x6 = x3;
  for( int j=0; j<3; j++ ) fd_secp256k1_fp_sqr( &x6, &x6 );
  fd_secp256k1_fp_mul( &x6, &x6, &x3 );

  fd_secp256k1_fp_t x9 = x6;
  for( int j=0; j<3; j++ ) fd_secp256k1_fp_sqr( &x9, &x9 );
  fd_secp256k1_fp_mul( &x9, &x9, &x3 );

  fd_secp256k1_fp_t x11 = x9;
  for( int j=0; j<2; j++ ) fd_secp256k1_fp_sqr( &x11, &x11 );
  fd_secp256k1_fp_mul( &x11, &x11, &x2 );

  fd_secp256k1_fp_t x22 = x11;
  for( int j=0; j<11; j++ ) fd_secp256k1_fp_sqr( &x22, &x22 );
  fd_secp256k1_fp_mul( &x22, &x22, &x11 );

  fd_secp256k1_fp_t x44 = x22;
  for( int j=0; j<22; j++ ) fd_secp256k1_fp_sqr( &x44, &x44 );
  fd_secp256k1_fp_mul( &x44, &x44, &x22 );

  fd_secp256k1_fp_t x88 = x44;
  for( int j=0; j<44; j++ ) fd_secp256k1_fp_sqr( &x88, &x88 );
  fd_secp256k1_fp_mul( &x88, &x88, &x44 );

  fd_secp256k1_fp_t x176 = x88;
  for( int j=0; j<88; j++ ) fd_secp256k1_fp_sqr( &x176, &x176 );
  fd_secp256k1_fp_mul( &x176, &x176, &x88 );

  fd_secp256k1_fp_t x220 = x176;
  for( int j=0; j<44; j++ ) fd_secp256k1_fp_sqr( &x220, &x220 );
  fd_secp256k1_fp_mul( &x220, &x220, &x44 );

  fd_secp256k1_fp_t x223 = x220;
  for( int j=0; j<3; j++ ) fd_secp256k1_fp_sqr( &x223, &x223 );
  fd_secp256k1_fp_mul( &x223, &x223, &x3 );

  fd_secp256k1_fp_t t1 = x223;
  for( int j=0; j<23; j++ ) fd_secp256k1_fp_sqr( &t1, &t1 );
  fd_secp256k1_fp_mul( &t1, &t1, &x22 );

  for( int j=0; j<6; j++ ) fd_secp256k1_fp_sqr( &t1, &t1 );
  fd_secp256k1_fp_mul( &t1, &t1, &x2 );
  fd_secp256k1_fp_sqr( &t1, &t1 );
  fd_secp256k1_fp_sqr( r, &t1 );

  fd_secp256k1_fp_sqr( &t1, r );
  if( FD_UNLIKELY( !fd_secp256k1_fp_eq( &t1, a ) ) ) {
    return NULL;
  }

  return r;
}

/* Point operations in plain (non-Montgomery) Jacobian coordinates.
   s2n-bignum's secp256k1 point ops work in this domain. */

/* r = a + b */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_add( fd_secp256k1_point_t *       r,
                        fd_secp256k1_point_t const * a,
                        fd_secp256k1_point_t const * b ) {
  secp256k1_jadd( (ulong *)r, (ulong const *)a, (ulong const *)b );
  return r;
}

/* r = 2 * a */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_dbl( fd_secp256k1_point_t *       r,
                        fd_secp256k1_point_t const * a ) {
  secp256k1_jdouble( (ulong *)r, (ulong const *)a );
  return r;
}

/* r = -a */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_neg( fd_secp256k1_point_t *       r,
                        fd_secp256k1_point_t const * a ) {
  if( r != a ) fd_memcpy( r, a, sizeof(*r) );
  bignum_neg_p256k1( r->y->limbs, r->y->limbs );
  return r;
}

/* r = a - b */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_sub( fd_secp256k1_point_t *       r,
                        fd_secp256k1_point_t const * a,
                        fd_secp256k1_point_t const * b ) {
  fd_secp256k1_point_t neg[1];
  fd_secp256k1_point_neg( neg, b );
  return fd_secp256k1_point_add( r, a, neg );
}

/* Mixed addition: a (Jacobian) + b (affine xy as 8 ulongs). */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_add_mixed( fd_secp256k1_point_t *       r,
                              fd_secp256k1_point_t const * a,
                              ulong                const   b[ 8 ] ) {
  secp256k1_jmixadd( (ulong *)r, (ulong const *)a, (ulong *)b );
  return r;
}

static inline fd_secp256k1_point_t *
fd_secp256k1_point_sub_mixed( fd_secp256k1_point_t *       r,
                              fd_secp256k1_point_t const * a,
                              ulong                const   b[ 8 ] ) {
  ulong neg[8];
  fd_memcpy( neg, b, 64 );
  bignum_neg_p256k1( neg+4, neg+4 );
  secp256k1_jmixadd( (ulong *)r, (ulong const *)a, neg );
  return r;
}

/* Double base multiplication */

static inline schar *
fd_secp256k1_slide( schar       r[ 65 ],
                    uchar const s[ 32 ] ) {
  for( int i=0; i<32; i++ ) {
    r[i*2+0] = (schar)(s[i] & 0xF);
    r[i*2+1] = (schar)((s[i] >> 4) & 0xF);
  }
  /* Now, r[0..63] is between 0 and 15, r[63] is between 0 and 7 */
  schar carry = 0;
  for( int i=0; i<64; i++ ) {
    r[i] += carry;
    carry = (schar)(r[i] + 8) >> 4;
    r[i] -= (schar)(carry * 16);
    /* r[i] MUST be between [-8, 8] */
  }
  r[64] = carry;
  /* carry MUST be between [-8, 8] */
  return r;
}

static inline fd_secp256k1_point_t *
fd_secp256k1_precompute( fd_secp256k1_point_t         tbl[ 9 ],
                         fd_secp256k1_point_t const * a ) {
  fd_memset( &tbl[0], 0, sizeof(fd_secp256k1_point_t) );
  fd_memcpy( &tbl[1], a, sizeof(fd_secp256k1_point_t) );
  for( int i=2; i<=8; i++ ) {
    if( i & 1 ) {
      fd_secp256k1_point_add( &tbl[i], &tbl[i-1], a );
    } else {
      fd_secp256k1_point_dbl( &tbl[i], &tbl[i/2] );
    }
  }
  return tbl;
}

/* Computes s1*G + s2*P2 in plain (non-Montgomery) Jacobian coordinates.
   All inputs and the output are in plain Jacobian. */
static inline fd_secp256k1_point_t *
fd_secp256k1_double_scalar_mul_base( fd_secp256k1_point_t *        r,
                                     fd_secp256k1_scalar_t const * s1,
                                     fd_secp256k1_point_t  const * p2,
                                     fd_secp256k1_scalar_t const * s2 ) {
  schar e1[ 65 ];
  schar e2[ 65 ];
  fd_secp256k1_slide( e1, s1->buf );
  fd_secp256k1_slide( e2, s2->buf );

  fd_secp256k1_point_t tbl[9];
  fd_secp256k1_precompute( tbl, p2 );

  fd_memset( r, 0, sizeof(*r) );

  for( int pos=64; ; pos-- ) {
    schar slot1 = e1[pos];
    if( slot1 > 0 ) {
      fd_secp256k1_point_add_mixed( r, r, fd_secp256k1_base_point_table[ (ulong)slot1 ].x->limbs );
    } else if( slot1 < 0 ) {
      fd_secp256k1_point_sub_mixed( r, r, fd_secp256k1_base_point_table[ (ulong)(-slot1) ].x->limbs );
    }

    schar slot2 = e2[pos];
    if( slot2 > 0 ) {
      fd_secp256k1_point_add( r, r, &tbl[ (ulong)slot2 ] );
    } else if( slot2 < 0 ) {
      fd_secp256k1_point_sub( r, r, &tbl[ (ulong)(-slot2) ] );
    }

    if( pos == 0 ) break;
    fd_secp256k1_point_dbl( r, r );
    fd_secp256k1_point_dbl( r, r );
    fd_secp256k1_point_dbl( r, r );
    fd_secp256k1_point_dbl( r, r );
  }

  return r;
}

/* Converts plain Jacobian (X/Z^2, Y/Z^3) to plain affine. */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_to_affine( fd_secp256k1_point_t *       r,
                              fd_secp256k1_point_t const * a ) {
  ulong z_inv[4], z_inv2[4], z_inv3[4];
  ulong t[12];
  bignum_modinv( 4, z_inv, (ulong *)a->z->limbs, (ulong *)fd_secp256k1_const_p[0].limbs, t );
  bignum_sqr_p256k1( z_inv2, z_inv );
  bignum_mul_p256k1( z_inv3, z_inv2, z_inv );
  bignum_mul_p256k1( r->x->limbs, (ulong *)a->x->limbs, z_inv2 );
  bignum_mul_p256k1( r->y->limbs, (ulong *)a->y->limbs, z_inv3 );
  return r;
}

static inline int
fd_secp256k1_point_is_identity( fd_secp256k1_point_t const *a ) {
  return fd_secp256k1_fp_eq( a->z, fd_secp256k1_const_zero );
}
