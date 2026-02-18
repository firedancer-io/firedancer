#include <stdint.h>
#include <s2n-bignum.h>

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

/* Operates on scalars NOT in the montgomery domain. */
fd_secp256k1_scalar_t *
fd_secp256k1_scalar_invert( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  ulong t[ 12 ];
  bignum_modinv( 4, r->limbs, (ulong *)a->limbs, (ulong *)fd_secp256k1_const_n[ 0 ].limbs, t );
  return r;
}

static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_mul( fd_secp256k1_scalar_t *       r,
                         fd_secp256k1_scalar_t const * a,
                         fd_secp256k1_scalar_t const * b ) {
  /* bignum_montmul has an undocumented restriction
     that the input and outputs may not alias. */
  ulong t1[ 4 ];
  ulong t2[ 4 ];
  memcpy( t1, a->limbs, 32 );
  memcpy( t2, b->limbs, 32 );
  bignum_montmul( 4, r->limbs, t1, t2, (ulong *)fd_secp256k1_const_n[0].limbs );
  return r;
}

/* r = -a */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_negate( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  /* If a == 0, then n % n will return 0. Otherwise we return n - a. */
  bignum_modsub( 4, r->limbs, (ulong *)fd_secp256k1_const_n[ 0 ].limbs, (ulong *)a->limbs, (ulong *)fd_secp256k1_const_n[ 0 ].limbs );
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

/* r = a + b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_add( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  bignum_add_p256k1( r->limbs, (ulong *)a->limbs, (ulong *)b->limbs );
  return r;
}

/* r = a - b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_sub( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  bignum_sub_p256k1( r->limbs, (ulong *)a->limbs, (ulong *)b->limbs );
  return r;
}

/* r = 2 * a */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_dbl( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a ) {
  bignum_double_p256k1( r->limbs, (ulong *)a->limbs );
  return r;
}

/* r = a * b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_mul( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  bignum_montmul_p256k1( r->limbs, (ulong *)a->limbs, (ulong *)b->limbs );
  return r;
}

/* r = a^2 */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_sqr( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a ) {
  bignum_montsqr_p256k1( r->limbs, (ulong *)a->limbs );
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
  fd_secp256k1_fp_t scratch[1];
  bignum_demont_p256k1( scratch->limbs, (ulong *)r->limbs );
  return scratch->limbs[ 0 ] & 1;
}

static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_invert( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  fd_secp256k1_fp_t ad[1];
  bignum_demont_p256k1( ad->limbs, (ulong *)a->limbs );
  ulong t[ 12 ];
  bignum_modinv( 4, r->limbs, (ulong *)ad->limbs, (ulong *)fd_secp256k1_const_p[0].limbs, t );
  bignum_tomont_p256k1( r->limbs, (ulong *)r->limbs );
  return r;
}

static inline uchar *
fd_secp256k1_fp_tobytes( uchar                    r[ 32 ],
                         fd_secp256k1_fp_t const *a ) {
  fd_secp256k1_fp_t swapped[1];
  bignum_demont_p256k1( swapped->limbs, (ulong *)a->limbs );
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
    x22   = a^(2^22 − 1) # All of these are all 1s
    x44   = a^(2^44 − 1)
    x88   = a^(2^88 − 1)
    x176  = a^(2^176 − 1)
    x220  = a^(2^220 − 1)
    x223  = a^(2^223 − 1)

  These "all 1s" exponents are convenient because:
    (2^k - 1)*(2^m)+(2^m - 1) = 2^(k+m) - 1
  Allowing us to quickly build them.

  If a is NOT a square, then
    a^((p-1)/2) = -1
  and the result will fail the final verification.
*/
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_sqrt( fd_secp256k1_fp_t *       r,
                      fd_secp256k1_fp_t const * a ) {
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

/* Point */

/* Sets a group element to the identity element in Jacobian coordinates */
static inline void
fd_secp256k1_point_set_identity( fd_secp256k1_point_t *r ) {
  fd_secp256k1_fp_set( r->x, fd_secp256k1_const_zero );
  fd_secp256k1_fp_set( r->y, fd_secp256k1_const_one_mont );
  fd_secp256k1_fp_set( r->z, fd_secp256k1_const_zero );
}

/* Sets a group element to the base element in Jacobian coordinates */
static inline void
fd_secp256k1_point_set_base( fd_secp256k1_point_t *r ) {
  fd_secp256k1_fp_set( r->x, fd_secp256k1_const_base_x_mont );
  fd_secp256k1_fp_set( r->y, fd_secp256k1_const_base_y_mont );
  fd_secp256k1_fp_set( r->z, fd_secp256k1_const_one_mont );
}

/* r = a */
static inline void
fd_secp256k1_point_set( fd_secp256k1_point_t *       r,
                        fd_secp256k1_point_t const * a ) {
  fd_secp256k1_fp_set( r->x, a->x );
  fd_secp256k1_fp_set( r->y, a->y );
  fd_secp256k1_fp_set( r->z, a->z );
}

/* https://eprint.iacr.org/2015/1060.pdf, Algorithm 7 */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_add( fd_secp256k1_point_t *       r,
                        fd_secp256k1_point_t const * a,
                        fd_secp256k1_point_t const * b ) {
  fd_secp256k1_fp_t t0[ 1 ];
  fd_secp256k1_fp_t t1[ 1 ];
  fd_secp256k1_fp_t t2[ 1 ];
  fd_secp256k1_fp_t t3[ 1 ];
  fd_secp256k1_fp_t t4[ 1 ];

  fd_secp256k1_fp_t X3[ 1 ];
  fd_secp256k1_fp_t Y3[ 1 ];
  fd_secp256k1_fp_t Z3[ 1 ];

  /* t0 = X1 * X2 */
  fd_secp256k1_fp_mul( t0, a->x, b->x );
  /* t1 = Y1 * Y2 */
  fd_secp256k1_fp_mul( t1, a->y, b->y );
  /* t2 = Z1 * Z2 */
  fd_secp256k1_fp_mul( t2, a->z, b->z );

  /* t3 = (a.x + a.y) * (b.x + b.y) - (t0 + t1) */
  fd_secp256k1_fp_add( t3, a->x, a->y );
  fd_secp256k1_fp_add( t4, b->x, b->y );
  fd_secp256k1_fp_mul( t3, t3, t4 );
  fd_secp256k1_fp_add( t4, t0, t1 );
  fd_secp256k1_fp_sub( t3, t3, t4 );

  /* t4 = (a.y + a.z) * (b.y + b.z) - (t1 + t2) */
  fd_secp256k1_fp_add( t4, a->y, a->z );
  fd_secp256k1_fp_add( X3, b->y, b->z );
  fd_secp256k1_fp_mul( t4, t4, X3 );
  fd_secp256k1_fp_add( X3, t1, t2 );
  fd_secp256k1_fp_sub( t4, t4, X3 );

  /* Y3 = (a.x + a.z) * (b.x + b.z) - (t0 + t2) */
  fd_secp256k1_fp_add( X3, a->x, a->z );
  fd_secp256k1_fp_add( Y3, b->x, b->z );
  fd_secp256k1_fp_mul( X3, X3, Y3 );
  fd_secp256k1_fp_add( Y3, t0, t2 );
  fd_secp256k1_fp_sub( Y3, X3, Y3 );

  /* t0 = 3 * t0 */
  bignum_triple_p256k1( t0->limbs, (ulong *)t0->limbs );

  /* b3 = (2^2)^2 + 2^2 + 1 = 21 */
  fd_secp256k1_fp_t t2_4[ 1 ];
  fd_secp256k1_fp_t t5[ 1 ];
  fd_secp256k1_fp_dbl( t2_4, t2 );
  fd_secp256k1_fp_dbl( t2_4, t2_4 );
  fd_secp256k1_fp_dbl( t5, t2_4 );
  fd_secp256k1_fp_dbl( t5, t5 );
  fd_secp256k1_fp_add( t5, t5, t2_4 );
  fd_secp256k1_fp_add( t2, t5, t2 );

  /* Z3 = t1 * t2
     t1 = t1 - t2 */
  fd_secp256k1_fp_add( Z3, t1, t2 );
  fd_secp256k1_fp_sub( t1, t1, t2 );

  fd_secp256k1_fp_t Y3_4[ 1 ];
  fd_secp256k1_fp_dbl( Y3_4, Y3 );
  fd_secp256k1_fp_dbl( Y3_4, Y3_4 );
  fd_secp256k1_fp_dbl( t5, Y3_4 );
  fd_secp256k1_fp_dbl( t5, t5 );
  fd_secp256k1_fp_add( t5, t5, Y3_4 );
  fd_secp256k1_fp_add( Y3, t5, Y3 );

  fd_secp256k1_fp_mul( X3, t4, Y3 );
  fd_secp256k1_fp_mul( t2, t3, t1 );
  fd_secp256k1_fp_sub( r->x, t2, X3 );
  fd_secp256k1_fp_mul( Y3, Y3, t0 );
  fd_secp256k1_fp_mul( t1, t1, Z3 );
  fd_secp256k1_fp_add( r->y, t1, Y3 );
  fd_secp256k1_fp_mul( t0, t0, t3 );
  fd_secp256k1_fp_mul( Z3, Z3, t4 );
  fd_secp256k1_fp_add( r->z, Z3, t0 );

  return r;
}

/* https://eprint.iacr.org/2015/1060.pdf, Algorithm 9 */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_dbl( fd_secp256k1_point_t *       r,
                        fd_secp256k1_point_t const * a ) {
  fd_secp256k1_fp_t t0[ 1 ];
  fd_secp256k1_fp_t t1[ 1 ];
  fd_secp256k1_fp_t t2[ 1 ];

  fd_secp256k1_fp_t X3[ 1 ];
  fd_secp256k1_fp_t Y3[ 1 ];
  fd_secp256k1_fp_t Z3[ 1 ];

  /* t0 = Y * Y*/
  fd_secp256k1_fp_sqr( t0, a->y );
  /* Z3 = 8 * t0 */
  fd_secp256k1_fp_dbl( Z3, t0 );
  fd_secp256k1_fp_dbl( Z3, Z3 );
  fd_secp256k1_fp_dbl( Z3, Z3 );

  /* t1 = Y * Z */
  fd_secp256k1_fp_mul( t1, a->y, a->z );
  /* t2 = Z * Z */
  fd_secp256k1_fp_sqr( t2, a->z );

  /* b3 = (2^2)^2 + 2^2 + 1
     t2 = b3 * t2 */
  fd_secp256k1_fp_t t2_4[1], t5[1];
  fd_secp256k1_fp_dbl( t2_4, t2 );
  fd_secp256k1_fp_dbl( t2_4, t2_4 );
  fd_secp256k1_fp_dbl( t5, t2_4 );
  fd_secp256k1_fp_dbl( t5, t5 );
  fd_secp256k1_fp_add( t5, t5, t2_4 );
  fd_secp256k1_fp_add( t2, t5, t2 );

  /* X3 = t2 * Z3 */
  fd_secp256k1_fp_mul( X3, t2, Z3 );
  /* Y3 = t0 + t2 */
  fd_secp256k1_fp_add( Y3, t0, t2 );

  fd_secp256k1_fp_mul( r->z, t1, Z3 );

  fd_secp256k1_fp_dbl( t1, t2 );
  fd_secp256k1_fp_add( t2, t1, t2 );
  fd_secp256k1_fp_sub( t0, t0, t2 );
  fd_secp256k1_fp_mul( Y3, t0, Y3 );
  /* compute t1 first, as the next add may overwrite a->y */
  fd_secp256k1_fp_mul( t1, a->x, a->y );
  fd_secp256k1_fp_add( r->y, X3, Y3 );

  fd_secp256k1_fp_mul( X3, t0, t1 );
  fd_secp256k1_fp_dbl( r->x, X3 );

  return r;
}

/* r = -a */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_neg( fd_secp256k1_point_t *       r,
                        fd_secp256k1_point_t const * a ) {
  fd_secp256k1_fp_set( r->x, a->x );
  fd_secp256k1_fp_set( r->z, a->z );
  fd_secp256k1_fp_negate( r->y, a->y );
  return r;
}

/* r = a - b */
static inline fd_secp256k1_point_t *
fd_secp256k1_point_sub( fd_secp256k1_point_t *       r,
                        fd_secp256k1_point_t const * a,
                        fd_secp256k1_point_t const * b ) {
  fd_secp256k1_point_t tmp[ 1 ];
  fd_secp256k1_point_neg( tmp, b );
  return fd_secp256k1_point_add( r, a, tmp );
}

/* Double base multiplication */

static inline schar *
fd_secp256k1_slide( schar       r[ 2 * 32 + 1 ],
                    uchar const s[ 32 ] ) {
  for(int i = 0; i<32; i++) {
    uchar x = s[i];
    r[i * 2 + 0] = x & 0xF;
    r[i * 2 + 1] = (x >> 4) & 0xF;
  }
  /* Now, r[0..63] is between 0 and 15, r[63] is between 0 and 7 */
  schar carry = 0;
  for(int i = 0; i<64; i++) {
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
fd_secp256k1_precompute( fd_secp256k1_point_t         r[ 9 ],
                         fd_secp256k1_point_t const * a ) {
  fd_secp256k1_point_set_identity( &r[0] );
  fd_secp256k1_point_set( &r[1], a );
  for(int i = 2; i <= 8; i++) {
    if(i % 2) {
      fd_secp256k1_point_add( &r[i], &r[i - 1], a );
    } else {
      fd_secp256k1_point_dbl( &r[i], &r[i / 2]    );
    }
  }
  return r;
}

/* Computes s1*G + s2*P2, where G is the base point */
static inline fd_secp256k1_point_t *
fd_secp256k1_double_base_mul( fd_secp256k1_point_t *        r,
                              fd_secp256k1_scalar_t const * s1,
                              fd_secp256k1_point_t const *  p2,
                              fd_secp256k1_scalar_t const * s2 ) {
  fd_secp256k1_point_t base[ 1 ];
  fd_secp256k1_point_set_base( base );

  fd_secp256k1_point_t pc1[ 9 ];
  fd_secp256k1_point_t pc2[ 9 ];
  /* TODO: Precompute the basepoint table in a generated table */
  fd_secp256k1_precompute( pc1, base );
  fd_secp256k1_precompute( pc2, p2 );

  schar e1[ 2 * 32 + 1 ];
  schar e2[ 2 * 32 + 1 ];
  fd_secp256k1_slide( e1, s1->buf );
  fd_secp256k1_slide( e2, s2->buf );

  fd_secp256k1_point_set_identity( r );
  for( int pos = 2 * 32; ; pos -= 1 ) {
    schar slot1 = e1[pos];
    if( slot1 > 0 ) {
      fd_secp256k1_point_add( r, r, &pc1[(ulong)slot1] );
    } else if( slot1 < 0 ) {
      fd_secp256k1_point_sub( r, r, &pc1[(ulong)(-slot1)] );
    }

    schar slot2 = e2[pos];
    if( slot2 > 0 ) {
      fd_secp256k1_point_add( r, r, &pc2[(ulong)slot2] );
    } else if( slot2 < 0 ) {
      fd_secp256k1_point_sub( r, r, &pc2[(ulong)(-slot2)] );
    }

    if( pos == 0 ) break;
    fd_secp256k1_point_dbl( r, r );
    fd_secp256k1_point_dbl( r, r );
    fd_secp256k1_point_dbl( r, r );
    fd_secp256k1_point_dbl( r, r );
  }

  return r;
}

static inline fd_secp256k1_point_t *
fd_secp256k1_point_to_affine( fd_secp256k1_point_t *       r,
                              fd_secp256k1_point_t const * a ) {
  fd_secp256k1_fp_t z[1];
  fd_secp256k1_fp_invert( z, a->z );
  fd_secp256k1_fp_mul( r->x, a->x, z );
  fd_secp256k1_fp_mul( r->y, a->y, z );
  return r;
}

static inline int
fd_secp256k1_point_is_identity( fd_secp256k1_point_t const *a ) {
  int affine =
     fd_secp256k1_fp_eq( a->x, fd_secp256k1_const_zero ) &
     ( fd_secp256k1_fp_eq( a->y, fd_secp256k1_const_zero     ) |
       fd_secp256k1_fp_eq( a->y, fd_secp256k1_const_one_mont ) );
  return fd_secp256k1_fp_eq( a->z, fd_secp256k1_const_zero ) | affine;
}
