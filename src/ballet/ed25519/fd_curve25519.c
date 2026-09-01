#include "fd_curve25519.h"
#include "../hex/fd_hex.h"

/*
 * Secure implementations (const time + clean temp vars)
 */
#include "fd_curve25519_secure.c"

#if FD_HAS_AVX512
#include "avx512/fd_curve25519.c"
#else
#include "ref/fd_curve25519.c"
#endif

#define WNAF_BIT_SZ 4
#define WNAF_TBL_SZ 8

#if FD_HAS_ARM && FD_HAS_S2NBIGNUM
FD_25519_INLINE void
fd_ed25519_arm_pepadd( ulong                       out[16],
                       ulong const                 acc[16],
                       fd_ed25519_point_t const *  p,
                       int                         negate ) {
  ulong pre[12];
  if( negate ) {
    memcpy( pre,     p->Y->el, 32UL );
    memcpy( pre + 4, p->X->el, 32UL );
    bignum_neg_p25519( pre + 8, p->T->el );
  } else {
    memcpy( pre,     p->X->el, 32UL );
    memcpy( pre + 4, p->Y->el, 32UL );
    memcpy( pre + 8, p->T->el, 32UL );
  }
  edwards25519_pepadd_alt( out, acc, pre );
}
#endif

/*
 * Ser/de
 */

 void
 fd_ed25519_debug( char const *               name,
                   fd_ed25519_point_t const * a ) {
  fd_f25519_t x[1], y[1], z[1], t[1];
  fd_ed25519_point_to( x, y, z, t, a );
  FD_LOG_WARNING(( "%s", name ));
  fd_f25519_debug( "x", x );
  fd_f25519_debug( "y", y );
  fd_f25519_debug( "z", z );
  fd_f25519_debug( "t", t );
 }

fd_ed25519_point_t *
fd_ed25519_point_frombytes( fd_ed25519_point_t * r,
                            uchar const          buf[ 32 ] ) {
#if FD_HAS_ARM && FD_HAS_S2NBIGNUM
  ulong xy[8];
  if( FD_LIKELY( !edwards25519_decode_alt( xy, buf ) ) ) {
    memcpy( r->X->el, xy,     32UL );
    memcpy( r->Y->el, xy + 4, 32UL );
    fd_f25519_set( r->Z, fd_f25519_one );
    fd_f25519_mul( r->T, r->X, r->Y );
    return r;
  }
#endif
  fd_f25519_t x[1], y[1], t[1];
  fd_f25519_frombytes( y, buf );
  uchar expected_x_sign = buf[31] >> 7;

  fd_f25519_t u[1];
  fd_f25519_t v[1];
  fd_f25519_sqr( u, y                );
  fd_f25519_mul( v, u, fd_f25519_d   );
  fd_f25519_sub( u, u, fd_f25519_one ); /* u = y^2-1 */
  fd_f25519_add( v, v, fd_f25519_one ); /* v = dy^2+1 */

  int was_square = fd_f25519_sqrt_ratio( x, u, v );
  if( FD_UNLIKELY( !was_square ) ) {
    return NULL;
  }

  /* Note: RFC 8032 Section 5.1.3 says "if x=0 and x_0=1, decoding
     fails", but Dalek does not enforce this — neg(0)==0 so it silently
     accepts the point.  We match Dalek for compatibility.
     https://github.com/dalek-cryptography/curve25519-dalek/blob/curve25519-4.1.3/curve25519-dalek/src/edwards.rs#L194-L240
     https://github.com/dalek-cryptography/curve25519-dalek/blob/3.2.1/src/edwards.rs#L193-L209 */
  if( fd_f25519_sgn(x)!=expected_x_sign ) { /* 50% prob */
    fd_f25519_neg( x, x );
  }

  fd_f25519_mul( t, x, y );
  fd_ed25519_point_from( r, x, y, fd_f25519_one, t );

  return r;
}

uchar *
fd_ed25519_point_tobytes( uchar                      out[ 32 ],
                          fd_ed25519_point_t const * a ) {
#if FD_HAS_ARM && FD_HAS_S2NBIGNUM
  if( FD_LIKELY( fd_f25519_eq( a->Z, fd_f25519_one ) ) )
    return fd_ed25519_affine_tobytes( out, a );
#endif
  fd_f25519_t x[1], y[1], z[1], t[1];
  fd_ed25519_point_to( x, y, z, t, a );
  fd_f25519_inv( t, z );
  fd_f25519_mul2( x, x, t,
                  y, y, t );
  fd_f25519_tobytes( out, y );
  out[31] ^= (uchar)(fd_f25519_sgn( x ) << 7);
  return out;
}

/*
 * Scalar multiplication
 */

fd_ed25519_point_t *
fd_ed25519_scalar_mul( fd_ed25519_point_t *       r,
                       uchar const                n[ 32 ],
                       fd_ed25519_point_t const * a ) {
  short nslide[256];
  fd_curve25519_scalar_wnaf( nslide, n, WNAF_BIT_SZ );

  fd_ed25519_point_t ai[WNAF_TBL_SZ]; /* A,3A,5A,7A,9A,11A,13A,15A */
  fd_ed25519_point_t a2[1];           /* 2A (temp) */
  fd_ed25519_point_t t[1];

  /* pre-computed table */
  fd_ed25519_point_set( &ai[0], a );
  fd_ed25519_point_dbln( a2, a, 1 ); // note: a is affine, we could save 1mul
  fd_curve25519_into_precomputed( &ai[0] );
  for( int i=1; i<WNAF_TBL_SZ; i++ ) {
    fd_ed25519_point_add_with_opts( t, a2, &ai[i-1], i==1, 1, 1 );
    fd_ed25519_point_add_final_mul( &ai[i], t );
    /* pre-compute kT, to save 1mul during the loop */
    fd_curve25519_into_precomputed( &ai[i] );
  }

  /* main dbl-and-add loop. note: last iter unrolled */
  fd_ed25519_point_set_zero( r );
  int i;
  for( i=255; i>=0; i-- ) { if( nslide[i] ) break; }
  for(      ; i>=0; i-- ) {
    fd_ed25519_partial_dbl( t, r );
    if(      nslide[i] > 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_add_with_opts( t, r, &ai[  nslide[i]  / 2], nslide[i]==1, 1, 1 ); }
    else if( nslide[i] < 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_sub_with_opts( t, r, &ai[(-nslide[i]) / 2], nslide[i]==-1, 1, 1 ); }

    /* ignore r->T because dbl doesn't need it, except in the last cycle */
    if (i == 0) {
      fd_ed25519_point_add_final_mul( r, t );            // compute r->T
    } else {
      fd_ed25519_point_add_final_mul_projective( r, t ); // ignore r->T
    }
  }
  return r;
}

fd_ed25519_point_t *
fd_ed25519_double_scalar_mul_base( fd_ed25519_point_t *       r,
                                   uchar const                n1[ 32 ],
                                   fd_ed25519_point_t const * a,
                                   uchar const                n2[ 32 ] ) {

  short n1slide[256]; fd_curve25519_scalar_wnaf( n1slide, n1, WNAF_BIT_SZ );
  short n2slide[256]; fd_curve25519_scalar_wnaf( n2slide, n2, 8 );

#if FD_HAS_ARM && FD_HAS_S2NBIGNUM
  ulong ai[WNAF_TBL_SZ][16];
  ulong ai_neg[WNAF_TBL_SZ][16];
  ulong a2[16];
#else
  fd_ed25519_point_t ai[WNAF_TBL_SZ]; /* A,3A,5A,7A,9A,11A,13A,15A */
  fd_ed25519_point_t a2[1];           /* 2A (temp) */
  fd_ed25519_point_t t[1];
#endif

  /* pre-computed table */
#if FD_HAS_ARM && FD_HAS_S2NBIGNUM
  memcpy( ai[0],      a->X->el, 32UL );
  memcpy( ai[0] + 4,  a->Y->el, 32UL );
  memcpy( ai[0] + 8,  a->Z->el, 32UL );
  memcpy( ai[0] + 12, a->T->el, 32UL );
  edwards25519_epdouble_alt( a2, ai[0] );
  for( int i=1; i<WNAF_TBL_SZ; i++ )
    edwards25519_epadd_alt( ai[i], a2, ai[i-1] );
  for( int i=0; i<WNAF_TBL_SZ; i++ ) {
    bignum_neg_p25519( ai_neg[i],      ai[i]      );
    memcpy(             ai_neg[i] + 4,  ai[i] + 4, 64UL );
    bignum_neg_p25519( ai_neg[i] + 12, ai[i] + 12 );
  }
#else
  fd_ed25519_point_set( &ai[0], a );
  fd_ed25519_point_dbln( a2, a, 1 ); // note: a is affine, we could save 1mul
  fd_curve25519_into_precomputed( &ai[0] );
  for( int i=1; i<WNAF_TBL_SZ; i++ ) {
    fd_ed25519_point_add_with_opts( t, a2, &ai[i-1], i==1, 1, 1 );
    fd_ed25519_point_add_final_mul( &ai[i], t );
    /* pre-compute kT, to save 1mul during the loop */
    fd_curve25519_into_precomputed( &ai[i] );
  }
#endif

  /* main dbl-and-add loop */
#if FD_HAS_ARM && FD_HAS_S2NBIGNUM
  ulong acc0[16] = { 0UL };
  ulong acc1[16];
  ulong * acc = acc0;
  ulong * out = acc1;
  acc[4] = 1UL;
  acc[8] = 1UL;

  int i;
  for( i=255; i>=0; i-- ) { if( n1slide[i] || n2slide[i] ) break; }
  for( ; i>=0; i-- ) {
    if( FD_LIKELY( i && !(n1slide[i] | n2slide[i]) ) )
      edwards25519_pdouble_alt( out, acc );
    else
      edwards25519_epdouble_alt( out, acc );
    ulong * swap = acc; acc = out; out = swap;

    if( n1slide[i] ) {
      uint idx = fd_int_abs( n1slide[i] ) / 2U;
      edwards25519_epadd_alt( out, acc, n1slide[i]<0 ? ai_neg[idx] : ai[idx] );
      ulong * swap = acc; acc = out; out = swap;
    }
    if( n2slide[i] ) {
      fd_ed25519_arm_pepadd( out, acc, &fd_ed25519_base_point_wnaf_table[fd_int_abs( n2slide[i] ) / 2], n2slide[i]<0 );
      ulong * swap = acc; acc = out; out = swap;
    }
  }

  memcpy( r->X->el, acc,      32UL );
  memcpy( r->Y->el, acc + 4,  32UL );
  memcpy( r->Z->el, acc + 8,  32UL );
  memcpy( r->T->el, acc + 12, 32UL );
  return r;
#else
  fd_ed25519_point_set_zero( r );

  int i;
  for( i=255; i>=0; i-- ) { if( n1slide[i] || n2slide[i] ) break; }
  for(      ; i>=0; i-- ) {
    fd_ed25519_partial_dbl( t, r );
    if(      n1slide[i] > 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_add_with_opts( t, r, &ai[  n1slide[i]  / 2], n1slide[i]==1, 1, 1 ); }
    else if( n1slide[i] < 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_sub_with_opts( t, r, &ai[(-n1slide[i]) / 2], n1slide[i]==-1, 1, 1 ); }
    if(      n2slide[i] > 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_add_with_opts( t, r, &fd_ed25519_base_point_wnaf_table[  n2slide[i]  / 2], 1, 1, 1 ); }
    else if( n2slide[i] < 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_sub_with_opts( t, r, &fd_ed25519_base_point_wnaf_table[(-n2slide[i]) / 2], 1, 1, 1 ); }

    /* ignore r->T because dbl doesn't need it, except in the last cycle */
    if (i == 0) {
      fd_ed25519_point_add_final_mul( r, t );            // compute r->T
    } else {
      fd_ed25519_point_add_final_mul_projective( r, t ); // ignore r->T
    }
  }
  return r;
#endif
}


FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_multi_scalar_mul_with_opts( fd_ed25519_point_t *     r,
                                       uchar const              n[], /* sz * 32 */
                                       fd_ed25519_point_t const a[], /* sz */
                                       ulong const              sz,
                                       ulong const              base_sz ) {
  short nslide[FD_BALLET_CURVE25519_MSM_BATCH_SZ][256];
  fd_ed25519_point_t ai[FD_BALLET_CURVE25519_MSM_BATCH_SZ][WNAF_TBL_SZ]; /* A,3A,5A,7A,9A,11A,13A,15A */
  fd_ed25519_point_t a2[1];                          /* 2A (temp) */
  fd_ed25519_point_t t[1];                           /* temp */

  if( base_sz ) {
    fd_curve25519_scalar_wnaf( nslide[0], &n[32*0], 8 );
  }
  for( ulong j=base_sz; j<sz; j++ ) {
    fd_curve25519_scalar_wnaf( nslide[j], &n[32*j], WNAF_BIT_SZ );

    /* pre-computed table */
    fd_ed25519_point_set( &ai[j][0], &a[j] );
    fd_ed25519_point_dbln( a2, &a[j], 1 ); // note: a is affine, we could save 1mul
    fd_curve25519_into_precomputed( &ai[j][0] );
    for( int i=1; i<WNAF_TBL_SZ; i++ ) {
      fd_ed25519_point_add_with_opts( t, a2, &ai[j][i-1], i==1, 1, 1 );
      fd_ed25519_point_add_final_mul( &ai[j][i], t );
      /* pre-compute kT, to save 1mul during the loop */
      fd_curve25519_into_precomputed( &ai[j][i] );
    }
  }

  /* main dbl-and-add loop */
  fd_ed25519_point_set_zero( r );
  for( int i=255; i>=0; i-- ) {
    fd_ed25519_partial_dbl( t, r );
    if( base_sz ) {
      if(      nslide[0][i] > 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_add_with_opts( t, r, &fd_ed25519_base_point_wnaf_table[  nslide[0][i]  / 2], 1, 1, 1 ); }
      else if( nslide[0][i] < 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_sub_with_opts( t, r, &fd_ed25519_base_point_wnaf_table[(-nslide[0][i]) / 2], 1, 1, 1 ); }
    }
    for( ulong j=base_sz; j<sz; j++ ) {
      short n = nslide[j][i];
      if(      n > 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_add_with_opts( t, r, &ai[j][  n  / 2], (n==1), 1, 1 ); }
      else if( n < 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_sub_with_opts( t, r, &ai[j][(-n) / 2], (n==-1), 1, 1 ); }
    }

    /* ignore r->T because dbl doesn't need it, except in the last cycle */
    if (i == 0) {
      fd_ed25519_point_add_final_mul( r, t );            // compute r->T
    } else {
      fd_ed25519_point_add_final_mul_projective( r, t ); // ignore r->T
    }
  }
  return r;
}

fd_ed25519_point_t *
fd_ed25519_multi_scalar_mul( fd_ed25519_point_t *     r,
                             uchar const              n[], /* sz * 32 */
                             fd_ed25519_point_t const a[], /* sz */
                             ulong const              sz ) {

  fd_ed25519_point_t h[1];
  fd_ed25519_point_set_zero( r );

  for( ulong i=0; i<sz; i+=FD_BALLET_CURVE25519_MSM_BATCH_SZ ) {
    ulong batch_sz = fd_ulong_min(sz-i, FD_BALLET_CURVE25519_MSM_BATCH_SZ);

    fd_ed25519_multi_scalar_mul_with_opts( h, &n[ 32*i ], &a[ i ], batch_sz, 0 );
    fd_ed25519_point_add( r, r, h );
  }

  return r;
}

/*
 * Init
 */

fd_ed25519_point_t *
fd_curve25519_affine_add( fd_ed25519_point_t *       r,
                          fd_ed25519_point_t const * a,
                          fd_ed25519_point_t const * b ) {
  fd_ed25519_point_add_with_opts( r, a, b, 1, 0, 0 );
  return fd_curve25519_into_affine( r );
}

fd_ed25519_point_t *
fd_curve25519_affine_dbln( fd_ed25519_point_t *       r,
                           fd_ed25519_point_t const * a,
                           int const                  n ) {
  fd_ed25519_point_dbln( r, a, n );
  return fd_curve25519_into_affine( r );
}
