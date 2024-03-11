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
#define WNAF_TBL_SZ (2*WNAF_BIT_SZ)

/* Max batch size for MSM. */
#define MSM_MAX_BATCH 32

/*
 * Ser/de
 */

fd_ed25519_point_t *
fd_ed25519_point_frombytes( fd_ed25519_point_t * r,
                            uchar const          buf[ static 32 ] ) {
  fd_f25519_t x[1], y[1], t[1];
  fd_f25519_frombytes( y, buf );
  uchar expected_x_sign = buf[31] >> 7;

  fd_f25519_t u[1];
  fd_f25519_t v[1];
  fd_f25519_sqr( u, y                );
  fd_f25519_mul( v, u, fd_f25519_d   );
  fd_f25519_sub( u, u, fd_f25519_one ); /* u = y^2-1 */
  fd_f25519_add( v, v, fd_f25519_one ); /* v = dy^2+1 */

  fd_f25519_sqrt_ratio( x, u, v );

  fd_f25519_t vxx  [1];
  fd_f25519_t check[1];
  fd_f25519_sqr( vxx,   x      );
  fd_f25519_mul( vxx,   vxx, v );
  fd_f25519_sub( check, vxx, u );       /* vx^2-u */
  if( fd_f25519_is_nonzero( check ) ) { /* unclear prob */
    fd_f25519_add( check, vxx, u );     /* vx^2+u */
    if( FD_UNLIKELY( fd_f25519_is_nonzero( check ) ) ) {
      return NULL;
    }
    fd_f25519_mul( x, x, fd_f25519_sqrtm1 );
  }

  if( fd_f25519_sgn(x)!=expected_x_sign ) { /* 50% prob */
    fd_f25519_neg( x, x );
  }

  fd_f25519_mul( t, x, y );
  fd_ed25519_point_from( r, x, y, fd_f25519_one, t );

  return r;
}

uchar *
fd_ed25519_point_tobytes( uchar                      out[ static 32 ],
                          fd_ed25519_point_t const * a ) {
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
                       uchar const                n[ static 32 ],
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
                                   uchar const                n1[ static 32 ],
                                   fd_ed25519_point_t const * a,
                                   uchar const                n2[ static 32 ] ) {

  short n1slide[256]; fd_curve25519_scalar_wnaf( n1slide, n1, WNAF_BIT_SZ );
  short n2slide[256]; fd_curve25519_scalar_wnaf( n2slide, n2, 8 );

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

  /* main dbl-and-add loop */
  fd_ed25519_point_set_zero( r );

  int i;
  for( i=255; i>=0; i-- ) { if( n1slide[i] || n2slide[i] ) break; }
  for(      ; i>=0; i-- ) {
    fd_ed25519_partial_dbl( t, r );
    if(      n1slide[i] > 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_add_with_opts( t, r, &ai[  n1slide[i]  / 2], n1slide[i]==1, 1, 1 ); }
    else if( n1slide[i] < 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_sub_with_opts( t, r, &ai[(-n1slide[i]) / 2], n1slide[i]==-1, 1, 1 ); }
    if(      n2slide[i] > 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_add_with_opts( t, r, &fd_ed25519_base_point_wnaf_table[  n2slide[i]  / 2], 1, 1, 1 ); }
    else if( n2slide[i] < 0 ) { fd_ed25519_point_add_final_mul( r, t ); fd_ed25519_point_sub_with_opts( t, r, &fd_ed25519_base_point_wnaf_table[(-n2slide[i]) / 2], 1, 1, 1 ); }
    fd_ed25519_point_add_final_mul_projective( r, t ); /* save 1mul */
  }

  /* we won't need r->T */

  return r;
}


FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_multi_scalar_mul_with_opts( fd_ed25519_point_t *     r,
                                       uchar const              n[], /* sz * 32 */
                                       fd_ed25519_point_t const a[], /* sz */
                                       ulong const              sz,
                                       ulong const              base_sz ) {
  short nslide[MSM_MAX_BATCH][256];
  fd_ed25519_point_t ai[MSM_MAX_BATCH][WNAF_TBL_SZ]; /* A,3A,5A,7A,9A,11A,13A,15A */
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

  for( ulong i=0; i<sz; i+=MSM_MAX_BATCH ) {
    ulong batch_sz = fd_ulong_min(sz-i, MSM_MAX_BATCH);

    fd_ed25519_multi_scalar_mul_with_opts( h, &n[ 32*i ], &a[ i ], batch_sz, 0 );
    fd_ed25519_point_add( r, r, h );
  }

  return r;
}

fd_ed25519_point_t *
fd_ed25519_multi_scalar_mul_base( fd_ed25519_point_t *     r,
                                  uchar const              n[], /* sz * 32 */
                                  fd_ed25519_point_t const a[], /* sz */
                                  ulong const              sz ) {
  if (sz > MSM_MAX_BATCH) {
    return NULL;
  }
  return fd_ed25519_multi_scalar_mul_with_opts( r, n, a, sz, 1 );
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
