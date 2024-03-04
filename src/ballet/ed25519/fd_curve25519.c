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
