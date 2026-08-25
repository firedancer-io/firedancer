#include "../fd_bls.h"
#include "../../../third_party/blst/bindings/blst.h"

/* The public prepared type is backend-selected.  Keep the reference payload
   opaque here too, so forcing this implementation in an AVX-512 build does
   not depend on the reference header's struct member. */
FD_STATIC_ASSERT( sizeof(fd_bls_g2_prepared_t)>=sizeof(fd_bls_g2_t),
                  bls_ref_g2_prepared_footprint );

static inline void
fd_bls_ref_g2_prepared_store( fd_bls_g2_prepared_t * out,
                              fd_bls_g2_t const *     q ) {
  memcpy( out, q, sizeof(fd_bls_g2_t) );
}

static inline void
fd_bls_ref_g2_prepared_load( fd_bls_g2_t *                q,
                             fd_bls_g2_prepared_t const * in ) {
  memcpy( q, in, sizeof(fd_bls_g2_t) );
}

static inline void
fd_bls_ref_g1_from_normal( blst_p1_affine *    out,
                           fd_bls_g1_t const * in ) {
  blst_fp_from_uint64( &out->x, in->x );
  blst_fp_from_uint64( &out->y, in->y );
}

static inline void
fd_bls_ref_g2_from_normal( blst_p2_affine *    out,
                           fd_bls_g2_t const * in ) {
  blst_fp_from_uint64( &out->x.fp[0], in->x[0] );
  blst_fp_from_uint64( &out->x.fp[1], in->x[1] );
  blst_fp_from_uint64( &out->y.fp[0], in->y[0] );
  blst_fp_from_uint64( &out->y.fp[1], in->y[1] );
}

static int
fd_bls_ref_miller( blst_fp12 *       out,
                   fd_bls_g1_t const * p,
                   fd_bls_g2_t const * q,
                   ulong               cnt,
                   ulong               q_subgroup_mask ) {
  blst_p1_affine pa[ FD_BLS_PAIR_MAX ];
  blst_p2_affine qa[ FD_BLS_PAIR_MAX ];
  blst_p1_affine const * pp[ FD_BLS_PAIR_MAX ];
  blst_p2_affine const * qq[ FD_BLS_PAIR_MAX ];
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_bls_ref_g1_from_normal( pa+i, p+i );
    fd_bls_ref_g2_from_normal( qa+i, q+i );
    if( (q_subgroup_mask & (1UL<<i)) && FD_UNLIKELY( !blst_p2_affine_in_g2( qa+i ) ) ) return 0;
    pp[i] = pa+i;
    qq[i] = qa+i;
  }
  blst_miller_loop_n( out, qq, pp, cnt );
  return 1;
}

int
fd_bls_g2_prepare( fd_bls_g2_prepared_t * out,
                   fd_bls_g2_t const *     q ) {
  if( FD_UNLIKELY( !out || !q ) ) return -1;
  fd_bls_ref_g2_prepared_store( out, q );
  return 0;
}

int
fd_bls_pairing_finalverify_prepared_checked(
    fd_bls_g1_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const *          p_checked,
    fd_bls_g2_t const *          q_checked ) {
  if( FD_UNLIKELY( !p_prepared || !q_prepared || !p_checked || !q_checked ) ) return -1;
  fd_bls_g2_t q0[1];
  fd_bls_ref_g2_prepared_load( q0, q_prepared );
  fd_bls_g1_t p[2] = { *p_prepared, *p_checked };
  fd_bls_g2_t q[2] = { *q0, *q_checked };
  return fd_bls_pairing_finalverify_checked( p, q, 2UL, 2UL );
}

int
fd_bls_pairing_finalverify_checked( fd_bls_g1_t const * p,
                                    fd_bls_g2_t const * q,
                                    ulong               cnt,
                                    ulong               q_subgroup_mask ) {
  if( FD_UNLIKELY( !p || !q || !cnt || cnt>FD_BLS_PAIR_MAX ) ) return -1;
  if( FD_UNLIKELY( cnt<8UL*sizeof(ulong) && (q_subgroup_mask>>cnt) ) ) return -1;
  blst_fp12 product[1];
  int valid = fd_bls_ref_miller( product, p, q, cnt, q_subgroup_mask );
  if( FD_UNLIKELY( !valid ) ) return 0;
  return !!blst_fp12_finalverify( product, blst_fp12_one() );
}

int
fd_bls_pairing_finalverify( fd_bls_g1_t const * p,
                            fd_bls_g2_t const * q,
                            ulong               cnt ) {
  return fd_bls_pairing_finalverify_checked( p, q, cnt, 0UL );
}

int
fd_bls_pairing( ulong               out[12][6],
                fd_bls_g1_t const * p,
                fd_bls_g2_t const * q,
                ulong               cnt ) {
  if( FD_UNLIKELY( !out || cnt>FD_BLS_PAIR_MAX || (cnt && (!p || !q)) ) ) return -1;
  blst_fp12 result[1];
  if( FD_UNLIKELY( !cnt ) ) memcpy( result, blst_fp12_one(), sizeof(blst_fp12) );
  else {
    (void)fd_bls_ref_miller( result, p, q, cnt, 0UL );
    blst_final_exp( result, result );
  }
  for( ulong i=0UL; i<12UL; i++ )
    blst_uint64_from_fp( out[i], &result->fp6[i/6UL].fp2[(i/2UL)%3UL].fp[i%2UL] );
  return 0;
}
