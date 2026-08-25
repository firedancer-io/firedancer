#include "../fd_bls.h"
#include "../fd_bls_backend.h"

/* Reference backend pairing and aggregate-verification entry points,
   implemented on blst.  fd_bls_sec_t/pub_t/sig_t/hash_t are typedefs of
   the corresponding blst types, so values pass through unconverted. */

/* The public prepared type is backend-selected.  Keep the reference
   payload opaque here too, so forcing this implementation in an AVX-512
   build does not depend on the reference header's struct member. */
FD_STATIC_ASSERT( sizeof(fd_bls_g2_prepared_t)>=sizeof(fd_bls_g2_t),
                  bls_ref_g2_prepared_footprint );

static inline void
fd_bls_ref_g2_prepared_store( fd_bls_g2_prepared_t * out,
                              fd_bls_g2_t const *    q ) {
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

static inline void
fd_bls_ref_g1_from_affine( fd_bls_g1_t *          out,
                           blst_p1_affine const * in ) {
  blst_uint64_from_fp( out->x, &in->x );
  blst_uint64_from_fp( out->y, &in->y );
}

static inline void
fd_bls_ref_g2_from_affine( fd_bls_g2_t *          out,
                           blst_p2_affine const * in ) {
  blst_uint64_from_fp( out->x[0], &in->x.fp[0] );
  blst_uint64_from_fp( out->x[1], &in->x.fp[1] );
  blst_uint64_from_fp( out->y[0], &in->y.fp[0] );
  blst_uint64_from_fp( out->y[1], &in->y.fp[1] );
}

static int
fd_bls_ref_miller( blst_fp12 *         out,
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
fd_bls_ref_g2_prepare( fd_bls_g2_prepared_t * out,
                       fd_bls_g2_t const *    q ) {
  if( FD_UNLIKELY( !out || !q ) ) return -1;
  fd_bls_ref_g2_prepared_store( out, q );
  return 0;
}

int
fd_bls_ref_pairing_finalverify_prepared_checked(
    fd_bls_g1_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const *          p_checked,
    fd_bls_g2_t const *          q_checked ) {
  if( FD_UNLIKELY( !p_prepared || !q_prepared || !p_checked || !q_checked ) ) return -1;
  fd_bls_g2_t q0[1];
  fd_bls_ref_g2_prepared_load( q0, q_prepared );
  fd_bls_g1_t p[2] = { *p_prepared, *p_checked };
  fd_bls_g2_t q[2] = { *q0, *q_checked };
  return fd_bls_ref_pairing_finalverify_checked( p, q, 2UL, 2UL );
}

int
fd_bls_ref_pairing_finalverify_checked( fd_bls_g1_t const * p,
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
fd_bls_ref_pairing_finalverify( fd_bls_g1_t const * p,
                                fd_bls_g2_t const * q,
                                ulong               cnt ) {
  return fd_bls_ref_pairing_finalverify_checked( p, q, cnt, 0UL );
}

int
fd_bls_ref_pairing( ulong               out[12][6],
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

/* --- secret keys --- */

void
fd_bls_ref_sec_to_pub( fd_bls_sec_t const * sec,
                       fd_bls_pub_t *       pub ) {
  blst_sk_to_pk_in_g1( pub, sec );
}

void
fd_bls_ref_sec_derive( fd_bls_sec_t * sec,
                       uchar const *  ikm,
                       ulong          ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_keygen( sec, ikm, ikm_sz, NULL, 0UL );
}

void
fd_bls_ref_sec_sign( fd_bls_sec_t const * sec,
                     uchar const *        msg,
                     ulong                msg_sz,
                     fd_bls_sig_t *       sig ) {
  blst_p2 hash[1];
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)FD_BLS_DST,
                   FD_BLS_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( sig, hash, sec );
}

/* --- public keys (G1) --- */

void
fd_bls_ref_pub_ser( fd_bls_pub_t const * pub,
                    uchar                buf[ static FD_BLS_PUB_SZ ] ) {
  blst_p1_affine a[1];
  blst_p1_to_affine( a, pub );
  blst_p1_affine_serialize( buf, a );
}

void
fd_bls_ref_pub_compress( fd_bls_pub_t const * pub,
                         uchar                buf[ static FD_BLS_PUB_COMPRESSED_SZ ] ) {
  blst_p1_affine a[1];
  blst_p1_to_affine( a, pub );
  blst_p1_affine_compress( buf, a );
}

static int
fd_bls_ref_pub_from_bytes( blst_p1_affine * out,
                           uchar const *    in,
                           ulong            in_sz ) {
  BLST_ERROR err;
  switch( in_sz ) {
  case FD_BLS_PUB_COMPRESSED_SZ: err = blst_p1_uncompress( out, in ); break;
  case FD_BLS_PUB_SZ:
    if( FD_UNLIKELY( in[0]&0xA0U ) ) return 0;
    err = blst_p1_deserialize( out, in );
    break;
  default: return 0;
  }
  return err==BLST_SUCCESS &&
         !blst_p1_affine_is_inf( out ) &&
         blst_p1_affine_in_g1( out );
}

int
fd_bls_ref_pub_de( fd_bls_pub_t * pub,
                   uchar const *  buf,
                   ulong          buf_sz ) {
  blst_p1_affine a[1];
  if( FD_UNLIKELY( !fd_bls_ref_pub_from_bytes( a, buf, buf_sz ) ) ) return -1;
  blst_p1_from_affine( pub, a );
  return 0;
}

int
fd_bls_ref_pub_de_compressed( fd_bls_pub_t * pub,
                              uchar const    buf[ static FD_BLS_PUB_COMPRESSED_SZ ] ) {
  return fd_bls_ref_pub_de( pub, buf, FD_BLS_PUB_COMPRESSED_SZ );
}

void
fd_bls_ref_pub_add( fd_bls_pub_t *       out,
                    fd_bls_pub_t const * a,
                    fd_bls_pub_t const * b ) {
  blst_p1_add_or_double( out, a, b );
}

void
fd_bls_ref_pub_neg( fd_bls_pub_t *       out,
                    fd_bls_pub_t const * a ) {
  *out = *a;
  blst_p1_cneg( out, 1 );
}

int
fd_bls_ref_pub_is_inf( fd_bls_pub_t const * pub ) {
  return !!blst_p1_is_inf( pub );
}

int
fd_bls_ref_pub_eq( fd_bls_pub_t const * a,
                   fd_bls_pub_t const * b ) {
  return !!blst_p1_is_equal( a, b );
}

void
fd_bls_ref_pub_sum( fd_bls_pub_t *       out,
                    fd_bls_pub_t const * pubs,
                    fd_bls_set_t const * set ) {
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    blst_p1_add_or_double( out, out, pubs+rank );
  }
}

/* --- signatures (G2) --- */

void
fd_bls_ref_sig_ser( fd_bls_sig_t const * sig,
                    uchar                buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  blst_p2_to_affine( a, sig );
  blst_p2_affine_serialize( buf, a );
}

void
fd_bls_ref_sig_compress( fd_bls_sig_t const * sig,
                         uchar                buf[ static FD_BLS_SIG_COMPRESSED_SZ ] ) {
  blst_p2_affine a[1];
  blst_p2_to_affine( a, sig );
  blst_p2_affine_compress( buf, a );
}

int
fd_bls_ref_sig_de( fd_bls_sig_t * sig,
                   uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_deserialize( a, buf )!=BLST_SUCCESS ) ) return -1;
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( a ) ) )                  return -1;
  blst_p2_from_affine( sig, a );
  return 0;
}

int
fd_bls_ref_sig_de_unchecked( fd_bls_sig_t * sig,
                             uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_deserialize( a, buf )!=BLST_SUCCESS ) ) return -1;
  blst_p2_from_affine( sig, a );
  return 0;
}

int
fd_bls_ref_sig_de_compressed( fd_bls_sig_t * sig,
                              uchar const    buf[ static FD_BLS_SIG_COMPRESSED_SZ ] ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_uncompress( a, buf )!=BLST_SUCCESS ) ) return -1;
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( a ) ) )                 return -1;
  blst_p2_from_affine( sig, a );
  return 0;
}

void
fd_bls_ref_sig_add( fd_bls_sig_t *       out,
                    fd_bls_sig_t const * a,
                    fd_bls_sig_t const * b ) {
  blst_p2_add_or_double( out, a, b );
}

void
fd_bls_ref_sig_neg( fd_bls_sig_t *       out,
                    fd_bls_sig_t const * a ) {
  *out = *a;
  blst_p2_cneg( out, 1 );
}

int
fd_bls_ref_sig_validate( fd_bls_sig_t const * sig ) {
  return !!blst_p2_in_g2( sig );
}

int
fd_bls_ref_sig_is_inf( fd_bls_sig_t const * sig ) {
  return !!blst_p2_is_inf( sig );
}

int
fd_bls_ref_sig_eq( fd_bls_sig_t const * a,
                   fd_bls_sig_t const * b ) {
  return !!blst_p2_is_equal( a, b );
}

/* --- hash-to-curve and aggregate verification --- */

void
fd_bls_ref_hash_msg( uchar const *   msg,
                     ulong           msg_sz,
                     fd_bls_hash_t * h ) {
  blst_p2 p[1];
  blst_hash_to_g2( p, msg, msg_sz, (uchar const *)FD_BLS_DST,
                   FD_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( h, p );
}

/* fd_bls_ref_agg_to_pair converts the aggregate-verification inputs
   (one or two (pubkey,hash) pairs plus -G1 and the signature) into the
   backend-neutral pairing arrays.  Returns 0 if any input is infinity. */

int
fd_bls_ref_agg_to_pair( fd_bls_hash_t const * h,
                        fd_bls_pub_t const *  pub,
                        fd_bls_hash_t const * h_fb,
                        fd_bls_pub_t const *  pub_fb,
                        fd_bls_sig_t const *  sig,
                        fd_bls_g1_t *         pair_p,
                        fd_bls_g2_t *         pair_q,
                        ulong *               pair_cnt ) {
  ulong cnt = 1UL + !!pub_fb;
  if( FD_UNLIKELY( blst_p2_affine_is_inf( h ) ||
                   blst_p1_is_inf( pub ) ||
                   (pub_fb && (blst_p2_affine_is_inf( h_fb ) ||
                               blst_p1_is_inf( pub_fb ))) ||
                   blst_p2_is_inf( sig ) ) ) return 0;

  blst_p1_affine p[3];
  blst_p2_affine q[3];
  blst_p1_to_affine( p, pub );
  q[0] = *h;
  if( FD_UNLIKELY( pub_fb ) ) {
    blst_p1_to_affine( p+1, pub_fb );
    q[1] = *h_fb;
  }
  p[cnt] = BLS12_381_NEG_G1;
  blst_p2_to_affine( q+cnt, sig );

  for( ulong i=0UL; i<=cnt; i++ ) {
    fd_bls_ref_g1_from_affine( pair_p+i, p+i );
    fd_bls_ref_g2_from_affine( pair_q+i, q+i );
  }
  *pair_cnt = cnt+1UL;
  return 1;
}

int
fd_bls_ref_agg_verify_hashed( fd_bls_hash_t const * h,
                              fd_bls_pub_t const *  pub,
                              fd_bls_hash_t const * h_fb,
                              fd_bls_pub_t const *  pub_fb,
                              fd_bls_sig_t const *  sig ) {
  fd_bls_g1_t p[3];
  fd_bls_g2_t q[3];
  ulong cnt;
  if( FD_UNLIKELY( !fd_bls_ref_agg_to_pair( h, pub, h_fb, pub_fb, sig, p, q, &cnt ) ) ) return 0;
  return fd_bls_ref_pairing_finalverify( p, q, cnt )==1;
}
