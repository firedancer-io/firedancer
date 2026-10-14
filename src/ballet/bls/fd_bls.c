#include "fd_bls.h"

#include "../../third_party/blst/bindings/blst.h"

void
fd_bls_sec_to_pub( fd_bls_sec_t const * sk,
                   fd_bls_pub_t *       pk ) {
  blst_sk_to_pk_in_g1( pk, sk );
}

void
fd_bls_sec_sign( fd_bls_sec_t const * sk,
                 uchar const *        msg,
                 ulong                msg_sz,
                 fd_bls_sig_t *       sig ) {
  blst_p2 hash[1];
  blst_p2 p[1];
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( p, hash, sk );
  blst_p2_to_affine( sig, p );
}

void
fd_bls_sec_derive( fd_bls_sec_t * sk,
                   uchar const *  ikm,
                   ulong          ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_keygen( sk, ikm, ikm_sz, NULL, 0UL );
}

void
fd_bls_sig_ser( fd_bls_sig_t const * sig,
                uchar                buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine_serialize( buf, sig );
}

int
fd_bls_sig_de( fd_bls_sig_t * sig,
               uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  if( FD_UNLIKELY( blst_p2_deserialize( sig, buf )!=BLST_SUCCESS ) ) return -1;
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( sig ) ) )                  return -1;
  return 0;
}

static int
pub_from_bytes( blst_p1_affine * out,
                uchar const *    in,
                ulong            in_sz ) {
  BLST_ERROR err;
  switch( in_sz ) {
  case FD_BLS_PUB_COMPRESSED_SZ: err = blst_p1_uncompress ( out, in ); break;
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
fd_bls_pub_de( fd_bls_pub_t * pub,
               uchar const *  buf,
               ulong          buf_sz ) {
  blst_p1_affine a[1];
  if( FD_UNLIKELY( !pub_from_bytes( a, buf, buf_sz ) ) ) return -1;
  blst_p1_from_affine( pub, a );
  return 0;
}

fd_bls_agg_t *
fd_bls_agg_null( fd_bls_agg_t * agg ) {
  fd_memset( &agg->pub, 0, sizeof(fd_bls_pub_t) );
  fd_memset( &agg->sig, 0, sizeof(blst_p2) );
  fd_bls_set_null( agg->set );
  return agg;
}

fd_bls_agg_t *
fd_bls_agg_construct( fd_bls_agg_t *       agg,
                      fd_bls_pub_t const * pub,
                      fd_bls_sig_t const * sig,
                      fd_bls_set_t const * set ) {
  fd_bls_set_copy( agg->set, set );
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    blst_p1_add_or_double( &agg->pub, &agg->pub, pub+rank );
    blst_p2_add_or_double_affine( &agg->sig, &agg->sig, sig+rank );
  }
  return agg;
}

fd_bls_pub_t *
fd_bls_pub_sum( fd_bls_pub_t *         pub,
                blst_p1_affine const * key,
                ulong                  key_cnt,
                fd_bls_set_t const *   set,
                fd_bls_pub_t const *   full ) {
  fd_memset( pub, 0, sizeof(fd_bls_pub_t) ); /* point at infinity */

  if( FD_LIKELY( !full || 2UL*fd_bls_set_cnt( set )<=key_cnt ) ) {
    for( ulong rank=0UL; rank<key_cnt; rank++ ) {
      if( fd_bls_set_test( set, rank ) ) blst_p1_add_or_double_affine( pub, pub, key+rank );
    }
    return pub;
  }

  /* full minus the keys not in set */
  for( ulong rank=0UL; rank<key_cnt; rank++ ) {
    if( !fd_bls_set_test( set, rank ) ) blst_p1_add_or_double_affine( pub, pub, key+rank );
  }
  blst_p1_cneg( pub, 1 );
  blst_p1_add_or_double( pub, full, pub );
  return pub;
}


void
fd_bls_hash_msg( uchar const *    msg,
                 ulong            msg_sz,
                 blst_p2_affine * h ) {
  blst_p2 p[1];
  blst_hash_to_g2( p, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( h, p );
}

/* agg_pairing computes gt = e(pub,h) / e(G1,sig), which is the identity iff
   sig is a valid signature on h under pub. */

static blst_fp12 *
agg_pairing( blst_fp12 *            gt,
        blst_p2_affine const * h,
        fd_bls_pub_t const *   pub,
        blst_p2 const *        sig ) {
  blst_p1_affine         a[2];
  blst_p2_affine         b[2];
  blst_p1_affine const * aptr[2];
  blst_p2_affine const * bptr[2];
  ulong                  n = 0UL;
  if( FD_LIKELY( !blst_p1_is_inf( pub ) && !blst_p2_affine_is_inf( h ) ) ) { blst_p1_to_affine( a+n, pub ); b[n] = *h;                     aptr[n] = a+n; bptr[n] = b+n; n++; }
  if( FD_LIKELY( !blst_p2_is_inf( sig )                                ) ) { a[n] = BLS12_381_NEG_G1;       blst_p2_to_affine( b+n, sig ); aptr[n] = a+n; bptr[n] = b+n; n++; }
  if( FD_UNLIKELY( !n ) ) { *gt = *blst_fp12_one(); return gt; }
  blst_miller_loop_n( gt, bptr, aptr, n );
  blst_final_exp( gt, gt );
  return gt;
}

int
fd_bls_agg_verify_hashed( blst_p2_affine const * h,
                          fd_bls_pub_t const *   pub,
                          blst_p2 const *        sig ) {
  if( FD_UNLIKELY( blst_p2_affine_is_inf( h ) || blst_p1_is_inf( pub ) || blst_p2_is_inf( sig ) ) ) return 0;
  blst_fp12 gt[1];
  return !!blst_fp12_is_one( agg_pairing( gt, h, pub, sig ) );
}

int
fd_bls_agg_verify( uchar const *        msg,
                   ulong                msg_sz,
                   fd_bls_pub_t const * pub,
                   blst_p2 const *      sig ) {
  if( FD_UNLIKELY( blst_p1_is_inf( pub ) || blst_p2_is_inf( sig ) ) ) return 0;
  blst_p2_affine h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  return fd_bls_agg_verify_hashed( h, pub, sig );
}

static fd_bls_set_t *
verify_linear_hashed( fd_bls_agg_t const *   agg,
                      blst_p2_affine const * h,
                      fd_bls_pub_t const *   pub,
                      fd_bls_sig_t const *   sig,
                      fd_bls_set_t *         bad ) {
  fd_bls_set_null( bad );
  for( ulong rank = fd_bls_set_const_iter_init( agg->set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( agg->set, rank ) ) {
    blst_p2 one;
    blst_p2_from_affine( &one, sig+rank );
    if( FD_UNLIKELY( !fd_bls_agg_verify_hashed( h, pub+rank, &one ) ) ) fd_bls_set_insert( bad, rank );
  }
  return bad;
}

/* verify_bisect_rec descends the contiguous run ranks[ lo, hi ) of
   the signer list.  pub_aff and sig_aff are the signers' pub and sig
   points in affine form, in signer-list (not rank) order.  The caller
   guarantees gt!=1, i.e. the run contains a bad signer.  p, s and gt
   are consumed by the descent, which lets both halves be derived
   without copying the parent: the hi run's sums are p-lp and its gt
   is conj( lgt*conj(gt) ) = conj(lgt)*gt. */

#define BISECT_DEPTH_MAX (11UL)
FD_STATIC_ASSERT( FD_BLS_SET_MAX<=(1UL<<BISECT_DEPTH_MAX), bisect_depth );

static void
verify_bisect_rec( blst_p2_affine const * h,
                   blst_p1_affine const * pub_aff,
                   blst_p2_affine const * sig_aff,
                   ushort const *         ranks,
                   ushort                 lo,
                   ushort                 hi,
                   blst_p1 *              p,
                   blst_p2 *              s,
                   blst_fp12 *            gt,
                   fd_bls_set_t *         bad ) {
  if( hi-lo==1 ) { fd_bls_set_insert( bad, ranks[ lo ] ); return; }

  ushort mid = (ushort)( lo + ( (ulong)hi-(ulong)lo )/2UL );

  /* Sum the lo half's pub and sig points in one batch each. */
  blst_p1_affine const * pub_sum[2] = { pub_aff+lo, NULL };
  blst_p2_affine const * sig_sum[2] = { sig_aff+lo, NULL };
  blst_p1 lp[1]; blst_p2 ls[1];
  blst_p1s_add( lp, pub_sum, (size_t)( (ulong)mid-(ulong)lo ) );
  blst_p2s_add( ls, sig_sum, (size_t)( (ulong)mid-(ulong)lo ) );

  blst_p1_cneg( p, 1 );
  blst_p2_cneg( s, 1 );
  blst_p1 hp[1]; blst_p2 hs[1];
  blst_p1_add_or_double( hp, lp, p ); blst_p1_cneg( hp, 1 ); /* hp = p-lp */
  blst_p2_add_or_double( hs, ls, s ); blst_p2_cneg( hs, 1 ); /* hs = s-ls */

  blst_fp12 lgt[1];
  agg_pairing( lgt, h, lp, ls );
  blst_fp12_conjugate( gt );
  blst_fp12 hgt[1];
  blst_fp12_mul( hgt, lgt, gt );
  blst_fp12_conjugate( hgt ); /* hgt = conj(lgt)*gt */

  if( FD_LIKELY( !blst_fp12_is_one( lgt ) ) ) verify_bisect_rec( h, pub_aff, sig_aff, ranks, lo, mid, lp, ls, lgt, bad );
  if( FD_LIKELY( !blst_fp12_is_one( hgt ) ) ) verify_bisect_rec( h, pub_aff, sig_aff, ranks, mid, hi, hp, hs, hgt, bad );
}

static fd_bls_set_t *
verify_bisect_hashed( fd_bls_agg_t const *   agg,
                      blst_p2_affine const * h,
                      fd_bls_pub_t const *   pub,
                      fd_bls_sig_t const *   sig,
                      fd_bls_set_t *         bad ) {
  fd_bls_set_null( bad );
  if( FD_UNLIKELY( fd_bls_set_is_null( agg->set ) ) ) return bad;

  /* a valid aggregate, the common case */
  blst_p1   p[1]; p[ 0 ] = agg->pub; /* consumed by the descent */
  blst_p2   s[1]; s[ 0 ] = agg->sig;
  blst_fp12 gt[1];
  agg_pairing( gt, h, &agg->pub, &agg->sig );
  if( FD_LIKELY( blst_fp12_is_one( gt ) ) ) return bad;

  ushort           ranks  [ FD_BLS_SET_MAX ];
  blst_p1 const *  pub_ptr[ FD_BLS_SET_MAX ];
  blst_p1_affine   pub_aff[ FD_BLS_SET_MAX ];
  blst_p2_affine   sig_aff[ FD_BLS_SET_MAX ]; /* sigs are stored affine, so they are gathered rather than converted */
  ulong  cnt = 0UL;
  for( ulong rank = fd_bls_set_const_iter_init( agg->set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( agg->set, rank ) ) {
    ranks  [ cnt ] = (ushort)rank;
    pub_ptr[ cnt ] = pub+rank;
    sig_aff[ cnt ] = sig[ rank ];
    cnt++;
  }

  /* blst_p1s_to_affine cannot take a point at infinity. A signer with an
     infinity pub or sig cannot verify anyway, so fall back to the linear
     scan, which flags them. */
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( blst_p1_is_inf( pub_ptr[ i ] ) || blst_p2_affine_is_inf( sig_aff+i ) ) )
      return verify_linear_hashed( agg, h, pub, sig, bad );
  }

  blst_p1s_to_affine( pub_aff, pub_ptr, cnt );
  verify_bisect_rec( h, pub_aff, sig_aff, ranks, 0, (ushort)cnt, p, s, gt, bad );
  return bad;
}

fd_bls_set_t *
fd_bls_agg_verify_linear( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad ) {
  blst_p2_affine h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  return verify_linear_hashed( agg, h, pub, sig, bad );
}

fd_bls_set_t *
fd_bls_agg_verify_bisect( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad ) {
  blst_p2_affine h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  return verify_bisect_hashed( agg, h, pub, sig, bad );
}

int
fd_bls_agg_verify_subtract( fd_bls_agg_t *       agg,
                            uchar const *        msg,
                            ulong                msg_sz,
                            fd_bls_pub_t const * pub,
                            fd_bls_sig_t const * sig,
                            fd_bls_set_t *       bad ) {
  blst_p2_affine h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  verify_bisect_hashed( agg, h, pub, sig, bad );
  if( FD_UNLIKELY( !fd_bls_set_is_null( bad ) ) ) {
    fd_bls_agg_t sub = { 0 };
    fd_bls_agg_construct( &sub, pub, sig, bad );
    blst_p1_cneg( &sub.pub, 1 ); blst_p1_add_or_double( &agg->pub, &agg->pub, &sub.pub );
    blst_p2_cneg( &sub.sig, 1 ); blst_p2_add_or_double( &agg->sig, &agg->sig, &sub.sig );
    fd_bls_set_subtract( agg->set, agg->set, bad );
  }
  /* an aggregate whose keys cancel to infinity carries no stake even
     when every signer is individually valid */
  if( FD_UNLIKELY( blst_p1_is_inf( &agg->pub ) ) ) return -1;
  return 0;
}
