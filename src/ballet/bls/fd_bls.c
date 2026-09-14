#include "fd_bls.h"

#include "fd_bls12_381.h"
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
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( sig, hash, sk );
}

void
fd_bls_sec_derive( fd_bls_sec_t * sk,
                   uchar const *  ikm,
                   ulong          ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_keygen( sk, ikm, ikm_sz, NULL, 0UL );
}

void
fd_bls_sig_ser( uchar                out[ static FD_BLS_SIG_SZ ],
                fd_bls_sig_t const * sig ) {
  blst_p2_affine a[1];
  blst_p2_to_affine( a, sig );
  blst_p2_affine_serialize( out, a );
}

int
fd_bls_sig_de( fd_bls_sig_t * sig,
               uchar const    in[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_deserialize( a, in )!=BLST_SUCCESS ) ) return -1;
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( a ) ) )                 return -1;
  blst_p2_from_affine( sig, a );
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
               uchar const *  in,
               ulong          in_sz ) {
  blst_p1_affine a[1];
  if( FD_UNLIKELY( !pub_from_bytes( a, in, in_sz ) ) ) return -1;
  blst_p1_from_affine( pub, a );
  return 0;
}

int
fd_bls_agg_verify( uchar const *        msg,
                   ulong                msg_sz,
                   fd_bls_pub_t const * pub,
                   fd_bls_sig_t const * sig ) {
  if( FD_UNLIKELY( blst_p1_is_inf( pub ) || blst_p2_is_inf( sig ) ) ) return 0; /* the miller loop is wrong on an infinity operand */

  blst_p1_affine a[2];
  blst_p2_affine b[2];
  blst_p2        h[1];
  blst_p1_to_affine( a, pub );
  blst_hash_to_g2( h, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( b, h );
  a[1] = BLS12_381_NEG_G1;
  blst_p2_to_affine( b+1, sig );

  blst_p1_affine const * aptr[2] = { a, a+1 };
  blst_p2_affine const * bptr[2] = { b, b+1 };
  blst_fp12 r[1];
  blst_miller_loop_n( r, bptr, aptr, 2UL );
  return !!blst_fp12_finalverify( r, blst_fp12_one() );
}

fd_bls_set_t *
fd_bls_agg_verify_linear( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad ) {
  fd_bls_set_null( bad );
  for( ulong rank = fd_bls_set_const_iter_init( agg->set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( agg->set, rank ) ) {
    if( FD_UNLIKELY( !fd_bls_agg_verify( msg, msg_sz, pub+rank, sig+rank ) ) ) fd_bls_set_insert( bad, rank );
  }
  return bad;
}

fd_bls_set_t *
fd_bls_agg_verify_bisect( fd_bls_agg_t const * agg,
                          uchar const *        msg,
                          ulong                msg_sz,
                          fd_bls_pub_t const * pub,
                          fd_bls_sig_t const * sig,
                          fd_bls_set_t *       bad ) {
  fd_bls_set_null( bad );
  fd_bls_agg_t key = *agg;
  ulong        cnt = fd_bls_set_cnt( key.set );
  while( FD_LIKELY( cnt>1UL ) ) {
    fd_bls_agg_t lo = { 0 };
    fd_bls_agg_t hi; fd_bls_set_null( hi.set );
    ulong        mid = 0UL;
    for( ulong rank = fd_bls_set_const_iter_init( key.set );
                     !fd_bls_set_const_iter_done( rank );
               rank = fd_bls_set_const_iter_next( key.set, rank ) ) {
      if( FD_LIKELY( mid++<cnt/2UL ) ) { fd_bls_set_insert( lo.set, rank ); blst_p1_add_or_double( &lo.pub, &lo.pub, pub+rank ); blst_p2_add_or_double( &lo.sig, &lo.sig, sig+rank ); }
      else                             { fd_bls_set_insert( hi.set, rank ); }
    }
    hi.pub = lo.pub; blst_p1_cneg( &hi.pub, 1 ); blst_p1_add_or_double( &hi.pub, &hi.pub, &key.pub );
    hi.sig = lo.sig; blst_p2_cneg( &hi.sig, 1 ); blst_p2_add_or_double( &hi.sig, &hi.sig, &key.sig );

    int lo_ok = fd_bls_agg_verify( msg, msg_sz, &lo.pub, &lo.sig ); /* verify lo first, because agg is sorted by stake, so lo has higher-staked validators (which we assume are more likely to be honest) */
    if( FD_LIKELY( lo_ok ) ) key = hi; /* lo is good */
    else { /* lo is bad */
      int hi_ok = fd_bls_agg_verify( msg, msg_sz, &hi.pub, &hi.sig );
      if( FD_UNLIKELY( !hi_ok ) ) break; /* hi is also bad... have to linear scan */
      key = lo;
    }
    cnt = fd_bls_set_cnt( key.set );
  }
  return fd_bls_agg_verify_linear( &key, msg, msg_sz, pub, sig, bad );
}
