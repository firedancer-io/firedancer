#include "fd_bls.h"

#include "../../third_party/blst/bindings/blst.h"

static inline void
fd_bls_g1_from_blst( fd_bls_g1_t *        out,
                     blst_p1_affine const * in ) {
  blst_uint64_from_fp( out->x, &in->x );
  blst_uint64_from_fp( out->y, &in->y );
}

static inline void
fd_bls_g2_from_blst( fd_bls_g2_t *        out,
                     blst_p2_affine const * in ) {
  blst_uint64_from_fp( out->x[0], &in->x.fp[0] );
  blst_uint64_from_fp( out->x[1], &in->x.fp[1] );
  blst_uint64_from_fp( out->y[0], &in->y.fp[0] );
  blst_uint64_from_fp( out->y[1], &in->y.fp[1] );
}

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
fd_bls_sig_ser( fd_bls_sig_t const * sig,
                uchar                buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  blst_p2_to_affine( a, sig );
  blst_p2_affine_serialize( buf, a );
}

int
fd_bls_sig_de( fd_bls_sig_t * sig,
               uchar const    buf[ static FD_BLS_SIG_SZ ] ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_deserialize( a, buf )!=BLST_SUCCESS ) ) return -1;
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
  fd_memset( &agg->sig, 0, sizeof(fd_bls_sig_t) );
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
    blst_p2_add_or_double( &agg->sig, &agg->sig, sig+rank );
  }
  return agg;
}

static int
fd_bls_agg_verify_impl( uchar const *        msg,
                        ulong                msg_sz,
                        fd_bls_pub_t const * pub,
                        uchar const *        msg_fb,
                        ulong                msg_fb_sz,
                        fd_bls_pub_t const * pub_fb,
                        fd_bls_sig_t const * sig ) {
  ulong cnt = 1UL + !!pub_fb;
  if( FD_UNLIKELY( blst_p1_is_inf( pub ) ||
                   (pub_fb && blst_p1_is_inf( pub_fb )) ||
                   blst_p2_is_inf( sig ) ) ) return 0; /* the Miller loop is wrong on an infinity operand */

  blst_p1_affine a[3];
  blst_p2_affine b[3];
  blst_p2        h[1];
  blst_p1_to_affine( a, pub );
  blst_hash_to_g2( h, msg, msg_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( b, h );
  if( FD_UNLIKELY( pub_fb ) ) {
    blst_p1_to_affine( a+1, pub_fb );
    blst_hash_to_g2( h, msg_fb, msg_fb_sz, (uchar const *)FD_BLS_DST, FD_BLS_DST_SZ, NULL, 0UL );
    blst_p2_to_affine( b+1, h );
  }
  a[cnt] = BLS12_381_NEG_G1;
  blst_p2_to_affine( b+cnt, sig );

  fd_bls_g1_t pair_p[3];
  fd_bls_g2_t pair_q[3];
  for( ulong i=0UL; i<=cnt; i++ ) {
    fd_bls_g1_from_blst( pair_p+i, a+i );
    fd_bls_g2_from_blst( pair_q+i, b+i );
  }
  return fd_bls_pairing_finalverify( pair_p, pair_q, cnt+1UL )==1;
}

int
fd_bls_agg_verify( uchar const *        msg,
                   ulong                msg_sz,
                   fd_bls_pub_t const * pub,
                   fd_bls_sig_t const * sig ) {
  return fd_bls_agg_verify_impl( msg, msg_sz, pub, NULL, 0UL, NULL, sig );
}

int
fd_bls_agg_verify_pair( uchar const *        msg,
                        ulong                msg_sz,
                        fd_bls_pub_t const * pub,
                        uchar const *        msg_fb,
                        ulong                msg_fb_sz,
                        fd_bls_pub_t const * pub_fb,
                        fd_bls_sig_t const * sig ) {
  if( FD_UNLIKELY( !msg_fb || !pub_fb ) ) return 0;
  return fd_bls_agg_verify_impl( msg, msg_sz, pub, msg_fb, msg_fb_sz, pub_fb, sig );
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

int
fd_bls_agg_verify_subtract( fd_bls_agg_t *       agg,
                            uchar const *        msg,
                            ulong                msg_sz,
                            fd_bls_pub_t const * pub,
                            fd_bls_sig_t const * sig,
                            fd_bls_set_t *       bad ) {
  if( FD_LIKELY( fd_bls_agg_verify( msg, msg_sz, &agg->pub, &agg->sig ) ) ) { fd_bls_set_null( bad ); return 0; }
  fd_bls_agg_verify_bisect( agg, msg, msg_sz, pub, sig, bad );
  fd_bls_agg_t sub = { 0 };
  fd_bls_agg_construct( &sub, pub, sig, bad );
  blst_p1_cneg( &sub.pub, 1 ); blst_p1_add_or_double( &agg->pub, &agg->pub, &sub.pub );
  blst_p2_cneg( &sub.sig, 1 ); blst_p2_add_or_double( &agg->sig, &agg->sig, &sub.sig );
  fd_bls_set_subtract( agg->set, agg->set, bad );
  if( FD_UNLIKELY( blst_p1_is_inf( &agg->pub ) ) ) return -1;
  return 0;
}

#if FD_HAS_AVX512
#include "avx512/fd_bls.c"
#else
#include "ref/fd_bls.c"
#endif
