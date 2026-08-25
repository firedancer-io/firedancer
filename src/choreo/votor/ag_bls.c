#include "ag_bls.h"

#include "../../ballet/bls/fd_bls12_381.h"
#include "../../third_party/blst/bindings/blst.h"

#define AG_BLS_DST        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define AG_BLS_DST_SZ     (sizeof(AG_BLS_DST)-1UL)

#define AG_BLS_VERIFY_MAX (2UL)

void
ag_bls_sec_to_pub( ag_bls_sec_t const sk,
                   ag_bls_pub_t *     pk ) {
  blst_scalar    scalar[1];
  blst_p1        p[1];
  blst_p1_affine a[1];
  blst_scalar_from_lendian( scalar, sk );
  blst_sk_to_pk_in_g1( p, scalar );
  blst_p1_to_affine( a, p );
  blst_p1_affine_serialize( pk->bytes, a );
}

void
ag_bls_sec_sign( ag_bls_sec_t const sk,
                 ag_bls_sig_t       sig,
                 uchar const *      msg,
                 ulong              msg_sz ) {
  blst_scalar    scalar[1];
  blst_p2        hash[1];
  blst_p2        s[1];
  blst_p2_affine a[1];
  blst_scalar_from_lendian( scalar, sk );
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)AG_BLS_DST, AG_BLS_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( s, hash, scalar );
  blst_p2_to_affine( a, s );
  blst_p2_affine_serialize( sig, a );
}

void
ag_bls_sec_derive( ag_bls_sec_t  sk,
                   uchar const * ikm,
                   ulong         ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_scalar scalar[1];
  blst_keygen( scalar, ikm, ikm_sz, NULL, 0UL );
  fd_memcpy( sk, scalar->b, AG_BLS_SEC_SZ );
}

/* ag_bls_pub_t values have already passed the subgroup check at their
   construction boundary. */

static int
pub_deserialize( blst_p1_affine * out,
                 ag_bls_pub_t const * in ) {
  return blst_p1_deserialize( out, in->bytes )==BLST_SUCCESS &&
         !blst_p1_affine_is_inf( out );
}

static int
pub_from_bytes( blst_p1_affine * out,
                uchar const *    in,
                ulong            in_sz ) {
  BLST_ERROR err;
  switch( in_sz ) {
  case AG_BLS_PUB_COMPRESSED_SZ: err = blst_p1_uncompress ( out, in ); break;
  case AG_BLS_PUB_SZ:            
    if( FD_UNLIKELY( in[0]&0xA0U ) ) return 0;  
    err = blst_p1_deserialize( out, in ); 
    break;
  default: return 0;
  }
  return err==BLST_SUCCESS &&
         !blst_p1_affine_is_inf( out ) &&
         blst_p1_affine_in_g1( out );
}

static int
pub_aggregate( blst_p1_affine *    out,
               ag_bls_pub_t const * pks,
               signer_set_t const * signers,
               ulong                pk_cnt ) {
  if( FD_UNLIKELY( !pk_cnt || pk_cnt>AG_BLS_SIGNERS_MAX ) ) return -1;

  static FD_TL blst_p1_affine         affine[ AG_BLS_SIGNERS_MAX ];
  static FD_TL blst_p1_affine const * points[ AG_BLS_SIGNERS_MAX ];
  ulong point_cnt = 0UL;
  for( ulong i=0UL; i<pk_cnt; i++ ) {
    if( signers && !signer_set_test( signers, i ) ) continue;
    if( FD_UNLIKELY( !pub_deserialize( affine+point_cnt, pks+i ) ) ) return -1;
    points[ point_cnt ] = affine+point_cnt;
    point_cnt++;
  }
  if( FD_UNLIKELY( !point_cnt ) ) return -1;

  blst_p1 sum[1];
  blst_p1s_add( sum, points, point_cnt );
  blst_p1_to_affine( out, sum );
  if( FD_UNLIKELY( blst_p1_affine_is_inf( out ) ) ) return -1;
  return 0;
}

int
ag_bls_pub_try_from_bytes( ag_bls_pub_t * out,
                           uchar const *  in,
                           ulong          in_sz ) {
  blst_p1_affine pub[1];
  if( FD_UNLIKELY( !pub_from_bytes( pub, in, in_sz ) ) ) return -1;
  blst_p1_affine_serialize( out->bytes, pub );
  return 0;
}

static int
verify_affine_pairs( blst_p1_affine const * a,
                     uchar const * const *  msgs,
                     ulong const *          msg_szs,
                     ulong                  cnt,
                     uchar const *          sig ) {
  if( FD_UNLIKELY( !cnt || cnt>AG_BLS_VERIFY_MAX ) ) return 0;

  blst_p2        h[ AG_BLS_VERIFY_MAX ];
  blst_p2_affine b[ AG_BLS_VERIFY_MAX ];
  for( ulong i=0UL; i<cnt; i++ ) {
    blst_hash_to_g2( h+i, msgs[i], msg_szs[i], (uchar const *)AG_BLS_DST, AG_BLS_DST_SZ, NULL, 0UL );
    blst_p2_to_affine( b+i, h+i );
  }

  blst_p2_affine signature[1];
  if( FD_UNLIKELY( sig[0]&0xA0U ) ) return 0;
  if( FD_UNLIKELY( blst_p2_deserialize( signature, sig )!=BLST_SUCCESS ) ) return 0;
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( signature )                  ) ) return 0;
  if( FD_UNLIKELY( blst_p2_affine_is_inf( signature )                  ) ) return 0;

  blst_p1_affine const * aptr[ AG_BLS_VERIFY_MAX+1UL ];
  blst_p2_affine const * bptr[ AG_BLS_VERIFY_MAX+1UL ];
  for( ulong i=0UL; i<cnt; i++ ) { aptr[i] = a+i; bptr[i] = b+i; }
  aptr[cnt] = &BLS12_381_NEG_G1;
  bptr[cnt] = signature;

  blst_fp12 r[1];
  blst_miller_loop_n( r, bptr, aptr, cnt+1UL );
  return !!blst_fp12_finalverify( r, blst_fp12_one() );
}

int
ag_bls_sig_verify( ag_bls_sig_t const self,
                   ag_bls_pub_t const * pk,
                   uchar const *      msg,
                   ulong              msg_sz ) {
  blst_p1_affine pub[1];
  if( FD_UNLIKELY( !pub_deserialize( pub, pk ) ) ) return 0;
  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_affine_pairs( pub, msgs, msg_szs, 1UL, self );
}

void
ag_bls_agg_zero( ag_bls_agg_t * agg ) {
  fd_memset( agg->sig, 0, AG_BLS_SIG_SZ );
  signer_set_null( agg->bitmask );
}

void
ag_bls_agg_add( ag_bls_agg_t *     self,
                ulong              rank,
                ag_bls_sig_t const sig ) {
  FD_TEST( rank<AG_BLS_SIGNERS_MAX );
  FD_TEST( !signer_set_test( self->bitmask, rank ) );

  int first = ( signer_set_cnt( self->bitmask )==0UL );
  signer_set_insert( self->bitmask, rank );

  if( FD_UNLIKELY( first ) ) {
    fd_memcpy( self->sig, sig, AG_BLS_SIG_SZ );
    return;
  }

  fd_bls12_381_g2_add_syscall( self->sig, self->sig, sig, 1 );
}

void
ag_bls_agg_merge( ag_bls_agg_t * dst,
                  ag_bls_agg_t * src ) {
  if( FD_UNLIKELY( signer_set_cnt( src->bitmask )==0UL ) ) return;

  if( signer_set_cnt( dst->bitmask )==0UL ) {
    fd_memcpy( dst->sig, src->sig, AG_BLS_SIG_SZ );
  } else {
    fd_bls12_381_g2_add_syscall( dst->sig, dst->sig, src->sig, 1 );
  }
  fd_memset( src->sig, 0, AG_BLS_SIG_SZ );
}

int
ag_bls_agg_is_identity( ag_bls_agg_t const * self ) {
  blst_p2_affine a[1];
  if( FD_UNLIKELY( blst_p2_deserialize( a, self->sig )!=BLST_SUCCESS ) ) return 0;
  return !!blst_p2_affine_is_inf( a );
}

int
ag_bls_agg_verify( ag_bls_agg_t const * self,
                   uchar const *        msg,
                   ulong                msg_sz,
                   ag_bls_pub_t const * pks,
                   ulong                pk_cnt ) {
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( self->bitmask )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pks                                                                            ) ) return 0;

  blst_p1_affine apk[1];
  if( FD_UNLIKELY( pub_aggregate( apk, pks, self->bitmask, pk_cnt ) ) ) return 0;

  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_affine_pairs( apk, msgs, msg_szs, 1UL, self->sig );
}

int
ag_bls_agg_verify_without_bitmask( ag_bls_agg_t const * self,
                                   uchar const *        msg,
                                   ulong                msg_sz,
                                   ag_bls_pub_t const * pks,
                                   ulong                pk_cnt ) {
  if( FD_UNLIKELY( ag_bls_agg_signer_cnt( self )!=pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pks || !pk_cnt                          ) ) return 0;

  blst_p1_affine apk[1];
  if( FD_UNLIKELY( pub_aggregate( apk, pks, NULL, pk_cnt ) ) ) return 0;

  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_affine_pairs( apk, msgs, msg_szs, 1UL, self->sig );
}

int
ag_bls_agg_verify_merged( ag_bls_agg_t const * agg_base,
                         uchar const *        msg_base,
                         ulong                msg_base_sz,
                         ag_bls_agg_t const * agg_fb,
                         uchar const *        msg_fb,
                         ulong                msg_fb_sz,
                         ag_bls_pub_t const * pks,
                         ulong                pk_cnt ) {
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg_base->bitmask )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg_fb->bitmask   )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pks                                                                                ) ) return 0;

  blst_p1_affine apk[2];
  signer_set_t const * masks[2] = { agg_base->bitmask, agg_fb->bitmask };
  ulong cnt[2] = { 0UL, 0UL };
  for( ulong g=0UL; g<2UL; g++ ) {
    cnt[g] = signer_set_cnt( masks[g] );
    if( cnt[g] && FD_UNLIKELY( pub_aggregate( apk+g, pks, masks[g], pk_cnt ) ) ) return 0;
  }

  if( FD_UNLIKELY( cnt[0]==0UL && cnt[1]==0UL ) ) return 0;

  blst_p1_affine packed_apk[ AG_BLS_VERIFY_MAX ];
  uchar const * msgs   [ AG_BLS_VERIFY_MAX ];
  ulong         msg_szs[ AG_BLS_VERIFY_MAX ];
  ulong         n = 0UL;
  if( cnt[0] ) { packed_apk[n] = apk[0]; msgs[n] = msg_base; msg_szs[n] = msg_base_sz; n++; }
  if( cnt[1] ) { packed_apk[n] = apk[1]; msgs[n] = msg_fb;   msg_szs[n] = msg_fb_sz;   n++; }

  return verify_affine_pairs( packed_apk, msgs, msg_szs, n, agg_base->sig );
}
