#include "ag_bls.h"

#include "../../ballet/bls/fd_bls12_381.h"
#include "../../third_party/blst/bindings/blst.h"

#define AG_BLS_DST        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define AG_BLS_DST_SZ     (sizeof(AG_BLS_DST)-1UL)

#define AG_BLS_VERIFY_MAX (2UL)

#define AG_BLS_GT_SZ      (48UL*12UL)

FD_STATIC_ASSERT( AG_BLS_VERIFY_MAX+1UL<=FD_BLS12_381_PAIRING_BATCH_SZ, pairing_batch );

void
ag_bls_sec_to_pub( ag_bls_sec_t const sk,
                   ag_bls_pub_t       pk ) {
  blst_scalar    scalar[1];
  blst_p1        p[1];
  blst_p1_affine a[1];
  blst_scalar_from_lendian( scalar, sk );
  blst_sk_to_pk_in_g1( p, scalar );
  blst_p1_to_affine( a, p );
  blst_p1_affine_serialize( pk, a );
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

static int
pub_validate( uchar const * pk ) {
  if( FD_UNLIKELY( !fd_bls12_381_g1_validate_syscall( pk, 1 ) ) ) return 0;

  blst_p1_affine a[1];
  if( FD_UNLIKELY( blst_p1_deserialize( a, pk )!=BLST_SUCCESS ) ) return 0;
  return !blst_p1_affine_is_inf( a );
}

static int
pub_aggregate( uchar *       out,
               uchar const * pks,
               ulong         cnt ) {
  if( FD_UNLIKELY( !cnt ) ) return -1;

  for( ulong i=0UL; i<cnt; i++ ) {
    uchar const * pk = pks + i*AG_BLS_PUB_SZ; /* assumes pks are validated epoch_info keys */
    if( FD_UNLIKELY( !i ) ) { fd_memcpy( out, pk, AG_BLS_PUB_SZ ); continue; }
    if( FD_UNLIKELY( fd_bls12_381_g1_add_syscall( out, out, pk, 1 ) ) ) return -1;
  }
  return 0;
}

int
ag_bls_pub_try_from_bytes( ag_bls_pub_t  out,
                           uchar const * in,
                           ulong         in_sz ) {
  uchar affine[ AG_BLS_PUB_SZ ];
  switch( in_sz ) {
  case AG_BLS_PUB_COMPRESSED_SZ:
    if( FD_UNLIKELY( fd_bls12_381_g1_decompress_syscall( affine, in, 1 ) ) ) return -1;
    break;
  case AG_BLS_PUB_SZ:
    fd_memcpy( affine, in, AG_BLS_PUB_SZ );
    break;
  default:
    return -1;
  }
  if( FD_UNLIKELY( !pub_validate( affine ) ) ) return -1;
  fd_memcpy( out, affine, AG_BLS_PUB_SZ );
  return 0;
}

static void
hash_to_g2( uchar *       out,
            uchar const * msg,
            ulong         msg_sz ) {
  blst_p2        h[1];
  blst_p2_affine a[1];
  blst_hash_to_g2( h, msg, msg_sz, (uchar const *)AG_BLS_DST, AG_BLS_DST_SZ, NULL, 0UL );
  blst_p2_to_affine( a, h );
  blst_p2_affine_serialize( out, a );
}

static int
verify_pairs( uchar const * const * pks,
              uchar const * const * msgs,
              ulong const *         msg_szs,
              ulong                 cnt,
              uchar const *         sig ) {
  if( FD_UNLIKELY( !cnt || cnt>AG_BLS_VERIFY_MAX ) ) return 0;

  uchar a[ (AG_BLS_VERIFY_MAX+1UL)*AG_BLS_PUB_SZ ];
  uchar b[ (AG_BLS_VERIFY_MAX+1UL)*AG_BLS_SIG_SZ ];

  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !pub_validate( pks[ i ] ) ) ) return 0;
    fd_memcpy        ( a + i*AG_BLS_PUB_SZ, pks [ i ], AG_BLS_PUB_SZ );
    hash_to_g2( b + i*AG_BLS_SIG_SZ, msgs[ i ], msg_szs[ i ]  );
  }
  blst_p1_affine_serialize( a + cnt*AG_BLS_PUB_SZ, &BLS12_381_NEG_G1 );
  fd_memcpy               ( b + cnt*AG_BLS_SIG_SZ, sig, AG_BLS_SIG_SZ );

  uchar r [ AG_BLS_GT_SZ ];
  uchar id[ AG_BLS_GT_SZ ];
  if( FD_UNLIKELY( fd_bls12_381_pairing_syscall( r,  a, b, cnt+1UL, 1 ) ) ) return 0;
  if( FD_UNLIKELY( fd_bls12_381_pairing_syscall( id, a, b, 0UL,     1 ) ) ) return 0;

  return fd_memeq( r, id, AG_BLS_GT_SZ );
}

int
ag_bls_sig_verify( ag_bls_sig_t const self,
                   ag_bls_pub_t const pk,
                   uchar const *      msg,
                   ulong              msg_sz ) {
  uchar const * pks    [1] = { pk  };
  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_pairs( pks, msgs, msg_szs, 1UL, self );
}

void
ag_bls_agg_zero( ag_bls_agg_t * agg ) {
  fd_memset( agg->sig, 0, AG_BLS_SIG_SZ );
  signer_set_null( agg->bitmask );
}

void
ag_bls_agg_add( ag_bls_agg_t *     self,
                ulong              signer_idx,
                ag_bls_sig_t const sig ) {
  FD_TEST( signer_idx<AG_BLS_SIGNERS_MAX );
  FD_TEST( !signer_set_test( self->bitmask, signer_idx ) );

  int first = ( signer_set_cnt( self->bitmask )==0UL );
  signer_set_insert( self->bitmask, signer_idx );

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
                   uchar const *        pk0,
                   ulong                pk_stride,
                   ulong                pk_cnt ) {
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( self->bitmask )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pk0                                                                            ) ) return 0;

  static FD_TL uchar gathered[ AG_BLS_SIGNERS_MAX * AG_BLS_PUB_SZ ];
  ulong k = 0UL;
  for( ulong i=0UL; i<pk_cnt; i++ ) {
    if( FD_LIKELY( signer_set_test( self->bitmask, i ) ) ) {
      fd_memcpy( gathered + k*AG_BLS_PUB_SZ, pk0 + i*pk_stride, AG_BLS_PUB_SZ );
      k++;
    }
  }
  if( FD_UNLIKELY( k==0UL ) ) return 0;

  uchar apk[ AG_BLS_PUB_SZ ];
  if( FD_UNLIKELY( pub_aggregate( apk, gathered, k ) ) ) return 0;

  uchar const * pks    [1] = { apk    };
  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_pairs( pks, msgs, msg_szs, 1UL, self->sig );
}

int
ag_bls_agg_verify_without_bitmask( ag_bls_agg_t const * self,
                                   uchar const *        msg,
                                   ulong                msg_sz,
                                   uchar const *        pk0,
                                   ulong                pk_stride,
                                   ulong                pk_cnt ) {
  if( FD_UNLIKELY( ag_bls_agg_signer_cnt( self )!=pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pk0 || !pk_cnt                          ) ) return 0;

  static FD_TL uchar gathered[ AG_BLS_SIGNERS_MAX * AG_BLS_PUB_SZ ];
  if( FD_UNLIKELY( pk_cnt>AG_BLS_SIGNERS_MAX ) ) return 0;
  for( ulong i=0UL; i<pk_cnt; i++ ) {
    fd_memcpy( gathered + i*AG_BLS_PUB_SZ, pk0 + i*pk_stride, AG_BLS_PUB_SZ );
  }

  uchar apk[ AG_BLS_PUB_SZ ];
  if( FD_UNLIKELY( pub_aggregate( apk, gathered, pk_cnt ) ) ) return 0;

  uchar const * pks    [1] = { apk    };
  uchar const * msgs   [1] = { msg    };
  ulong         msg_szs[1] = { msg_sz };
  return verify_pairs( pks, msgs, msg_szs, 1UL, self->sig );
}

int
ag_bls_agg_verify_merged( ag_bls_agg_t const * agg_base,
                         uchar const *        msg_base,
                         ulong                msg_base_sz,
                         ag_bls_agg_t const * agg_fb,
                         uchar const *        msg_fb,
                         ulong                msg_fb_sz,
                         uchar const *        pk0,
                         ulong                pk_stride,
                         ulong                pk_cnt ) {
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg_base->bitmask )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg_fb->bitmask   )+1UL )>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pk0                                                                                ) ) return 0;

  static FD_TL uchar gathered[ AG_BLS_SIGNERS_MAX * AG_BLS_PUB_SZ ];
  uchar apk[ 2*AG_BLS_PUB_SZ ];

  signer_set_t const * masks[2] = { agg_base->bitmask, agg_fb->bitmask };
  ulong cnt[2] = { 0UL, 0UL };
  for( ulong g=0UL; g<2UL; g++ ) {
    ulong k = 0UL;
    for( ulong i=0UL; i<pk_cnt; i++ ) {
      if( signer_set_test( masks[g], i ) ) { fd_memcpy( gathered + k*AG_BLS_PUB_SZ, pk0 + i*pk_stride, AG_BLS_PUB_SZ ); k++; }
    }
    cnt[g] = k;
    if( k && FD_UNLIKELY( pub_aggregate( apk + g*AG_BLS_PUB_SZ, gathered, k ) ) ) return 0;
  }

  if( FD_UNLIKELY( cnt[0]==0UL && cnt[1]==0UL ) ) return 0;

  uchar const * pks    [ AG_BLS_VERIFY_MAX ];
  uchar const * msgs   [ AG_BLS_VERIFY_MAX ];
  ulong         msg_szs[ AG_BLS_VERIFY_MAX ];
  ulong         n = 0UL;
  if( cnt[0] ) { pks[n] = apk;               msgs[n] = msg_base; msg_szs[n] = msg_base_sz; n++; }
  if( cnt[1] ) { pks[n] = apk+AG_BLS_PUB_SZ; msgs[n] = msg_fb;   msg_szs[n] = msg_fb_sz;   n++; }

  return verify_pairs( pks, msgs, msg_szs, n, agg_base->sig );
}
