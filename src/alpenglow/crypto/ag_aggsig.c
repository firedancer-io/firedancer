#include "ag_aggsig.h"

#include "../../ballet/bls/fd_bls12_381.h"
#include <blst.h>

#define AG_AGGSIG_DST     "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define AG_AGGSIG_DST_SZ  (sizeof(AG_AGGSIG_DST)-1UL)

void
ag_aggsig_sk_to_pk( ag_aggsig_pk_t *       pk,
                    ag_aggsig_sk_t const * sk ) {
  blst_scalar    scalar[1];
  blst_p1        p[1];
  blst_p1_affine a[1];
  blst_scalar_from_lendian( scalar, sk->v );
  blst_sk_to_pk_in_g1( p, scalar );
  blst_p1_to_affine( a, p );
  blst_p1_affine_serialize( pk->v, a );
}

void
ag_aggsig_sk_to_pk_compressed( uchar                  out[ AG_AGGSIG_PUBKEY_COMPRESSED_SZ ],
                               ag_aggsig_sk_t const * sk ) {
  blst_scalar    scalar[1];
  blst_p1        p[1];
  blst_p1_affine a[1];
  blst_scalar_from_lendian( scalar, sk->v );
  blst_sk_to_pk_in_g1( p, scalar );
  blst_p1_to_affine( a, p );
  blst_p1_affine_compress( out, a );
}

void
ag_aggsig_sign_bytes( ag_aggsig_sig_t *      sig,
                      ag_aggsig_sk_t const * sk,
                      uchar const *          msg,
                      ulong                  msg_sz ) {
  blst_scalar    scalar[1];
  blst_p2        hash[1];
  blst_p2        s[1];
  blst_p2_affine a[1];
  blst_scalar_from_lendian( scalar, sk->v );
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)AG_AGGSIG_DST, AG_AGGSIG_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( s, hash, scalar );
  blst_p2_to_affine( a, s );
  blst_p2_affine_serialize( sig->v, a );
}

void
ag_aggsig_sk_derive( ag_aggsig_sk_t * sk,
                     uchar const *    ikm,
                     ulong            ikm_sz ) {
  FD_TEST( ikm_sz>=32UL );
  blst_scalar scalar[1];
  blst_keygen( scalar, ikm, ikm_sz, NULL, 0UL );
  fd_memcpy( sk->v, scalar->b, AG_AGGSIG_SECKEY_SZ );
}

int
ag_aggsig_individual_verify_bytes( ag_aggsig_sig_t const * self,
                                   ag_aggsig_pk_t const *  pk,
                                   uchar const *           msg,
                                   ulong                   msg_sz ) {
  ulong msg_len = msg_sz;
  return fd_bls12_381_batch_verify( msg, &msg_len, pk->v, self->v, 1UL )==0;
}

void
ag_aggsig_sign_local( void *            ctx,
                      ag_aggsig_sig_t * sig,
                      uchar const *     payload,
                      ulong             payload_sz ) {
  ag_aggsig_sign_bytes( sig, (ag_aggsig_sk_t const *)ctx, payload, payload_sz );
}

void
ag_aggsig_init( ag_aggsig_t * agg,
                ulong         nbits ) {
  FD_TEST( nbits<=AG_AGGSIG_MAX_SIGNERS );
  fd_memset( agg->sig, 0, AG_AGGSIG_SIG_SZ );
  agg->nbits = nbits;
  voter_set_null( agg->bitmask );
}

void
ag_aggsig_add( ag_aggsig_t *           self,
               ulong                   signer_idx,
               ag_aggsig_sig_t const * sig ) {
  FD_TEST( signer_idx<self->nbits );
  FD_TEST( !voter_set_test( self->bitmask, signer_idx ) );

  int first = ( voter_set_cnt( self->bitmask )==0UL );
  voter_set_insert( self->bitmask, signer_idx );

  if( FD_UNLIKELY( first ) ) {

    fd_memcpy( self->sig, sig->v, AG_AGGSIG_SIG_SZ );
    return;
  }

  fd_bls12_381_g2_add_syscall( self->sig, self->sig, sig->v, 1 );
}

void
ag_aggsig_merge_sig( ag_aggsig_t * dst,
                     ag_aggsig_t * src ) {
  if( FD_UNLIKELY( voter_set_cnt( src->bitmask )==0UL ) ) return;

  if( voter_set_cnt( dst->bitmask )==0UL ) {
    fd_memcpy( dst->sig, src->sig, AG_AGGSIG_SIG_SZ );
  } else {
    fd_bls12_381_g2_add_syscall( dst->sig, dst->sig, src->sig, 1 );
  }
  fd_memset( src->sig, 0, AG_AGGSIG_SIG_SZ );
}

void
ag_aggsig_new( ag_aggsig_t *           agg,
               ag_aggsig_sig_t const * sigs,
               ulong const *           indices,
               ulong                   cnt,
               ulong                   nbits ) {
  FD_TEST( cnt>0UL );
  FD_TEST( nbits<=AG_AGGSIG_MAX_SIGNERS );
  ag_aggsig_init( agg, nbits );
  for( ulong i=0UL; i<cnt; i++ ) ag_aggsig_add( agg, indices[i], &sigs[i] );
}

int
ag_aggsig_verify_bytes( ag_aggsig_t const * self,
                        uchar const *       msg,
                        ulong               msg_sz,
                        uchar const *       pk0,
                        ulong               pk_stride,
                        ulong               pk_cnt ) {

  if( FD_UNLIKELY( self->nbits > pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pk0                 ) ) return 0;

  static FD_TL uchar gathered[ AG_AGGSIG_MAX_SIGNERS * AG_AGGSIG_PUBKEY_SZ ];
  ulong k = 0UL;
  for( ulong i=0UL; i<pk_cnt; i++ ) {
    if( FD_LIKELY( voter_set_test( self->bitmask, i ) ) ) {
      fd_memcpy( gathered + k*AG_AGGSIG_PUBKEY_SZ, pk0 + i*pk_stride, AG_AGGSIG_PUBKEY_SZ );
      k++;
    }
  }
  if( FD_UNLIKELY( k==0UL ) ) return 0;

  uchar apk[ AG_AGGSIG_PUBKEY_SZ ];
  if( FD_UNLIKELY( fd_bls12_381_aggregate_pubkey( apk, gathered, k ) ) ) return 0;

  ulong msg_len = msg_sz;
  return fd_bls12_381_batch_verify( msg, &msg_len, apk, self->sig, 1UL )==0;
}

int
ag_aggsig_verify_mixed_bytes( ag_aggsig_t const * agg_base,
                              uchar const *       msg_base,
                              ulong               msg_base_sz,
                              ag_aggsig_t const * agg_fb,
                              uchar const *       msg_fb,
                              ulong               msg_fb_sz,
                              uchar const *       pk0,
                              ulong               pk_stride,
                              ulong               pk_cnt ) {

  if( FD_UNLIKELY( agg_base->nbits>pk_cnt || agg_fb->nbits>pk_cnt ) ) return 0;
  if( FD_UNLIKELY( !pk0                                          ) ) return 0;

  static FD_TL uchar gathered[ AG_AGGSIG_MAX_SIGNERS * AG_AGGSIG_PUBKEY_SZ ];
  uchar apk[ 2*AG_AGGSIG_PUBKEY_SZ ];

  voter_set_t const * masks[2] = { agg_base->bitmask, agg_fb->bitmask };
  ulong cnt[2] = { 0UL, 0UL };
  for( ulong g=0UL; g<2UL; g++ ) {
    ulong k = 0UL;
    for( ulong i=0UL; i<pk_cnt; i++ ) {
      if( voter_set_test( masks[g], i ) ) { fd_memcpy( gathered + k*AG_AGGSIG_PUBKEY_SZ, pk0 + i*pk_stride, AG_AGGSIG_PUBKEY_SZ ); k++; }
    }
    cnt[g] = k;
    if( k && FD_UNLIKELY( fd_bls12_381_aggregate_pubkey( apk + g*AG_AGGSIG_PUBKEY_SZ, gathered, k ) ) ) return 0;
  }

  if( FD_UNLIKELY( cnt[0]==0UL && cnt[1]==0UL ) ) return 0;
  if( cnt[1]==0UL ) { ulong ml = msg_base_sz; return fd_bls12_381_batch_verify( msg_base, &ml, apk,                       agg_base->sig, 1UL )==0; }
  if( cnt[0]==0UL ) { ulong ml = msg_fb_sz;   return fd_bls12_381_batch_verify( msg_fb,   &ml, apk+AG_AGGSIG_PUBKEY_SZ,  agg_base->sig, 1UL )==0; }

  blst_p2        z[1];    fd_memset( z, 0, sizeof(blst_p2) );
  blst_p2_affine zaff[1]; blst_p2_to_affine( zaff, z );
  uchar sigs[ 2*AG_AGGSIG_SIG_SZ ];
  fd_memcpy( sigs, agg_base->sig, AG_AGGSIG_SIG_SZ );
  blst_p2_affine_serialize( sigs + AG_AGGSIG_SIG_SZ, zaff );

  uchar mbuf[ 256 ];
  FD_TEST( msg_base_sz + msg_fb_sz <= sizeof(mbuf) );
  fd_memcpy( mbuf,             msg_base, msg_base_sz );
  fd_memcpy( mbuf+msg_base_sz, msg_fb,   msg_fb_sz   );
  ulong mlens[2] = { msg_base_sz, msg_fb_sz };

  return fd_bls12_381_batch_verify( mbuf, mlens, apk, sigs, 2UL )==0;
}

ulong
ag_aggsig_serialize( ag_aggsig_t const * agg,
                     uchar *             out,
                     ulong               out_max ) {
  ulong num_words = AG_AGGSIG_WORDS_FOR_BITS( agg->nbits );
  ulong sz        = AG_AGGSIG_SERIALIZED_SZ( agg->nbits );
  if( FD_UNLIKELY( out_max<sz ) ) return 0UL;

  ulong o = 0UL;
  fd_memcpy( out+o, agg->sig, AG_AGGSIG_SIG_SZ ); o += AG_AGGSIG_SIG_SZ;
  FD_STORE( ulong, out+o, agg->nbits  ); o += 8UL;
  FD_STORE( ulong, out+o, num_words   ); o += 8UL;
  for( ulong w=0UL; w<num_words; w++ ) {
    FD_STORE( ulong, out+o, (ulong)agg->bitmask[w] ); o += 8UL;
  }
  FD_TEST( o==sz );
  return sz;
}

ulong
ag_aggsig_deserialize( ag_aggsig_t * agg,
                       uchar const * in,
                       ulong         in_sz ) {
  if( FD_UNLIKELY( in_sz < AG_AGGSIG_SIG_SZ + 16UL ) ) return 0UL;

  ulong o = 0UL;
  fd_memcpy( agg->sig, in+o, AG_AGGSIG_SIG_SZ ); o += AG_AGGSIG_SIG_SZ;
  ulong num_bits  = FD_LOAD( ulong, in+o ); o += 8UL;
  ulong num_words = FD_LOAD( ulong, in+o ); o += 8UL;

  if( FD_UNLIKELY( num_words > AG_AGGSIG_WORDS_FOR_BITS( AG_AGGSIG_MAX_SIGNERS ) ) ) return 0UL;
  if( FD_UNLIKELY( num_bits  > num_words*64UL                                   ) ) return 0UL;
  if( FD_UNLIKELY( in_sz < o + num_words*8UL                                    ) ) return 0UL;

  voter_set_null( agg->bitmask );
  agg->nbits = num_bits;
  for( ulong w=0UL; w<num_words; w++ ) {
    agg->bitmask[w] = (voter_set_t)FD_LOAD( ulong, in+o ); o += 8UL;
  }
  return o;
}
