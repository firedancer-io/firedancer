#include "fd_aggsig.h"

/* Public keys are uncompressed affine G1 (96 bytes), signatures
   uncompressed affine G2 (192 bytes), secret keys are little-endian
   32-byte scalars. */

#if FD_HAS_BLST

#include "../../ballet/bls/fd_bls12_381.h"
#include <blst.h>

/* MUST match FD_BLS_SIG_DOMAIN_SIG in src/ballet/bls/fd_bls12_381.c, the
   ciphersuite fd_bls12_381_batch_verify hashes with. */
#define FD_AGGSIG_DST     "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define FD_AGGSIG_DST_SZ  (sizeof(FD_AGGSIG_DST)-1UL)

void
fd_aggsig_sk_to_pk( fd_aggsig_pk_t *       pk,
                    fd_aggsig_sk_t const * sk ) {
  blst_scalar    scalar[1];
  blst_p1        p[1];
  blst_p1_affine a[1];
  blst_scalar_from_lendian( scalar, sk->v ); /* sk is a little-endian scalar */
  blst_sk_to_pk_in_g1( p, scalar );
  blst_p1_to_affine( a, p );
  blst_p1_affine_serialize( pk->v, a );      /* 96B uncompressed affine G1 */
}

void
fd_aggsig_sign_bytes( fd_aggsig_sig_t *      sig,
                      fd_aggsig_sk_t const * sk,
                      uchar const *          msg,
                      ulong                  msg_sz ) {
  blst_scalar    scalar[1];
  blst_p2        hash[1];
  blst_p2        s[1];
  blst_p2_affine a[1];
  blst_scalar_from_lendian( scalar, sk->v );
  blst_hash_to_g2( hash, msg, msg_sz, (uchar const *)FD_AGGSIG_DST, FD_AGGSIG_DST_SZ, NULL, 0UL );
  blst_sign_pk_in_g1( s, hash, scalar );
  blst_p2_to_affine( a, s );
  blst_p2_affine_serialize( sig->v, a );     /* 192B uncompressed affine G2 */
}

int
fd_aggsig_individual_verify_bytes( fd_aggsig_sig_t const * sig,
                                   fd_aggsig_pk_t const *  pk,
                                   uchar const *           msg,
                                   ulong                   msg_sz ) {
  ulong msg_len = msg_sz;
  return fd_bls12_381_batch_verify( msg, &msg_len, pk->v, sig->v, 1UL )==0;
}

#else

/* stub_fill produces a deterministic point-sized blob from a key and a
   message.  Not cryptographically meaningful — only deterministic so that
   serialize/round-trip tests are stable. */

static void
stub_fill( uchar         out[ FD_AGGSIG_SIG_SZ ],
           uchar const   key[ FD_AGGSIG_SECKEY_SZ ],
           uchar const * msg,
           ulong         msg_sz ) {
  ulong acc = 0x9e3779b97f4a7c15UL;
  for( ulong i=0UL; i<FD_AGGSIG_SECKEY_SZ; i++ ) acc = acc*1099511628211UL ^ (ulong)key[i];
  for( ulong i=0UL; i<msg_sz;              i++ ) acc = acc*1099511628211UL ^ (ulong)msg[i];
  acc ^= msg_sz;
  for( ulong i=0UL; i<FD_AGGSIG_SIG_SZ; i++ ) {
    acc = acc*6364136223846793005UL + 1442695040888963407UL;
    out[i] = (uchar)( acc >> 56 );
  }
}

void
fd_aggsig_sk_to_pk( fd_aggsig_pk_t *       pk,
                    fd_aggsig_sk_t const * sk ) {
  fd_memset( pk->v, 0, FD_AGGSIG_PUBKEY_SZ );
  stub_fill( pk->v, sk->v, (uchar const *)"pk", 2UL );
}

void
fd_aggsig_sign_bytes( fd_aggsig_sig_t *      sig,
                      fd_aggsig_sk_t const * sk,
                      uchar const *          msg,
                      ulong                  msg_sz ) {
  stub_fill( sig->v, sk->v, msg, msg_sz );
}

int
fd_aggsig_individual_verify_bytes( fd_aggsig_sig_t const * sig,
                                   fd_aggsig_pk_t const *  pk,
                                   uchar const *           msg,
                                   ulong                   msg_sz ) {
  (void)sig; (void)pk; (void)msg; (void)msg_sz;
  return 1; /* STUB: accept */
}

#endif /* end stubs */

void
fd_aggsig_init( fd_aggsig_t * agg,
                ulong         nbits ) {
  FD_TEST( nbits<=FD_AGGSIG_MAX_SIGNERS );
  fd_memset( agg->sig, 0, FD_AGGSIG_SIG_SZ );
  agg->nbits = nbits;
  signer_set_null( agg->bitmask );
}

void
fd_aggsig_add( fd_aggsig_t *           agg,
               ulong                   signer_idx,
               fd_aggsig_sig_t const * sig ) {
  FD_TEST( signer_idx<agg->nbits );
  FD_TEST( !signer_set_test( agg->bitmask, signer_idx ) ); /* no duplicate signer */

  int first = ( signer_set_cnt( agg->bitmask )==0UL );
  signer_set_insert( agg->bitmask, signer_idx );

  if( FD_UNLIKELY( first ) ) {
    /* aggregate identity + p == p */
    fd_memcpy( agg->sig, sig->v, FD_AGGSIG_SIG_SZ );
    return;
  }

#if FD_HAS_BLST
  /* aggregate signature = sum of the individual G2 signature points
     (big-endian: standard BLS12-381 serialization) */
  fd_bls12_381_g2_add_syscall( agg->sig, agg->sig, sig->v, 1 );
#else
  for( ulong i=0UL; i<FD_AGGSIG_SIG_SZ; i++ ) agg->sig[i] = (uchar)( agg->sig[i] ^ sig->v[i] );
#endif
}

void
fd_aggsig_new( fd_aggsig_t *           agg,
               fd_aggsig_sig_t const * sigs,
               ulong const *           indices,
               ulong                   cnt,
               ulong                   nbits ) {
  FD_TEST( cnt>0UL );                  /* sigs and indices must not be empty */
  FD_TEST( nbits<=FD_AGGSIG_MAX_SIGNERS );
  fd_aggsig_init( agg, nbits );
  for( ulong i=0UL; i<cnt; i++ ) fd_aggsig_add( agg, indices[i], &sigs[i] );
}

int
fd_aggsig_verify_bytes( fd_aggsig_t const *    agg,
                        uchar const *          msg,
                        ulong                  msg_sz,
                        fd_aggsig_pk_t const * pks,
                        ulong                  pk_cnt ) {
  /* number bits must be less than or equal to the total number of public keys */
  if( FD_UNLIKELY( agg->nbits > pk_cnt ) ) return 0;

#if FD_HAS_BLST
  if( FD_UNLIKELY( !pks ) ) return 0;

  /* Gather the signers' G1 pubkeys (the sparse subset selected by the
     bitmask) into a contiguous buffer for aggregation.  pks are assumed
     PoP-verified */
  static FD_TL uchar gathered[ FD_AGGSIG_MAX_SIGNERS * FD_AGGSIG_PUBKEY_SZ ];
  ulong k = 0UL;
  for( ulong i=0UL; i<pk_cnt; i++ ) {
    if( FD_LIKELY( signer_set_test( agg->bitmask, i ) ) ) {
      fd_memcpy( gathered + k*FD_AGGSIG_PUBKEY_SZ, pks[i].v, FD_AGGSIG_PUBKEY_SZ );
      k++;
    }
  }
  if( FD_UNLIKELY( k==0UL ) ) return 0; /* empty signer set never verifies */

  /* apk = sum of the signer pubkeys (single 96B affine G1). */
  uchar apk[ FD_AGGSIG_PUBKEY_SZ ];
  if( FD_UNLIKELY( fd_bls12_381_aggregate_pubkey( apk, gathered, k ) ) ) return 0;

  /* fast-aggregate-verify: one triple (msg, apk, agg->sig).  batch_verify
     hashes msg->G2 and runs the pairing; agg->sig is the 192B uncompressed
     G2 aggregate signature. */
  ulong msg_len = msg_sz;
  return fd_bls12_381_batch_verify( msg, &msg_len, apk, agg->sig, 1UL )==0;
#else
  (void)msg; (void)msg_sz; (void)pks;
  return 1; /* STUB: accept */
#endif
}

int
fd_aggsig_verify_mixed_bytes( fd_aggsig_t const *    agg_base,
                              uchar const *          msg_base,
                              ulong                  msg_base_sz,
                              fd_aggsig_t const *    agg_fb,
                              uchar const *          msg_fb,
                              ulong                  msg_fb_sz,
                              fd_aggsig_pk_t const * pks,
                              ulong                  pk_cnt ) {
  /* Mixed cert: ONE aggregate signature (canonically in agg_base->sig) over up
     to TWO disjoint signer sets that signed two different messages --
     agg_base->bitmask signed msg_base, agg_fb->bitmask signed msg_fb.  When
     both sets are non-empty this is a distinct-message aggregate verify:
       e(g1, sig) == e(apk_base, H(msg_base)) * e(apk_fb, H(msg_fb)).
     A mixed cert may legitimately carry only one of the two sets (e.g. a
     NotarizeFallback built purely from notar votes, or a Skip purely from skip
     votes), in which case the single sig is just the aggregate over that one
     set and we degenerate to a plain aggregate verify of its message.  agg_fb's
     own sig bytes are never read -- the one wire sig always lives in agg_base. */
  if( FD_UNLIKELY( agg_base->nbits>pk_cnt || agg_fb->nbits>pk_cnt ) ) return 0;

#if FD_HAS_BLST
  if( FD_UNLIKELY( !pks ) ) return 0;

  static FD_TL uchar gathered[ FD_AGGSIG_MAX_SIGNERS * FD_AGGSIG_PUBKEY_SZ ];
  uchar apk[ 2*FD_AGGSIG_PUBKEY_SZ ]; /* [apk_base | apk_fb] */

  /* aggregate each signer set's pubkeys; remember how many keys each had */
  signer_set_t const * masks[2] = { agg_base->bitmask, agg_fb->bitmask };
  ulong cnt[2] = { 0UL, 0UL };
  for( ulong g=0UL; g<2UL; g++ ) {
    ulong k = 0UL;
    for( ulong i=0UL; i<pk_cnt; i++ ) {
      if( signer_set_test( masks[g], i ) ) { fd_memcpy( gathered + k*FD_AGGSIG_PUBKEY_SZ, pks[i].v, FD_AGGSIG_PUBKEY_SZ ); k++; }
    }
    cnt[g] = k;
    if( k && FD_UNLIKELY( fd_bls12_381_aggregate_pubkey( apk + g*FD_AGGSIG_PUBKEY_SZ, gathered, k ) ) ) return 0;
  }

  /* Degenerate cases: an empty signer set contributes nothing.  Verify the one
     non-empty set's aggregate sig against its message (single-pairing). */
  if( FD_UNLIKELY( cnt[0]==0UL && cnt[1]==0UL ) ) return 0; /* nobody signed */
  if( cnt[1]==0UL ) { ulong ml = msg_base_sz; return fd_bls12_381_batch_verify( msg_base, &ml, apk,                       agg_base->sig, 1UL )==0; }
  if( cnt[0]==0UL ) { ulong ml = msg_fb_sz;   return fd_bls12_381_batch_verify( msg_fb,   &ml, apk+FD_AGGSIG_PUBKEY_SZ,  agg_base->sig, 1UL )==0; }

  /* batch_verify sums the input sigs, so pass the single aggregate sig plus the
     G2 identity (point at infinity) as the second "signature" -> sum == sig. */
  blst_p2        z[1];    fd_memset( z, 0, sizeof(blst_p2) ); /* projective infinity (Z==0) */
  blst_p2_affine zaff[1]; blst_p2_to_affine( zaff, z );
  uchar sigs[ 2*FD_AGGSIG_SIG_SZ ];
  fd_memcpy( sigs, agg_base->sig, FD_AGGSIG_SIG_SZ );
  blst_p2_affine_serialize( sigs + FD_AGGSIG_SIG_SZ, zaff );

  uchar mbuf[ 256 ];
  FD_TEST( msg_base_sz + msg_fb_sz <= sizeof(mbuf) );
  fd_memcpy( mbuf,             msg_base, msg_base_sz );
  fd_memcpy( mbuf+msg_base_sz, msg_fb,   msg_fb_sz   );
  ulong mlens[2] = { msg_base_sz, msg_fb_sz };

  return fd_bls12_381_batch_verify( mbuf, mlens, apk, sigs, 2UL )==0;
#else
  (void)agg_base; (void)msg_base; (void)msg_base_sz;
  (void)agg_fb;   (void)msg_fb;   (void)msg_fb_sz;   (void)pks;
  return 1; /* STUB: accept */
#endif
}

ulong
fd_aggsig_serialize( fd_aggsig_t const * agg,
                     uchar *             out,
                     ulong               out_max ) {
  ulong num_words = FD_AGGSIG_WORDS_FOR_BITS( agg->nbits );
  ulong sz        = FD_AGGSIG_SERIALIZED_SZ( agg->nbits );
  if( FD_UNLIKELY( out_max<sz ) ) return 0UL;

  ulong o = 0UL;
  fd_memcpy( out+o, agg->sig, FD_AGGSIG_SIG_SZ ); o += FD_AGGSIG_SIG_SZ;
  FD_STORE( ulong, out+o, agg->nbits  ); o += 8UL; /* num_bits  (usize LE) */
  FD_STORE( ulong, out+o, num_words   ); o += 8UL; /* num_words (Vec<usize> len prefix) */
  for( ulong w=0UL; w<num_words; w++ ) {
    FD_STORE( ulong, out+o, (ulong)agg->bitmask[w] ); o += 8UL;
  }
  FD_TEST( o==sz );
  return sz;
}

ulong
fd_aggsig_deserialize( fd_aggsig_t * agg,
                       uchar const * in,
                       ulong         in_sz ) {
  if( FD_UNLIKELY( in_sz < FD_AGGSIG_SIG_SZ + 16UL ) ) return 0UL;

  ulong o = 0UL;
  fd_memcpy( agg->sig, in+o, FD_AGGSIG_SIG_SZ ); o += FD_AGGSIG_SIG_SZ;
  ulong num_bits  = FD_LOAD( ulong, in+o ); o += 8UL;
  ulong num_words = FD_LOAD( ulong, in+o ); o += 8UL;

  /* Reject bitmasks longer than MAX_SIGNERS, and num_bits exceeding the words
     provided (mirrors read_bitvec validation). */
  if( FD_UNLIKELY( num_words > FD_AGGSIG_WORDS_FOR_BITS( FD_AGGSIG_MAX_SIGNERS ) ) ) return 0UL;
  if( FD_UNLIKELY( num_bits  > num_words*64UL                                   ) ) return 0UL;
  if( FD_UNLIKELY( in_sz < o + num_words*8UL                                    ) ) return 0UL;

  signer_set_null( agg->bitmask );
  agg->nbits = num_bits;
  for( ulong w=0UL; w<num_words; w++ ) {
    agg->bitmask[w] = (signer_set_t)FD_LOAD( ulong, in+o ); o += 8UL;
  }
  return o;
}
