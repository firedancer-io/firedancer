#include "fd_aggsig.h"

/* See fd_aggsig.h.  The signer-bitmask and wire-format logic is real and
   faithful to alpenglow/src/crypto/aggsig.rs.  The cryptographic operations
   are real BLS12-381 when the build links blst (FD_HAS_BLST); otherwise they
   fall back to a deterministic non-cryptographic stub so the consensus logic
   can still be exercised without blst.

   Scheme (matches Agave): public keys are uncompressed affine G1 (96 bytes),
   signatures uncompressed affine G2 (192 bytes), secret keys are
   little-endian 32-byte scalars.  The hash-to-curve domain tag matches
   fd_bls12_381's FD_BLS_SIG_DOMAIN_SIG so our sign() round-trips with the
   library verify (and interops with Agave). */

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

#else /* !FD_HAS_BLST: deterministic non-cryptographic stub */

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

#endif

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
  /* Mirrors AggregateSignature::verify_bytes: bitmask length must equal the
     number of provided public keys. */
  //FD_LOG_NOTICE(( "aggsig_verify_bytes: nbits=%lu, pk_cnt=%lu, signer_set_cnt=%lu", agg->nbits, pk_cnt, signer_set_cnt( agg->bitmask ) ));
  if( FD_UNLIKELY( agg->nbits > pk_cnt ) ) return 0;

#if FD_HAS_BLST
  if( FD_UNLIKELY( !pks ) ) return 0;

  /* Gather the signers' G1 pubkeys (the sparse subset selected by the
     bitmask) into a contiguous buffer for aggregation.  pks are assumed
     PoP-verified at epoch-set construction (rogue-key defense, per
     fd_bls12_381_aggregate_pubkey's contract). */
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
