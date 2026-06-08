#include "fd_aggsig.h"

/* See fd_aggsig.h.  This is the STUB implementation: the signer-bitmask and
   wire-format logic is real and faithful to alpenglow/src/crypto/aggsig.rs;
   the cryptographic sign/verify operations are placeholders pending real BLS
   support in src/ballet/bls. */

/* stub_fill produces a deterministic 96-byte "signature" from a 32-byte key
   and a message.  Not cryptographically meaningful — only deterministic so
   that serialize/round-trip tests are stable. */

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
  /* STUB: deterministic, not a real sk->pk map.  PUBKEY_SZ==SIG_SZ==96. */
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

/* agg_fold xors a signature into the aggregate point, giving a deterministic
   (non-cryptographic) combine for the stub. */

static inline void
agg_fold( fd_aggsig_t *           agg,
          fd_aggsig_sig_t const * sig ) {
  for( ulong i=0UL; i<FD_AGGSIG_SIG_SZ; i++ ) agg->sig[i] = (uchar)( agg->sig[i] ^ sig->v[i] );
}

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
  signer_set_insert( agg->bitmask, signer_idx );
  agg_fold( agg, sig );
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
  (void)msg; (void)msg_sz; (void)pks;
  /* Mirrors AggregateSignature::verify_bytes: bitmask length must equal the
     number of provided public keys. */
  if( FD_UNLIKELY( agg->nbits!=pk_cnt ) ) return 0;
  return 1; /* STUB: accept */
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
