#include "ag_bls_serde.h"

FD_STATIC_ASSERT( sizeof(ag_bls_serde_t)==AG_BLS_SIG_SZ+16UL, ag_bls_serde );

int
ag_bls_ser( ag_bls_agg_t const * agg,
            uchar *              buf,
            ulong                buf_max,
            ulong *              buf_sz ) {
  ulong word_cnt = AG_BLS_WORDS_FOR_BITS( agg->nbits );
  ulong sz       = AG_BLS_SERIALIZED_SZ( agg->nbits );
  if( FD_UNLIKELY( buf_max<sz ) ) return -1;

  ag_bls_serde_t * out = (ag_bls_serde_t *)buf;

  fd_memcpy( out->signature, agg->sig, AG_BLS_SIG_SZ );
  out->bit_cnt  = agg->nbits;
  out->word_cnt = word_cnt;

  uchar * p = (uchar *)( out+1 );
  for( ulong w=0UL; w<word_cnt; w++ ) {
    FD_STORE( ulong, p, (ulong)agg->bitmask[w] ); p += 8UL;
  }

  if( buf_sz ) *buf_sz = sz;
  return 0;
}

ulong
ag_bls_de( ag_bls_agg_t * agg,
           uchar const *  buf,
           ulong          buf_max ) {
  if( FD_UNLIKELY( buf_max<sizeof(ag_bls_serde_t) ) ) return 0UL;

  ag_bls_serde_t const * serde    = (ag_bls_serde_t const *)buf;
  ulong                  bit_cnt  = serde->bit_cnt;
  ulong                  word_cnt = serde->word_cnt;

  if( FD_UNLIKELY( word_cnt>AG_BLS_WORDS_FOR_BITS( AG_BLS_MAX_SIGNERS ) ) ) return 0UL;
  if( FD_UNLIKELY( bit_cnt >AG_BLS_MAX_SIGNERS                          ) ) return 0UL;
  if( FD_UNLIKELY( bit_cnt >word_cnt*64UL                               ) ) return 0UL;
  if( FD_UNLIKELY( buf_max <sizeof(ag_bls_serde_t)+word_cnt*8UL         ) ) return 0UL;

  fd_memcpy( agg->sig, serde->signature, AG_BLS_SIG_SZ );
  voter_set_null( agg->bitmask );
  agg->nbits = bit_cnt;

  uchar const * p = (uchar const *)( serde+1 );
  for( ulong w=0UL; w<word_cnt; w++ ) {
    agg->bitmask[w] = (voter_set_t)FD_LOAD( ulong, p ); p += 8UL;
  }

  /* aggsig.rs read_bitvec ends with `bitmask.truncate(num_bits)`; drop any
     bit the sender set above the declared count so the set stays valid and
     signer_cnt/signers() cannot report a rank >= nbits. */
  ulong tail = bit_cnt & 63UL;
  ulong last = bit_cnt >> 6;
  if( tail ) agg->bitmask[ last ] &= (voter_set_t)( (1UL<<tail)-1UL );
  for( ulong w=(tail ? last+1UL : last); w<word_cnt; w++ ) agg->bitmask[ w ] = (voter_set_t)0UL;

  return sizeof(ag_bls_serde_t) + word_cnt*8UL;
}
