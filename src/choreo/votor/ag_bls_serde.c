#include "ag_bls_serde.h"

FD_STATIC_ASSERT( sizeof(ag_bls_serde_t)==AG_BLS_SIG_SZ+16UL, ag_bls_serde );

ulong
ag_bls_ser( ag_bls_agg_t const * agg,
            uchar                buf[ static AG_BLS_SER_MAX ] ) {
  ulong bits     = fd_ulong_min( AG_BLS_SIGNERS_MAX, signer_set_last( agg->bitmask )+1UL );
  ulong word_cnt = AG_BLS_WORDS_FOR_BITS( bits );
  ulong sz       = AG_BLS_SER_SZ( bits );

  ag_bls_serde_t * out = (ag_bls_serde_t *)buf;

  memcpy( out->signature, agg->sig, AG_BLS_SIG_SZ );
  out->bit_cnt  = bits;
  out->word_cnt = word_cnt;

  uchar * p = (uchar *)( out+1 );
  for( ulong w=0UL; w<word_cnt; w++ ) {
    FD_STORE( ulong, p, (ulong)agg->bitmask[w] ); p += 8UL;
  }

  return sz;
}

int
ag_bls_de( ag_bls_agg_t * agg,
           uchar const *  buf,
           ulong          buf_sz ) {
  if( FD_UNLIKELY( buf_sz<sizeof(ag_bls_serde_t) ) ) return AG_BLS_DE_ERR_SZ;

  ag_bls_serde_t const * serde    = (ag_bls_serde_t const *)buf;
  ulong                  bit_cnt  = serde->bit_cnt;
  ulong                  word_cnt = serde->word_cnt;

  if( FD_UNLIKELY( word_cnt>signer_set_word_cnt                 ) ) return AG_BLS_DE_ERR_SZ;
  if( FD_UNLIKELY( bit_cnt >AG_BLS_SIGNERS_MAX                  ) ) return AG_BLS_DE_ERR_SZ;
  if( FD_UNLIKELY( bit_cnt >word_cnt*64UL                       ) ) return AG_BLS_DE_ERR_SZ;
  if( FD_UNLIKELY( buf_sz  !=sizeof(ag_bls_serde_t)+word_cnt*8UL ) ) return AG_BLS_DE_ERR_SZ; /* too few, or trailing bytes */

  memcpy( agg->sig, serde->signature, AG_BLS_SIG_SZ );
  signer_set_null( agg->bitmask );

  uchar const * p = (uchar const *)( serde+1 );
  for( ulong w=0UL; w<word_cnt; w++ ) {
    agg->bitmask[w] = (signer_set_t)FD_LOAD( ulong, p ); p += 8UL;
  }

  /* aggsig.rs read_bitvec ends with `bitmask.truncate(num_bits)`; drop any
     bit the sender set above the declared count so the set stays valid and
     signer_cnt/signers() cannot report a rank >= bits. */
  ulong tail = bit_cnt & 63UL;
  ulong last = bit_cnt >> 6;
  if( tail ) agg->bitmask[ last ] &= (signer_set_t)( (1UL<<tail)-1UL );
  for( ulong w=(tail ? last+1UL : last); w<word_cnt; w++ ) agg->bitmask[ w ] = (signer_set_t)0UL;

  return AG_BLS_DE_SUCCESS;
}
