#include "ag_aggsig_serde.h"

FD_STATIC_ASSERT( sizeof(ag_aggsig_serde_t)==AG_AGGSIG_SIG_SZ+16UL, ag_aggsig_serde );

int
ag_aggsig_ser( ag_aggsig_t const * agg,
               uchar *             buf,
               ulong               buf_max,
               ulong *             buf_sz ) {
  ulong word_cnt = AG_AGGSIG_WORDS_FOR_BITS( agg->nbits );
  ulong sz       = AG_AGGSIG_SERIALIZED_SZ( agg->nbits );
  if( FD_UNLIKELY( buf_max<sz ) ) return -1;

  ag_aggsig_serde_t * out = (ag_aggsig_serde_t *)buf;

  fd_memcpy( out->signature.v, agg->sig, AG_AGGSIG_SIG_SZ );
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
ag_aggsig_de( ag_aggsig_t * agg,
              uchar const * buf,
              ulong         buf_max ) {
  if( FD_UNLIKELY( buf_max<sizeof(ag_aggsig_serde_t) ) ) return 0UL;

  ag_aggsig_serde_t const * serde    = (ag_aggsig_serde_t const *)buf;
  ulong                     bit_cnt  = serde->bit_cnt;
  ulong                     word_cnt = serde->word_cnt;

  if( FD_UNLIKELY( word_cnt>AG_AGGSIG_WORDS_FOR_BITS( AG_AGGSIG_MAX_SIGNERS ) ) ) return 0UL;
  if( FD_UNLIKELY( bit_cnt >word_cnt*64UL                                    ) ) return 0UL;
  if( FD_UNLIKELY( buf_max <sizeof(ag_aggsig_serde_t)+word_cnt*8UL           ) ) return 0UL;

  fd_memcpy( agg->sig, serde->signature.v, AG_AGGSIG_SIG_SZ );
  voter_set_null( agg->bitmask );
  agg->nbits = bit_cnt;

  uchar const * p = (uchar const *)( serde+1 );
  for( ulong w=0UL; w<word_cnt; w++ ) {
    agg->bitmask[w] = (voter_set_t)FD_LOAD( ulong, p ); p += 8UL;
  }
  return sizeof(ag_aggsig_serde_t) + word_cnt*8UL;
}
