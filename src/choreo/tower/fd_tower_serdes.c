#include "fd_tower_serdes.h"

#define DE( T, name ) do {                                \
    if( FD_UNLIKELY( buf_sz<sizeof(T) ) ) return -1;      \
    serde->name = FD_LOAD( T, buf );                      \
    buf    += sizeof(T);                                  \
    buf_sz -= sizeof(T);                                  \
} while(0)

static int
de_short_u16( ushort * dst, uchar const ** src, ulong * src_sz ) {
  uchar const * s = *src;
  if( FD_UNLIKELY( *src_sz<1 ) ) return -1;
  if( FD_LIKELY( !( 0x80U & s[0] ) ) ) {
    *dst = (ushort)s[0];
    *src += 1;
    *src_sz -= 1;
    return 0;
  }
  if( FD_UNLIKELY( *src_sz<2 ) ) return -1;
  if( FD_LIKELY( !( 0x80U & s[1] ) ) ) {
    if( FD_UNLIKELY( !s[1] ) ) return -1; /* non-canonical: value fits in 1 byte */
    *dst = (ushort)( (ulong)(s[0]&0x7FUL) + (((ulong)s[1])<<7) );
    *src += 2;
    *src_sz -= 2;
    return 0;
  }
  if( FD_UNLIKELY( *src_sz<3    ) ) return -1;
  if( FD_UNLIKELY( 0x80U & s[2] ) ) return -1; /* 3rd byte is final; continuation bit is invalid */
  if( FD_UNLIKELY( !s[2]        ) ) return -1; /* non-canonical: value fits in 2 bytes */
  ulong val = (ulong)(s[0]&0x7FUL) + (((ulong)(s[1]&0x7FUL))<<7) + (((ulong)s[2])<<14);
  if( FD_UNLIKELY( val>USHORT_MAX ) ) return -1;
  *dst = (ushort)val;
  *src += 3;
  *src_sz -= 3;
  return 0;
}

static int
de_var_int( ulong * dst, uchar const ** src, ulong * src_sz ) {
  *dst = 0;
  ulong bit = 0;
  while( FD_LIKELY( bit < 64 ) ) {
    if( FD_UNLIKELY( !*src_sz ) ) return -1;
    uchar byte = **src;
    (*src)++; (*src_sz)--;
    *dst |= (ulong)(byte & 0x7FUL) << bit;
    if( FD_LIKELY( (byte & 0x80U) == 0U ) ) {
      if( FD_UNLIKELY( (*dst>>bit) != byte                ) ) return -1;
      if( FD_UNLIKELY( byte==0U && (bit!=0U || *dst!=0UL) ) ) return -1;
      return 0;
    }
    bit += 7;
  }
  return -1;
}

int
fd_compact_tower_sync_de( fd_compact_tower_sync_serde_t * serde,
                          uchar const *                   buf,
                          ulong                           buf_sz ) {
  DE( ulong, root );
  if( FD_UNLIKELY( de_short_u16( &serde->lockouts_cnt, &buf, &buf_sz ) ) ) return -1;
  if( FD_UNLIKELY( serde->lockouts_cnt > FD_TOWER_VOTE_MAX ) ) return -1;
  for( ulong i = 0; i < serde->lockouts_cnt; i++ ) {
    if( FD_UNLIKELY( de_var_int( &serde->lockouts[i].offset, &buf, &buf_sz ) ) ) return -1;
    DE( uchar, lockouts[i].confirmation_count );
  }
  DE( fd_hash_t, hash             );
  DE( uchar,     timestamp_option );
  if( FD_UNLIKELY( serde->timestamp_option!=1 && serde->timestamp_option!=0 ) ) return -1;
  if( FD_LIKELY( serde->timestamp_option ) ) {
    DE( long, timestamp );
  }
  DE( fd_hash_t, block_id );
  return 0;
}

int
fd_txn_parse_simple_vote( fd_txn_t const *                txn,
                          uchar    const *                payload,
                          fd_compact_tower_sync_serde_t * opt_tower_sync ) {
  fd_txn_instr_t const * instr      = &txn->instr[ 0 ];
  ulong required_accts = txn->signature_cnt==1 ? 2UL : 3UL;
  if( FD_UNLIKELY( !fd_txn_is_simple_vote_transaction( txn, payload ) || instr->data_sz < sizeof(uint) || txn->acct_addr_cnt < required_accts ) ) return 0;

  uchar const *          instr_data = payload + instr->data_off;
  uint                   kind       = fd_uint_load_4_fast( instr_data );
  /* Older vote instruction kinds are deprecated / ignored */
  if( FD_UNLIKELY( kind == FD_VOTE_IX_KIND_TOWER_SYNC || kind == FD_VOTE_IX_KIND_TOWER_SYNC_SWITCH ) ) {
    fd_compact_tower_sync_serde_t compact_tower_sync_serde[ 1 ];
    int err = fd_compact_tower_sync_de( compact_tower_sync_serde, instr_data + sizeof(uint), instr->data_sz - sizeof(uint) );
    if( FD_LIKELY( !err ) ) {
      if( !!opt_tower_sync ) *opt_tower_sync = *compact_tower_sync_serde;
      return 1;
    }
  }
  return 0;
}

#undef DE
