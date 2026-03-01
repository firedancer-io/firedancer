#include "fd_tower_serdes.h"
#include "fd_tower.h"

#define SHORTVEC 0

#define DE( T, name ) do {                                  \
    if( FD_UNLIKELY( off+sizeof(T)>buf_sz ) ) return -1;    \
    serde->name = *(T const *)fd_type_pun_const( buf+off ); \
    off += sizeof(T);                                       \
} while(0)

#define SER( T, name ) do {                              \
    if( FD_UNLIKELY( off+sizeof(T)>buf_sz ) ) return -1; \
    FD_STORE( T, buf+off, serde->name );                 \
    off += sizeof(T);                                    \
} while(0)

static ulong
de_short_u16( ushort * dst, uchar const * src ) {
  if     ( FD_LIKELY( !(0x80U & src[0]) ) ) { *dst = (ushort)src[0];                                                                           return 1; }
  else if( FD_LIKELY( !(0x80U & src[1]) ) ) { *dst = (ushort)((ulong)(src[0]&0x7FUL) + (((ulong)src[1])<<7));                                  return 2; }
  else                                      { *dst = (ushort)((ulong)(src[0]&0x7FUL) + (((ulong)(src[1]&0x7FUL))<<7) + (((ulong)src[2])<<14)); return 3; }
}

static ulong
de_var_int( ulong *       dst,
            uchar const * src,
            ulong         src_sz ) {
  *dst = 0;
  ulong off = 0;
  ulong bit = 0;
  while( FD_LIKELY( bit < 64 ) ) {
    if( FD_UNLIKELY( off >= src_sz ) ) return 0;
    uchar byte = *(uchar const *)(src+off);
    off       += 1;
    *dst      |= (byte & 0x7FUL) << bit;
    if( FD_LIKELY( (byte & 0x80U) == 0U ) ) {
      if( FD_UNLIKELY( (*dst>>bit) != byte                ) ) return 0;
      if( FD_UNLIKELY( byte==0U && (bit!=0U || *dst!=0UL) ) ) return 0;
      return off;
    }
    bit += 7;
  }
  return 0;
}

static ulong
ser_short_u16( uchar * dst, ushort val ) {
  if     ( FD_LIKELY( val < 0x80U ) ) {
    dst[0] = (uchar)val;
    return 1;
  }
  else if( FD_LIKELY( val < 0x4000U ) ) {
    dst[0] = (uchar)((val & 0x7FUL) | 0x80U);
    dst[1] = (uchar)(val >> 7);
    return 2;
  }
  else {
    dst[0] = (uchar)((val & 0x7FUL) | 0x80U);
    dst[1] = (uchar)(((val >> 7) & 0x7FUL) | 0x80U);
    dst[2] = (uchar)(val >> 14);
    return 3;
  }
}

static ulong
ser_var_int( uchar * dst, ulong val ) {
  ulong off = 0;
  while( FD_LIKELY( val >= 0x80UL ) ) {
    dst[off] = (uchar)((val & 0x7FUL) | 0x80U);
    val >>= 7;
    off  += 1;
  }
  dst[off] = (uchar)val;
  return off + 1;
}

int
fd_compact_tower_sync_de( fd_compact_tower_sync_serde_t * serde,
                          uchar const *                   buf,
                          ulong                           buf_sz ) {
  ulong off = 0;
  DE( ulong, root );
  off += de_short_u16( &serde->lockouts_cnt, buf+off );
  if( FD_UNLIKELY( serde->lockouts_cnt > FD_TOWER_VOTE_MAX ) ) return -1;
  for( ulong i = 0; i < serde->lockouts_cnt; i++ ) {
    ulong varint_sz = de_var_int( &serde->lockouts[i].offset, buf+off, buf_sz-off );
    if( FD_UNLIKELY( !varint_sz ) ) return -1;
    off += varint_sz;
    DE( uchar, lockouts[i].confirmation_count );
  }
  DE( fd_hash_t, hash             );
  DE( uchar,     timestamp_option );
  if( FD_LIKELY( serde->timestamp_option ) ) {
    DE( long, timestamp );
  }
  DE( fd_hash_t, block_id );
  return 0;
}

int
fd_compact_tower_sync_ser( fd_compact_tower_sync_serde_t const * serde,
                           uchar *                               buf,
                           ulong                                 buf_sz,
                           ulong *                               out_sz ) {
  ulong off = 0;
  SER( ulong, root );
  off += ser_short_u16( buf+off, serde->lockouts_cnt );
  if( FD_UNLIKELY( serde->lockouts_cnt > FD_TOWER_VOTE_MAX ) ) return -1;
  for( ulong i = 0; i < serde->lockouts_cnt; i++ ) {
    off += ser_var_int( buf+off, serde->lockouts[i].offset );
    SER( uchar, lockouts[i].confirmation_count );
  }
  SER( fd_hash_t, hash             );
  SER( uchar,     timestamp_option );
  if( FD_LIKELY( serde->timestamp_option ) ) {
    SER( long, timestamp );
  }
  SER( fd_hash_t, block_id );
  if( FD_LIKELY( out_sz ) ) *out_sz = off;
  return 0;
}

static fd_vote_acc_vote_t const *
v4_off( fd_vote_acc_t const * voter ) {
  return (fd_vote_acc_vote_t const *)( voter->v4.bls_pubkey_compressed + voter->v4.has_bls_pubkey_compressed * sizeof(voter->v4.bls_pubkey_compressed) + sizeof(ulong) );
}

ulong
fd_vote_acc_vote_cnt( uchar const * vote_account_data ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_account_data );
  switch( voter->kind ) {
  case FD_VOTE_ACC_V4: return fd_ulong_load_8( voter->v4.bls_pubkey_compressed + voter->v4.has_bls_pubkey_compressed * sizeof(voter->v4.bls_pubkey_compressed) );
  case FD_VOTE_ACC_V3: return voter->v3.votes_cnt;
  case FD_VOTE_ACC_V2: return voter->v2.votes_cnt;
  default:          FD_LOG_HEXDUMP_CRIT(( "bad voter", vote_account_data, 3762 ));
  }
}

/* fd_vote_acc_vote_slot takes a voter's vote account data and returns the
   voter's most recent vote slot in the tower.  Returns ULONG_MAX if
   they have an empty tower. */

ulong
fd_vote_acc_vote_slot( uchar const * vote_account_data ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_account_data );
  ulong              cnt   = fd_vote_acc_vote_cnt( vote_account_data );
  switch( voter->kind ) {
  case FD_VOTE_ACC_V4: return cnt ? v4_off( voter )[cnt-1].slot : ULONG_MAX;
  case FD_VOTE_ACC_V3: return cnt ? voter->v3.votes[cnt-1].slot : ULONG_MAX;
  case FD_VOTE_ACC_V2: return cnt ? voter->v2.votes[cnt-1].slot : ULONG_MAX;
  default:          FD_LOG_HEXDUMP_CRIT(( "bad voter", vote_account_data, 3762 ));
  }
}

/* fd_vote_acc_root_slot takes a voter's vote account data and returns the
   voter's root slot.  Returns ULONG_MAX if they don't have a root. */

ulong
fd_vote_acc_root_slot( uchar const * vote_account_data ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_account_data );
  ulong              cnt   = fd_vote_acc_vote_cnt( vote_account_data );
  switch( voter->kind ) {
  case FD_VOTE_ACC_V4: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&v4_off( voter )[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&v4_off( voter )[cnt] + 1UL ) : ULONG_MAX; }
  case FD_VOTE_ACC_V3: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&voter->v3.votes[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&voter->v3.votes[cnt] + 1UL ) : ULONG_MAX; }
  case FD_VOTE_ACC_V2: { uchar root_option = fd_uchar_load_1_fast( (uchar *)&voter->v2.votes[cnt] ); return root_option ? fd_ulong_load_8_fast( (uchar *)&voter->v2.votes[cnt] + 1UL ) : ULONG_MAX; }
  default:          FD_LOG_CRIT(( "unhandled kind %u", voter->kind ));
  }
}
