#include "fd_tower_serde.h"
#include "fd_tower.h"

#define SHORTVEC 0

#define SER( T, name ) do {                                                                 \
    if( FD_UNLIKELY( off+sizeof(T)>buf_max ) ) {                                            \
      FD_LOG_WARNING(( "ser %s: overflow (off %lu > buf_max: %lu)", #name, off, buf_max )); \
      return -1;                                                                            \
    }                                                                                       \
    FD_STORE( T, buf+off, serde->name );                                                    \
    off += sizeof(T);                                                                       \
} while(0)

#define DE( T, name ) do {                                                               \
    if( FD_UNLIKELY( off+sizeof(T)>buf_sz ) ) {                                          \
      FD_LOG_WARNING(( "de %s: overflow (off %lu > buf_sz: %lu)", #name, off, buf_sz )); \
      return -1;                                                                         \
    }                                                                                    \
    serde->name = *(T const *)fd_type_pun_const( buf+off );                              \
    off += sizeof(T);                                                                    \
} while(0)

static ulong
ser_short_u16( uchar * dst, ushort src ) {
  if     ( FD_LIKELY( src < 0x80UL   ) ) { *dst   = (uchar)  src;                                                                                          return 1; }
  else if( FD_LIKELY( src < 0x4000UL ) ) { *dst++ = (uchar)((src&0x7FUL)|0x80UL); *dst++ = (uchar)(  src>>7);                                              return 2; }
  else                                   { *dst++ = (uchar)((src&0x7FUL)|0x80UL); *dst++ = (uchar)(((src>>7)&0x7FUL)|0x80UL); *dst++ = (uchar)(src>>14UL); return 3; }
}

static ulong
ser_var_int( uchar * dst, ulong src ) {
  ulong off = 0;
  while( FD_LIKELY( 1 ) ) {
    if( FD_LIKELY( src < 0x80UL ) ) {
      *(dst) = (uchar)src;
      off   += 1;
      return off;
    }
    *(dst+off) = (uchar)((src&0x7FUL)|0x80UL);
    off       += 1;
    src      >>= 7;
  }
}

static ulong
de_short_u16( ushort * dst, uchar const * src ) {
  if     ( FD_LIKELY( !(0x80U & src[0]) ) ) { *dst = (ushort)src[0];                                                                           return 1; }
  else if( FD_LIKELY( !(0x80U & src[1]) ) ) { *dst = (ushort)((ulong)(src[0]&0x7FUL) + (((ulong)src[1])<<7));                                  return 2; }
  else                                      { *dst = (ushort)((ulong)(src[0]&0x7FUL) + (((ulong)(src[1]&0x7FUL))<<7) + (((ulong)src[2])<<14)); return 3; }
}

static ulong
de_var_int( ulong * dst, uchar const * src ) {
  *dst = 0;
  ulong off = 0;
  ulong bit = 0;
  while( FD_LIKELY( bit < 64 ) ) {
    uchar byte = *(uchar const *)(src+off);
    off       += 1;
    *dst      |= (byte & 0x7FUL) << bit;
    if( FD_LIKELY( (byte & 0x80U) == 0U ) ) {
      if( FD_UNLIKELY( (*dst>>bit) != byte                ) ) FD_LOG_CRIT(( "de_varint" ));
      if( FD_UNLIKELY( byte==0U && (bit!=0U || *dst!=0UL) ) ) FD_LOG_CRIT(( "de_varint" ));
      return off;
    }
    bit += 7;
  }
  FD_LOG_CRIT(( "de_varint" ));
}

// fd_tower_sync_serde_t *
// fd_tower_sync_to( fd_tower_sync_serde_t * serde, uchar * buf, ulong buf_max, ulong * buf_sz ) {
//   ser->root         = &root;
//   ser->lockouts_cnt = (ushort)fd_tower_votes_cnt( tower );
//   ushort i          = 0;
//   ulong  prev       = root;
//   for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init( tower );
//                                    !fd_tower_votes_iter_done( tower, iter );
//                              iter = fd_tower_votes_iter_next( tower, iter ) ) {
//     fd_tower_vote_t const * vote        = fd_tower_votes_iter_ele_const( tower, iter );
//     ser->lockouts[i].offset             = vote->slot - prev;
//     ser->lockouts[i].confirmation_count = (uchar const *)fd_type_pun_const( &vote->conf );
//     i++;
//   }
//   ser->hash              = bank_hash;
//   ser->timestamp_option  = &option_some;
//   ser->timestamp         = &ts;
//   ser->block_id          = block_id;
//   return ser;
// }

int
fd_tower_sync_serialize( fd_tower_sync_serde_t * serde,
                         uchar *                 buf,
                         ulong                   buf_max,
                         ulong *                 buf_sz ) {
  ulong off = 0;
  SER( ulong, root );
  off += ser_short_u16( buf+off, serde->lockouts_cnt );
  if( FD_UNLIKELY( serde->lockouts_cnt > FD_TOWER_VOTE_MAX ) ) {
    FD_LOG_WARNING(( "lockouts_cnt > 31: %u", serde->lockouts_cnt ));
    return -1;
  }
  for( ulong i = 0; i < fd_ulong_min( serde->lockouts_cnt, 31 ); i++ ) {
    off += ser_var_int( buf+off, serde->lockouts[i].offset );
    SER( uchar, lockouts[i].confirmation_count );
  }
  SER( fd_hash_t, hash             );
  SER( uchar,     timestamp_option );
  if( FD_LIKELY( serde->timestamp_option ) ) {
    SER( long, timestamp );
  }
  SER( fd_hash_t, block_id );
  *buf_sz = off;
  return 0;
}

int
fd_tower_sync_deserialize( fd_tower_sync_serde_t * serde,
                           uchar const *           buf,
                           ulong                   buf_sz ) {
  ulong off = 0;
  DE( ulong, root );
  off += de_short_u16( &serde->lockouts_cnt, buf+off );
  if( FD_UNLIKELY( serde->lockouts_cnt > FD_TOWER_VOTE_MAX ) ) {
    FD_LOG_WARNING(( "lockouts_cnt > 31: %u", serde->lockouts_cnt ));
    return -1;
  }
  for( ulong i = 0; i < fd_ulong_min( serde->lockouts_cnt, 31 ); i++ ) {
    off += de_var_int( &serde->lockouts[i].offset, buf+off );
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
