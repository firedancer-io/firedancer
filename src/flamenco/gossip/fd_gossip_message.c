#include "fd_gossip_message.h"

#include <string.h>

#include "../../ballet/txn/fd_compact_u16.h"
#include "../runtime/fd_system_ids.h"
#include "../types/fd_types.h"

/* https://github.com/anza-xyz/agave/blob/bff4df9cf6f41520a26c9838ee3d4d8c024a96a1/gossip/src/crds_data.rs#L22-L23 */
#define WALLCLOCK_MAX_MILLIS (1000000000000000UL)
#define MAX_SLOT             (1000000000000000UL)

/* https://github.com/anza-xyz/agave/blob/master/gossip/src/epoch_slots.rs#L15 */
#define MAX_SLOTS_PER_EPOCH_SLOT (2048UL*8UL)

#define FD_GOSSIP_VOTE_IDX_MAX (32)
#define FD_GOSSIP_EPOCH_SLOTS_IDX_MAX (255U)
#define FD_GOSSIP_DUPLICATE_SHRED_IDX_MAX (512U)

#define CHECK( cond ) do {               \
  if( FD_UNLIKELY( !(cond) ) ) return 0; \
} while( 0 )

#define READ_BYTES( dst, n, payload, payload_sz ) do { \
  CHECK( (n)<=(*(payload_sz)) );                       \
  fd_memcpy( (dst), *(payload), (n) );                 \
  *(payload) += (n);                                   \
  *(payload_sz) -= (n);                                \
} while( 0 )

#define SKIP_BYTES( n, payload, payload_sz ) do { \
  CHECK( (n)<=(*(payload_sz)) );                  \
  *(payload) += (n);                              \
  *(payload_sz) -= (n);                           \
} while( 0 )

#define READ_OPTION( dst, payload, payload_sz ) do { \
  READ_U8( dst, payload, payload_sz );               \
  CHECK( (dst)==0 || (dst)==1 );                     \
} while( 0 )

#define READ_ENUM( dst, n, payload, payload_sz ) do { \
  CHECK( 4UL<=(*(payload_sz)) );                      \
  (dst) = FD_LOAD( uint, *(payload) );                \
  CHECK( (dst)<n );                                   \
  *(payload) += 4UL;                                  \
  *(payload_sz) -= 4UL;                               \
} while( 0 )

#define READ_U8( dst, payload, payload_sz ) do { \
  CHECK( 1UL<=(*(payload_sz)) );                 \
  (dst) = FD_LOAD( uchar, *(payload) );          \
  *(payload) += 1UL;                             \
  *(payload_sz) -= 1UL;                          \
} while( 0 )

#define READ_U16( dst, payload, payload_sz ) do { \
  CHECK( 2UL<=(*(payload_sz)) );                  \
  (dst) = FD_LOAD( ushort, *(payload) );          \
  *(payload) += 2UL;                              \
  *(payload_sz) -= 2UL;                           \
} while( 0 )

#define READ_U32( dst, payload, payload_sz ) do { \
  CHECK( 4UL<=(*(payload_sz)) );                  \
  (dst) = FD_LOAD( uint, *(payload) );            \
  *(payload) += 4UL;                              \
  *(payload_sz) -= 4UL;                           \
} while( 0 )

#define READ_U64( dst, payload, payload_sz ) do { \
  CHECK( 8UL<=(*(payload_sz)) );                  \
  (dst) = FD_LOAD( ulong, *(payload) );           \
  *(payload) += 8UL;                              \
  *(payload_sz) -= 8UL;                           \
} while( 0 )

#define READ_U16_VARINT( dst, payload, payload_sz ) do {   \
  ulong _sz = fd_cu16_dec_sz( *(payload), *(payload_sz) ); \
  CHECK( _sz );                                            \
  (dst) = fd_cu16_dec_fixed( *(payload), _sz );            \
  *(payload) += _sz;                                       \
  *(payload_sz) -= _sz;                                    \
} while( 0 )

#define READ_U64_VARINT( dst, payload, payload_sz ) do {                       \
  ulong _val = 0UL;                                                            \
  uint  _shift = 0U;                                                           \
  for(;;) {                                                                    \
    CHECK( 1UL<=(*(payload_sz)) );                                             \
    uchar _byte = FD_LOAD( uchar, *(payload) );                                \
    *(payload) += 1UL;                                                         \
    *(payload_sz) -= 1UL;                                                      \
    _val |= (ulong)(_byte & 0x7F) << _shift;                                   \
    if( FD_LIKELY( !(_byte & 0x80) ) ) {                                       \
      CHECK( (_val>>_shift)==(ulong)_byte );     /* last byte not truncated */ \
      CHECK( _byte || !_shift );                 /* no trailing zero bytes */  \
      (dst) = _val;                                                            \
      break;                                                                   \
    }                                                                          \
    _shift += 7U;                                                              \
    CHECK( _shift<64U );                                                       \
  }                                                                            \
} while( 0 )

#define READ_WALLCLOCK( dst, payload, payload_sz ) do { \
  ulong wallclock_millis;                               \
  READ_U64( wallclock_millis, payload, payload_sz );    \
  CHECK( wallclock_millis<WALLCLOCK_MAX_MILLIS );       \
  (dst) = wallclock_millis;                             \
} while( 0 )

static int
deser_legacy_contact_info( fd_gossip_value_t * value,
                           uchar const **      payload,
                           ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  for( ulong i=0UL; i<10UL; i++ ) {
    uint is_ip6 = 0U;
    READ_ENUM( is_ip6, 2UL, payload, payload_sz );
    SKIP_BYTES( is_ip6 ? 16UL+2UL : 4UL+2UL, payload, payload_sz );
  }
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  SKIP_BYTES( 2UL, payload, payload_sz );
  return 1;
}

static int
deser_vote_instruction( uchar const * data,
                        ulong         data_len ) {
  // TODO: NO FD TYPES
  fd_bincode_decode_ctx_t ctx = { .data = data, .dataend = data+data_len };
  ulong total_sz = 0UL;
  CHECK( !fd_vote_instruction_decode_footprint( &ctx, &total_sz ) );
  uchar * buf = fd_alloca_check( alignof(fd_vote_instruction_t), total_sz );
  fd_vote_instruction_t * vote_instruction = fd_vote_instruction_decode( buf, &ctx );
  CHECK( vote_instruction );
  CHECK(
    vote_instruction->discriminant==fd_vote_instruction_enum_vote ||
    vote_instruction->discriminant==fd_vote_instruction_enum_vote_switch ||
    vote_instruction->discriminant==fd_vote_instruction_enum_update_vote_state ||
    vote_instruction->discriminant==fd_vote_instruction_enum_update_vote_state_switch ||
    vote_instruction->discriminant==fd_vote_instruction_enum_compact_update_vote_state  ||
    vote_instruction->discriminant==fd_vote_instruction_enum_compact_update_vote_state_switch  ||
    vote_instruction->discriminant==fd_vote_instruction_enum_tower_sync  ||
    vote_instruction->discriminant==fd_vote_instruction_enum_tower_sync_switch );
  // Oddly, trailing garbage is allowed here at the end of the instruction
  return 1;
}

static int
deser_vote_txn( fd_gossip_vote_t * vote,
                uchar const **     payload,
                ulong *            payload_sz ) {
  uchar const * payload_start = *payload;

  ushort signatures_len;
  READ_U16_VARINT( signatures_len, payload, payload_sz );
  SKIP_BYTES( signatures_len*64UL, payload, payload_sz );
  uchar num_required_signatures, num_readonly_signed_accounts, num_readonly_unsigned_accounts;
  READ_U8( num_required_signatures, payload, payload_sz );
  READ_U8( num_readonly_signed_accounts, payload, payload_sz );
  READ_U8( num_readonly_unsigned_accounts, payload, payload_sz );
  ushort account_keys_len;
  READ_U16_VARINT( account_keys_len, payload, payload_sz );
  uchar const * account_keys = *payload;
  SKIP_BYTES( account_keys_len*32UL, payload, payload_sz );
  SKIP_BYTES( 32UL, payload, payload_sz ); /* recent blockhash */
  ushort instructions_len;
  READ_U16_VARINT( instructions_len, payload, payload_sz );
  for( ulong i=0UL; i<instructions_len; i++ ) {
    uchar program_id_index;
    READ_U8( program_id_index, payload, payload_sz );
    CHECK( program_id_index<account_keys_len );
    CHECK( program_id_index );
    ushort accounts_len;
    READ_U16_VARINT( accounts_len, payload, payload_sz );
    for( ulong j=0UL; j<accounts_len; j++ ) {
      uchar account_index;
      READ_U8( account_index, payload, payload_sz );
      CHECK( account_index<account_keys_len );
    }
    ushort data_len;
    READ_U16_VARINT( data_len, payload, payload_sz );
    uchar data[ 1232UL ];
    READ_BYTES( data, data_len, payload, payload_sz );
    if( FD_LIKELY( i==0UL ) ) {
      CHECK( accounts_len );
      uchar const * account_key = account_keys+32UL*program_id_index;
      CHECK( !memcmp( account_key, fd_solana_vote_program_id.uc, 32UL ) );
      CHECK( deser_vote_instruction( data, data_len ) );
    }
  }

  CHECK( num_required_signatures<=signatures_len );
  CHECK( signatures_len<=account_keys_len );
  CHECK( num_required_signatures+num_readonly_unsigned_accounts<=account_keys_len );
  CHECK( num_readonly_signed_accounts<num_required_signatures );
  CHECK( instructions_len );

  vote->transaction_len = (ulong)(*payload-payload_start);
  fd_memcpy( vote->transaction, payload_start, vote->transaction_len );
  return 1;
}

static int
deser_vote( fd_gossip_value_t * value,
            uchar const **      payload,
            ulong *             payload_sz ) {
  READ_U8( value->vote->index, payload, payload_sz );
  CHECK( value->vote->index<FD_GOSSIP_VOTE_IDX_MAX );
  READ_BYTES( value->origin, 32UL, payload, payload_sz );

  CHECK( deser_vote_txn( value->vote, payload, payload_sz ) );
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  return 1;
}

static int
deser_lowest_slot( fd_gossip_value_t * value,
                   uchar const **      payload,
                   ulong *             payload_sz ) {
  uchar ix;
  READ_U8( ix, payload, payload_sz );
  CHECK( !ix );
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  ulong root;
  READ_U64( root, payload, payload_sz );
  CHECK( !root );
  ulong lowest;
  READ_U64( lowest, payload, payload_sz );
  CHECK( lowest<MAX_SLOT );
  ulong slots_len;
  READ_U64( slots_len, payload, payload_sz );
  CHECK( !slots_len );
  ulong stash_len;
  READ_U64( stash_len, payload, payload_sz );
  CHECK( !stash_len );
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  return 1;
}

static int
deser_legacy_snapshot_hashes( fd_gossip_value_t * value,
                              uchar const **      payload,
                              ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  ulong hashes_len;
  READ_U64( hashes_len, payload, payload_sz );
  for( ulong i=0UL; i<hashes_len; i++ ) {
    ulong slot;
    READ_U64( slot, payload, payload_sz );
    CHECK( slot<MAX_SLOT );
    SKIP_BYTES( 32UL, payload, payload_sz ); /* hash */
  }
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  return 1;
}

static int
deser_account_hashes( fd_gossip_value_t * value,
                    uchar const **      payload,
                    ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  ulong hashes_len;
  READ_U64( hashes_len, payload, payload_sz );
  for( ulong i=0UL; i<hashes_len; i++ ) {
    ulong slot;
    READ_U64( slot, payload, payload_sz );
    CHECK( slot<MAX_SLOT );
    SKIP_BYTES( 32UL, payload, payload_sz ); /* hash */
  }
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  return 1;
}

static int
deser_bitvec_u8_epoch_slots( uchar const ** payload,
                             ulong *        payload_sz ) {
  uchar has_bits;
  READ_OPTION( has_bits, payload, payload_sz );
  if( FD_UNLIKELY( !has_bits ) ) {
    ulong bits_cnt;
    READ_U64( bits_cnt, payload, payload_sz );
    CHECK( !bits_cnt );
    return 1;
  }

  ulong bits_cap;
  READ_U64( bits_cap, payload, payload_sz );
  CHECK( bits_cap );
  SKIP_BYTES( bits_cap, payload, payload_sz );
  ulong bits_cnt;
  READ_U64( bits_cnt, payload, payload_sz );
  CHECK( bits_cnt==bits_cap*8UL );
  return 1;
}

static int
deser_epoch_slots( fd_gossip_value_t * value,
                   uchar const **      payload,
                   ulong *             payload_sz ) {
  READ_U8( value->epoch_slots->index, payload, payload_sz );
  CHECK( value->epoch_slots->index<FD_GOSSIP_EPOCH_SLOTS_IDX_MAX );
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  ulong slots_len;
  READ_U64( slots_len, payload, payload_sz );
  for( ulong i=0UL; i<slots_len; i++ ) {
    uint is_uncompressed;
    READ_ENUM( is_uncompressed, 2UL, payload, payload_sz );
    ulong first_slot;
    READ_U64( first_slot, payload, payload_sz );
    CHECK( first_slot<MAX_SLOT );
    ulong num;
    READ_U64( num, payload, payload_sz );
    CHECK( num<MAX_SLOTS_PER_EPOCH_SLOT );
    if( FD_UNLIKELY( is_uncompressed ) ) {
      CHECK( deser_bitvec_u8_epoch_slots( payload, payload_sz ) );
    } else {
      ulong compressed_len;
      READ_U64( compressed_len, payload, payload_sz );
      SKIP_BYTES( compressed_len, payload, payload_sz );
    }
  }
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  return 1;
}

static int
deser_legacy_version( fd_gossip_value_t * value,
                      uchar const **      payload,
                      ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  SKIP_BYTES( 6UL, payload, payload_sz ); /* major, minor, patch */
  uchar has_commit;
  READ_OPTION( has_commit, payload, payload_sz );
  if( FD_LIKELY( has_commit ) ) SKIP_BYTES( 4UL, payload, payload_sz ); /* commit */
  return 1;
}

static int
deser_version( fd_gossip_value_t * value,
               uchar const **      payload,
               ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  SKIP_BYTES( 6UL, payload, payload_sz ); /* major, minor, patch */
  uchar has_commit;
  READ_OPTION( has_commit, payload, payload_sz );
  if( FD_LIKELY( has_commit ) ) SKIP_BYTES( 4UL, payload, payload_sz ); /* commit */
  SKIP_BYTES( 4UL, payload, payload_sz ); /* feature set */
  return 1;
}

static int
deser_node_instance( fd_gossip_value_t * value,
                     uchar const **      payload,
                     ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  READ_U64( value->node_instance->timestamp, payload, payload_sz );
  READ_U64( value->node_instance->token, payload, payload_sz );
  return 1;
}

static int
deser_duplicate_shred( fd_gossip_value_t * value,
                       uchar const **      payload,
                       ulong *             payload_sz ) {
  READ_U16( value->duplicate_shred->index, payload, payload_sz );
  CHECK( value->duplicate_shred->index<FD_GOSSIP_DUPLICATE_SHRED_IDX_MAX );
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  READ_U64( value->duplicate_shred->slot, payload, payload_sz );
  SKIP_BYTES( 5UL, payload, payload_sz ); /* (unused) + shred type (unused) */
  READ_U8( value->duplicate_shred->num_chunks, payload, payload_sz );
  READ_U8( value->duplicate_shred->chunk_index, payload, payload_sz );
  CHECK( value->duplicate_shred->chunk_index<value->duplicate_shred->num_chunks );
  READ_U64( value->duplicate_shred->chunk_len, payload, payload_sz );
  READ_BYTES( value->duplicate_shred->chunk, value->duplicate_shred->chunk_len, payload, payload_sz );
  return 1;
}

static int
deser_snapshot_hashes( fd_gossip_value_t * value,
                       uchar const **      payload,
                       ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  READ_U64( value->snapshot_hashes->full_slot, payload, payload_sz );
  CHECK( value->snapshot_hashes->full_slot<MAX_SLOT );
  READ_BYTES( value->snapshot_hashes->full_hash, 32UL, payload, payload_sz );
  READ_U64( value->snapshot_hashes->incremental_len, payload, payload_sz );
  for( ulong i=0UL; i<value->snapshot_hashes->incremental_len; i++ ) {
    READ_U64( value->snapshot_hashes->incremental[ i ].slot, payload, payload_sz );
    CHECK( value->snapshot_hashes->incremental[ i ].slot<MAX_SLOT );
    CHECK( value->snapshot_hashes->incremental[ i ].slot>value->snapshot_hashes->full_slot );
    READ_BYTES( value->snapshot_hashes->incremental[ i ].hash, 32UL, payload, payload_sz );
  }
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  return 1;
}

static int
deser_contact_info( fd_gossip_value_t * value,
                    uchar const **      payload,
                    ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  READ_U64_VARINT( value->wallclock, payload, payload_sz );
  CHECK( value->wallclock<WALLCLOCK_MAX_MILLIS );
  READ_U64( value->contact_info->outset, payload, payload_sz );
  READ_U16( value->contact_info->shred_version, payload, payload_sz );
  READ_U16_VARINT( value->contact_info->version.major, payload, payload_sz );
  READ_U16_VARINT( value->contact_info->version.minor, payload, payload_sz );
  READ_U16_VARINT( value->contact_info->version.patch, payload, payload_sz );
  READ_U32( value->contact_info->version.commit, payload, payload_sz );
  READ_U32( value->contact_info->version.feature_set, payload, payload_sz );
  READ_U16_VARINT( value->contact_info->version.client, payload, payload_sz );

  /* Tightest bounds for array sizes given network constraints.

     IPv6 minimum MTU             = 1280
     IPv6 header                  =   40
     UDP header                   =    8
     PACKET_DATA_SIZE             = 1232   (= 1280 - 40 - 8)

     Bytes consumed before addrs loop:
       Protocol tag(4) + from(32) + values_len(8) + signature(64) +
       CrdsData tag(4) + origin(32) + wallclock_varint(1) + outset(8) +
       shred_version(2) + major(1) + minor(1) + patch(1) + commit(4) +
       feature_set(4) + client(1) + addrs_len_varint(1)             = 168

     Remaining: 1232 - 168 = 1064
     Each addr: READ_ENUM(4) + READ_U32(4) = 8 bytes minimum
     Max addrs = floor(1064/8) = 133

     Bytes consumed before sockets loop:
       (same as above) + sockets_len_varint(1)                     = 169

     Remaining: 1232 - 169 = 1063
     Each socket: READ_U8(1) + READ_U8(1) + READ_U16_VARINT(1) = 3 bytes minimum
     Max sockets = floor(1063/3) = 354  */

#define FD_GOSSIP_CONTACT_INFO_MAX_ADDRESSES (133UL)
#define FD_GOSSIP_CONTACT_INFO_MAX_SOCKETS   (354UL)

  uint is_ip6[ FD_GOSSIP_CONTACT_INFO_MAX_ADDRESSES ];
  union {
    uint ip4;
    uchar ip6[ 16UL ];
  } ips[ FD_GOSSIP_CONTACT_INFO_MAX_ADDRESSES ];

  ulong addrs_len;
  READ_U16_VARINT( addrs_len, payload, payload_sz );
  for( ulong i=0UL; i<addrs_len; i++ ) {
    READ_ENUM( is_ip6[ i ], 2UL, payload, payload_sz );
    if( !is_ip6[ i ] ) READ_U32( ips[ i ].ip4, payload, payload_sz );
    else               READ_BYTES( ips[ i ].ip6, 16UL, payload, payload_sz );
  }

  struct {
    uchar  key;
    uchar  index;
    ushort offset;
  } sockets[ FD_GOSSIP_CONTACT_INFO_MAX_SOCKETS ];

  ulong sockets_len;
  READ_U16_VARINT( sockets_len, payload, payload_sz );
  for( ulong i=0UL; i<sockets_len; i++ ) {
    READ_U8( sockets[ i ].key, payload, payload_sz );
    READ_U8( sockets[ i ].index, payload, payload_sz );
    READ_U16_VARINT( sockets[ i ].offset, payload, payload_sz );
  }

  ulong extensions_len;
  READ_U16_VARINT( extensions_len, payload, payload_sz );
  for( ulong i=0UL; i<extensions_len; i++ ) {
    SKIP_BYTES( 1UL, payload, payload_sz ); /* type */
    ushort bytes_len;
    READ_U16_VARINT( bytes_len, payload, payload_sz );
    SKIP_BYTES( bytes_len, payload, payload_sz );
  }

  /* Duplicate IPs are not allowed */
  for( ulong i=0UL; i<addrs_len; i++ ) {
    for( ulong j=0UL; j<addrs_len; j++ ) {
      if( i==j ) continue;
      if( is_ip6[ i ] != is_ip6[ j ] ) continue;
      if( FD_LIKELY( !is_ip6[ i ] ) ) CHECK( ips[ i ].ip4!=ips[ j ].ip4 );
      else CHECK( memcmp( ips[ i ].ip6, ips[ j ].ip6, 16UL ) );
    }
  }

  /* Each socket must reference unique key */
  int seen_socket_key[ 256UL ] = {0};
  for( ulong i=0UL; i<sockets_len; i++ ) {
    CHECK( !seen_socket_key[ sockets[ i ].key ] );
    seen_socket_key[ sockets[ i ].key ] = 1;
  }

  /* Each IP address must be referenced by at least one socket */
  int seen_ip_addr[ FD_GOSSIP_CONTACT_INFO_MAX_ADDRESSES ] = {0};
  for( ulong i=0UL; i<sockets_len; i++ ) {
    CHECK( sockets[ i ].index<addrs_len );
    seen_ip_addr[ sockets[ i ].index ] = 1;
  }
  for( ulong i=0UL; i<addrs_len; i++ ) CHECK( seen_ip_addr[ i ] );

  /* Port offsets don't overflow */
  ushort cur_port = 0U;
  for( ulong i=0UL; i<sockets_len; i++ ) {
    ushort result;
    CHECK( !__builtin_add_overflow( cur_port, sockets[ i ].offset, &result ) );
    cur_port = result;
  }

  memset( value->contact_info->sockets, 0, sizeof( value->contact_info->sockets ) );

  cur_port = 0U;
  for( ulong i=0UL; i<sockets_len; i++ ) {
    if( FD_LIKELY( sockets[ i ].key<FD_GOSSIP_CONTACT_INFO_SOCKET_CNT ) ) {
      value->contact_info->sockets[ sockets[ i ].key ].is_ipv6 = is_ip6[ sockets[ i ].index ];
      if( FD_LIKELY( !is_ip6[ sockets[ i ].index ] ) ) value->contact_info->sockets[ sockets[ i ].key ].ip4 = ips[ sockets[ i ].index ].ip4;
      else                                             fd_memcpy( value->contact_info->sockets[ sockets[ i ].key ].ip6, ips[ sockets[ i ].index ].ip6, 16UL );

      cur_port = (ushort)(cur_port + sockets[ i ].offset);
      value->contact_info->sockets[ sockets[ i ].key ].port = fd_ushort_bswap( cur_port );
    }
  }
  return 1;
}

static int
deser_bitvec_u8_restart_last_voted_fork_slots( uchar const ** payload,
                                               ulong *        payload_sz ) {
  uchar has_bits;
  READ_OPTION( has_bits, payload, payload_sz );
  if( FD_UNLIKELY( !has_bits ) ) {
    ulong bits_cnt;
    READ_U64( bits_cnt, payload, payload_sz );
    CHECK( !bits_cnt );
    return 1;
  }

  ulong bits_cap;
  READ_U64( bits_cap, payload, payload_sz );
  CHECK( bits_cap );
  SKIP_BYTES( bits_cap, payload, payload_sz );
  ulong bits_cnt;
  READ_U64( bits_cnt, payload, payload_sz );
  CHECK( bits_cnt<=bits_cap*8UL );
  return 1;
}

static int
deser_restart_last_voted_fork_slots( fd_gossip_value_t * value,
                                     uchar const **      payload,
                                     ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  uint is_raw_offsets;
  READ_ENUM( is_raw_offsets, 2UL, payload, payload_sz );
  if( FD_LIKELY( is_raw_offsets ) ) {
    CHECK( deser_bitvec_u8_restart_last_voted_fork_slots( payload, payload_sz ) );
  } else {
    ulong slots_len;
    READ_U64( slots_len, payload, payload_sz );
    for( ulong i=0UL; i<slots_len; i++ ) {
      ushort _slot;
      READ_U16_VARINT( _slot, payload, payload_sz );
      (void)_slot;
    }
  }
  SKIP_BYTES( 8UL+32UL+2UL, payload, payload_sz ); /* last voted slot + last voted hash + shred version */
  return 1;
}

static int
deser_restart_heaviest_fork( fd_gossip_value_t * value,
                             uchar const **      payload,
                             ulong *             payload_sz ) {
  READ_BYTES( value->origin, 32UL, payload, payload_sz );
  READ_WALLCLOCK( value->wallclock, payload, payload_sz );
  SKIP_BYTES( 8UL+32UL+8UL+2UL, payload, payload_sz ); /* last slot + last slot hash + observed stake + shred version */
  return 1;
}

static int
deser_value( fd_gossip_value_t * value,
             uchar const **      payload,
             ulong *             payload_sz ) {
  READ_BYTES( value->signature, 64UL, payload, payload_sz );
  READ_ENUM( value->tag, FD_GOSSIP_VALUE_CNT, payload, payload_sz );

  switch( value->tag ) {
    case FD_GOSSIP_VALUE_LEGACY_CONTACT_INFO:           return deser_legacy_contact_info( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_VOTE:                          return deser_vote( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_LOWEST_SLOT:                   return deser_lowest_slot( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_LEGACY_SNAPSHOT_HASHES:        return deser_legacy_snapshot_hashes( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_ACCOUNT_HASHES:                return deser_account_hashes( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_EPOCH_SLOTS:                   return deser_epoch_slots( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_LEGACY_VERSION:                return deser_legacy_version( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_VERSION:                       return deser_version( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_NODE_INSTANCE:                 return deser_node_instance( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED:               return deser_duplicate_shred( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_SNAPSHOT_HASHES:               return deser_snapshot_hashes( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_CONTACT_INFO:                  return deser_contact_info( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_RESTART_LAST_VOTED_FORK_SLOTS: return deser_restart_last_voted_fork_slots( value, payload, payload_sz );
    case FD_GOSSIP_VALUE_RESTART_HEAVIEST_FORK:         return deser_restart_heaviest_fork( value, payload, payload_sz );
    default: FD_LOG_CRIT(( "impossible" ));
  }
}

static int
deser_bitvec_u64( fd_gossip_bloom_t * bloom,
                  uchar const **      payload,
                  ulong *             payload_sz ) {
  uchar has_bits;
  READ_OPTION( has_bits, payload, payload_sz );
  if( FD_UNLIKELY( !has_bits ) ) {
    bloom->bits_cap = 0UL;
    READ_U64( bloom->bits_len, payload, payload_sz );
    return 0; /* Bloom sanitize rejects empty bits */
  }

  READ_U64( bloom->bits_cap, payload, payload_sz );
  CHECK( bloom->bits_cap );
  ulong dummy;
  CHECK( !__builtin_mul_overflow( bloom->bits_cap, 8UL, &dummy ) );
  READ_BYTES( bloom->bits, bloom->bits_cap*8UL, payload, payload_sz );
  READ_U64( bloom->bits_len, payload, payload_sz );
  CHECK( bloom->bits_len<=bloom->bits_cap*64UL );
  CHECK( bloom->bits_len ); /* Bloom sanitize rejects empty bits */
  return 1;
}

static int
deser_pull_request( fd_gossip_message_t * message,
                    uchar const **        payload,
                    ulong *               payload_sz,
                    ulong                 original_sz ) {
  READ_U64( message->pull_request->crds_filter->filter->keys_len, payload, payload_sz );
  for( ulong i=0UL; i<message->pull_request->crds_filter->filter->keys_len; i++ ) {
    READ_U64( message->pull_request->crds_filter->filter->keys[ i ], payload, payload_sz );
  }

  CHECK( deser_bitvec_u64( message->pull_request->crds_filter->filter, payload, payload_sz ) );

  READ_U64( message->pull_request->crds_filter->filter->num_bits_set, payload, payload_sz );
  READ_U64( message->pull_request->crds_filter->mask, payload, payload_sz );
  READ_U32( message->pull_request->crds_filter->mask_bits, payload, payload_sz );

  message->pull_request->contact_info->offset = original_sz-*payload_sz;
  CHECK( deser_value( message->pull_request->contact_info, payload, payload_sz ) );
  message->pull_request->contact_info->length = original_sz-*payload_sz-message->pull_request->contact_info->offset;
  CHECK( message->pull_request->contact_info->tag==FD_GOSSIP_VALUE_LEGACY_CONTACT_INFO ||
         message->pull_request->contact_info->tag==FD_GOSSIP_VALUE_CONTACT_INFO );
  return 1;
}

static int
deser_pull_response( fd_gossip_message_t * message,
                     uchar const **        payload,
                     ulong *               payload_sz,
                     ulong                 original_sz ) {
  READ_BYTES( message->pull_response->from, 32UL, payload, payload_sz );
  READ_U64( message->pull_response->values_len, payload, payload_sz );
  for( ulong i=0UL; i<message->pull_response->values_len; i++ ) {
    message->pull_response->values[ i ].offset = original_sz-*payload_sz;
    CHECK( deser_value( &message->pull_response->values[ i ], payload, payload_sz ) );
    message->pull_response->values[ i ].length = original_sz-*payload_sz-message->pull_response->values[ i ].offset;
  }
  return 1;
}

static int
deser_push( fd_gossip_message_t * message,
            uchar const **        payload,
            ulong *               payload_sz,
            ulong                 original_sz ) {
  READ_BYTES( message->push->from, 32UL, payload, payload_sz );
  READ_U64( message->push->values_len, payload, payload_sz );
  for( ulong i=0UL; i<message->push->values_len; i++ ) {
    message->push->values[ i ].offset = original_sz-*payload_sz;
    CHECK( deser_value( &message->push->values[ i ], payload, payload_sz ) );
    message->push->values[ i ].length = original_sz-*payload_sz-message->push->values[ i ].offset;
  }
  return 1;
}

static int
deser_prune( fd_gossip_message_t * message,
             uchar const **        payload,
             ulong *               payload_sz ) {
  READ_BYTES( message->prune->sender, 32UL, payload, payload_sz );
  READ_BYTES( message->prune->pubkey, 32UL, payload, payload_sz );
  CHECK( !memcmp( message->prune->sender, message->prune->pubkey, 32UL ) );
  READ_U64( message->prune->prunes_len, payload, payload_sz );
  for( ulong i=0UL; i<message->prune->prunes_len; i++ ) {
    READ_BYTES( message->prune->prunes[ i ], 32UL, payload, payload_sz );
  }
  READ_BYTES( message->prune->signature, 64UL, payload, payload_sz );
  READ_BYTES( message->prune->destination, 32UL, payload, payload_sz );
  READ_WALLCLOCK( message->prune->wallclock, payload, payload_sz );
  return 1;
}

static int
deser_ping( fd_gossip_message_t * message,
            uchar const **        payload,
            ulong *               payload_sz ) {
  READ_BYTES( message->ping->from, 32UL, payload, payload_sz );
  READ_BYTES( message->ping->token, 32UL, payload, payload_sz );
  READ_BYTES( message->ping->signature, 64UL, payload, payload_sz );
  return 1;
}

static int
deser_pong( fd_gossip_message_t * message,
            uchar const **        payload,
            ulong *               payload_sz ) {
  READ_BYTES( message->pong->from, 32UL, payload, payload_sz );
  READ_BYTES( message->pong->hash, 32UL, payload, payload_sz );
  READ_BYTES( message->pong->signature, 64UL, payload, payload_sz );
  return 1;
}

int
fd_gossip_message_deserialize( fd_gossip_message_t * message,
                               uchar const *         _payload,
                               ulong                 _payload_sz ) {
  uchar const ** payload = &_payload;
  ulong * payload_sz = &_payload_sz;
  ulong original_sz = _payload_sz;

  CHECK( _payload_sz<=1232UL );
  READ_ENUM( message->tag, FD_GOSSIP_MESSAGE_CNT, payload, payload_sz );

  switch( message->tag ){
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:  CHECK( deser_pull_request( message, payload, payload_sz, original_sz ) ); break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE: CHECK( deser_pull_response( message, payload, payload_sz, original_sz ) ); break;
    case FD_GOSSIP_MESSAGE_PUSH:          CHECK( deser_push( message, payload, payload_sz, original_sz ) ); break;
    case FD_GOSSIP_MESSAGE_PRUNE:         CHECK( deser_prune( message, payload, payload_sz ) ); break;
    case FD_GOSSIP_MESSAGE_PING:          CHECK( deser_ping( message, payload, payload_sz ) ); break;
    case FD_GOSSIP_MESSAGE_PONG:          CHECK( deser_pong( message, payload, payload_sz ) ); break;
    default: FD_LOG_CRIT(( "invalid message tag" ));
  }

  return !*payload_sz;
}

#define CHECK1( cond ) do {               \
  if( FD_UNLIKELY( !(cond) ) ) return -1; \
} while( 0 )

#define WRITE_BYTES( src, src_sz, out, out_sz ) do { \
  CHECK1( *out_sz>=src_sz );                         \
  fd_memcpy( *out, src, src_sz );                    \
  (*out) += src_sz;                                  \
  (*out_sz) -= src_sz;                               \
} while( 0 )

#define WRITE_SKIP_BYTES( skip_sz, out, out_sz ) do { \
  CHECK1( *out_sz>=skip_sz );                         \
  (*out) += skip_sz;                                  \
  (*out_sz) -= skip_sz;                               \
} while( 0 )

#define WRITE_U8( val, out, out_sz ) do { \
  CHECK1( *out_sz>=1UL );                 \
  FD_STORE( uchar, *out, val );           \
  (*out) += 1UL;                          \
  (*out_sz) -= 1UL;                       \
} while( 0 )

#define WRITE_U16( val, out, out_sz ) do { \
  CHECK1( *out_sz>=2UL );                  \
  FD_STORE( ushort, *out, val );           \
  (*out) += 2UL;                           \
  (*out_sz) -= 2UL;                        \
} while( 0 )

#define WRITE_U32( val, out, out_sz ) do { \
  CHECK1( *out_sz>=4UL );                  \
  FD_STORE( uint, *out, val );             \
  (*out) += 4UL;                           \
  (*out_sz) -= 4UL;                        \
} while( 0 )

#define WRITE_U64( val, out, out_sz ) do { \
  CHECK1( *out_sz>=8UL );                  \
  FD_STORE( ulong, *out, val );            \
  (*out) += 8UL;                           \
  (*out_sz) -= 8UL;                        \
} while( 0 )

#define WRITE_U16_VARINT( val, out, out_sz ) do {                   \
  ushort _val = (val);                                              \
  if( FD_LIKELY( _val<128U ) ) {                                    \
    CHECK1( *(out_sz)>=1UL );                                       \
    FD_STORE( uchar, *out, (uchar)_val );                           \
    (*out) += 1UL;                                                  \
    (*out_sz) -= 1UL;                                               \
  } else if( FD_LIKELY( _val<16384U ) ) {                           \
    CHECK1( *out_sz>=2UL );                                         \
    FD_STORE( uchar, (*out),   (uchar)((_val&0x7FU)|0x80U) );       \
    FD_STORE( uchar, (*out)+1, (uchar)(_val>>7U) );                 \
    (*out) += 2UL;                                                  \
    (*out_sz) -= 2UL;                                               \
  } else {                                                          \
    CHECK1( *out_sz>=3UL );                                         \
    FD_STORE( uchar, (*out),   (uchar)((_val&0x7FU)|0x80U) );       \
    FD_STORE( uchar, (*out)+1, (uchar)(((_val>>7U)&0x7FU)|0x80U) ); \
    FD_STORE( uchar, (*out)+2, (uchar)(_val>>14U) );                \
    (*out) += 3UL;                                                  \
    (*out_sz) -= 3UL;                                               \
  }                                                                 \
} while( 0 )

#define WRITE_U64_VARINT( val, out, out_sz ) do {           \
  ulong _val = (val);                                       \
  while( _val>=0x80UL ) {                                   \
    CHECK1( *(out_sz)>=1UL );                               \
    FD_STORE( uchar, *out, (uchar)((_val&0x7FUL)|0x80UL) ); \
    (*out) += 1UL;                                          \
    (*out_sz) -= 1UL;                                       \
    _val >>= 7;                                             \
  }                                                         \
  CHECK1( *(out_sz)>=1UL );                                 \
  FD_STORE( uchar, *out, (uchar)_val );                     \
  (*out) += 1UL;                                            \
  (*out_sz) -= 1UL;                                         \
} while( 0 )

static int
ser_vote( fd_gossip_value_t const * value,
          uchar **                  out,
          ulong *                   out_sz ) {
  WRITE_U8( value->vote->index, out, out_sz );
  WRITE_BYTES( value->origin, 32UL, out, out_sz );
  WRITE_BYTES( value->vote->transaction, value->vote->transaction_len, out, out_sz );
  WRITE_U64( value->wallclock, out, out_sz );
  return 1;
}

static int
ser_node_instance( fd_gossip_value_t const * value,
                   uchar **                  out,
                   ulong *                   out_sz ) {
  WRITE_BYTES( value->origin, 32UL, out, out_sz );
  WRITE_U64( value->wallclock, out, out_sz );
  WRITE_U64( value->node_instance->timestamp, out, out_sz );
  WRITE_U64( value->node_instance->token, out, out_sz );
  return 1;
}

static int
ser_duplicate_shred( fd_gossip_value_t const * value,
                     uchar **                  out,
                     ulong *                   out_sz ) {
  WRITE_U16( value->duplicate_shred->index, out, out_sz );
  WRITE_BYTES( value->origin, 32UL, out, out_sz );
  WRITE_U64( value->wallclock, out, out_sz );
  WRITE_U64( value->duplicate_shred->slot, out, out_sz );
  WRITE_BYTES( "\0\0\0\0\0", 5UL, out, out_sz ); /* (unused) + shred type (unused) */
  WRITE_U8( value->duplicate_shred->num_chunks, out, out_sz );
  WRITE_U8( value->duplicate_shred->chunk_index, out, out_sz );
  WRITE_U64( value->duplicate_shred->chunk_len, out, out_sz );
  WRITE_BYTES( value->duplicate_shred->chunk, value->duplicate_shred->chunk_len, out, out_sz );
  return 1;
}

static int
ser_snapshot_hashes( fd_gossip_value_t const * value,
                     uchar **                  out,
                     ulong *                   out_sz ) {
  WRITE_BYTES( value->origin, 32UL, out, out_sz );
  WRITE_U64( value->snapshot_hashes->full_slot, out, out_sz );
  WRITE_BYTES( value->snapshot_hashes->full_hash, 32UL, out, out_sz );
  WRITE_U64( value->snapshot_hashes->incremental_len, out, out_sz );
  for( ulong i=0UL; i<value->snapshot_hashes->incremental_len; i++ ) {
    WRITE_U64( value->snapshot_hashes->incremental[ i ].slot, out, out_sz );
    WRITE_BYTES( value->snapshot_hashes->incremental[ i ].hash, 32UL, out, out_sz );
  }
  WRITE_U64( value->wallclock, out, out_sz );
  return 1;
}

static int
ser_contact_info( fd_gossip_value_t const * value,
                  uchar **                  out,
                  ulong *                   out_sz ) {
  WRITE_BYTES( value->origin, 32UL, out, out_sz );
  WRITE_U64_VARINT( value->wallclock, out, out_sz );
  WRITE_U64( value->contact_info->outset, out, out_sz );
  WRITE_U16( value->contact_info->shred_version, out, out_sz );
  WRITE_U16_VARINT( value->contact_info->version.major, out, out_sz );
  WRITE_U16_VARINT( value->contact_info->version.minor, out, out_sz );
  WRITE_U16_VARINT( value->contact_info->version.patch, out, out_sz );
  WRITE_U32( value->contact_info->version.commit, out, out_sz );
  WRITE_U32( value->contact_info->version.feature_set, out, out_sz );
  WRITE_U16_VARINT( value->contact_info->version.client, out, out_sz );

  ulong num_sockets = 0UL;
  ulong num_unique_addrs = 0UL;
  int duplicate[ FD_GOSSIP_CONTACT_INFO_SOCKET_CNT ] = {0};
  ulong address_map[ FD_GOSSIP_CONTACT_INFO_SOCKET_CNT ];
  for( ulong i=0UL; i<FD_GOSSIP_CONTACT_INFO_SOCKET_CNT; i++ ) {
    if( FD_UNLIKELY( !value->contact_info->sockets[ i ].port ) ) continue;
    num_sockets++;

    if( FD_UNLIKELY( duplicate[ i ] ) ) continue;

    address_map[ i ] = num_unique_addrs;
    num_unique_addrs++;

    for( ulong j=i+1UL; j<FD_GOSSIP_CONTACT_INFO_SOCKET_CNT; j++ ) {
      if( FD_UNLIKELY( value->contact_info->sockets[ i ].is_ipv6!=value->contact_info->sockets[ j ].is_ipv6 ) ) continue;
      if( FD_LIKELY( !value->contact_info->sockets[ i ].is_ipv6 ) ) {
        if( FD_LIKELY( value->contact_info->sockets[ i ].ip4!=value->contact_info->sockets[ j ].ip4 ) ) continue;
      } else {
        if( FD_LIKELY( memcmp( value->contact_info->sockets[ i ].ip6, value->contact_info->sockets[ j ].ip6, 16UL ) ) ) continue;
      }

      duplicate[ j ] = 1;
      address_map[ j ] = address_map[ i ];
    }
  }

  WRITE_U16_VARINT( (ushort)num_unique_addrs, out, out_sz );
  for( ulong i=0UL; i<FD_GOSSIP_CONTACT_INFO_SOCKET_CNT; i++ ) {
    if( FD_UNLIKELY( !value->contact_info->sockets[ i ].port ) ) continue;
    if( FD_UNLIKELY( duplicate[ i ] ) ) continue;

    WRITE_U32( value->contact_info->sockets[ i ].is_ipv6, out, out_sz );
    if( FD_LIKELY( !value->contact_info->sockets[ i ].is_ipv6 ) ) WRITE_U32( value->contact_info->sockets[ i ].ip4, out, out_sz );
    else                                                          WRITE_BYTES( value->contact_info->sockets[ i ].ip6, 16UL, out, out_sz );
  }

  WRITE_U16_VARINT( (ushort)num_sockets, out, out_sz );

  int already_written[ FD_GOSSIP_CONTACT_INFO_SOCKET_CNT ] = {0};
  ushort prev_port = 0U;
  for( ulong i=0UL; i<num_sockets; i++ ) {
    ulong lowest_port_index = ULONG_MAX;
    for( ulong j=0UL; j<FD_GOSSIP_CONTACT_INFO_SOCKET_CNT; j++ ) {
      if( FD_UNLIKELY( !value->contact_info->sockets[ j ].port ) ) continue;
      if( FD_UNLIKELY( already_written[ j ] ) ) continue;
      if( FD_UNLIKELY( lowest_port_index==ULONG_MAX || fd_ushort_bswap( value->contact_info->sockets[ j ].port )<fd_ushort_bswap( value->contact_info->sockets[ lowest_port_index ].port ) ) ) lowest_port_index = j;
    }
    if( FD_UNLIKELY( lowest_port_index==ULONG_MAX ) ) break;
    already_written[ lowest_port_index ] = 1;

    WRITE_U8( (uchar)lowest_port_index, out, out_sz );
    WRITE_U8( (uchar)address_map[ lowest_port_index ], out, out_sz );

    ushort port_offset = (ushort)(fd_ushort_bswap( value->contact_info->sockets[ lowest_port_index ].port )-prev_port);
    WRITE_U16_VARINT( port_offset, out, out_sz );
    prev_port = fd_ushort_bswap( value->contact_info->sockets[ lowest_port_index ].port );
  }

  WRITE_U16_VARINT( 0UL, out, out_sz ); /* extensions_len */
  return 1;
}

long
fd_gossip_value_serialize( fd_gossip_value_t const * value,
                           uchar *                   _out,
                           ulong                     _out_sz ) {

  uchar ** out = &_out;
  ulong original_size = _out_sz;
  ulong * out_sz = &_out_sz;

  WRITE_BYTES( value->signature, 64UL, out, out_sz );
  WRITE_U32( value->tag, out, out_sz );

  switch( value->tag ) {
    case FD_GOSSIP_VALUE_VOTE:            if( FD_UNLIKELY( -1==ser_vote( value, out, out_sz ) ) ) return -1; break;
    case FD_GOSSIP_VALUE_NODE_INSTANCE:   if( FD_UNLIKELY( -1==ser_node_instance( value, out, out_sz ) ) ) return -1; break;
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED: if( FD_UNLIKELY( -1==ser_duplicate_shred( value, out, out_sz ) ) ) return -1; break;
    case FD_GOSSIP_VALUE_SNAPSHOT_HASHES: if( FD_UNLIKELY( -1==ser_snapshot_hashes( value, out, out_sz ) ) ) return -1; break;
    case FD_GOSSIP_VALUE_CONTACT_INFO:    if( FD_UNLIKELY( -1==ser_contact_info( value, out, out_sz ) ) ) return -1; break;

    // UNUSED VALUES, WE DO NOT SERIALIZE THESE
    // case FD_GOSSIP_VALUE_LEGACY_CONTACT_INFO:           return ser_legacy_contact_info( value, out, out_sz );
    // case FD_GOSSIP_VALUE_LOWEST_SLOT:                   return ser_lowest_slot( value, out, out_sz );
    // case FD_GOSSIP_VALUE_LEGACY_SNAPSHOT_HASHES:        return ser_legacy_snapshot_hashes( value, out, out_sz );
    // case FD_GOSSIP_VALUE_ACCOUNT_HASHES:                return ser_account_hashes( value, out, out_sz );
    // case FD_GOSSIP_VALUE_EPOCH_SLOTS:                   return ser_epoch_slots( value, out, out_sz );
    // case FD_GOSSIP_VALUE_LEGACY_VERSION:                return ser_legacy_version( value, out, out_sz );
    // case FD_GOSSIP_VALUE_VERSION:                       return ser_version( value, out, out_sz );
    // case FD_GOSSIP_VALUE_RESTART_LAST_VOTED_FORK_SLOTS: return ser_restart_last_voted_fork_slots( value, out, out_sz );
    // case FD_GOSSIP_VALUE_RESTART_HEAVIEST_FORK:         return ser_restart_heaviest_fork( value, out, out_sz );
    default: FD_LOG_CRIT(( "impossible" ));
  }

  return (long)(original_size-_out_sz);
}

long
fd_gossip_pull_request_init( uchar *       payload,
                             ulong         payload_sz,
                             ulong         num_keys,
                             ulong         num_bits,
                             ulong         mask,
                             uint          mask_bits,
                             uchar const * contact_info_crds,
                             ulong         contact_info_crds_sz,
                             ulong **      out_bloom_keys,
                             ulong **      out_bloom_bits,
                             ulong **      out_bits_set ) {
  uchar ** out = &payload;
  ulong original_size = payload_sz;
  ulong * out_sz = &payload_sz;

  WRITE_U32( FD_GOSSIP_MESSAGE_PULL_REQUEST, out, out_sz );
  WRITE_U64( num_keys, out, out_sz );
  *out_bloom_keys = fd_type_pun( payload+(payload_sz-*out_sz) );
  WRITE_SKIP_BYTES( num_keys*8UL, out, out_sz );

  if( FD_LIKELY( !!num_bits ) ) {
    /* Bloom bits is a bitvec<u64>, so we need to be careful about converting bloom bits count to vector lengths */
    ulong bloom_vec_len = (num_bits+63UL)/64UL;
    WRITE_U8( 1, out, out_sz ); /* has_bits */
    WRITE_U64( bloom_vec_len, out, out_sz );
    *out_bloom_bits = fd_type_pun( payload+(payload_sz-*out_sz) );
    WRITE_SKIP_BYTES( bloom_vec_len*8UL, out, out_sz );
  } else {
    WRITE_U8( 0, out, out_sz ); /* has_bits */
    *out_bloom_bits = NULL;
  }
  WRITE_U64( num_bits, out, out_sz );
  *out_bits_set = fd_type_pun( payload+(payload_sz-*out_sz) );
  WRITE_SKIP_BYTES( 8UL, out, out_sz );
  WRITE_U64( mask, out, out_sz );
  WRITE_U32( mask_bits, out, out_sz );
  WRITE_BYTES( contact_info_crds, contact_info_crds_sz, out, out_sz );

  return (long)(original_size-*out_sz);
}
