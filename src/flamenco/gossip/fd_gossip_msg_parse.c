#include "fd_gossip_private.h"
#include "../../ballet/txn/fd_compact_u16.h"

/* Adapted from fd_txn_parse.c */
#define CHECK_INIT( payload, payload_sz, offset )   \
  uchar const * _payload        = (payload);        \
  ulong const   _payload_sz     = (payload_sz);     \
  ushort const  _offset         = (offset);         \
  ushort        _i              = (offset);         \
  (void)        _payload;                           \
  (void)        _offset;                            \

#define CHECK( cond ) do {              \
  if( FD_UNLIKELY( !(cond) ) ) {        \
    FD_LOG_WARNING(( "Gossip message parse error at offset %u, size %lu: %s", _i, _payload_sz, #cond )); \
    return 0;                           \
  }                                     \
} while( 0 )

#define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-_i) )

#define INC( n ) (_i += (ushort)(n))

#define CHECKED_INC( n ) do { \
  CHECK_LEFT( n );            \
  INC( n );                   \
} while( 0 )

#define READ_CHECKED_COMPACT_U16( out_sz, var_name, where )                 \
  do {                                                                      \
    ulong _where = (where);                                                 \
    ulong _out_sz = fd_cu16_dec_sz( _payload+_where, _payload_sz-_where );  \
    CHECK( _out_sz );                                                       \
    (var_name) = fd_cu16_dec_fixed( _payload+_where, _out_sz );             \
    (out_sz)   = _out_sz;                                                   \
  } while( 0 )
#define CUR_OFFSET      (_i)
#define CURSOR          (_payload+_i)
#define BYTES_CONSUMED  (_i-_offset)
#define BYTES_REMAINING (_payload_sz-_i)

static ulong
decode_u64_varint( uchar const * payload,
                   ulong         payload_sz,
                   ushort        start_offset,
                   ulong *       out_value ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  ulong value = 0UL;
  uchar shift = 0U;
  while( FD_LIKELY( _i < _payload_sz ) ) {
    uchar byte = FD_LOAD( uchar, CURSOR ); INC( 1U );
    value |= (ulong)(byte & 0x7F) << shift;
    if( !(byte & 0x80) ) break;
    shift += 7U;
    if( FD_UNLIKELY( shift >= 64U ) ) return 0;
  }
  *out_value = value;
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_legacy_contact_info_parse( fd_gossip_view_crds_value_t * crds_val,
                                              uchar const *                 payload,
                                              ulong                         payload_sz,
                                              ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  /* https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/legacy_contact_info.rs#L13 */
  CHECK_LEFT( 32U ); crds_val->pubkey_off = CUR_OFFSET                                         ; INC( 32U );
  for( ulong i=0UL; i<10; i++ ) {
    CHECK_LEFT( 4U ); uint is_ip6 = FD_LOAD( uint, CURSOR )                                    ; INC(  4U );
    if( !is_ip6 ){
      CHECKED_INC( 4U+2U ); /* ip4 + port */
    } else {
      CHECKED_INC( 16U+2U+4U+4U ); /* ip6 + port + flowinfo + scope_id */
    }
  }
  CHECK_LEFT(  8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );
  CHECKED_INC( 2U ); /* shred_version */
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_vote_parse( fd_gossip_view_crds_value_t * crds_val,
                               uchar const *                 payload,
                               ulong                         payload_sz,
                               ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT(  1U ); crds_val->vote->index = FD_LOAD( uchar, CURSOR ); INC(  1U );
  CHECK_LEFT( 32U ); crds_val->pubkey_off  = CUR_OFFSET              ; INC( 32U );
  ulong transaction_sz;
  CHECK( fd_txn_parse_core( CURSOR, BYTES_REMAINING, NULL, NULL, &transaction_sz )!=0UL );
  crds_val->vote->txn_off = CUR_OFFSET;
  crds_val->vote->txn_sz  = transaction_sz;
  INC( transaction_sz );
  CHECK_LEFT( 8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC( 8U );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_lowest_slot_parse( fd_gossip_view_crds_value_t * crds_val,
                                      uchar const *                 payload,
                                      ulong                         payload_sz,
                                      ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECKED_INC(           1U );
  CHECK_LEFT(           32U ); crds_val->pubkey_off = CUR_OFFSET                                          ; INC( 32U );

  CHECKED_INC(           8U ); /* root */

  CHECK_LEFT(            8U ); crds_val->lowest_slot = FD_LOAD( ulong, CURSOR )                           ; INC( 8U );

  /* slots set is deprecated, so we skip it. */
  CHECK_LEFT(            8U ); ulong slots_len = FD_LOAD( ulong, CURSOR )                                 ; INC( 8U );
  CHECKED_INC( slots_len*8U ); /* slots */

  /* TODO: stash vector<EpochIncompleteSlots> is deprecated, but is hard to skip
     since EpochIncompleteSlots is a dynamically sized type. So we fail this
     parse if there are any entries. Might be worth implementing a skip instead,
     TBD after live testing.
     Idea: rip out parser from fd_types
     https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/deprecated.rs#L19 */
  CHECK_LEFT(            8U ); ulong stash_len = FD_LOAD( ulong, CURSOR )                                 ; INC( 8U );
  CHECK(      stash_len==0U );

  CHECK_LEFT(            8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC( 8U );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_account_hashes_parse( fd_gossip_view_crds_value_t * crds_val,
                                         uchar const *                 payload,
                                         ulong                         payload_sz,
                                         ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT( 32U ); crds_val->pubkey_off = CUR_OFFSET                                          ; INC( 32U );
  CHECK_LEFT(  8U ); ulong hashes_len     = FD_LOAD( ulong, CURSOR )                            ; INC( 8U );
  CHECKED_INC( hashes_len*32U ); /* hashes */

  CHECK_LEFT( 8U );  crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC( 8U );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_epoch_slots_parse( fd_gossip_view_crds_value_t * crds_val,
                                      uchar const *                 payload,
                                      ulong                         payload_sz,
                                      ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT(  1U ); crds_val->epoch_slots->index = FD_LOAD( uchar, CURSOR )                   ; INC(  1U );
  CHECK_LEFT( 32U ); crds_val->pubkey_off         = CUR_OFFSET                                 ; INC( 32U );
  CHECK_LEFT(  8U ); ulong slots_len              = FD_LOAD( ulong, CURSOR )                   ; INC(  8U );

  for( ulong i=0UL; i<slots_len; i++ ) {
    CHECK_LEFT( 4U ); uint is_uncompressed = FD_LOAD( uint, CURSOR )                           ; INC( 4U );
    if( is_uncompressed ) {
      CHECKED_INC( 8U+8U ); /* first_slot + num */
      uchar has_bits = 0;
      CHECK_LEFT( 1U ); has_bits = FD_LOAD( uchar, CURSOR )                                    ; INC( 1U );
      if( has_bits ) {
        CHECK_LEFT( 8U ); ulong bits_len = FD_LOAD( ulong, CURSOR )                            ; INC( 8U );
        CHECKED_INC( bits_len ); /* bitvec<u8> */
        CHECKED_INC( 8U );
      }
    } else {
      CHECKED_INC( 8U+8U ); /* first_slot + num */
      CHECK_LEFT( 8U ); ulong compressed_len = FD_LOAD( ulong, CURSOR )                        ; INC( 8U );
      CHECKED_INC( compressed_len ); /* compressed bitvec */
    }
  }
  CHECK_LEFT( 8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC( 8U );

  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_legacy_version_parse( fd_gossip_view_crds_value_t * crds_val,
                                         uchar const *                 payload,
                                         ulong                         payload_sz,
                                         ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT( 32U ); crds_val->pubkey_off      = CUR_OFFSET                                     ; INC( 32U );
  CHECK_LEFT(  8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );

  CHECKED_INC( 3*2U ); /* major, minor, patch (all u16s)*/
  CHECK_LEFT(    1U ); uchar has_commit = FD_LOAD( uchar, CURSOR )                              ; INC( 1U );
  if( has_commit ) {
    CHECKED_INC( 4U );
  }
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_version_parse( fd_gossip_view_crds_value_t * crds_val,
                                  uchar const *                 payload,
                                  ulong                         payload_sz,
                                  ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  INC( fd_gossip_msg_crds_legacy_version_parse( crds_val, payload, payload_sz, start_offset ) );
  CHECKED_INC( 4U ); /* feature set */
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_node_instance_parse( fd_gossip_view_crds_value_t * crds_val,
                                        uchar const *                 payload,
                                        ulong                         payload_sz,
                                        ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT( 32U ); crds_val->pubkey_off      = CUR_OFFSET                                     ; INC( 32U );
  CHECK_LEFT(  8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC( 8U );
  CHECKED_INC( 8U+8U ); /* timestamp + token*/
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_duplicate_shred_parse( fd_gossip_view_crds_value_t * crds_val,
                                          uchar const *                 payload,
                                          ulong                         payload_sz,
                                          ushort                        start_offset ) {
  fd_gossip_view_duplicate_shred_t * ds = crds_val->duplicate_shred;

  CHECK_INIT( payload, payload_sz, start_offset );

  CHECK_LEFT(            2U ); ds->index = FD_LOAD( ushort, CURSOR )                                      ; INC(            2U );
  CHECK_LEFT(           32U ); crds_val->pubkey_off = CUR_OFFSET                                          ; INC(           32U );
  CHECK_LEFT(            8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(            8U );
  CHECK_LEFT(            8U ); ds->slot = FD_LOAD( ulong, CURSOR )                                        ; INC(            8U );
  CHECKED_INC(        4U+1U ); /* (unused) + shred type (unused) */
  CHECK_LEFT(            1U ); ds->num_chunks  = FD_LOAD( uchar, CURSOR )                                 ; INC(            1U );
  CHECK_LEFT(            1U ); ds->chunk_index = FD_LOAD( uchar, CURSOR )                                 ; INC(            1U );
  CHECK_LEFT(            8U ); ds->chunk_len   = FD_LOAD( ulong, CURSOR )                                 ; INC(            8U );
  CHECK_LEFT( ds->chunk_len ); ds->chunk_off   = CUR_OFFSET                                               ; INC( ds->chunk_len );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_snapshot_hashes_parse( fd_gossip_view_crds_value_t * crds_val,
                                          uchar const *                 payload,
                                          ulong                         payload_sz,
                                          ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT(                  32U ); crds_val->pubkey_off = CUR_OFFSET                                          ; INC(                 32U );
  CHECK_LEFT(                  40U ); crds_val->snapshot_hashes->full_off = CUR_OFFSET                           ; INC(                 40U );
  CHECK_LEFT(                   8U ); ulong incremental_len = FD_LOAD( ulong, CURSOR )                           ; INC(                  8U );
  CHECK_LEFT(  incremental_len*40U ); crds_val->snapshot_hashes->inc_off = CUR_OFFSET                            ; INC( incremental_len*40U );
  CHECK_LEFT(                   8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );
  crds_val->snapshot_hashes->inc_len = incremental_len;
  return BYTES_CONSUMED;
}

static ulong
version_parse( fd_gossip_view_version_t * version,
               uchar const *              payload,
               ulong                      payload_sz,
               ushort                     start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  ulong decode_sz;
  READ_CHECKED_COMPACT_U16( decode_sz, version->major, CUR_OFFSET ) ; INC( decode_sz );
  READ_CHECKED_COMPACT_U16( decode_sz, version->minor, CUR_OFFSET ) ; INC( decode_sz );
  READ_CHECKED_COMPACT_U16( decode_sz, version->patch, CUR_OFFSET ) ; INC( decode_sz );
  CHECK_LEFT( 4U ); version->commit = FD_LOAD( uint, CURSOR )      ; INC( 4U );
  CHECK_LEFT( 4U ); version->feature_set = FD_LOAD( uint, CURSOR ) ; INC( 4U );
  READ_CHECKED_COMPACT_U16( decode_sz, version->client, CUR_OFFSET ); INC( decode_sz );
  return BYTES_CONSUMED;
}

/* Contact Infos are checked for the following properties
   - All addresses in addrs are unique
   - Each socket entry references a unique socket tag
   - Socket offsets do not cause an overflow
   - All addresses are referenced at least once across all sockets
   https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/contact_info.rs#L599 */

#define SET_NAME ip4_seen_set
#define SET_MAX  (1<<15)
#include "../../util/tmpl/fd_set.c"

#define SET_NAME ip6_seen_set
#define SET_MAX  (1<<14)
#include "../../util/tmpl/fd_set.c"

struct ipv6_addr {
  ulong hi;
  ulong lo;
};

typedef struct ipv6_addr ipv6_addr_t;

static inline ulong
ipv6_hash( ipv6_addr_t const * addr ) {
return fd_ulong_hash( addr->hi ^ fd_ulong_hash( addr->lo ) );
}

/* Existing sets for socket validation */
#define SET_NAME addr_idx_set
#define SET_MAX  FD_GOSSIP_CONTACT_INFO_MAX_ADDRESSES
#include "../../util/tmpl/fd_set.c"

#define SET_NAME socket_tag_set
#define SET_MAX  FD_GOSSIP_CONTACT_INFO_MAX_SOCKETS
#include "../../util/tmpl/fd_set.c"

static ulong
fd_gossip_msg_crds_contact_info_parse( fd_gossip_view_crds_value_t * crds_val,
                                       uchar const *                 payload,
                                       ulong                         payload_sz,
                                       ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT( 32U ); crds_val->pubkey_off = CUR_OFFSET                                                                         ; INC( 32U );
  ulong wallclock = 0UL;
  INC( decode_u64_varint( payload, payload_sz, CUR_OFFSET, &wallclock ) );
  crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( wallclock );

  CHECK_LEFT( 8U ); crds_val->contact_info->instance_creation_wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );
  CHECK_LEFT( 2U ); crds_val->contact_info->shred_version = FD_LOAD( ushort, CURSOR )                                          ; INC(  2U );
  INC( version_parse( crds_val->contact_info->version, payload, payload_sz, CUR_OFFSET ) );

  ulong decode_sz;
  READ_CHECKED_COMPACT_U16( decode_sz, crds_val->contact_info->addrs_len, CUR_OFFSET )                                         ; INC( decode_sz );
  CHECK( crds_val->contact_info->addrs_len<=FD_GOSSIP_CONTACT_INFO_MAX_ADDRESSES );

  ip4_seen_set_t ip4_seen[ ip4_seen_set_word_cnt ];
  ip6_seen_set_t ip6_seen[ ip6_seen_set_word_cnt ];
  ip4_seen_set_new( ip4_seen );
  ip6_seen_set_new( ip6_seen );

  for( ulong i=0UL; i<crds_val->contact_info->addrs_len; i++ ) {
    fd_gossip_view_ipaddr_t * addr = &crds_val->contact_info->addrs[i];
    CHECK_LEFT( 4U ); addr->is_ip6 = FD_LOAD( uchar, CURSOR )                                                                  ; INC( 4U );
    if( FD_LIKELY( !addr->is_ip6 ) ) {
      CHECK_LEFT( 4U ); addr->ip4 = FD_LOAD( uint, CURSOR )                                                                    ; INC( 4U );
      ulong idx = fd_uint_hash( addr->ip4 )&(ip4_seen_set_max( ip4_seen )-1);
      CHECK( !ip4_seen_set_test( ip4_seen, idx ) ); /* Should not be set initially */
      ip4_seen_set_insert( ip4_seen, idx );
    } else {
      CHECK_LEFT( 16U ); addr->ip6_off = CUR_OFFSET                                                                            ; INC( 16U );
      ulong idx = ipv6_hash( (ipv6_addr_t *)(payload+addr->ip6_off) )&(ip6_seen_set_max( ip6_seen )-1);
      CHECK( !ip6_seen_set_test( ip6_seen, idx ) );
      ip6_seen_set_insert( ip6_seen, idx );
    }
  }

  addr_idx_set_t ip_addr_hits[ addr_idx_set_word_cnt ];
  socket_tag_set_t socket_tag_hits[ socket_tag_set_word_cnt ];
  addr_idx_set_new( ip_addr_hits );
  socket_tag_set_new( socket_tag_hits );

  READ_CHECKED_COMPACT_U16( decode_sz, crds_val->contact_info->sockets_len, CUR_OFFSET )                                       ; INC( decode_sz );
  CHECK( crds_val->contact_info->sockets_len<=FD_GOSSIP_CONTACT_INFO_MAX_SOCKETS );

  ushort offset = 0U;
  for( ulong i=0UL; i<crds_val->contact_info->sockets_len; i++ ) {
    fd_gossip_view_socket_t * socket = &crds_val->contact_info->sockets[i];
    CHECK_LEFT( 1U ); socket->key   = FD_LOAD( uchar, CURSOR )                                                                 ; INC( 1U );
    CHECK_LEFT( 1U ); socket->index = FD_LOAD( uchar, CURSOR )                                                                 ; INC( 1U );
    READ_CHECKED_COMPACT_U16( decode_sz, socket->offset, CUR_OFFSET )                                                          ; INC( decode_sz );
    CHECK( socket->offset+offset>=offset ); /* Check for overflow */
    offset += socket->offset;
    CHECK( !socket_tag_set_test( socket_tag_hits, socket->key ) ); socket_tag_set_insert( socket_tag_hits, socket->key );
    CHECK( socket->index<crds_val->contact_info->addrs_len );
    addr_idx_set_insert( ip_addr_hits, socket->index );
  }
  CHECK( addr_idx_set_cnt( ip_addr_hits )==crds_val->contact_info->addrs_len );

  /* extensions are currently unused */
  READ_CHECKED_COMPACT_U16( decode_sz, crds_val->contact_info->ext_len, CUR_OFFSET )                                           ; INC( decode_sz );
  CHECKED_INC( 4*crds_val->contact_info->ext_len );

  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_last_voted_fork_slots_parse( fd_gossip_view_crds_value_t * crds_val,
                                                uchar const *                 payload,
                                                ulong                         payload_sz,
                                                ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT( 32U ); crds_val->pubkey_off      = CUR_OFFSET                                     ; INC( 32U );
  CHECK_LEFT(  8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC( 8U );
  CHECK_LEFT(  4U ); uint is_rawoffsets        = FD_LOAD( uint, CURSOR )                        ; INC( 4U );
  if( !is_rawoffsets ) {
    CHECK_LEFT( 8U ); ulong slots_len = FD_LOAD( ulong, CURSOR )                                ; INC( 8U );
    CHECKED_INC( slots_len*4U ); /* RunLengthEncoding */
  } else {
    CHECK_LEFT( 1U ); uchar has_bits = FD_LOAD( uchar, CURSOR )                                 ; INC( 1U );
    if( has_bits ) {
      CHECK_LEFT( 8U ); ulong bits_len = FD_LOAD( ulong, CURSOR )                               ; INC( 8U );
      CHECKED_INC( bits_len ); /* bitvec<u8 > */
      CHECKED_INC( 8U ); /* bits num set */
    }
  }
  CHECKED_INC(  8U+32U+2U ); /* last voted slot + last voted hash + shred version */
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_restart_heaviest_fork_parse( fd_gossip_view_crds_value_t * crds_val,
                                                uchar const *                 payload,
                                                ulong                         payload_sz,
                                                ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT(  32U ); crds_val->pubkey_off      = CUR_OFFSET                                     ; INC( 32U );
  CHECK_LEFT(   8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC( 8U );
  CHECKED_INC(  8U+32U+8U+2U ); /* last slot + last slot hash + observed stake + shred version */
  return BYTES_CONSUMED;
}


static ulong
fd_gossip_msg_crds_data_parse( fd_gossip_view_crds_value_t * crds_val,
                               uchar const *                 payload,
                               ulong                         payload_sz,
                               ushort                        start_offset ) {
  switch( crds_val->tag ){
    case FD_GOSSIP_VALUE_LEGACY_CONTACT_INFO:
      return fd_gossip_msg_crds_legacy_contact_info_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_VOTE:
      return fd_gossip_msg_crds_vote_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_LOWEST_SLOT:
      return fd_gossip_msg_crds_lowest_slot_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_LEGACY_SNAPSHOT_HASHES:
    case FD_GOSSIP_VALUE_ACCOUNT_HASHES:
      return fd_gossip_msg_crds_account_hashes_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_EPOCH_SLOTS:
      return fd_gossip_msg_crds_epoch_slots_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_LEGACY_VERSION:
      return fd_gossip_msg_crds_legacy_version_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_VERSION:
      return fd_gossip_msg_crds_version_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_NODE_INSTANCE:
      return fd_gossip_msg_crds_node_instance_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
      return fd_gossip_msg_crds_duplicate_shred_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_INC_SNAPSHOT_HASHES:
      return fd_gossip_msg_crds_snapshot_hashes_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_CONTACT_INFO:
      return fd_gossip_msg_crds_contact_info_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_RESTART_LAST_VOTED_FORK_SLOTS:
      return fd_gossip_msg_crds_last_voted_fork_slots_parse( crds_val, payload, payload_sz, start_offset );
    case FD_GOSSIP_VALUE_RESTART_HEAVIEST_FORK:
      return fd_gossip_msg_crds_restart_heaviest_fork_parse( crds_val, payload, payload_sz, start_offset );
    default:
      FD_LOG_WARNING(( "Unknown CRDS value tag %d", crds_val->tag ));
      return 0;
  }
}

/* start_offset should point to first byte in first crds value. In
   push/pullresponse messages this would be after the crds len */
static ulong
fd_gossip_msg_crds_vals_parse( fd_gossip_view_crds_value_t * crds_values,
                               ulong                         crds_values_len,
                               uchar const *                 payload,
                               ulong                         payload_sz,
                               ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );

  for( ulong j=0UL; j<crds_values_len; j++ ) {
    fd_gossip_view_crds_value_t * crds_view = &crds_values[j];
    CHECK_LEFT( 64U ); crds_view->signature_off = CUR_OFFSET             ; INC( 64U );
    CHECK_LEFT( 4U );  crds_view->tag           = FD_LOAD(uchar, CURSOR ); INC(  4U );
    ulong crds_data_sz = fd_gossip_msg_crds_data_parse( crds_view, payload, payload_sz, CUR_OFFSET );
    crds_view->length  = (ushort)crds_data_sz + 64U + 4U; /* signature + tag */
    INC( crds_data_sz );
  }
  return BYTES_CONSUMED;
}
static ulong
fd_gossip_msg_ping_pong_parse( fd_gossip_view_t * view,
                               uchar const *      payload,
                               ulong              payload_sz,
                               ushort             start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  /* Ping/Pong share the same memory layout */
  CHECK_LEFT( sizeof(fd_gossip_view_ping_t) );
  view->ping = (fd_gossip_view_ping_t *)(CURSOR);
  INC( sizeof(fd_gossip_view_ping_t) );

  return BYTES_CONSUMED;
}

static ulong
fd_gossip_pull_req_parse( fd_gossip_view_t * view,
                          uchar const *      payload,
                          ulong              payload_sz,
                          ushort             start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  fd_gossip_view_pull_request_t * pr = view->pull_request;

  CHECK_LEFT(                      8U ); pr->bloom_keys_len    = FD_LOAD( ulong, CURSOR ) ; INC( 8U );
  CHECK_LEFT(   pr->bloom_keys_len*8U ); pr->bloom_keys_offset = CUR_OFFSET               ; INC( pr->bloom_keys_len*8U );

  uchar has_bits = 0;
  CHECK_LEFT(                      1U ); has_bits = FD_LOAD( uchar, CURSOR )              ; INC( 1U );
  if( has_bits ) {
    CHECK_LEFT(                    8U ); pr->bloom_len         = FD_LOAD( ulong, CURSOR )    ; INC( 8U );
    CHECK_LEFT( pr->bloom_len*8U      ); pr->bloom_bits_offset = CUR_OFFSET                  ; INC( pr->bloom_len*8U );
    CHECK_LEFT(                    8U ); pr->bloom_bits_cnt    = FD_LOAD( ulong, CURSOR )    ; INC( 8U );
  } else {
    pr->bloom_len = 0U;
  }
  CHECK_LEFT(                      8U ); pr->bloom_num_bits_set = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT(                      8U ); pr->mask      = FD_LOAD( ulong, CURSOR )         ; INC( 8U );
  CHECK_LEFT(                      4U ); pr->mask_bits = FD_LOAD( uint, CURSOR )          ; INC( 4U );

  INC( fd_gossip_msg_crds_vals_parse( pr->contact_info,
                                      1U, /* pull request holds only one contact info */
                                      payload,
                                      payload_sz,
                                      CUR_OFFSET ) );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_container_parse( fd_gossip_view_t * view,
                                    uchar const *      payload,
                                    ulong              payload_sz,
                                    ushort             start_offset ) {
  /* Push and Pull Responses are CRDS composite types, */
  CHECK_INIT( payload, payload_sz, start_offset );
  fd_gossip_view_crds_container_t * container = view->tag==FD_GOSSIP_MESSAGE_PUSH ? view->push
                                                                                  : view->pull_response;
  CHECK_LEFT( 32U ); container->from_off        = CUR_OFFSET               ; INC( 32U );
  CHECK_LEFT(  8U ); container->crds_values_len = FD_LOAD( ushort, CURSOR ); INC(  8U );
  CHECK( container->crds_values_len<=FD_GOSSIP_MSG_MAX_CRDS );
  INC( fd_gossip_msg_crds_vals_parse( container->crds_values,
                                      container->crds_values_len,
                                      payload,
                                      payload_sz,
                                      CUR_OFFSET ) );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_prune_parse( fd_gossip_view_t * view,
                           uchar const *      payload,
                           ulong              payload_sz,
                           ushort             start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  fd_gossip_view_prune_t * prune = view->prune;
  CHECKED_INC( 32U ); /* pubkey is sent twice */
  CHECK_LEFT(                      32U ); prune->origin_off      = CUR_OFFSET               ; INC( 32U );
  CHECK_LEFT(                       8U ); prune->prunes_len      = FD_LOAD( ulong, CURSOR ) ; INC(  2U );
  CHECK_LEFT(    prune->prunes_len*32U ); prune->prunes_off      = CUR_OFFSET               ; INC( prune->prunes_len*32U );
  CHECK_LEFT(                      64U ); prune->signature_off   = CUR_OFFSET               ; INC( 64U );
  CHECK_LEFT(                      32U ); prune->destination_off = CUR_OFFSET               ; INC( 32U );
  CHECK_LEFT(                       8U ); prune->wallclock       = FD_LOAD( ulong, CURSOR ) ; INC(  8U );

  /* Convert wallclock to nanos */
  prune->wallclock_nanos = FD_MILLI_TO_NANOSEC( prune->wallclock );

  return BYTES_CONSUMED;
}

ulong
fd_gossip_msg_parse( fd_gossip_view_t * view,
                     uchar const *      payload,
                     ulong              payload_sz ) {
  CHECK_INIT( payload, payload_sz, 0U );
  CHECK(     payload_sz<=FD_GOSSIP_MTU );

  /* Extract enum discriminant/tag (4b encoded) */
  uint tag = 0;
  CHECK_LEFT(                      4U );   tag = FD_LOAD( uchar, CURSOR ); INC( 4U );
  CHECK(   tag<=FD_GOSSIP_MESSAGE_LAST );
  view->tag = (uchar)tag;

  switch( view->tag ){
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      INC( fd_gossip_pull_req_parse( view, payload, payload_sz, CUR_OFFSET ) );
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
    case FD_GOSSIP_MESSAGE_PUSH:
      INC( fd_gossip_msg_crds_container_parse( view, payload, payload_sz, CUR_OFFSET ) );
      CHECK( payload_sz==CUR_OFFSET );
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      INC( fd_gossip_msg_prune_parse( view, payload, payload_sz, CUR_OFFSET ) );
      break;
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
      INC( fd_gossip_msg_ping_pong_parse( view, payload, payload_sz, CUR_OFFSET ) );
      CHECK( payload_sz==CUR_OFFSET );
      break;
    default:
      FD_LOG_WARNING(( "Unknown Gossip message type %d", view->tag ));
      return 0;
  }
  CHECK( CUR_OFFSET<=payload_sz );
  return BYTES_CONSUMED;
}
