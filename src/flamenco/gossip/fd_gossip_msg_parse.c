#include "fd_gossip_private.h"
#include "../../ballet/txn/fd_compact_u16.h"

/* Adapted from fd_txn_parse.c */
#define CHECK_INIT( payload, payload_sz, offset )   \
  uchar const * _payload        = (payload);        \
  ulong const   _payload_sz     = (payload_sz);     \
  ulong const   _offset         = (offset);         \
  ulong         _i              = (offset);         \
  (void)        _payload;                           \
  (void)        _offset;                            \

#define CHECK( cond ) do {              \
  if( FD_UNLIKELY( !(cond) ) ) {        \
    FD_LOG_WARNING(( "Gossip message parse error at offset %lu, size %lu: %s", _i, _payload_sz, #cond )); \
    return 0;                           \
  }                                     \
} while( 0 )

#define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-_i) )

#define INC( n ) (_i += (ulong)(n))

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
#define CUR_OFFSET      ((ushort)_i)
#define CURSOR          (_payload+_i)
#define BYTES_CONSUMED  (_i-_offset)
#define BYTES_REMAINING (_payload_sz-_i)

static ulong
decode_u64_varint( uchar const * payload,
                   ulong         payload_sz,
                   ulong         start_offset,
                   ulong *       out_value ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  ulong value = 0UL;
  ulong shift = 0U;
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
                                              ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  /* https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/legacy_contact_info.rs#L13 */
  CHECK_LEFT( 32U ); crds_val->pubkey_off = CUR_OFFSET                                          ; INC( 32U );
  for( ulong i=0UL; i<10; i++ ) {
    CHECK_LEFT( 4U ); uint is_ip6 = FD_LOAD( uint, CURSOR )                                     ; INC(  4U );
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
                               ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT(  1U ); crds_val->vote->index = FD_LOAD( uchar, CURSOR )                           ; INC(  1U );
  CHECK_LEFT( 32U ); crds_val->pubkey_off  = CUR_OFFSET                                         ; INC( 32U );
  ulong transaction_sz;
  CHECK( fd_txn_parse_core( CURSOR, BYTES_REMAINING, NULL, NULL, &transaction_sz )!=0UL );
  crds_val->vote->txn_off = CUR_OFFSET;
  crds_val->vote->txn_sz  = transaction_sz;
  INC( transaction_sz );
  CHECK_LEFT(  8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_lowest_slot_parse( fd_gossip_view_crds_value_t * crds_val,
                                      uchar const *                 payload,
                                      ulong                         payload_sz,
                                      ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECKED_INC( 1U ); /* deprecated */
  CHECK_LEFT( 32U ); crds_val->pubkey_off = CUR_OFFSET                                          ; INC( 32U );

  CHECKED_INC( 8U ); /* root: deprecated */

  CHECK_LEFT(  8U ); crds_val->lowest_slot = FD_LOAD( ulong, CURSOR )                           ; INC(  8U );

  /* slots set is deprecated, so we skip it. */
  CHECK_LEFT(  8U ); ulong slots_len = FD_LOAD( ulong, CURSOR )                                 ; INC(  8U );
  CHECKED_INC( slots_len*8U ); /* overflowing this currently doesn't matter, but be careful */

  /* TODO: stash vector<EpochIncompleteSlots> is deprecated, but is hard to skip
     since EpochIncompleteSlots is a dynamically sized type. So we fail this
     parse if there are any entries. Might be worth implementing a skip instead,
     TBD after live testing.
     Idea: rip out parser from fd_types
     https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/deprecated.rs#L19 */
  CHECK_LEFT(  8U ); ulong stash_len = FD_LOAD( ulong, CURSOR )                                 ; INC(  8U );
  CHECK( stash_len==0U );

  CHECK_LEFT(  8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_account_hashes_parse( fd_gossip_view_crds_value_t * crds_val,
                                         uchar const *                 payload,
                                         ulong                         payload_sz,
                                         ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT( 32U ); crds_val->pubkey_off = CUR_OFFSET                                           ; INC( 32U );
  CHECK_LEFT(  8U ); ulong hashes_len     = FD_LOAD( ulong, CURSOR )                             ; INC(  8U );
  CHECKED_INC( hashes_len*32U ); /* overflowing this currently doesn't matter, but be careful */

  CHECK_LEFT(  8U );  crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_epoch_slots_parse( fd_gossip_view_crds_value_t * crds_val,
                                      uchar const *                 payload,
                                      ulong                         payload_sz,
                                      ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT(  1U ); crds_val->epoch_slots->index = FD_LOAD( uchar, CURSOR )                   ; INC(  1U );
  CHECK_LEFT( 32U ); crds_val->pubkey_off         = CUR_OFFSET                                 ; INC( 32U );
  CHECK_LEFT(  8U ); ulong slots_len              = FD_LOAD( ulong, CURSOR )                   ; INC(  8U );

  for( ulong i=0UL; i<slots_len; i++ ) {
    CHECK_LEFT( 4U ); uint is_uncompressed = FD_LOAD( uint, CURSOR )                           ; INC(  4U );
    if( is_uncompressed ) {
      CHECKED_INC( 8U+8U ); /* first_slot + num */
      uchar has_bits = 0;
      CHECK_LEFT( 1U ); has_bits = FD_LOAD( uchar, CURSOR )                                    ; INC(  1U );
      if( has_bits ) {
        CHECK_LEFT( 8U ); ulong bits_len = FD_LOAD( ulong, CURSOR )                            ; INC(  8U );
        CHECKED_INC( bits_len ); /* bitvec<u8> */
        CHECKED_INC( 8U );
      }
    } else {
      CHECKED_INC( 8U+8U ); /* first_slot + num */
      CHECK_LEFT( 8U ); ulong compressed_len = FD_LOAD( ulong, CURSOR )                        ; INC(  8U );
      CHECKED_INC( compressed_len ); /* compressed bitvec */
    }
  }
  CHECK_LEFT( 8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );

  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_legacy_version_parse( fd_gossip_view_crds_value_t * crds_val,
                                         uchar const *                 payload,
                                         ulong                         payload_sz,
                                         ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT( 32U ); crds_val->pubkey_off      = CUR_OFFSET                                     ; INC( 32U );
  CHECK_LEFT(  8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );

  CHECKED_INC( 3*2U ); /* major, minor, patch (all u16s)*/
  CHECK_LEFT(    1U ); uchar has_commit = FD_LOAD( uchar, CURSOR )                              ; INC(  1U );
  if( has_commit ) {
    CHECKED_INC( 4U );
  }
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_version_parse( fd_gossip_view_crds_value_t * crds_val,
                                  uchar const *                 payload,
                                  ulong                         payload_sz,
                                  ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  INC( fd_gossip_msg_crds_legacy_version_parse( crds_val, payload, payload_sz, start_offset ) );
  CHECKED_INC( 4U ); /* feature set */
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_node_instance_parse( fd_gossip_view_crds_value_t * crds_val,
                                        uchar const *                 payload,
                                        ulong                         payload_sz,
                                        ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT( 32U ); crds_val->pubkey_off           = CUR_OFFSET                                     ; INC( 32U );
  CHECK_LEFT(  8U ); crds_val->wallclock_nanos      = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );
  CHECKED_INC( 8U ); /* timestamp (currently unused) */
  CHECK_LEFT(  8U ); crds_val->node_instance->token = FD_LOAD( ulong, CURSOR )                       ; INC(  8U );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_duplicate_shred_parse( fd_gossip_view_crds_value_t * crds_val,
                                          uchar const *                 payload,
                                          ulong                         payload_sz,
                                          ulong                         start_offset ) {
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
                                          ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT(                 32U ); crds_val->pubkey_off = CUR_OFFSET                                          ; INC(                 32U );
  CHECK_LEFT(                 40U ); crds_val->snapshot_hashes->full_off = CUR_OFFSET                           ; INC(                 40U );
  CHECK_LEFT(                  8U ); ulong incremental_len = FD_LOAD( ulong, CURSOR )                           ; INC(                  8U );
  CHECK_LEFT( incremental_len*40U ); crds_val->snapshot_hashes->inc_off = CUR_OFFSET                            ; INC( incremental_len*40U );
  CHECK_LEFT(                  8U ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(                  8U );
  crds_val->snapshot_hashes->inc_len = incremental_len;
  return BYTES_CONSUMED;
}

static ulong
version_parse( fd_contact_info_t * ci,
               uchar const *       payload,
               ulong               payload_sz,
               ulong               start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  ulong decode_sz;
  READ_CHECKED_COMPACT_U16( decode_sz, ci->version.major, CUR_OFFSET ) ; INC( decode_sz );
  READ_CHECKED_COMPACT_U16( decode_sz, ci->version.minor, CUR_OFFSET ) ; INC( decode_sz );
  READ_CHECKED_COMPACT_U16( decode_sz, ci->version.patch, CUR_OFFSET ) ; INC( decode_sz );
  CHECK_LEFT( 4U ); ci->version.commit      = FD_LOAD( uint, CURSOR )  ; INC( 4U );
  CHECK_LEFT( 4U ); ci->version.feature_set = FD_LOAD( uint, CURSOR )  ; INC( 4U );
  READ_CHECKED_COMPACT_U16( decode_sz, ci->version.client, CUR_OFFSET ); INC( decode_sz );
  return BYTES_CONSUMED;
}

/* Contact Infos are checked for the following properties
   - All addresses in addrs are unique
   - Each socket entry references a unique socket tag
   - Socket offsets do not cause an overflow
   - All addresses are referenced at least once across all sockets
   https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/contact_info.rs#L599

   We perform additional checks when populating the
   contact_info->sockets array:
   - Address must be ipv4
   - Socket tag must fall within range of tags defined in
     fd_gossip_types.c (bounded by FD_CONTACT_INFO_SOCKET_LAST)

  Note that these additional checks are not parser failure conditions.
  These sockets are simply skipped when populating
  contact_info->sockets (marked as null entries). The CRDS value is
  considered valid and is still processed into the CRDS table. */

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
                                       ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT( 32U ); crds_val->pubkey_off = CUR_OFFSET                                                     ; INC( 32U );
  ulong wallclock = 0UL;
  INC( decode_u64_varint( payload, payload_sz, CUR_OFFSET, &wallclock ) );
  crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( wallclock );

  fd_contact_info_t * ci = crds_val->ci_view->contact_info;
  fd_memcpy( ci->pubkey.uc, payload + crds_val->pubkey_off, 32UL );
  ci->wallclock_nanos = crds_val->wallclock_nanos;

  CHECK_LEFT( 8U ); ci->instance_creation_wallclock_nanos = FD_MICRO_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC(  8U );
  CHECK_LEFT( 2U ); ci->shred_version = FD_LOAD( ushort, CURSOR )                                          ; INC(  2U );
  INC( version_parse( ci, payload, payload_sz, CUR_OFFSET ) );

  ulong decode_sz, addrs_len;
  READ_CHECKED_COMPACT_U16( decode_sz, addrs_len, CUR_OFFSET )                                             ; INC( decode_sz );
  CHECK( addrs_len<=FD_GOSSIP_CONTACT_INFO_MAX_ADDRESSES );

  ip4_seen_set_t ip4_seen[ ip4_seen_set_word_cnt ];
  ip6_seen_set_t ip6_seen[ ip6_seen_set_word_cnt ];
  ip4_seen_set_new( ip4_seen );
  ip6_seen_set_new( ip6_seen );

  uint ip4_addrs[ FD_GOSSIP_CONTACT_INFO_MAX_ADDRESSES ];

  for( ulong i=0UL; i<addrs_len; i++ ) {
    CHECK_LEFT( 4U ); uchar is_ip6 = FD_LOAD( uchar, CURSOR )                                              ; INC( 4U );
    if( FD_LIKELY( !is_ip6 ) ) {
      CHECK_LEFT( 4U ); ip4_addrs[ i ] = FD_LOAD( uint, CURSOR )                                           ; INC( 4U );
      ulong idx = fd_uint_hash( ip4_addrs[ i ] )&(ip4_seen_set_max( ip4_seen )-1);
      CHECK( !ip4_seen_set_test( ip4_seen, idx ) ); /* Should not be set initially */
      ip4_seen_set_insert( ip4_seen, idx );
    } else {
      /* TODO: Support IPv6 ... */
      CHECK_LEFT( 16U ); ipv6_addr_t * ip6_addr = (ipv6_addr_t *)CURSOR                                    ; INC( 16U );
      ulong idx = ipv6_hash( ip6_addr )&(ip6_seen_set_max( ip6_seen )-1);
      CHECK( !ip6_seen_set_test( ip6_seen, idx ) );
      ip6_seen_set_insert( ip6_seen, idx );
      ip4_addrs[ i ] = 0U; /* Mark as null entry */
    }
  }
  crds_val->ci_view->ip6_cnt = ip6_seen_set_cnt( ip6_seen );

  addr_idx_set_t ip_addr_hits[ addr_idx_set_word_cnt ];
  socket_tag_set_t socket_tag_hits[ socket_tag_set_word_cnt ];
  addr_idx_set_new( ip_addr_hits );
  socket_tag_set_new( socket_tag_hits );

  ulong sockets_len;
  READ_CHECKED_COMPACT_U16( decode_sz, sockets_len, CUR_OFFSET )                                           ; INC( decode_sz );
  CHECK( sockets_len<=FD_GOSSIP_CONTACT_INFO_MAX_SOCKETS );

  fd_memset( ci->sockets, 0, (FD_CONTACT_INFO_SOCKET_LAST+1UL)*sizeof(fd_ip4_port_t) );
  crds_val->ci_view->unrecognized_socket_tag_cnt = 0UL;

  ushort cur_port = 0U;
  for( ulong i=0UL; i<sockets_len; i++ ) {
    uchar tag, addr_idx;
    CHECK_LEFT( 1U ); tag      = FD_LOAD( uchar, CURSOR )                                                  ; INC( 1U );
    CHECK_LEFT( 1U ); addr_idx = FD_LOAD( uchar, CURSOR )                                                  ; INC( 1U );

    ushort offset;
    READ_CHECKED_COMPACT_U16( decode_sz, offset, CUR_OFFSET )                                              ; INC( decode_sz );
    CHECK( ((uint)cur_port + (uint)offset)<=(uint)USHORT_MAX ); /* overflow check */
    cur_port = (ushort)(cur_port + offset);
    CHECK( !socket_tag_set_test( socket_tag_hits, tag ) ); socket_tag_set_insert( socket_tag_hits, tag );
    CHECK( addr_idx<addrs_len );
    addr_idx_set_insert( ip_addr_hits, addr_idx );

    if( FD_LIKELY( tag<=FD_CONTACT_INFO_SOCKET_LAST ) ) {
      if( FD_UNLIKELY( !!ip4_addrs[ addr_idx ] ) ) {
        ci->sockets[ tag ].addr = ip4_addrs[ addr_idx ];
        ci->sockets[ tag ].port = fd_ushort_bswap( cur_port ); /* TODO: change this to host order */
      }
    } else {
      crds_val->ci_view->unrecognized_socket_tag_cnt++;
    }
  }
  CHECK( addr_idx_set_cnt( ip_addr_hits )==addrs_len );

  /* extensions are currently unused */
  READ_CHECKED_COMPACT_U16( decode_sz, crds_val->ci_view->ext_len, CUR_OFFSET )                            ; INC( decode_sz );
  CHECKED_INC( 4*crds_val->ci_view->ext_len );

  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_last_voted_fork_slots_parse( fd_gossip_view_crds_value_t * crds_val,
                                                uchar const *                 payload,
                                                ulong                         payload_sz,
                                                ulong                         start_offset ) {
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
                                                ulong                         start_offset ) {
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
                               ulong                         start_offset ) {
  switch( crds_val->tag ) {
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
                               ulong                         start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );

  for( ulong i=0UL; i<crds_values_len; i++ ) {
    fd_gossip_view_crds_value_t * crds_view = &crds_values[i];
    CHECK_LEFT( 64U ); crds_view->signature_off = CUR_OFFSET             ; INC( 64U );
    CHECK_LEFT(  4U ); crds_view->tag           = FD_LOAD(uchar, CURSOR ); INC(  4U );
    ulong crds_data_sz = fd_gossip_msg_crds_data_parse( crds_view, payload, payload_sz, CUR_OFFSET );
    crds_view->length  = (ushort)(crds_data_sz + 64U + 4U); /* signature + tag */
    INC( crds_data_sz );
  }
  return BYTES_CONSUMED;
}
static ulong
fd_gossip_msg_ping_pong_parse( fd_gossip_view_t * view,
                               uchar const *      payload,
                               ulong              payload_sz,
                               ulong              start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  /* Ping/Pong share the same memory layout */
  FD_STATIC_ASSERT( sizeof(fd_gossip_view_ping_t)==sizeof(fd_gossip_view_pong_t), compat );
  CHECK_LEFT( sizeof(fd_gossip_view_ping_t) );
  view->ping_pong_off = CUR_OFFSET;
  INC( sizeof(fd_gossip_view_ping_t) );

  return BYTES_CONSUMED;
}

static ulong
fd_gossip_pull_req_parse( fd_gossip_view_t * view,
                          uchar const *      payload,
                          ulong              payload_sz,
                          ulong              start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  fd_gossip_view_pull_request_t * pr = view->pull_request;

  CHECK_LEFT(                    8U ); pr->bloom_keys_len    = FD_LOAD( ulong, CURSOR ) ; INC( 8U );
  CHECK( pr->bloom_keys_len<=((ULONG_MAX-7U)/8U) );
  CHECK_LEFT( pr->bloom_keys_len*8U ); pr->bloom_keys_offset = CUR_OFFSET               ; INC( pr->bloom_keys_len*8U );

  uchar has_bits = 0;
  CHECK_LEFT(                    1U ); has_bits = FD_LOAD( uchar, CURSOR )              ; INC( 1U );
  if( has_bits ) {
    CHECK_LEFT(                  8U ); pr->bloom_len         = FD_LOAD( ulong, CURSOR ) ; INC( 8U );
    CHECK( pr->bloom_len<=((ULONG_MAX-7U)/8U) );
    CHECK_LEFT(    pr->bloom_len*8U ); pr->bloom_bits_offset = CUR_OFFSET               ; INC( pr->bloom_len*8U );
    CHECK_LEFT(                  8U ); pr->bloom_bits_cnt    = FD_LOAD( ulong, CURSOR ) ; INC( 8U );
  } else {
    pr->bloom_len = 0U;
  }
  CHECK_LEFT(                    8U ); pr->bloom_num_bits_set = FD_LOAD( ulong, CURSOR ); INC( 8U );
  CHECK_LEFT(                    8U ); pr->mask      = FD_LOAD( ulong, CURSOR )         ; INC( 8U );
  CHECK_LEFT(                    4U ); pr->mask_bits = FD_LOAD( uint, CURSOR )          ; INC( 4U );

  INC( fd_gossip_msg_crds_vals_parse( pr->pr_ci,
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
                                    ulong              start_offset ) {
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
                           ulong              start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  fd_gossip_view_prune_t * prune = view->prune;
  CHECKED_INC( 32U ); /* pubkey is sent twice */
  CHECK_LEFT(                   32U ); prune->pubkey_off      = CUR_OFFSET               ; INC( 32U );
  CHECK_LEFT(                    8U ); prune->origins_len     = FD_LOAD( ulong, CURSOR ) ; INC(  8U );
  CHECK( prune->origins_len<=((ULONG_MAX-31U)/32U) );
  CHECK_LEFT( prune->origins_len*32U ); prune->origins_off    = CUR_OFFSET               ; INC( prune->origins_len*32U );
  CHECK_LEFT(                   64U ); prune->signature_off   = CUR_OFFSET               ; INC( 64U );
  CHECK_LEFT(                   32U ); prune->destination_off = CUR_OFFSET               ; INC( 32U );
  CHECK_LEFT(                    8U ); prune->wallclock       = FD_LOAD( ulong, CURSOR ) ; INC(  8U );

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
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      INC( fd_gossip_msg_prune_parse( view, payload, payload_sz, CUR_OFFSET ) );
      break;
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
      INC( fd_gossip_msg_ping_pong_parse( view, payload, payload_sz, CUR_OFFSET ) );
      break;
    default:
      FD_LOG_WARNING(( "Unknown Gossip message type %d", view->tag ));
      return 0;
  }
  CHECK( payload_sz==CUR_OFFSET );
  return BYTES_CONSUMED;
}
