#include "fd_gossip_private.h"
// #include "../../ballet/txn/fd_compact_u16.h"
#include "../../disco/fd_disco_base.h"


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
    return 0;                           \
  }                                     \
} while( 0 )

#define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-_i) )

#define INC( n ) (_i += (n))

#define CHECKED_INC( n ) do { \
  CHECK_LEFT( n );            \
  INC( n );                   \
} while( 0 )

#define CUR_OFFSET      (_i)
#define CURSOR          (_payload + _i)
#define BYTES_CONSUMED  (_i-_offset)
#define BYTES_REMAINING (_payload_sz-_i)

/*
#define READ_CHECKED_COMPACT_U16( out_sz, var_name, where )                 \
  do {                                                                      \
    ulong _where = (where);                                                 \
    ulong _out_sz = fd_cu16_dec_sz( _payload+_where, _payload_sz-_where );  \
    CHECK( _out_sz );                                                       \
    (var_name) = fd_cu16_dec_fixed( _payload+_where, _out_sz );             \
    (out_sz)   = _out_sz;                                                   \
  } while( 0 )
*/

static ulong
fd_gossip_msg_crds_vote_parse( fd_gossip_view_crds_value_t * crds_val,
                               uchar const *                 payload,
                               ulong                         payload_sz,
                               ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  CHECK_LEFT(  1UL ); crds_val->vote->index = FD_LOAD( uchar, CURSOR ); INC(  1UL );
  CHECK_LEFT( 32UL ); crds_val->pubkey_off  = CUR_OFFSET              ; INC( 32UL );
  ulong transaction_sz;
  fd_txn_parse_core( CURSOR, BYTES_REMAINING, NULL, NULL, &transaction_sz );
  crds_val->vote->transaction_off = CUR_OFFSET;
  crds_val->vote->transaction_sz  = transaction_sz;
  INC( transaction_sz );
  return BYTES_CONSUMED;
}

static ulong
fd_gossip_msg_crds_legacy_contact_info_parse( fd_gossip_view_crds_value_t * crds_val,
                                              uchar const *                 payload,
                                              ulong                         payload_sz,
                                              ushort                        start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  /* https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/legacy_contact_info.rs#L13 */
  CHECK_LEFT( 32UL ); crds_val->pubkey_off = CUR_OFFSET; INC( 32UL ); /* pubkey */
  for( ulong i=0UL; i<10; i++ ) {
    CHECK_LEFT( 4UL ); uint is_ip4 = FD_LOAD( uint, CURSOR ); INC( 4UL ); /* is_ip4 */
    if( is_ip4 ){
      CHECKED_INC(  4UL ); /* ip4 */
      CHECKED_INC(  2UL ); /* port */
    } else {
      CHECKED_INC( 16UL ); /* ip6 */
      CHECKED_INC(  2UL ); /* port */
      CHECKED_INC(  4UL ); /* flowinfo */
      CHECKED_INC(  4UL ); /* scope_id */
    }
  }
  CHECK_LEFT( 8UL ); crds_val->wallclock_nanos = FD_MILLI_TO_NANOSEC( FD_LOAD( ulong, CURSOR ) ); INC( 8UL );
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
    case FD_GOSSIP_VALUE_LEGACY_SNAPSHOT_HASHES:
    case FD_GOSSIP_VALUE_ACCOUNT_HASHES:
    case FD_GOSSIP_VALUE_EPOCH_SLOTS:
    case FD_GOSSIP_VALUE_LEGACY_VERSION:
    case FD_GOSSIP_VALUE_VERSION:
    case FD_GOSSIP_VALUE_NODE_INSTANCE:
    case FD_GOSSIP_VALUE_DUPLICATE_SHRED:
    case FD_GOSSIP_VALUE_SNAPSHOT_HASHES:
    case FD_GOSSIP_VALUE_CONTACT_INFO:
    case FD_GOSSIP_VALUE_RESTART_LAST_VOTED_FORK_SLOTS:
    case FD_GOSSIP_VALUE_RESTART_HEAVIEST_FORK:
    default:
      return 0; /* Not implemented yet */
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
    CHECK_LEFT( 64UL ); crds_view->signature_off = CUR_OFFSET             ; INC( 64UL );
    CHECK_LEFT( 4UL );  crds_view->tag           = FD_LOAD(uchar, CURSOR ); INC(  4UL );
    ulong crds_data_sz = fd_gossip_msg_crds_data_parse( crds_view, payload, payload_sz, CUR_OFFSET );
    crds_view->length  = (ushort)crds_data_sz + 64UL + 4UL; /* signature + tag */
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

  CHECK_LEFT(                      8UL ); pr->bloom_keys_len    = FD_LOAD( ulong, CURSOR ) ; INC( 8UL );
  CHECK_LEFT(   pr->bloom_keys_len*8UL ); pr->bloom_keys_offset = CUR_OFFSET               ; INC( pr->bloom_keys_len*8UL );

  uchar has_bits = 0;
  CHECK_LEFT(                      1UL ); has_bits = FD_LOAD( uchar, CURSOR )              ; INC( 1UL );
  if( has_bits ) {
    CHECK_LEFT(                    8UL ); pr->bloom_bits_len = FD_LOAD( ulong, CURSOR )    ; INC( 8UL );
    CHECK_LEFT( pr->bloom_bits_len*8UL ); pr->bloom_bits_offset = CUR_OFFSET               ; INC( pr->bloom_bits_len*8UL );
    /* bits_len (TODO: check this vs bitvec len above?) */
    CHECK_LEFT(                    8UL ); pr->bloom_len = FD_LOAD( ulong, CURSOR )         ; INC( 8UL );
  } else {
    pr->bloom_bits_len = 0UL;
  }
  CHECK_LEFT(                      8UL ); pr->bloom_num_bits_set = FD_LOAD( ulong, CURSOR ); INC( 8UL );
  CHECK_LEFT(                      8UL ); pr->mask      = FD_LOAD( ulong, CURSOR )         ; INC( 8UL );
  CHECK_LEFT(                      4UL ); pr->mask_bits = FD_LOAD( uint, CURSOR )          ; INC( 4UL );

  /* TODO: Parse contact info */

  return BYTES_CONSUMED;
}

ulong
fd_gossip_msg_parse( fd_gossip_view_t *   view,
                     uchar const *        payload,
                     ulong                payload_sz ) {
  CHECK_INIT( payload, payload_sz, 0UL );
  CHECK(     payload_sz<=FD_GOSSIP_MTU );

  /* Extract enum discriminant/tag (4b encoded) */
  uint tag = 0;
  CHECK_LEFT(                      4UL );   tag = FD_LOAD( uchar, CURSOR ); INC( 4UL );
  CHECK(   tag<=FD_GOSSIP_MESSAGE_LAST );
  view->tag = (uchar)tag;

  switch( view->tag ){
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      fd_gossip_pull_req_parse( view, payload, payload_sz, CUR_OFFSET );
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
    case FD_GOSSIP_MESSAGE_PUSH:
    case FD_GOSSIP_MESSAGE_PRUNE:
      FD_LOG_ERR(( "Gossip message type %d parser not implemented", view->tag ));
      break;
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
      CUR_OFFSET+=fd_gossip_msg_ping_pong_parse( view, payload, payload_sz, CUR_OFFSET );
      CHECK( payload_sz==CUR_OFFSET ); /* should be fully parsed at this point */
      break;
    default:
      return 0;
  }
  CHECK( CUR_OFFSET<=payload_sz );
  return BYTES_CONSUMED;
}
