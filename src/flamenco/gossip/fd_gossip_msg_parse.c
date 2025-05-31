#include "fd_gossip_private.h"
// #include "../../ballet/txn/fd_compact_u16.h"
#include "../../disco/fd_disco_base.h"


/* Adapted from fd_txn_parse.c */
#define CHECK_INIT( payload, payload_sz, offset )   \
  uchar const * _payload        = (payload);        \
  ulong const   _payload_sz     = (payload_sz);     \
  ulong         _bytes_consumed = 0;                \
  ulong const   _offset         = (offset);         \
  ulong         i               = (offset);         \
  (void)        _payload;                           \
  (void)        _bytes_consumed;                    \
  (void)        _offset;                            \

#define CHECK( cond ) do {              \
  if( FD_UNLIKELY( !(cond) ) ) {        \
    return 0;                           \
  }                                     \
} while( 0 )

#define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-i) )

#define GET_OFFSET( i ) (ushort)(i)

// #define READ_CHECKED_COMPACT_U16( out_sz, var_name, where )                 \
//   do {                                                                      \
//     ulong _where = (where);                                                 \
//     ulong _out_sz = fd_cu16_dec_sz( _payload+_where, _payload_sz-_where );  \
//     CHECK( _out_sz );                                                       \
//     (var_name) = fd_cu16_dec_fixed( _payload+_where, _out_sz );             \
//     (out_sz)   = _out_sz;                                                   \
//   } while( 0 )

static ulong
fd_gossip_msg_ping_pong_parse( fd_gossip_view_t * view,
                               uchar const *      payload,
                               ulong              payload_sz,
                               ulong              start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  /* Ping/Pong share the same memory layout */
  fd_gossip_view_ping_t * ping = view->ping;
  CHECK_LEFT( 32UL ); ping->from_off  = GET_OFFSET(i); i+=32UL; /* Pubkey */
  CHECK_LEFT( 32UL ); ping->token_off = GET_OFFSET(i); i+=32UL; /* Token/Hash */
  CHECK_LEFT( 64UL ); ping->token_off = GET_OFFSET(i); i+=64UL; /* Signature */
  return i;
}

static ulong
fd_gossip_pull_req_parse( fd_gossip_view_t * view,
                          uchar const *      payload,
                          ulong              payload_sz,
                          ulong              start_offset ) {
  CHECK_INIT( payload, payload_sz, start_offset );
  fd_gossip_view_pull_request_t * pr = view->pull_request;

  CHECK_LEFT(                      8UL ); pr->bloom_keys_len    = FD_LOAD( ulong, payload+i ) ; i+=8UL;
  CHECK_LEFT(   pr->bloom_keys_len*8UL ); pr->bloom_keys_offset = GET_OFFSET(i)               ; i+=pr->bloom_keys_len*8UL;

  uchar has_bits = 0;
  CHECK_LEFT(                      1UL ); has_bits = FD_LOAD( uchar, payload+i )              ; i++;
  if( has_bits ) {
    CHECK_LEFT(                    8UL ); pr->bloom_bits_len = FD_LOAD( ulong, payload+i )    ; i+=8UL;
    CHECK_LEFT( pr->bloom_bits_len*8UL ); pr->bloom_bits_offset = GET_OFFSET(i)               ; i+=pr->bloom_bits_offset*8UL;
    /* bits_len (TODO: check this vs bitvec len above?) */
    CHECK_LEFT(                    8UL ); pr->bloom_len = FD_LOAD( ulong, payload+i )         ; i+=8UL;
  } else {
    pr->bloom_bits_len = 0UL;
  }
  CHECK_LEFT(                      8UL ); pr->bloom_num_bits_set = FD_LOAD( ulong, payload+i );        i+=8UL;

  CHECK_LEFT(                      8UL ); pr->mask      = FD_LOAD( ulong, payload+i )         ;        i+=8UL;
  CHECK_LEFT(                      4UL ); pr->mask_bits = FD_LOAD( uint, payload+i )          ;        i+=4UL;

  /* TODO: Parse contact info */

  return i;
}

ulong
fd_gossip_msg_parse( fd_gossip_view_t *   view,
                     uchar const *        payload,
                     ulong                payload_sz ) {
  CHECK_INIT( payload, payload_sz, 0UL );
  CHECK(     payload_sz<=FD_GOSSIP_MTU );

  /* Extract enum discriminant/tag (4b encoded) */
  uint tag = 0;
  CHECK_LEFT(                      4UL );   tag = payload[ i ];     i+=4;
  CHECK(   tag<=FD_GOSSIP_MESSAGE_LAST );
  view->tag = (uchar)tag;

  switch( view->tag ){
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
    case FD_GOSSIP_MESSAGE_PUSH:
    case FD_GOSSIP_MESSAGE_PRUNE:
      FD_LOG_ERR(( "Gossip message type %d parser not implemented", view->tag ));
      break;
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
      i = fd_gossip_msg_ping_pong_parse( view, payload, payload_sz, i );
      CHECK( payload_sz==i ); /* should be fully parsed at this point */
      break;
    default:
      return 0;
  }
  CHECK( i<=payload_sz );
  return i;
}
