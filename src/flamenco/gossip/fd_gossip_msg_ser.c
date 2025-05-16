#include "fd_gossip_msg.h"

#define CHECK_INIT( payload, payload_sz )         \
  uchar const * _payload = (payload);             \
  ulong _payload_sz = (payload_sz);               \
  ulong _bytes_consumed = 0;                      \
  ulong i = 0;                                    \
  (void) _payload;                                \
  (void) _bytes_consumed;                         \

#define CHECK( cond ) do {              \
  if( FD_UNLIKELY( !(cond) ) ) {        \
    return 0;                           \
  }                                     \
} while( 0 ) 

#define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-i) )


static ulong
fd_gossip_msg_ping_pong_serialize( fd_gossip_message_t const * msg,
                                   uchar *                     payload,
                                   ulong                       payload_sz ) {
  CHECK_INIT( payload, payload_sz );
  fd_gossip_ping_pong_t const * piong = msg->piong;
  CHECK_LEFT( 32 + 32 + 64 ); /* Pubkey + Hash/Token + Signature */
  fd_memcpy( payload+i, piong->from, 32UL ); i+=32UL; /* Pubkey */
  fd_memcpy( payload+i, piong->hash, 32UL ); i+=32UL; /* Hash */
  fd_memcpy( payload+i, piong->signature, 64UL ); i+=64UL; /* Signature */

  return i;
}

ulong
fd_gossip_msg_serialize( fd_gossip_message_t const * msg,
                         uchar *                  payload,
                         ulong                    payload_sz ) {
  /* Serialize tag */
  if( FD_UNLIKELY( msg->tag>=FD_GOSSIP_MESSAGE_END ) ) {
    FD_LOG_ERR(( "Invalid message tag %d", msg->tag ));
    return 0;
  }

  CHECK_INIT( payload, payload_sz );
  CHECK_LEFT( 4UL ); /* Tag/Discriminant is actually 4b */
  payload[i] = msg->tag; i+=4UL;

  ulong inner_payload_sz = 0UL;
  switch( msg->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      FD_LOG_ERR(( "Gossip message type %d serializer not implemented", msg->tag ));
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      FD_LOG_ERR(( "Gossip message type %d serializer not implemented", msg->tag ));
      break;
    case FD_GOSSIP_MESSAGE_PUSH:
      FD_LOG_ERR(( "Gossip message type %d serializer not implemented", msg->tag ));
      break;
    case FD_GOSSIP_MESSAGE_PRUNE:
      FD_LOG_ERR(( "Gossip message type %d serializer not implemented", msg->tag ));
      break;
    case FD_GOSSIP_MESSAGE_PING:
    case FD_GOSSIP_MESSAGE_PONG:
      inner_payload_sz = fd_gossip_msg_ping_pong_serialize( msg, payload+i, payload_sz-i );
      break;
    default:
      FD_LOG_ERR(( "Unknown message tag %d", msg->tag ));
  }
  CHECK( inner_payload_sz!=0UL );
  return payload_sz + i;
}
