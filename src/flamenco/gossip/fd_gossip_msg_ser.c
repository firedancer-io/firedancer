#include "fd_gossip_private.h"

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

ulong
fd_gossip_init_msg_payload( uchar * payload,
                            ulong   payload_sz,
                            uchar   tag ) {
  CHECK_INIT( payload, payload_sz );
  CHECK_LEFT( 4UL ); /* Tag/Discriminant is actually 4b */
  if( FD_UNLIKELY( tag>FD_GOSSIP_MESSAGE_LAST ) ) {
    FD_LOG_ERR(( "Invalid message tag %d", tag ));
  }
  payload[i] = tag; i+=4UL;
  return i; /* Return size of payload so far */
}
