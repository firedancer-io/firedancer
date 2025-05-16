#include "fd_gossip_msg.h"
void
fd_gossip_msg_init( fd_gossip_message_t * msg ) {
  fd_memset( msg, 0, sizeof(fd_gossip_message_t) );
  msg->tag = FD_GOSSIP_MESSAGE_END; /* default to invalid message */
}
