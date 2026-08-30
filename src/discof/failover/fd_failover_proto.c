#include "fd_failover_proto.h"

#include <string.h>

int
fd_failover_hello_check( fd_failover_hello_t const * self,
                         fd_failover_hello_t const * peer ) {
  if( FD_UNLIKELY( self->version!=peer->version ) )                              return FD_FAILOVER_HELLO_ERR_VERSION;
  if( FD_UNLIKELY( self->role>FD_FAILOVER_ROLE_ACTIVE ||
                   peer->role>FD_FAILOVER_ROLE_ACTIVE ) )                        return FD_FAILOVER_HELLO_ERR_ROLE;
  if( FD_UNLIKELY( !memcmp( self->session_nonce, peer->session_nonce, 16UL ) ) ) return FD_FAILOVER_HELLO_ERR_NONCE;
  if( FD_UNLIKELY(  memcmp( self->staked_pubkey, peer->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_STAKED;
  if( FD_UNLIKELY(  memcmp( self->vote_account,  peer->vote_account,  32UL ) ) ) return FD_FAILOVER_HELLO_ERR_VOTE_ACCT;
  if( FD_UNLIKELY( !memcmp( self->junk_pubkey,   peer->junk_pubkey,   32UL ) ) ) return FD_FAILOVER_HELLO_ERR_JUNK_EQ;
  if( FD_UNLIKELY( !memcmp( self->junk_pubkey,   self->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_JUNK_STAKE;
  if( FD_UNLIKELY( !memcmp( peer->junk_pubkey,   peer->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_JUNK_STAKE;
  if( FD_UNLIKELY( self->role==FD_FAILOVER_ROLE_ACTIVE &&
                   peer->role==FD_FAILOVER_ROLE_ACTIVE &&
                   self->term==peer->term ) )                                    return FD_FAILOVER_HELLO_ERR_BOTH_ACT;
  return FD_FAILOVER_HELLO_OK;
}

ulong
fd_failover_session_step( ulong state,
                          int   dial_peer,
                          int   event ) {
  if( FD_UNLIKELY( state>=FD_FAILOVER_SESSION_CNT ) )       return state;
  if( FD_UNLIKELY( dial_peer<0 || dial_peer>1 ) )           return state;
  if( FD_UNLIKELY( event<0 || event>=FD_FAILOVER_EV_CNT ) ) return state;
  if( FD_UNLIKELY( state==FD_FAILOVER_SESSION_REJECTED ) )  return FD_FAILOVER_SESSION_REJECTED;

  switch( state ) {
  case FD_FAILOVER_SESSION_LISTENING:
    if( event==FD_FAILOVER_EV_PEER_CONNECTED ) return FD_FAILOVER_SESSION_HELLO;
    break;
  case FD_FAILOVER_SESSION_DIALING:
    if( event==FD_FAILOVER_EV_CONNECTED )      return FD_FAILOVER_SESSION_HELLO;
    if( event==FD_FAILOVER_EV_TIMEOUT   )      return FD_FAILOVER_SESSION_BACKOFF;
    if( event==FD_FAILOVER_EV_LINK_LOST )      return FD_FAILOVER_SESSION_BACKOFF;
    break;
  case FD_FAILOVER_SESSION_HELLO:
    if( event==FD_FAILOVER_EV_HELLO_OK    )    return FD_FAILOVER_SESSION_PAIRED;
    if( event==FD_FAILOVER_EV_HELLO_FATAL )    return FD_FAILOVER_SESSION_REJECTED;
    if( event==FD_FAILOVER_EV_TIMEOUT     )    return FD_FAILOVER_SESSION_BACKOFF;
    if( event==FD_FAILOVER_EV_LINK_LOST   )    return FD_FAILOVER_SESSION_BACKOFF;
    break;
  case FD_FAILOVER_SESSION_PAIRED:
    if( event==FD_FAILOVER_EV_TIMEOUT   )      return FD_FAILOVER_SESSION_BACKOFF;
    if( event==FD_FAILOVER_EV_LINK_LOST )      return FD_FAILOVER_SESSION_BACKOFF;
    break;
  case FD_FAILOVER_SESSION_BACKOFF:
    if( event==FD_FAILOVER_EV_RETRY ) {
      return dial_peer ? FD_FAILOVER_SESSION_DIALING : FD_FAILOVER_SESSION_LISTENING;
    }
    break;
  }
  return state;
}
