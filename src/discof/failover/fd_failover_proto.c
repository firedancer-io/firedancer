#include "fd_failover_proto.h"

#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../disco/keyguard/fd_keyguard.h"

FD_STATIC_ASSERT( FD_KEYGUARD_MEMBER_CERT_MSG_SZ==FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ+32UL, member_cert_msg );

int
fd_failover_hello_check( fd_failover_hello_t const * self,
                         fd_failover_hello_t const * peer ) {
  if( FD_UNLIKELY( self->version!=peer->version ) )                                return FD_FAILOVER_HELLO_ERR_VERSION;
  if( FD_UNLIKELY( self->role>FD_FAILOVER_ROLE_ACTIVE ||
                   peer->role>FD_FAILOVER_ROLE_ACTIVE ) )                          return FD_FAILOVER_HELLO_ERR_ROLE;
  if( FD_UNLIKELY( self->mode>=FD_FAILOVER_MODE_CNT ||
                   self->mode!=peer->mode ) )                                      return FD_FAILOVER_HELLO_ERR_MODE;
  if( FD_UNLIKELY( !self->boot_id || !peer->boot_id ) )                            return FD_FAILOVER_HELLO_ERR_BOOT_ID;
  if( FD_UNLIKELY( !fd_memeq( self->staked_pubkey, peer->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_STAKED;
  if( FD_UNLIKELY( !fd_memeq( self->vote_account,  peer->vote_account,  32UL ) ) ) return FD_FAILOVER_HELLO_ERR_VOTE_ACCT;
  if( FD_UNLIKELY(  fd_memeq( self->junk_pubkey,   peer->junk_pubkey,   32UL ) ) ) return FD_FAILOVER_HELLO_ERR_JUNK_EQ;
  if( FD_UNLIKELY(  fd_memeq( self->junk_pubkey,   self->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_JUNK_STAKE;
  if( FD_UNLIKELY(  fd_memeq( peer->junk_pubkey,   peer->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_JUNK_STAKE;
  if( FD_UNLIKELY( self->role==FD_FAILOVER_ROLE_ACTIVE &&
                   peer->role==FD_FAILOVER_ROLE_ACTIVE ) )                         return FD_FAILOVER_HELLO_ERR_BOTH_ACT;
  return FD_FAILOVER_HELLO_OK;
}

void
fd_failover_member_cert_msg( uchar       out[ 48 ],
                             uchar const junk_pubkey[ 32 ] ) {
  fd_memcpy( out,                                   FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memcpy( out+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, junk_pubkey,                    32UL                              );
}

int
fd_failover_member_cert_check( fd_failover_hello_t const * hello,
                               fd_sha512_t *               sha ) {
  uchar msg[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  fd_failover_member_cert_msg( msg, hello->junk_pubkey );
  if( FD_UNLIKELY( fd_ed25519_verify( msg, sizeof(msg), hello->member_cert, hello->staked_pubkey, sha )!=FD_ED25519_SUCCESS ) ) {
    return FD_FAILOVER_HELLO_ERR_CERT;
  }
  return FD_FAILOVER_HELLO_OK;
}

ulong
fd_failover_session_init( int dial_peer ) {
  return dial_peer ? FD_FAILOVER_SESSION_BACKOFF : FD_FAILOVER_SESSION_LISTENING;
}

ulong
fd_failover_session_step( ulong state,
                          int   dial_peer,
                          int   event ) {
  if( FD_UNLIKELY( state>=FD_FAILOVER_SESSION_CNT ) )       return state;
  if( FD_UNLIKELY( dial_peer<0 || dial_peer>1 ) )           return state;
  if( FD_UNLIKELY( event<0 || event>=FD_FAILOVER_EV_CNT ) ) return state;

  int lost = event==FD_FAILOVER_EV_LINK_LOST || event==FD_FAILOVER_EV_TIMEOUT || event==FD_FAILOVER_EV_HELLO_FATAL;

  if( !dial_peer ) {
    /* Candidates come and go without changing the listener's state. */
    switch( state ) {
    case FD_FAILOVER_SESSION_LISTENING:
      if( event==FD_FAILOVER_EV_HELLO_OK ) return FD_FAILOVER_SESSION_PAIRED;
      break;
    case FD_FAILOVER_SESSION_PAIRED:
      if( lost )                           return FD_FAILOVER_SESSION_LISTENING;
      break;
    }
    return state;
  }

  switch( state ) {
  case FD_FAILOVER_SESSION_BACKOFF:
    if( event==FD_FAILOVER_EV_RETRY )     return FD_FAILOVER_SESSION_DIALING;
    break;
  case FD_FAILOVER_SESSION_DIALING:
    if( event==FD_FAILOVER_EV_CONNECTED ) return FD_FAILOVER_SESSION_HELLO;
    if( lost )                            return FD_FAILOVER_SESSION_BACKOFF;
    break;
  case FD_FAILOVER_SESSION_HELLO:
    if( event==FD_FAILOVER_EV_HELLO_OK )  return FD_FAILOVER_SESSION_PAIRED;
    if( lost )                            return FD_FAILOVER_SESSION_BACKOFF;
    break;
  case FD_FAILOVER_SESSION_PAIRED:
    if( lost )                            return FD_FAILOVER_SESSION_BACKOFF;
    break;
  }
  return state;
}

