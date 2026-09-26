#include "fd_failover_proto.h"

#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_serdes.h"

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
  if( FD_UNLIKELY( self->cfg_hash!=peer->cfg_hash ) )                              return FD_FAILOVER_HELLO_ERR_CFG;
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
      if( lost ) return FD_FAILOVER_SESSION_LISTENING;
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

int
fd_failover_status_decode( fd_failover_status_t * out,
                           uchar const *          payload,
                           ulong                  payload_sz ) {
  if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_status_t) ) ) return 0;

  fd_failover_status_t status;
  fd_memcpy( &status, payload, sizeof(status) );
  if( FD_UNLIKELY( status.role>FD_FAILOVER_ROLE_ACTIVE ||
                   ( status.flags & (uchar)~( FD_FAILOVER_STATUS_BUSY |
                                              FD_FAILOVER_STATUS_STUCK ) ) ||
                   ( status.last_vote_slot!=FD_FAILOVER_SLOT_NULL &&
                     status.replay_slot!=FD_FAILOVER_SLOT_NULL &&
                     status.last_vote_slot>status.replay_slot ) ||
                   ( status.root_slot!=FD_FAILOVER_SLOT_NULL &&
                     status.replay_slot!=FD_FAILOVER_SLOT_NULL &&
                     status.root_slot>status.replay_slot ) ||
                   ( status.root_slot!=FD_FAILOVER_SLOT_NULL &&
                     status.last_vote_slot!=FD_FAILOVER_SLOT_NULL &&
                     status.root_slot>status.last_vote_slot ) ) ) return 0;

  *out = status;
  return 1;
}

ulong
fd_failover_demoted_encode( uchar *       out,
                            ulong         handoff_id,
                            ulong         target_boot_id,
                            ulong         last_vote_slot,
                            uchar const * state,
                            ulong         state_sz ) {
  if( FD_UNLIKELY( !state_sz || state_sz>FD_FAILOVER_TOWER_STATE_MAX ) ) return 0UL;

  fd_failover_demoted_t demoted = {
    .handoff_id     = handoff_id,
    .target_boot_id = target_boot_id,
    .last_vote_slot = last_vote_slot,
    .mode           = (uchar)FD_FAILOVER_MODE_TOWER,
    .state_len      = (ushort)state_sz,
  };
  fd_memcpy( out, &demoted, sizeof(demoted) );
  fd_memcpy( out+sizeof(demoted), state, state_sz );
  return sizeof(demoted)+state_sz;
}

int
fd_failover_demoted_decode( fd_failover_demoted_t * out,
                            uchar const *           payload,
                            ulong                   payload_sz ) {
  if( FD_UNLIKELY( payload_sz<sizeof(fd_failover_demoted_t) ||
                   payload_sz>FD_FAILOVER_DEMOTED_PAYLOAD_MAX ) ) return 0;

  fd_failover_demoted_t demoted;
  fd_memcpy( &demoted, payload, sizeof(demoted) );

  ulong state_sz = payload_sz-sizeof(fd_failover_demoted_t);
  if( FD_UNLIKELY( (ulong)demoted.state_len!=state_sz ||
                   !state_sz ||
                   demoted.mode!=(uchar)FD_FAILOVER_MODE_TOWER ||
                   demoted.last_vote_slot==FD_FAILOVER_SLOT_NULL ) ) return 0;

  fd_compact_tower_sync_serde_t serde;
  fd_tower_vote_t               votes[ FD_TOWER_VOTE_MAX ];
  ulong                         vote_cnt;
  ulong                         root;
  if( FD_UNLIKELY( fd_compact_tower_sync_de_exact( &serde, payload+sizeof(fd_failover_demoted_t), state_sz ) ||
                   fd_compact_tower_sync_to_votes( &serde, votes, &vote_cnt, &root ) ||
                   !vote_cnt || votes[ vote_cnt-1UL ].slot!=demoted.last_vote_slot ) ) return 0;

  *out = demoted;
  return 1;
}

ulong
fd_failover_promote_ack_encode( uchar * out,
                                ulong   handoff_id ) {
  fd_failover_promote_ack_t ack = { .handoff_id=handoff_id };
  fd_memcpy( out, &ack, sizeof(ack) );
  return sizeof(ack);
}

ulong
fd_failover_promote_rejected_encode( uchar * out,
                                     ulong   handoff_id,
                                     uchar   reason ) {
  if( FD_UNLIKELY( reason==(uchar)FD_FAILOVER_REJECT_NONE || reason>=(uchar)FD_FAILOVER_REJECT_CNT ) ) return 0UL;
  fd_failover_promote_rejected_t rej = { .handoff_id=handoff_id, .reason=reason };
  fd_memcpy( out, &rej, sizeof(rej) );
  return sizeof(rej);
}

int
fd_failover_promote_ack_decode( fd_failover_promote_ack_t * out,
                                uchar const *               payload,
                                ulong                       payload_sz ) {
  if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_promote_ack_t) ) ) return 0;
  fd_memcpy( out, payload, sizeof(fd_failover_promote_ack_t) );
  return 1;
}

int
fd_failover_promote_rejected_decode( fd_failover_promote_rejected_t * out,
                                     uchar const *                    payload,
                                     ulong                            payload_sz ) {
  if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_promote_rejected_t) ) ) return 0;
  fd_failover_promote_rejected_t rej;
  fd_memcpy( &rej, payload, sizeof(rej) );
  if( FD_UNLIKELY( rej.reason==(uchar)FD_FAILOVER_REJECT_NONE || rej.reason>=(uchar)FD_FAILOVER_REJECT_CNT ) ) return 0;
  *out = rej;
  return 1;
}
