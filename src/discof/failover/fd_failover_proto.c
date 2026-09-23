#include "fd_failover_proto.h"

#include <string.h>

int
fd_failover_hello_check( fd_failover_hello_t const * self,
                         fd_failover_hello_t const * peer ) {
  if( FD_UNLIKELY( self->version!=peer->version ) )                                return FD_FAILOVER_HELLO_ERR_VERSION;
  if( FD_UNLIKELY( self->role>FD_FAILOVER_ROLE_ACTIVE ||
                   peer->role>FD_FAILOVER_ROLE_ACTIVE ) )                          return FD_FAILOVER_HELLO_ERR_ROLE;
  if( FD_UNLIKELY( !fd_memeq( self->staked_pubkey, peer->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_STAKED;
  if( FD_UNLIKELY( !fd_memeq( self->vote_account,  peer->vote_account,  32UL ) ) ) return FD_FAILOVER_HELLO_ERR_VOTE_ACCT;
  if( FD_UNLIKELY(  fd_memeq( self->junk_pubkey,   peer->junk_pubkey,   32UL ) ) ) return FD_FAILOVER_HELLO_ERR_JUNK_EQ;
  if( FD_UNLIKELY(  fd_memeq( self->junk_pubkey,   self->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_JUNK_STAKE;
  if( FD_UNLIKELY(  fd_memeq( peer->junk_pubkey,   peer->staked_pubkey, 32UL ) ) ) return FD_FAILOVER_HELLO_ERR_JUNK_STAKE;
  if( FD_UNLIKELY( self->role==FD_FAILOVER_ROLE_ACTIVE &&
                   peer->role==FD_FAILOVER_ROLE_ACTIVE &&
                   self->term==peer->term ) )                                      return FD_FAILOVER_HELLO_ERR_BOTH_ACT;
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

ulong
fd_failover_state_boot( ulong saved_state ) {
  switch( saved_state ) {
  case FD_FAILOVER_STATE_ACTIVE:
  case FD_FAILOVER_STATE_RECLAIMING:
    return FD_FAILOVER_STATE_RECLAIMING;
  case FD_FAILOVER_STATE_DEMOTING:
  case FD_FAILOVER_STATE_STANDBY:
  case FD_FAILOVER_STATE_PROMOTING:
  default:
    return FD_FAILOVER_STATE_STANDBY;
  }
}

int
fd_failover_demoted_term_check( ulong demoted_term,
                                ulong local_term,
                                ulong peer_term,
                                ulong peer_role,
                                int   same_term_authorized ) {
  if( FD_UNLIKELY( demoted_term>=ULONG_MAX-1UL ||
                   peer_role!=FD_FAILOVER_ROLE_STANDBY ) ) return 0;

  int local_term_valid = ( demoted_term==local_term && same_term_authorized ) ||
                         ( local_term!=ULONG_MAX && demoted_term==local_term+1UL );
  int peer_term_valid  = demoted_term==peer_term ||
                         ( peer_term!=ULONG_MAX && demoted_term==peer_term+1UL );
  return local_term_valid && peer_term_valid;
}

uchar
fd_failover_handoff_req_check( fd_failover_handoff_req_t const * req,
                               fd_failover_status_t const *      target,
                               int                               local_request,
                               ulong                             min_slots_to_leader,
                               ulong                             deadline_slots,
                               uchar *                           reason ) {
  *reason = FD_FAILOVER_REJECT_NONE;

  if( FD_UNLIKELY( !req->proposed_term || req->baton_slot || req->attempt ||
                   !req->deadline_slots || req->deadline_slots!=deadline_slots ||
                   deadline_slots>=min_slots_to_leader ||
                   req->drill>1U || req->reason>=FD_FAILOVER_HANDOFF_REASON_CNT ||
                   req->reason!=( req->drill
                                  ? FD_FAILOVER_HANDOFF_REASON_DRILL
                                  : ( local_request ? FD_FAILOVER_HANDOFF_REASON_OPERATOR
                                                    : FD_FAILOVER_HANDOFF_REASON_STANDBY ) ) ) ) {
    *reason = FD_FAILOVER_REJECT_BAD_REQUEST;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( target->term>=ULONG_MAX-2UL ) ) {
    *reason = FD_FAILOVER_REJECT_TERM_EXHAUSTED;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( req->proposed_term<target->term ||
                   ( req->proposed_term==target->term &&
                     target->role!=FD_FAILOVER_ROLE_STANDBY ) ) )
    return FD_FAILOVER_HANDOFF_STALE_TERM;
  if( FD_UNLIKELY( req->proposed_term>target->term+1UL ) ) {
    *reason = FD_FAILOVER_REJECT_BAD_REQUEST;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  return FD_FAILOVER_HANDOFF_PROCEED;
}

uchar
fd_failover_handoff_peer_check( fd_failover_status_t const * local,
                                fd_failover_status_t const * peer,
                                int                          peer_fresh ) {
  if( FD_UNLIKELY( !peer_fresh ) )                                                    return FD_FAILOVER_REJECT_STATUS_STALE;
  if( FD_UNLIKELY( peer->role!=FD_FAILOVER_ROLE_STANDBY || peer->term!=local->term ) ) return FD_FAILOVER_REJECT_STATE_MISMATCH;
  if( FD_UNLIKELY( ( local->status|peer->status )&FD_FAILOVER_STATUS_BUSY ) )         return FD_FAILOVER_REJECT_BUSY;
  if( FD_UNLIKELY( ( local->status|peer->status )&FD_FAILOVER_STATUS_PAUSED ) )       return FD_FAILOVER_REJECT_PAUSED;
  if( FD_UNLIKELY( peer->status & ~FD_FAILOVER_STATUS_REPLAG ) )                      return FD_FAILOVER_REJECT_PEER_UNHEALTHY;
  if( FD_UNLIKELY( ( local->status|peer->status )&FD_FAILOVER_STATUS_REPLAG ) )       return FD_FAILOVER_REJECT_PEER_BEHIND;
  return FD_FAILOVER_REJECT_NONE;
}

uchar
fd_failover_handoff_check( fd_failover_handoff_req_t const * req,
                           fd_failover_status_t const *      local,
                           fd_failover_status_t const *      peer,
                           int                               peer_fresh,
                           int                               tower_replicated,
                           int                               accept_peer_requests,
                           int                               local_request,
                           ulong                             min_slots_to_leader,
                           ulong                             deadline_slots,
                           uchar *                           reason ) {
  uchar code = fd_failover_handoff_req_check( req, local, local_request,
                                              min_slots_to_leader, deadline_slots,
                                              reason );
  if( FD_UNLIKELY( code!=FD_FAILOVER_HANDOFF_PROCEED ) ) return code;
  if( FD_UNLIKELY( local->role==FD_FAILOVER_ROLE_STANDBY ) )
    return FD_FAILOVER_HANDOFF_ALREADY_STANDBY;
  if( FD_UNLIKELY( local->role!=FD_FAILOVER_ROLE_ACTIVE ) ) {
    *reason = FD_FAILOVER_REJECT_STATE_MISMATCH;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( !local_request && !req->drill && !accept_peer_requests ) ) {
    *reason = FD_FAILOVER_REJECT_REQUESTS_DISABLED;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( !peer_fresh ) ) {
    *reason = FD_FAILOVER_REJECT_STATUS_STALE;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( peer->role!=FD_FAILOVER_ROLE_STANDBY || peer->term!=local->term ) ) {
    *reason = FD_FAILOVER_REJECT_STATE_MISMATCH;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( ( local->status|peer->status )&FD_FAILOVER_STATUS_BUSY ) ) {
    *reason = FD_FAILOVER_REJECT_BUSY;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( ( local->status|peer->status )&FD_FAILOVER_STATUS_PAUSED ) ) {
    *reason = FD_FAILOVER_REJECT_PAUSED;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( local->status & ~FD_FAILOVER_STATUS_REPLAG ) ) {
    *reason = FD_FAILOVER_REJECT_LOCAL_UNHEALTHY;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( peer->status & ~FD_FAILOVER_STATUS_REPLAG ) ) {
    *reason = FD_FAILOVER_REJECT_PEER_UNHEALTHY;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( !( local->flags&FD_FAILOVER_FLAG_CAUGHT_UP ) ) ) {
    *reason = FD_FAILOVER_REJECT_LOCAL_UNHEALTHY;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( ( ( local->status|peer->status )&FD_FAILOVER_STATUS_REPLAG ) ||
                   !( peer->flags&FD_FAILOVER_FLAG_CAUGHT_UP ) || !tower_replicated ) ) {
    *reason = FD_FAILOVER_REJECT_PEER_BEHIND;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  if( FD_UNLIKELY( local->flags&FD_FAILOVER_FLAG_IS_LEADER ) ) {
    *reason = FD_FAILOVER_REJECT_LEADER_ACTIVE;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  ulong current_slot = local->replay_slot;
  if( FD_LIKELY( local->turbine_slot!=FD_FAILOVER_SLOT_NULL &&
                 ( current_slot==FD_FAILOVER_SLOT_NULL || local->turbine_slot>current_slot ) ) )
    current_slot = local->turbine_slot;
  if( FD_UNLIKELY( local->next_leader_slot!=FD_FAILOVER_SLOT_NULL &&
                   ( current_slot==FD_FAILOVER_SLOT_NULL ||
                     local->next_leader_slot<=current_slot ||
                     local->next_leader_slot-current_slot<min_slots_to_leader ) ) ) {
    *reason = FD_FAILOVER_REJECT_LEADER_NEAR;
    return FD_FAILOVER_HANDOFF_REJECTED;
  }
  return FD_FAILOVER_HANDOFF_PROCEED;
}

int
fd_failover_handoff_resp_check( fd_failover_handoff_resp_t const * resp,
                                fd_failover_handoff_req_t const *  req ) {
  return !req->baton_slot  && !req->attempt  &&
         !resp->baton_slot && !resp->attempt &&
         resp->proposed_term==req->proposed_term   &&
         resp->baton_slot==req->baton_slot         &&
         resp->attempt==req->attempt               &&
         resp->deadline_slots==req->deadline_slots &&
         resp->drill==req->drill                   &&
         resp->code<FD_FAILOVER_HANDOFF_CODE_CNT   &&
         resp->reason<FD_FAILOVER_REJECT_CNT       &&
         ( ( resp->code==FD_FAILOVER_HANDOFF_PROCEED &&
             resp->reason==FD_FAILOVER_REJECT_NONE ) ||
           ( resp->code==FD_FAILOVER_HANDOFF_REJECTED &&
             resp->reason!=FD_FAILOVER_REJECT_NONE ) ||
           ( ( resp->code==FD_FAILOVER_HANDOFF_ALREADY_STANDBY ||
               resp->code==FD_FAILOVER_HANDOFF_STALE_TERM ) &&
             resp->reason==FD_FAILOVER_REJECT_NONE ) );
}

ulong
fd_failover_reclaim_term( ulong local_term,
                          ulong peer_term ) {
  ulong t = local_term>peer_term ? local_term : peer_term;
  return t>=ULONG_MAX-2UL ? ULONG_MAX : t+1UL;
}

uchar
fd_failover_reclaim_check( fd_failover_reclaim_t const * req,
                           fd_failover_status_t const *  local,
                           fd_failover_status_t const *  peer,
                           int                           peer_fresh,
                           ulong                         local_state,
                           int                           junk_installed,
                           int                           switch_pending,
                           int                           owes_confirmation,
                           uchar *                       reason ) {
  *reason = FD_FAILOVER_REJECT_NONE;
  if( FD_UNLIKELY( !req->nonce ) ) { *reason = FD_FAILOVER_REJECT_BAD_REQUEST; return FD_FAILOVER_RECLAIM_REFUSED; }
  /* A holder does not stand down on request, that is what handoff is for. */
  if( FD_UNLIKELY( local->role==FD_FAILOVER_ROLE_ACTIVE || local_state==FD_FAILOVER_STATE_ACTIVE ) ) return FD_FAILOVER_RECLAIM_HELD;
  if( FD_UNLIKELY( !peer_fresh ) ) { *reason = FD_FAILOVER_REJECT_STATUS_STALE; return FD_FAILOVER_RECLAIM_REFUSED; }
  if( FD_UNLIKELY( peer->role!=FD_FAILOVER_ROLE_STANDBY ) ) { *reason = FD_FAILOVER_REJECT_STATE_MISMATCH; return FD_FAILOVER_RECLAIM_REFUSED; }
  ulong want = fd_failover_reclaim_term( local->term, peer->term );
  if( FD_UNLIKELY( want==ULONG_MAX ) ) { *reason = FD_FAILOVER_REJECT_TERM_EXHAUSTED; return FD_FAILOVER_RECLAIM_REFUSED; }
  if( FD_UNLIKELY( req->term!=want || req->term<=local->term ) ) return FD_FAILOVER_RECLAIM_STALE_TERM;
  if( FD_UNLIKELY( local->status & FD_FAILOVER_STATUS_PAUSED ) ) { *reason = FD_FAILOVER_REJECT_PAUSED; return FD_FAILOVER_RECLAIM_REFUSED; }
  /* A confirmation still owed says this machine stopped and nothing about
     whether the asker may start, so it is settled first. */
  if( FD_UNLIKELY( owes_confirmation ) ) { *reason = FD_FAILOVER_REJECT_STATE_MISMATCH; return FD_FAILOVER_RECLAIM_REFUSED; }
  if( FD_UNLIKELY( switch_pending ) ) { *reason = FD_FAILOVER_REJECT_SWITCH_PENDING; return FD_FAILOVER_RECLAIM_REFUSED; }
  if( FD_UNLIKELY( !junk_installed ) ) { *reason = FD_FAILOVER_REJECT_HOLDS_IDENTITY; return FD_FAILOVER_RECLAIM_REFUSED; }
  return FD_FAILOVER_RECLAIM_CONFIRMED;
}

int
fd_failover_confirm_check( fd_failover_confirm_t const * confirm,
                           fd_failover_reclaim_t const * req ) {
  return confirm->term==req->term && confirm->nonce==req->nonce &&
         confirm->code<FD_FAILOVER_RECLAIM_CODE_CNT &&
         confirm->reason<FD_FAILOVER_REJECT_CNT &&
         (( confirm->code==FD_FAILOVER_RECLAIM_REFUSED && confirm->reason!=FD_FAILOVER_REJECT_NONE ) ||
          ( confirm->code!=FD_FAILOVER_RECLAIM_REFUSED && confirm->reason==FD_FAILOVER_REJECT_NONE ));
}
