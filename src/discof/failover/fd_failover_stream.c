#include "fd_failover_stream.h"

#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../tango/fd_tango_base.h"

#include <string.h>

int
fd_failover_status_decode( fd_failover_status_t *      out,
                           fd_failover_hello_t const * peer,
                           ulong                       tx_seq,
                           uchar const *               payload,
                           ulong                       payload_sz ) {
  if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_status_t) ) ) return 0;

  fd_failover_status_t status;
  fd_memcpy( &status, payload, sizeof(status) );
  if( FD_UNLIKELY( status.role!=peer->role ||
                   status.term!=peer->term ||
                   ( status.ack_seq!=ULONG_MAX && status.ack_seq>=tx_seq ) ||
                   ( status.flags & (uchar)~( FD_FAILOVER_FLAG_VOTE_ROOTED |
                                              FD_FAILOVER_FLAG_IS_LEADER   |
                                              FD_FAILOVER_FLAG_CAUGHT_UP ) ) ||
                   ( status.status & ~( FD_FAILOVER_STATUS_CATCHUP |
                                        FD_FAILOVER_STATUS_REPLAG  |
                                        FD_FAILOVER_STATUS_STUCK   |
                                        FD_FAILOVER_STATUS_PAUSED ) ) ||
                   ( ( status.flags&FD_FAILOVER_FLAG_CAUGHT_UP ) &&
                     ( status.status&FD_FAILOVER_STATUS_CATCHUP ) ) ||
                   ( ( status.flags&FD_FAILOVER_FLAG_CAUGHT_UP) &&
                       status.replay_slot==FD_FAILOVER_SLOT_NULL ) ||
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

int
fd_failover_consensus_decode( fd_failover_consensus_cache_t * cache,
                              ulong                           self_role,
                              fd_failover_hello_t const *     peer,
                              uchar const *                   payload,
                              ulong                           payload_sz ) {
  if( FD_UNLIKELY( self_role!=FD_FAILOVER_ROLE_STANDBY ||
                   peer->role!=FD_FAILOVER_ROLE_ACTIVE ||
                   payload_sz<sizeof(fd_failover_consensus_state_t) ) ) return 0;

  fd_failover_consensus_state_t msg;
  fd_memcpy( &msg, payload, sizeof(msg) );
  ulong state_sz = payload_sz-sizeof(fd_failover_consensus_state_t);
  if( FD_UNLIKELY( msg.term!=peer->term ||
                   !msg.state_len ||
                   (ulong)msg.state_len!=state_sz ||
                   state_sz>FD_FAILOVER_TOWER_STATE_MAX ||
                   msg.vote_slot==FD_FAILOVER_SLOT_NULL ||
                   msg.mode!=(uchar)FD_FAILOVER_MODE_TOWER ) ) return 0;

  uchar const * state = payload+sizeof(fd_failover_consensus_state_t);

  fd_compact_tower_sync_serde_t serde;
  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  ulong vote_cnt;
  ulong root;
  if( FD_UNLIKELY( fd_compact_tower_sync_de_exact( &serde, state, state_sz ) ||
                   fd_compact_tower_sync_to_votes( &serde, votes, &vote_cnt, &root ) ||
                   !vote_cnt || votes[ vote_cnt-1UL ].slot!=msg.vote_slot ) ) return 0;

  if( FD_UNLIKELY( cache->valid ) ) {
    int same_tower = msg.vote_slot==cache->msg.vote_slot &&
                     state_sz==(ulong)cache->msg.state_len &&
                     !memcmp( state, cache->state, state_sz );
    if( FD_UNLIKELY( msg.term<cache->msg.term ||
                     (!same_tower && msg.vote_slot<=cache->msg.vote_slot) ) ) return 0;
    if( FD_UNLIKELY( cache->peer_boot_id==peer->boot_id ) ) {
      if( FD_UNLIKELY( msg.link_seq==cache->msg.link_seq ) ) {
        if( FD_UNLIKELY( !same_tower ) ) return 0;
      } else if( FD_UNLIKELY( !fd_seq_gt( msg.link_seq, cache->msg.link_seq ) ) ) return 0;
    }
  }

  cache->msg          = msg;
  cache->peer_boot_id = peer->boot_id;
  cache->valid        = 1;
  fd_memcpy( cache->state, state, state_sz );
  return 1;
}

ulong
fd_failover_replication_lag( int                                   peer_status_valid,
                             fd_failover_status_t const *          peer_status,
                             ulong                                 peer_boot_id,
                             fd_failover_consensus_cache_t const * cache ) {
  if( FD_UNLIKELY( !peer_status_valid ||
                   !cache->valid ||
                   cache->peer_boot_id!=peer_boot_id ||
                   peer_status->term!=cache->msg.term ||
                   peer_status->last_vote_slot==FD_FAILOVER_SLOT_NULL ) ) return FD_FAILOVER_SLOT_NULL;
  return ( peer_status->last_vote_slot>cache->msg.vote_slot )
    ? peer_status->last_vote_slot-cache->msg.vote_slot
    : 0UL;
}
