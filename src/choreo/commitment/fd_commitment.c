#include "fd_commitment.h"

fd_slot_commitment_t *
fd_commitment_slot_insert( fd_commitment_t * commitment, ulong slot ) {
  fd_slot_commitment_t * slot_commitment = fd_slot_commitment_pool_ele_acquire( commitment->pool );
  slot_commitment->slot                  = slot;
  fd_slot_commitment_map_ele_insert( commitment->map, slot_commitment, commitment->pool );
  return slot_commitment;
}

ulong
fd_commitment_highest_confirmed_query( FD_PARAM_UNUSED fd_commitment_t const * commitment ) {
  return 0;
}

ulong
fd_commitment_highest_finalized_query( FD_PARAM_UNUSED fd_commitment_t const * commitment ) {
  return 0;
}

// fd_option_slot_t root_slot = vote_state->inner.current.root_slot;

// FD_LOG_NOTICE( ( "root_slot is some? %d %lu", root_slot.is_some, root_slot.slot ) );
// if( FD_LIKELY( root_slot.is_some ) ) {
//   FD_LOG_NOTICE( ( "found root %lu", root_slot.slot ) );
//   /* TODO confirm there's no edge case where the root's ancestor is not rooted */
//   fd_blockstore_start_read( replay->blockstore );
//   ulong ancestor = root_slot.slot;
//   while( ancestor != FD_SLOT_NULL ) {
//     FD_LOG_NOTICE( ( "adding slot: %lu to finalized", ancestor ) );
//     fd_replay_commitment_t * commitment =
//         fd_replay_commitment_query( replay->commitment, ancestor, NULL );
//     if( FD_UNLIKELY( !commitment ) ) {
//       commitment = fd_replay_commitment_insert( replay->commitment, ancestor );
//     }
//     commitment->finalized_stake += vote_account->lamports;
//     ancestor = fd_blockstore_slot_parent_query( replay->blockstore, ancestor );
//   }
//   fd_blockstore_end_read( replay->blockstore );
// }

// fd_landed_vote_t * votes = vote_state->inner.current.votes;
// /* TODO double check with labs people we can use latency field like this */
// for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( votes );
//      !deq_fd_landed_vote_t_iter_done( votes, iter );
//      iter = deq_fd_landed_vote_t_iter_next( votes, iter ) ) {
//   fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_iter_ele( votes, iter );
//   FD_LOG_NOTICE( ( "landed_vote latency %lu", landed_vote->latency ) );
//   FD_LOG_NOTICE( ( "landed_vote lockout %lu", landed_vote->lockout.slot ) );
//   fd_replay_commitment_t * commitment =
//       fd_replay_commitment_query( replay->commitment, slot - landed_vote->latency, NULL );
//   if( FD_UNLIKELY( !commitment ) ) {
//     commitment = fd_replay_commitment_insert( replay->commitment, slot - landed_vote->latency
//     );
//   }
//   FD_TEST( landed_vote->lockout.confirmation_count < 32 ); // FIXME remove
//   commitment->confirmed_stake[landed_vote->lockout.confirmation_count] +=
//       vote_account->lamports;
// }
// }

// for( ulong i = 0; i < fd_replay_commitment_slot_cnt(); i++ ) {
//   fd_replay_commitment_t * commitment =
//       fd_replay_commitment_query( replay->commitment, i, NULL );
//   if( FD_UNLIKELY( commitment ) ) {
//     // FD_LOG_NOTICE( ( "confirmation stake:" ) );
//     // for( ulong i = 0; i < 32; i++ ) {
//     //   FD_LOG_NOTICE( ( "%lu: %lu", i, commitment->confirmed_stake[i] ) );
//     // }
//     FD_LOG_NOTICE(
//         ( "slot %lu: %lu finalized", commitment->slot, commitment->finalized_stake ) );
//   }
