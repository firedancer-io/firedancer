#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/fd_borrowed_account.h"
#include "../../flamenco/runtime/program/fd_program_util.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

#include "../fd_choreo_base.h"
#include "../ghost/fd_ghost.h"
#include "../tower/fd_tower.h"
#include "fd_tower.h"

// static void voted_stakes( fd_tower_t * tower, fd_ghost_t * threshold_ghost ) {
//   for ()
// }

void
fd_tower_threshold_check( fd_vote_accounts_t *  vote_accounts,
                          fd_valloc_t           valloc,
                          FD_PARAM_UNUSED ulong total_stake,
                          FD_PARAM_UNUSED ulong threshold_depth,
                          FD_PARAM_UNUSED float threshold_pct ) {

  __asm__("int $3");
  fd_vote_accounts_pair_t_mapnode_t const * vote_accounts_pool = vote_accounts->vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t const * vote_accounts_root = vote_accounts->vote_accounts_root;
  for( fd_vote_accounts_pair_t_mapnode_t const * node =
           fd_vote_accounts_pair_t_map_minimum_const( vote_accounts_pool, vote_accounts_root );
       node;
       node = fd_vote_accounts_pair_t_map_successor_const( vote_accounts_pool, node ) ) {

    fd_solana_account_t const * vote_account = &node->elem.value;

    fd_bincode_decode_ctx_t decode_ctx = { .data    = vote_account->data,
                                           .dataend = vote_account->data + vote_account->data_len,
                                           .valloc  = valloc };

    fd_vote_state_versioned_t versioned;
    int                       rc = fd_vote_state_versioned_decode( &versioned, &decode_ctx );
    if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) FD_LOG_ERR( ( "failed to decode" ) );
    fd_vote_convert_to_current( &versioned, valloc );
    fd_vote_state_t *  vote_state  = &versioned.inner.current;
    fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_peek_tail( vote_state->votes );
    if( landed_vote ) FD_LOG_NOTICE( ( "vote key %lu", landed_vote->lockout.slot ) );
  }

  //   if( FD_UNLIKELY( tower->slots_cnt < threshold_depth ) ) return 1;
  //   ulong             slot      = tower->slots[tower->slots_cnt - threshold_depth];
  //   fd_hash_t const * hash      = fd_blockstore_bank_hash_query( tower->blockstore, slot );
  //   fd_slot_hash_t    slot_hash = { .slot = slot, .hash = *hash };

  //   fd_ghost_node_t const * ghost_node = fd_ghost_node_query( tower->ghost, &slot_hash );

  // #if FD_TOWER_USE_HANDHOLDING

  //   /* This shouldn't happen because slot hashes are inserted into the ghost upon execution.
  //   Indicates
  //    * a likely programming error. */

  //   if( FD_UNLIKELY( ghost_node == NULL ) ) {
  //     FD_LOG_ERR(
  //         ( "invariant violation: slot %lu, hash: %32J not found in ghost", slot, hash->hash ) );
  //   }

  // #endif

  //   float pct = (float)ghost_node->weight / (float)total_stake;
  //   return pct > threshold_pct;
}

fd_hash_t const *
fd_tower_switch_proof_construct( FD_PARAM_UNUSED fd_tower_t * tower ) {
  FD_LOG_ERR( ( "unimplemented" ) );
}
