#include "fd_tower.h"

ulong
fd_tower_stakes_insert( fd_tower_t *      tower,
                        ulong             slot,
                        fd_hash_t const * vote_account,
                        ulong             stake,
                        ulong             prev_voter_idx ) {

  fd_tower_stakes_vtr_t * pool = tower->stk_vtr_pool;
  if( FD_UNLIKELY( !fd_tower_stakes_vtr_pool_free( pool ) ) ) FD_LOG_CRIT(( "no free voter stakes in pool" ));
  fd_tower_stakes_vtr_t * new_voter_stake = fd_tower_stakes_vtr_pool_ele_acquire( pool );
  new_voter_stake->key   = (fd_tower_stakes_vtr_xid_t){ .addr = *vote_account, .slot = slot };
  new_voter_stake->stake = stake;
  new_voter_stake->prev  = prev_voter_idx;
  fd_tower_stakes_vtr_map_ele_insert( tower->stk_vtr_map, new_voter_stake, pool );

  /* Point to first vtr (head of list). */

  fd_tower_stakes_slot_t * blk = fd_tower_stakes_slot_query( tower->stk_slot_map, slot, NULL );
  if( FD_UNLIKELY( !blk ) ) blk = fd_tower_stakes_slot_insert( tower->stk_slot_map, slot );
  blk->head = fd_tower_stakes_vtr_pool_idx( pool, new_voter_stake );
  return blk->head;
}

void
fd_tower_stakes_remove( fd_tower_t * tower,
                        ulong        slot ) {

  fd_tower_stakes_slot_t * blk = fd_tower_stakes_slot_query( tower->stk_slot_map, slot, NULL );
  if( FD_UNLIKELY( !blk ) ) return;
  ulong voter_idx = blk->head;

  /* Remove the linked list of voters. */

  while( FD_UNLIKELY( voter_idx!=ULONG_MAX ) ) {
    fd_tower_stakes_vtr_t * voter_stake = fd_tower_stakes_vtr_pool_ele( tower->stk_vtr_pool, voter_idx );
    voter_idx = voter_stake->prev;
    fd_tower_stakes_vtr_t * remove = fd_tower_stakes_vtr_map_ele_remove( tower->stk_vtr_map, &voter_stake->key, NULL, tower->stk_vtr_pool );
    if( FD_UNLIKELY( !remove ) ) FD_LOG_CRIT(( "invariant violation: voter stake does not exist in map" ));
    fd_tower_stakes_vtr_pool_ele_release( tower->stk_vtr_pool, voter_stake );
  }
  fd_tower_stakes_slot_remove( tower->stk_slot_map, blk );
}
