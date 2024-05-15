#include "fd_tower.h"

void none(void) {}

// int
// fd_tower_threshold_check( fd_tower_t * tower,
//                           ulong        total_stake,
//                           ulong        threshold_depth,
//                           float        threshold_pct ) {
//   if( FD_UNLIKELY( tower->slots_cnt < threshold_depth ) ) return 1;
//   ulong             slot      = tower->slots[tower->slots_cnt - threshold_depth];
//   fd_hash_t const * hash      = fd_blockstore_bank_hash_query( tower->blockstore, slot );
//   fd_slot_hash_t    slot_hash = { .slot = slot, .hash = *hash };

//   fd_ghost_node_t const * ghost_node = fd_ghost_node_query( tower->ghost, &slot_hash );

// #if FD_TOWER_USE_HANDHOLDING

//   /* This shouldn't happen because slot hashes are inserted into the ghost upon execution. Indicates
//    * a likely programming error. */

//   if( FD_UNLIKELY( ghost_node == NULL ) ) {
//     FD_LOG_ERR( ( "invariant violation: slot %lu, hash: %32J not found in ghost", slot, hash->hash ) );
//   }

// #endif

//   float pct = (float)ghost_node->weight / (float)total_stake;
//   return pct > threshold_pct;
// }

// int
// fd_tower_switch_proof_construct( fd_tower_t * tower ) {
//   FD_LOG_ERR(("unimplemented"));
// }
