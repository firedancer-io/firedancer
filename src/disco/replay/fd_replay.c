#include "fd_replay.h"

// fd_replay_fec_t *
// fd_replay_fec_insert( fd_replay_t * replay, fd_shred_t * shred ) {
// }

// void *
// fd_replay_new( void * shmem, ulong seed, ulong slice_max ) {

// }

fd_replay_t *
fd_replay_join( void * shreplay ) {
  return shreplay;
}

// void *
// fd_replay_leave( fd_replay_t const * replay ) {

// }

// void *
// fd_replay_delete( void * replay ) {

// }

// void
// fd_replay_init( fd_replay_t * replay, ulong root ) {

// }

// uint
// fd_replay_slice_prepare( fd_replay_t *     replay,
//                          fd_blockstore_t * blockstore,
//                          ulong             slot,
//                          uint              idx,
//                          ushort            parent_off,
//                          uchar             flags ) {

//   uint consumed_idx      = FD_SHRED_IDX_NULL;
//   uint buffered_idx      = FD_SHRED_IDX_NULL;
//   uint data_complete_idx = FD_SHRED_IDX_NULL;
//   uint slot_complete_idx = FD_SHRED_IDX_NULL;

//   for(;;) { /* Speculative loop */
//     fd_block_map_query_t query[1] = { 0 };
//     int err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
//     if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
//     if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) {
//       FD_LOG_WARNING(( "[%s] block_info %lu not found in blockstore. shred tile should have
//       already inserted.", __func__, slot )); return FD_SHRED_IDX_NULL;
//     }

//     fd_block_info_t * block_info = fd_block_map_query_ele( query );

//     /* Speculate */

//     uint consumed_idx      = block_info->consumed_idx;
//     uint data_complete_idx = block_info->data_complete_idx;
//     uint slot_complete_idx = block_info->slot_complete_idx;

//     memcpy( hash_out, &block_info->block_hash, sizeof(fd_hash_t) );
//     if( FD_LIKELY( fd_block_map_query_test( query ) == FD_MAP_SUCCESS ) ) return
//     FD_BLOCKSTORE_SUCCESS;
//   }

//   fd_replay_slice_map_query( replay->slice_map, slot, tick );

//   while( err == FD_MAP_ERR_AGAIN ){
//     err = fd_block_map_query_try( store->blockstore->block_map, &slot, NULL, query, 0 );
//     fd_block_info_t * blk = fd_block_map_query_ele( query );
//     if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
//     if( err == FD_MAP_ERR_KEY ) {
//       block_info = 0;
//       flags           = 0;
//       parent_slot     = FD_SLOT_NULL;
//       break;
//     }
//     block_info = 1;
//     flags           = blk->flags;
//     parent_slot     = blk->parent_slot;
//     err = fd_block_map_query_test( query );
//   }

//   if (  ) { /* Have we already replayed this slice? */
//     return;
//   }
// }
