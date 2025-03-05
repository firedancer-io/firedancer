#include "fd_replay.h"

void *
fd_replay_new( void * shmem, ulong fec_max, ulong slice_max, ulong block_max ) {
  int lg_fec_max   = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );
  int lg_block_max = fd_ulong_find_msb( fd_ulong_pow2_up( block_max ) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_replay_t * replay   = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_align(),             sizeof(fd_replay_t) );
  void * fec_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_fec_map_align(),     fd_replay_fec_map_footprint( lg_fec_max ) );
  void * fec_deque       = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_fec_deque_align(),   fd_replay_fec_deque_footprint( fec_max ) );
  void * slice_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_slice_map_align(),   fd_replay_slice_map_footprint( lg_block_max ) );

  for( ulong i = 0UL; i < block_max; i++ ) {
    void * slice_deque   = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_slice_deque_align(), fd_replay_slice_deque_footprint( slice_max ) );
    fd_replay_slice_deque_new( slice_deque, slice_max );
  }
  void * slice_buf       = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                         FD_SLICE_MAX );
  // FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_replay_align() ) == (ulong)shmem + fd_replay_footprint( fec_max, slice_max ) );

  fd_replay_fec_map_new( fec_map, lg_fec_max );
  fd_replay_fec_deque_new( fec_deque, fec_max );
  fd_replay_slice_map_new( slice_map, lg_block_max );

  replay->block_max = block_max;
  replay->fec_max   = fec_max;
  replay->slice_max = slice_max;

  (void)slice_buf;

  return replay;
}

fd_replay_t *
fd_replay_join( void * shreplay ) {

  FD_SCRATCH_ALLOC_INIT( l, shreplay );
  fd_replay_t * replay   = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_align(),             sizeof(fd_replay_t) );
  int lg_fec_max         = fd_ulong_find_msb( fd_ulong_pow2_up( replay->fec_max ) );
  int lg_block_max       = fd_ulong_find_msb( fd_ulong_pow2_up( replay->block_max ) );

  void * fec_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_fec_map_align(),     fd_replay_fec_map_footprint( lg_fec_max ) );
  void * fec_deque       = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_fec_deque_align(),   fd_replay_fec_deque_footprint( replay->fec_max ) );
  void * slice_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_slice_map_align(),   fd_replay_slice_map_footprint( lg_block_max ) );
  for( ulong i = 0UL; i < replay->block_max; i++ ) {
    void * slice_deque   = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_slice_deque_align(), fd_replay_slice_deque_footprint( replay->slice_max ) );
    if( FD_UNLIKELY( i == 0 ) ){
      replay->slice_deques = slice_deque;
    }
    fd_replay_slice_deque_join( slice_deque );
  }
  void * slice_buf       = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                         FD_SLICE_MAX );

  replay->fec_map     = fd_replay_fec_map_join( fec_map );
  replay->fec_deque   = fd_replay_fec_deque_join( fec_deque );
  replay->slice_map   = fd_replay_slice_map_join( slice_map );
  replay->slice_buf   = slice_buf;
  return replay;
}

//void
//fd_replay_init( fd_replay_t * replay ) {
  /* set map pointer slot whatever the hecks */
//}

void *
fd_replay_leave( fd_replay_t const * replay ) {

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING(( "NULL replay" ));
    return NULL;
  }

  return (void *)replay;
}

void *
fd_replay_delete( void * replay ) {

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING(( "NULL replay" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)replay, fd_replay_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned replay" ));
    return NULL;
  }

  // TODO: zero out mem?

  return replay;
}

void
fd_replay_init( fd_replay_t * replay, ulong root FD_PARAM_UNUSED ){
  /* Initialize each map slot to point to a deque. Each slot should
     always have a valid pointer that points to the head of deque in the
     replay mem. When a map entry is moved/evicted, map move does a
     shallow copy, and the correct deque pointer will move along with
     the key to the new map slot location. On insert, only the map->key
     is set. Thus the map deque pointer should be valid always, and each
     map slot should have a unique deque pointer always.  */
  fd_replay_slice_t * slice_map   = replay->slice_map;
  ulong               slice_deque = (ulong)replay->slice_deques;

  for( ulong i = 0; i < replay->block_max; i++ ) {
    fd_replay_slice_t * slice_map_entry = slice_map + i;
    slice_map_entry->deque = fd_replay_slice_deque_join( (void *)slice_deque );

    slice_deque += fd_replay_slice_deque_footprint( replay->slice_max );
    slice_deque  = fd_ulong_align_up( slice_deque, fd_replay_slice_deque_align() );
  }
}


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
