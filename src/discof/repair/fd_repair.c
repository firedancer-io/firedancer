#include "fd_repair.h"
#include <stdio.h>

void *
fd_repair_tile_ctx_new( void * shmem, ulong fec_max, ulong block_max ){
  int lg_fec_max   = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );
  int lg_block_max = fd_ulong_find_msb( fd_ulong_pow2_up( block_max ) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_repair_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  void * fec_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_fec_map_align(), fd_repair_fec_map_footprint( lg_fec_max ) );
  void * wmk_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_fec_wmk_align(), fd_repair_fec_wmk_footprint( lg_block_max ) );
  void * orphan_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_node_map_align(), fd_repair_node_map_footprint( block_max ) );
  void * orphan_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_node_pool_align(), fd_repair_node_pool_footprint( block_max ) );
  void * orphan_deque  = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_orphan_deque_align(), block_max );
  ulong top = FD_SCRATCH_ALLOC_FINI( l, fd_repair_tile_ctx_align() );
  FD_TEST( top == (ulong)shmem + fd_repair_tile_ctx_footprint( fec_max, block_max ) );

  fd_repair_fec_map_new( fec_map, lg_fec_max );
  fd_repair_fec_wmk_new( wmk_map, lg_block_max );

  fd_repair_node_map_new( orphan_map, block_max, 0 );
  fd_repair_node_pool_new( orphan_pool, block_max );
  fd_repair_orphan_deque_new( orphan_deque, block_max );

  ctx->fec_max   = fec_max;
  ctx->block_max = block_max;

  return ctx;
}

fd_repair_tile_ctx_t *
fd_repair_tile_ctx_join( void * shctx ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)shctx;
  int lg_fec_max   = fd_ulong_find_msb( fd_ulong_pow2_up( ctx->fec_max ) );
  int lg_block_max = fd_ulong_find_msb( fd_ulong_pow2_up( ctx->block_max ) );

  FD_SCRATCH_ALLOC_INIT( l, shctx );
  ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  void * fec_map      = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_fec_map_align(), fd_repair_fec_map_footprint( lg_fec_max ) );
  void * wmk_map      = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_fec_wmk_align(), fd_repair_fec_wmk_footprint( lg_block_max ) );
  void * orphan_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_node_map_align(), fd_repair_node_map_footprint( ctx->block_max ) );
  void * orphan_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_node_pool_align(), fd_repair_node_pool_footprint( ctx->block_max ) );
  void * orphan_deque = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_orphan_deque_align(), ctx->block_max );

  ctx->fec_map      = fd_repair_fec_map_join( fec_map );
  ctx->wmk_map      = fd_repair_fec_wmk_join( wmk_map );
  ctx->orphan_map   = fd_repair_node_map_join( orphan_map );
  ctx->orphan_pool  = fd_repair_node_pool_join( orphan_pool );
  ctx->orphan_deque = fd_repair_orphan_deque_join( orphan_deque );
  return ctx;
}

void *
fd_repair_tile_ctx_leave( fd_repair_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL ctx" ));
    return NULL;
  }

  return (void *)ctx;
}

void *
fd_repair_tile_ctx_delete( void * shctx ) {
  FD_LOG_WARNING(( "fd_repair_tile_ctx_delete not implemented" ));
  return shctx;
}

int
fd_repair_fec_insert( fd_repair_fec_t     * fec_map,
                      fd_repair_fec_wmk_t * wmk_map,
                      ulong                 slot,
                      uint                  start_idx,
                      uint                  data_cnt,
                      int                   last_in_slot,
                      uchar               * merkle_root,
                      uchar               * chained_merkle ) {

  if( FD_UNLIKELY( fd_repair_fec_map_key_cnt( fec_map ) == fd_repair_fec_map_key_max( fec_map ) ) ){
    return FD_REPAIR_CHAINED_VERIFY_FULL;
  }

  /* 1. Insert FEC set into the map. */

  ulong key = (ulong)slot << 32 | (ulong)start_idx;
  fd_repair_fec_t * fec = fd_repair_fec_map_insert( fec_map, key );
  fec->key = key;
  memcpy( fec->merkle_root, merkle_root, FD_SHRED_MERKLE_ROOT_SZ );
  memcpy( fec->chained_merkle, chained_merkle, FD_SHRED_MERKLE_ROOT_SZ );
  fec->data_cnt = data_cnt;

  /* 2. Initialize wmk entry */

  fd_repair_fec_wmk_t * wmk = fd_repair_fec_wmk_query( wmk_map, slot, NULL );
  if( !wmk ) {
    wmk               = fd_repair_fec_wmk_insert( wmk_map, slot );
    wmk->slot         = slot;
    wmk->fec_set_idx  = UINT_MAX;
    wmk->data_cnt     = 0;
    wmk->last_fec_idx = UINT_MAX;
  }

  if( FD_UNLIKELY( last_in_slot ) ){
    wmk->last_fec_idx = start_idx;
  }

  /* 3. Verify forward as much as possible */

  if( FD_UNLIKELY( !start_idx ) ) {
    wmk->fec_set_idx = start_idx;
    wmk->data_cnt    = data_cnt;
  } else if( FD_UNLIKELY( wmk->fec_set_idx == UINT_MAX ) ) {
    return FD_REPAIR_CHAINED_VERIFY_SUCCESS;
  }

  /* We know we have recieved at least the first fec set and we can
     begin checking the chaining */

  ulong verf_fec = (ulong)slot << 32 | (ulong) wmk->fec_set_idx;
  ulong next_fec = (ulong)slot << 32 | (ulong)( wmk->fec_set_idx + wmk->data_cnt );
  fd_repair_fec_t * curr = fd_repair_fec_map_query( fec_map, verf_fec, NULL );
  fd_repair_fec_t * next = fd_repair_fec_map_query( fec_map, next_fec, NULL );
  while( next ) {
    if( FD_UNLIKELY( memcmp( curr->merkle_root, next->chained_merkle, FD_SHRED_MERKLE_ROOT_SZ ) ) ) {
      return FD_REPAIR_CHAINED_VERIFY_FAIL;
    }

    /* Advance wmk */

    wmk->fec_set_idx = wmk->fec_set_idx + wmk->data_cnt;
    wmk->data_cnt    = next->data_cnt;

    /* Advance FEC ptr*/

    verf_fec = next_fec;
    next_fec = (ulong)slot << 32 | (ulong)( wmk->fec_set_idx + wmk->data_cnt );
    curr     = next;
    next     = fd_repair_fec_map_query( fec_map, next_fec, NULL );
  }

  if( FD_UNLIKELY( wmk->last_fec_idx != UINT_MAX && wmk->fec_set_idx == wmk->last_fec_idx ) ) {
    /* entire slot verified */
    return FD_REPAIR_CHAINED_VERIFY_SLOT_SUCCESS;
  }

  return FD_REPAIR_CHAINED_VERIFY_SUCCESS;
}

/* BFS traversal example. */
void
fd_repair_orphans_print( fd_repair_tile_ctx_t const * ctx, ulong slot ){
  fd_repair_node_map_t * orphan_map = ctx->orphan_map;
  fd_repair_node_t     * orphan_pool = ctx->orphan_pool;
  fd_repair_node_t     * parent = fd_repair_node_map_ele_query( orphan_map, &slot, NULL, orphan_pool );
  if( FD_UNLIKELY( !parent ) ) return;

  ulong * queue = ctx->orphan_deque; /* holds slots */
  FD_TEST( fd_repair_orphan_deque_empty( queue ) );
  fd_repair_orphan_deque_push_head( queue, slot );
  while( !fd_repair_orphan_deque_empty( queue ) ){
    ulong curr_slot = fd_repair_orphan_deque_pop_head( queue );
    fd_repair_node_t * curr = fd_repair_node_map_ele_query( orphan_map, &curr_slot, NULL, orphan_pool );

    printf("%lu \n", curr_slot);

    if( FD_LIKELY( curr->child_idx != fd_repair_node_pool_idx_null( orphan_pool ) ) ){
      fd_repair_node_t * child = fd_repair_node_pool_ele( orphan_pool, curr->child_idx );
      fd_repair_orphan_deque_push_tail( queue, child->slot );
      ulong sibling_idx = child->sibling_idx;
      while( sibling_idx != fd_repair_node_pool_idx_null( orphan_pool ) ){
          fd_repair_node_t * sibling = fd_repair_node_pool_ele( orphan_pool, sibling_idx );
          fd_repair_orphan_deque_push_tail( queue, sibling->slot );
          sibling_idx = sibling->sibling_idx;
      }
    }
  }
}

void
fd_repair_family_free( fd_repair_tile_ctx_t * ctx,
                       ulong                  parent_slot
                       /* fd_stem_context_t    * stem */ ) {
  fd_repair_node_t * parent = fd_repair_node_map_ele_query( ctx->orphan_map, &parent_slot, NULL, ctx->orphan_pool );
  if( FD_UNLIKELY( !parent ) ) return;

  ulong * queue = ctx->orphan_deque; /* holds slots */
  FD_TEST( fd_repair_orphan_deque_empty( queue ) );
  fd_repair_orphan_deque_push_head( queue, parent_slot );
  while( !fd_repair_orphan_deque_empty( queue ) ){
    ulong curr_slot = fd_repair_orphan_deque_pop_head( queue );
    fd_repair_node_t * curr = fd_repair_node_map_ele_query( ctx->orphan_map, &curr_slot, NULL, ctx->orphan_pool );

    // Do something with curr slot, like dispatch to replay
    printf("%lu \n", curr_slot);

    if( FD_LIKELY( curr->child_idx != fd_repair_node_pool_idx_null( ctx->orphan_pool ) ) ){
      fd_repair_node_t * child = fd_repair_node_pool_ele( ctx->orphan_pool, curr->child_idx );
      fd_repair_orphan_deque_push_tail( queue, child->slot );
      ulong sibling_idx = child->sibling_idx;
      while( sibling_idx != fd_repair_node_pool_idx_null( ctx->orphan_pool ) ){
          fd_repair_node_t * sibling = fd_repair_node_pool_ele( ctx->orphan_pool, sibling_idx );
          fd_repair_orphan_deque_push_tail( queue, sibling->slot );
          sibling_idx = sibling->sibling_idx;
      }
    }

    fd_repair_node_t * node = fd_repair_node_map_ele_remove( ctx->orphan_map, &curr_slot, NULL, ctx->orphan_pool );
    fd_repair_node_pool_ele_release( ctx->orphan_pool, node );
  }
}
