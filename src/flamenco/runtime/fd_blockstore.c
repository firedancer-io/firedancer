#include "fd_blockstore.h"

/* helper to "deshred" once we've received all shreds for a slot. private to the blockstore. */
static int
fd_blockstore_deshred( fd_blockstore_t * blockstore, ulong slot ) {
  if( FD_UNLIKELY( fd_blockstore_block_map_query( blockstore->block_map, slot, NULL ) ) ) {
    return FD_BLOCKSTORE_ERR_BLOCK_EXISTS;
  }

  // calculate the size of the block
  ulong                           block_sz = 0;
  fd_blockstore_slot_meta_map_t * slot_meta_entry =
      fd_blockstore_slot_meta_map_query( blockstore->slot_meta_map, slot, NULL );
  ulong shred_cnt = slot_meta_entry->slot_meta.last_index + 1;
  for( uint i = 0; i < shred_cnt; i++ ) {
    fd_blockstore_key_t key = { .slot = slot, .shred_idx = i };
    // explicitly query the shred map here because the payload should immediately follow the header
    fd_blockstore_shred_map_t const * query =
        fd_blockstore_shred_map_query_const( blockstore->shred_map, &key, NULL );
    if( FD_UNLIKELY( !query ) )
      FD_LOG_ERR( ( "missing shred when blockstore said slot was complete." ) );
    block_sz += fd_shred_payload_sz( &query->hdr );
  }

  if( FD_UNLIKELY( fd_blockstore_block_map_key_cnt( blockstore->block_map ) ==
                   fd_blockstore_block_map_key_max( blockstore->block_map ) ) ) {
    return FD_BLOCKSTORE_ERR_MAP_FULL;
  }

  // alloc mem for the block
  fd_blockstore_block_map_t * insert =
      fd_blockstore_block_map_insert( blockstore->block_map, slot );
  FD_TEST( insert );
  insert->block.shreds = fd_valloc_malloc( blockstore->valloc,
                                           sizeof( fd_blockstore_shred_t ),
                                           sizeof( fd_blockstore_shred_t ) * shred_cnt );
  FD_TEST( insert->block.shreds );
  insert->block.data = fd_valloc_malloc( blockstore->valloc, 1UL, block_sz );
  insert->block.sz   = block_sz;

  // deshred the shreds into the block mem
  fd_deshredder_t    deshredder = { 0 };
  fd_shred_t const * shreds[1]  = { 0 };
  fd_deshredder_init( &deshredder, insert->block.data, insert->block.sz, shreds, 0 );
  long  rc  = -FD_SHRED_EPIPE;
  ulong off = 0;
  for( uint i = 0; i < shred_cnt; i++ ) {
    // TODO can do this in one iteration with block sz loop... massage with deshredder API
    fd_blockstore_key_t               key = { .slot = slot, .shred_idx = i };
    fd_blockstore_shred_map_t const * query =
        fd_blockstore_shred_map_query_const( blockstore->shred_map, &key, NULL );
    if( FD_UNLIKELY( !query ) ) FD_LOG_ERR( ( "missing shred when slot is complete." ) );
    fd_shred_t const * shred = &query->hdr;
    deshredder.shreds        = &shred;
    // FD_LOG_NOTICE(("shred slot %lu idx %lu flags 0x%02X", shred->slot, shred->idx,
    // shred->data.flags));
    deshredder.shred_cnt = 1;
    rc                   = fd_deshredder_next( &deshredder );

    insert->block.shreds[i].hdr = *shred;
    insert->block.shreds[i].off = off;

    FD_TEST( !memcmp( &insert->block.shreds[i].hdr, shred, sizeof( fd_shred_t ) ) );
    FD_TEST( !memcmp( insert->block.data + insert->block.shreds[i].off,
                      fd_shred_data_payload( shred ),
                      fd_shred_payload_sz( shred ) ) );

    off += fd_shred_payload_sz( shred );
    fd_blockstore_shred_map_remove( blockstore->shred_map, &key );
  }

  // deshredder error handling
  switch( rc ) {
  case -FD_SHRED_EINVAL:
    return FD_BLOCKSTORE_ERR_INVALID_SHRED;
  case -FD_SHRED_ENOMEM:
    return FD_BLOCKSTORE_ERR_NO_MEM;
  }

  switch( deshredder.result ) {
  case FD_SHRED_ESLOT:
    return FD_BLOCKSTORE_OK;
  case FD_SHRED_EBATCH:
  case FD_SHRED_EPIPE:
    FD_LOG_ERR( ( "block was incomplete despite blockstore reporting it as shred-complete. likely "
                  "indicates programming error." ) );
  case FD_SHRED_EINVAL:
    return FD_BLOCKSTORE_ERR_INVALID_SHRED;
  case FD_SHRED_ENOMEM:
    return FD_BLOCKSTORE_ERR_NO_MEM;
  default:
    return FD_BLOCKSTORE_ERR_UNKNOWN;
  }
}

int
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred ) {
  fd_blockstore_slot_meta_map_t * slot_meta_entry;
  if( !( slot_meta_entry =
             fd_blockstore_slot_meta_map_query( blockstore->slot_meta_map, shred->slot, NULL ) ) ) {
    slot_meta_entry = fd_blockstore_slot_meta_map_insert( blockstore->slot_meta_map, shred->slot );
    ulong reference_tick = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;
    ulong ms             = reference_tick * FD_MS_PER_TICK;
    // the "reference tick" is the tick at the point the entry batch is being prepared
    ulong now                                        = (ulong)fd_log_wallclock() / 1000000UL;
    slot_meta_entry->slot_meta.slot                  = slot_meta_entry->slot;
    slot_meta_entry->slot_meta.first_shred_timestamp = now - ms;
  }
  fd_slot_meta_t * slot_meta = &slot_meta_entry->slot_meta;
  slot_meta->last_index      = fd_ulong_max( slot_meta->last_index, shred->idx );
  slot_meta->received        = fd_ulong_max( slot_meta->received, shred->idx );
  if( FD_UNLIKELY( shred->idx == slot_meta->consumed + 1 ) ) slot_meta->consumed++;
  FD_LOG_DEBUG( ( "received shred - slot: %lu idx: %u", slot_meta->slot, shred->idx ) );

  // TODO forking stuff: parents, children (next slots), is_connected
  // TODO indexes of contiguous shred window -- if we even want to do it that way

  fd_blockstore_key_t insert_key = { .slot = shred->slot, .shred_idx = shred->idx };
  if( fd_blockstore_shred_map_is_full( blockstore->shred_map ) ) {
    return FD_BLOCKSTORE_ERR_MAP_FULL;
  }
  fd_blockstore_shred_map_t * insert =
      fd_blockstore_shred_map_insert( blockstore->shred_map, &insert_key );
  if( FD_UNLIKELY( !insert ) ) { return FD_BLOCKSTORE_OK; }
  fd_memcpy( insert->raw, shred, fd_shred_sz( shred ) );

  if( FD_UNLIKELY( slot_meta->consumed == slot_meta->last_index ) ) {
    FD_LOG_DEBUG( ( "received all shreds for slot %lu - now building a block", slot_meta->slot ) );
    int rc = fd_blockstore_deshred( blockstore, slot_meta->slot );
    if( FD_UNLIKELY( rc != FD_BLOCKSTORE_OK ) )
      FD_LOG_ERR( ( "fd_blockstore_deshred err %d", rc ) );
  }

  return FD_BLOCKSTORE_OK;
}

fd_shred_t *
fd_blockstore_shred_query( fd_blockstore_t * blockstore, ulong slot, uint shred_idx ) {
  fd_blockstore_key_t         key = { .slot = slot, .shred_idx = shred_idx };
  fd_blockstore_shred_map_t * query =
      fd_blockstore_shred_map_query( blockstore->shred_map, &key, NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->hdr;
}

fd_blockstore_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_block_map_t * query =
      fd_blockstore_block_map_query( blockstore->block_map, slot, NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->block;
}

fd_slot_meta_t *
fd_blockstore_slot_meta_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_slot_meta_map_t * query =
      fd_blockstore_slot_meta_map_query( blockstore->slot_meta_map, slot, NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->slot_meta;
}

int
fd_blockstore_missing_shreds_query(
    FD_PARAM_UNUSED fd_blockstore_t *               blockstore,
    FD_PARAM_UNUSED ulong                           slot,
    FD_PARAM_UNUSED fd_blockstore_shred_idx_set_t * missing_shreds ) {
  //   fd_blocksto
  //   fd_blockstore_slot_meta_map_t * blockstore_slot_meta =
  //       fd_blockstore_slot_meta_map_query( blockstore->slot_meta_map, slot, NULL );
  //   if( FD_UNLIKELY( !blockstore_slot_meta ) ) return FD_BLOCKSTORE_ERR_QUERY_KEY_MISSING;
  //   fd_slot_meta_t * slot_meta = &blockstore_slot_meta->slot_meta;
  //   if( FD_UNLIKELY( slot_meta->consumed == slot_meta->received ) ) return FD_BLOCKSTORE_OK;

  //   for( ulong i = slot_meta->consumed + 1; i <= slot_meta->last_index; i++ ) {
  //     fd_blockstore_shred_t * shred = fd_blockstore_shred_query( blockstore, slot, (uint)i, );
  //     if( FD_LIKELY( !shred ) ) {
  //       // first 2 bits are the reference tick
  //       ulong reference_tick = shred->hdr.data.flags & FD_SHRED_DATA_REF_TICK_MASK;
  //       ulong timeout        = reference_tick + FD_REPAIR_TIMEOUT;
  //       ulong now            = (ulong)fd_log_wallclock() / 1000000UL / FD_MS_PER_TICK;
  //       ulong delay          = ( now - slot_meta->first_shred_timestamp ) / FD_MS_PER_TICK;
  //       if( FD_LIKELY( delay < timeout ) ) {
  //         fd_blockstore_shred_idx_set_insert(, )
  //             // TODO just directly set the contiguous bits in the fd_set?
  //             for( ulong k = i; k < j; k++ ) {
  //           fd_blockstore_shreds( missing_shreds, k );
  //         }
  //       };
  //     }
  //   }
  return FD_BLOCKSTORE_OK;
}
