#include "fd_blockstore.h"

int
fd_blockstore_upsert_shred( fd_blockstore_t *  blockstore,
                            fd_shred_t const * shred,
                            ulong              shred_sz ) {
  if( FD_LIKELY( shred->slot < blockstore->consumed ) ) {
    FD_LOG_NOTICE( ( "ignoring shred for complete slot %lu", shred->slot ) );
    return FD_BLOCKSTORE_OK;
  }
  fd_blockstore_slot_meta_t * slot_meta_entry;
  if( !( slot_meta_entry =
             fd_blockstore_slot_meta_query( blockstore->slot_metas, shred->slot, NULL ) ) ) {
    slot_meta_entry      = fd_blockstore_slot_meta_insert( blockstore->slot_metas, shred->slot );
    ulong reference_tick = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;
    ulong ms             = reference_tick * FD_MS_PER_TICK;
    // the "reference tick" is the tick at the point the entry batch is being prepared
    ulong now                                        = (ulong)fd_log_wallclock() / 1000000UL;
    slot_meta_entry->slot_meta.slot                  = slot_meta_entry->slot;
    slot_meta_entry->slot_meta.first_shred_timestamp = now - ms;
  }
  fd_slot_meta_t * slot_meta = &slot_meta_entry->slot_meta;
  if( FD_LIKELY( fd_shred_type( shred->variant ) == FD_SHRED_TYPE_MERKLE_CODE ||
                 fd_shred_type( shred->variant ) == FD_SHRED_TYPE_LEGACY_CODE ) ) {
    FD_LOG_NOTICE( ( "got coding shred" ) );
    slot_meta->last_index = shred->code.data_cnt - 1;
    // TODO should blockstore know about coding shreds?
    return FD_BLOCKSTORE_OK;
  }
  slot_meta->last_index = fd_ulong_max( slot_meta->last_index, shred->idx );
  slot_meta->received   = fd_ulong_max( slot_meta->received, shred->idx );
  // TODO off-by-one check
  if( FD_UNLIKELY( shred->idx == slot_meta->consumed + 1 ) ) slot_meta->consumed++;
  if( FD_UNLIKELY( slot_meta->consumed == slot_meta->last_index ) ) {}
  FD_LOG_DEBUG( ( "received shred - slot: %lu idx: %u", slot_meta->slot, shred->idx ) );
  // TODO forking stuffparents, children (next slots), is_connected
  // TODO indexes of contiguous shred window -- if we even want to do it that way

  fd_blockstore_key_t insert_key = { .slot = shred->slot, .shred_idx = shred->idx };
  if( fd_blockstore_shred_is_full( blockstore->shreds ) ) {
    FD_LOG_NOTICE( ( "here" ) );
    return FD_BLOCKSTORE_ERR_UPSERT_MAP_FULL;
  }
  fd_blockstore_shred_t * insert = fd_blockstore_shred_insert( blockstore->shreds, &insert_key );
  if( FD_UNLIKELY( !insert ) ) return FD_BLOCKSTORE_ERR_UPSERT_UNKNOWN;
  fd_memcpy( insert->shred_data, shred, shred_sz );
  insert->shred_sz = shred_sz;
  return FD_BLOCKSTORE_OK;
}

bool
fd_blockstore_upsert_root( fd_blockstore_t * blockstore, ulong root ) {
  // FIXME bootstrap hack
  if( FD_UNLIKELY( !blockstore->consumed ) ) blockstore->consumed = root;
  ulong old_root   = blockstore->root;
  blockstore->root = fd_ulong_max( root, blockstore->root );
  return blockstore->root > old_root;
}

int
fd_blockstore_query_block( fd_blockstore_t * blockstore,
                           ulong             slot,
                           void *            buf,
                           ulong             buf_sz,
                           ulong *           out ) {
  fd_deshredder_t    deshredder               = { 0 };
  fd_shred_t const * shreds[FD_SHRED_MAX_PER_SLOT] = { 0 };
  fd_deshredder_init( &deshredder, buf, buf_sz, shreds, 0 );

  fd_blockstore_slot_meta_t * slot_meta_entry =
      fd_blockstore_slot_meta_query( blockstore->slot_metas, slot, NULL );

  long rc;
  for( uint i = 0; i <= slot_meta_entry->slot_meta.last_index; i++ ) {
    fd_blockstore_key_t curr = { .slot = slot, .shred_idx = i };
    fd_blockstore_shred_t const * query =
        fd_blockstore_shred_query_const( blockstore->shreds, &curr, NULL );
    if( FD_UNLIKELY( query == NULL ) ) {
      FD_LOG_NOTICE( ( "null" ) );
      // return 0;
      return FD_BLOCKSTORE_ERR_QUERY_BLOCK_INCOMPLETE;
    }
    deshredder.shreds[0] = &query->shred_hdr;
    deshredder.shred_cnt = 1;
    rc = fd_deshredder_next( &deshredder );
  }
  switch( rc ) {
  case -FD_SHRED_EINVAL:
    return FD_BLOCKSTORE_ERR_QUERY_SHRED_DATA_INVALID;
  case -FD_SHRED_ENOMEM:
    return FD_BLOCKSTORE_ERR_QUERY_BUF_TOO_SMALL;
  default:
    *out = (ulong)((uchar*)deshredder.buf - (uchar*)buf);
  }

  switch( deshredder.result ) {
  case FD_SHRED_ESLOT:
    return FD_BLOCKSTORE_OK;
  case FD_SHRED_EBATCH:
  case FD_SHRED_EPIPE:
    return FD_BLOCKSTORE_ERR_QUERY_BLOCK_INCOMPLETE;
  case FD_SHRED_EINVAL:
    return FD_BLOCKSTORE_ERR_QUERY_SHRED_DATA_INVALID;
  case FD_SHRED_ENOMEM:
    return FD_BLOCKSTORE_ERR_QUERY_BUF_TOO_SMALL;
  default:
    return FD_BLOCKSTORE_ERR_QUERY_UNKNOWN;
  }
}

/* Returns the missing shreds in a given slot. Note there is a grace period for unreceived shreds.
 * This is calculated using the first timestamp info in SlotMeta and a configurable timeout. */
int
fd_blockstore_query_missing_shreds( fd_blockstore_t *                blockstore,
                                    ulong                            slot,
                                    fd_blockstore_missing_shreds_t * missing_shreds ) {
  // FD_LOG_NOTICE( ( "querying missing shreds for slot %lu", slot ) );
  fd_blockstore_slot_meta_t * blockstore_slot_meta =
      fd_blockstore_slot_meta_query( blockstore->slot_metas, slot, NULL );
  if( FD_UNLIKELY( !blockstore_slot_meta ) ) { return FD_BLOCKSTORE_ERR_QUERY_KEY_MISSING; }
  fd_slot_meta_t * slot_meta = &blockstore_slot_meta->slot_meta;
  if( FD_UNLIKELY( slot_meta->consumed == slot_meta->received ) ) return FD_BLOCKSTORE_OK;
  (void)missing_shreds;
  // ulong i = slot_meta->consumed;
  // while( i < slot_meta->received ) {
  //   for( ulong j = i; j < slot_meta->received; j++ ) {
  //     fd_blockstore_key_t           curr = { .slot = slot, .shred_idx = (uint)j };
  //     fd_blockstore_shred_t const * shred =
  //         fd_blockstore_shred_query_const( blockstore->shreds, &curr, NULL );
  //     if( FD_LIKELY( shred ) ) {
  //       // first 2 bits are the reference tick
  //       ulong reference_tick = shred->shred_hdr.data.flags & FD_SHRED_DATA_REF_TICK_MASK;
  //       ulong timeout        = reference_tick + FD_REPAIR_TIMEOUT;
  //       ulong now            = (ulong)fd_log_wallclock() / 1000000UL;
  //       ulong delay          = ( now - slot_meta->first_shred_timestamp ) / FD_MS_PER_TICK;
  //       if( FD_LIKELY( delay < timeout ) ) {
  //         // TODO just directly set the contiguous bits in the fd_set?
  //         for( ulong k = i; k < j; k++ ) {
  //           fd_blockstore_missing_shreds_insert( missing_shreds, k );
  //         }
  //       };
  //     }
  //   }
  //   i++;
  // }
  return FD_BLOCKSTORE_OK;
}
