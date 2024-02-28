#include "fd_store.h"

void *
fd_store_new( void * mem, ulong lo_wmark_slot ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_store_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  fd_memset( mem, 0, fd_store_footprint() );

  fd_store_t * store = (fd_store_t *)mem;
  store->pending_slots = fd_pending_slots_new( (uchar *)mem + fd_store_footprint(), lo_wmark_slot );
  if( FD_UNLIKELY( !store->pending_slots ) ) {    
    return NULL;
  }

  return mem;
}

fd_store_t * 
fd_store_join( void * store ) {
  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING( ( "NULL store" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)store, fd_store_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned replay" ) );
    return NULL;
  }

  fd_store_t * store_ = (fd_store_t *)store;
  store_->pending_slots = fd_pending_slots_join( store_->pending_slots );
  if( FD_UNLIKELY( !store_->pending_slots ) ) {    
    return NULL;
  }

  return store_;
}

void *
fd_store_leave( fd_store_t const * store ) {
  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING( ( "NULL store" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)store, fd_store_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned store" ) );
    return NULL;
  }

  return (void *)store;
}

void *
fd_store_delete( void * store ) {
  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING( ( "NULL store" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)store, fd_store_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned store" ) );
    return NULL;
  }

  return store;
}

int
fd_store_slot_prepare( fd_store_t *   store,
                       ulong          slot,
                       ulong *        repair_slot_out,
                       uchar const ** block_out,
                       ulong *        block_sz_out ) {
  fd_blockstore_start_read( store->blockstore );

  ulong re_adds[2];
  uint re_adds_cnt = 0;

  *repair_slot_out = 0;
  int rc = FD_STORE_SLOT_PREPARE_CONTINUE;

  fd_block_t * block = fd_blockstore_block_query( store->blockstore, slot );

  /* We already executed this block */
  if( FD_UNLIKELY( block && fd_uint_extract_bit( block->flags, FD_BLOCK_FLAG_EXECUTED ) ) ) goto end;

  fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( store->blockstore, slot );

  if( FD_UNLIKELY( !slot_meta ) ) {
    /* I know nothing about this block yet */
    rc = FD_STORE_SLOT_PREPARE_NEED_REPAIR;
    *repair_slot_out = slot;
    re_adds[re_adds_cnt++] = slot;
    goto end;
  }

  ulong            parent_slot  = slot_meta->parent_slot;
  fd_slot_meta_t * parent_slot_meta =
    fd_blockstore_slot_meta_query( store->blockstore, parent_slot );

  /* If the parent slot meta is missing, this block is an orphan and the ancestry needs to be
   * repaired before we can replay it. */
  if( FD_UNLIKELY( !parent_slot_meta ) ) {
    rc = FD_STORE_SLOT_PREPARE_NEED_ORPHAN;
    *repair_slot_out = slot;
    re_adds[re_adds_cnt++] = slot;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

  fd_block_t * parent_block = fd_blockstore_block_query( store->blockstore, parent_slot );

  /* We have a parent slot meta, and therefore have at least one shred of the parent block, so we
     have the ancestry and need to repair that block directly (as opposed to calling repair orphan).
  */
  if( FD_UNLIKELY( !parent_block ) ) {
    rc = FD_STORE_SLOT_PREPARE_NEED_REPAIR;
    *repair_slot_out = parent_slot;
    re_adds[re_adds_cnt++] = slot;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

  /* See if the parent is executed yet */
  if( FD_UNLIKELY( !fd_uint_extract_bit( parent_block->flags, FD_BLOCK_FLAG_EXECUTED ) ) ) {
    re_adds[re_adds_cnt++] = slot;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

  /* The parent is executed, but the block is still incomplete. Ask for more shreds. */
  if( FD_UNLIKELY( !block ) ) {
    rc = FD_STORE_SLOT_PREPARE_NEED_REPAIR;
    *repair_slot_out = slot;
    re_adds[re_adds_cnt++] = slot;
    goto end;
  }

  /* Prepare the replay_slot struct. */
  *block_out    = fd_blockstore_block_data_laddr( store->blockstore, block );
  *block_sz_out = block->sz;

  /* Mark the block as prepared, and thus unsafe to remove. */
  block->flags = fd_uint_set_bit( block->flags, FD_BLOCK_FLAG_PREPARED );

end:
  /* Block data ptr remains valid outside of the rw lock for the lifetime of the block alloc. */
  fd_blockstore_end_read( store->blockstore );

  for (uint i = 0; i < re_adds_cnt; ++i)
    fd_pending_slots_add( store->pending_slots, re_adds[i], store->now + FD_REPAIR_BACKOFF_TIME );

  return rc;
}

int
fd_store_shred_insert( fd_store_t * store,
                       fd_shred_t const * shred ) {
  fd_blockstore_t * blockstore = store->blockstore;

  fd_blockstore_start_write( blockstore );
  /* TODO remove this check when we can handle duplicate shreds and blocks */
  if( fd_blockstore_block_query( blockstore, shred->slot ) != NULL ) {
    fd_blockstore_end_write( blockstore );
    return FD_BLOCKSTORE_OK;
  }
  int rc = fd_blockstore_shred_insert( blockstore, shred );
  fd_blockstore_end_write( blockstore );

  /* FIXME */
  if( FD_UNLIKELY( rc < FD_BLOCKSTORE_OK ) ) {
    FD_LOG_ERR( ( "failed to insert shred. reason: %d", rc ) );
  } else if ( rc == FD_BLOCKSTORE_OK_SLOT_COMPLETE ) {
    fd_pending_slots_add( store->pending_slots, shred->slot, store->now );
  } else {
    fd_pending_slots_add( store->pending_slots, shred->slot, store->now + FD_REPAIR_BACKOFF_TIME );
  }
  return rc;
}

void
fd_store_add_pending( fd_store_t * store,
                      ulong slot,
                      ulong delay ) {
  fd_pending_slots_add( store->pending_slots, slot, store->now + (long)delay );
}

ulong
fd_store_slot_repair( fd_store_t * store,
                      ulong slot,
                      fd_repair_request_t * out_repair_reqs,
                      ulong out_repair_reqs_sz ) {
  ulong repair_req_cnt = 0;
  fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( store->blockstore, slot );

  if( fd_blockstore_is_slot_ancient( store->blockstore, slot ) ) {
    FD_LOG_ERR(( "repair is hopelessly behind by %lu slots, max history is %lu",
                 store->blockstore->max - slot, store->blockstore->slot_max ));
  }

  if( FD_LIKELY( !slot_meta ) ) {
    /* We haven't received any shreds for this slot yet */

    if( repair_req_cnt >= out_repair_reqs_sz ) { 
      FD_LOG_ERR(( "too many repair requests" ));
    }
    fd_repair_request_t * repair_req = &out_repair_reqs[repair_req_cnt++];
    repair_req->shred_index = 0;
    repair_req->slot = slot;
    repair_req->type = FD_REPAIR_REQ_TYPE_NEED_HIGHEST_WINDOW_INDEX;
  } else {
    /* We've received at least one shred, so fill in what's missing */

    ulong last_index = slot_meta->last_index;

    /* We don't know the last index yet */
    if( FD_UNLIKELY( last_index == ULONG_MAX ) ) {
      last_index = slot_meta->received - 1;
      if( repair_req_cnt >= out_repair_reqs_sz ) { 
        FD_LOG_ERR(( "too many repair requests" ));
      }
      fd_repair_request_t * repair_req = &out_repair_reqs[repair_req_cnt++];
      repair_req->shred_index = (uint)last_index;
      repair_req->slot = slot;
      repair_req->type = FD_REPAIR_REQ_TYPE_NEED_HIGHEST_WINDOW_INDEX;
    }

    /* First make sure we are ready to execute this block soon. Look for an ancestor that was executed. */
    ulong anc_slot = slot;
    int good = 0;
    for( uint i = 0; i < 3; ++i ) {
      anc_slot  = fd_blockstore_slot_parent_query( store->blockstore, anc_slot );
      fd_block_t * anc_block = fd_blockstore_block_query( store->blockstore, anc_slot );
      if( anc_block && fd_uint_extract_bit( anc_block->flags, FD_BLOCK_FLAG_EXECUTED ) ) {
        good = 1;
        break;
      }
    }
    if( !good ) return repair_req_cnt;
    
    /* Fill in what's missing */
    for( ulong i = slot_meta->consumed + 1; i <= last_index; i++ ) {
      if( fd_blockstore_shred_query( store->blockstore, slot, (uint)i ) != NULL ) continue;
      if( repair_req_cnt >= out_repair_reqs_sz ) { 
        FD_LOG_ERR(( "too many repair requests" ));
      }
      fd_repair_request_t * repair_req = &out_repair_reqs[repair_req_cnt++];
      repair_req->shred_index = (uint)i;
      repair_req->slot = slot;
      repair_req->type = FD_REPAIR_REQ_TYPE_NEED_WINDOW_INDEX;
    }
    if( repair_req_cnt ) {
      FD_LOG_NOTICE( ( "[repair] need %lu [%lu, %lu], sent %lu requests", slot, slot_meta->consumed + 1, last_index, repair_req_cnt ) );
    }
  }

  return repair_req_cnt;
}
