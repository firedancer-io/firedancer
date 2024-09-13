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
  store->first_turbine_slot = FD_SLOT_NULL;
  store->curr_turbine_slot = FD_SLOT_NULL;
  store->root = FD_SLOT_NULL;
  fd_repair_backoff_map_new( store->repair_backoff_map );
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
  fd_repair_backoff_map_join( store_->repair_backoff_map );
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

void
fd_store_expected_shred_version( fd_store_t * store, ulong expected_shred_version ) {
  store->expected_shred_version = expected_shred_version;
}

int
fd_store_slot_prepare( fd_store_t *   store,
                       ulong          slot,
                       ulong *        repair_slot_out,
                       uchar const ** block_out,
                       ulong *        block_sz_out ) {
  fd_blockstore_start_read( store->blockstore );

  ulong re_adds[2];
  uint re_adds_cnt           = 0U;
  long re_add_delays[2];

  *repair_slot_out = 0;
  int rc = FD_STORE_SLOT_PREPARE_CONTINUE;

  fd_block_t * block = fd_blockstore_block_query( store->blockstore, slot );
  fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( store->blockstore, slot );


  /* We already executed this block */
  if( FD_UNLIKELY( block && fd_uchar_extract_bit( block_map_entry->flags, FD_BLOCK_FLAG_REPLAYING ) ) ) {
    rc = FD_STORE_SLOT_PREPARE_ALREADY_EXECUTED;
    goto end;
  }

  if( FD_UNLIKELY( block && fd_uchar_extract_bit( block_map_entry->flags, FD_BLOCK_FLAG_PROCESSED ) ) ) {
    rc = FD_STORE_SLOT_PREPARE_ALREADY_EXECUTED;
    goto end;
  }

  if( FD_UNLIKELY( !block_map_entry ) ) {
    /* I know nothing about this block yet */
    rc = FD_STORE_SLOT_PREPARE_NEED_REPAIR;
    *repair_slot_out = slot;
    re_add_delays[re_adds_cnt] = FD_REPAIR_BACKOFF_TIME;
    re_adds[re_adds_cnt++] = slot;
    goto end;
  }

  ulong            parent_slot  = block_map_entry->parent_slot;
  fd_block_map_t * parent_block_map_entry = fd_blockstore_block_map_query( store->blockstore, parent_slot );

  /* If the parent slot meta is missing, this block is an orphan and the ancestry needs to be
   * repaired before we can replay it. */
  if( FD_UNLIKELY( !parent_block_map_entry ) ) {
    rc = FD_STORE_SLOT_PREPARE_NEED_ORPHAN;
    *repair_slot_out = slot;
    re_add_delays[re_adds_cnt] = FD_REPAIR_BACKOFF_TIME;
    re_adds[re_adds_cnt++] = slot;

    re_add_delays[re_adds_cnt] = FD_REPAIR_BACKOFF_TIME;
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
    re_add_delays[re_adds_cnt] = FD_REPAIR_BACKOFF_TIME;
    re_adds[re_adds_cnt++] = parent_slot;
    re_add_delays[re_adds_cnt] = FD_REPAIR_BACKOFF_TIME;
    re_adds[re_adds_cnt++] = slot;

    goto end;
  }

  /* See if the parent is executed yet */
  if( FD_UNLIKELY( !fd_uchar_extract_bit( parent_block_map_entry->flags, FD_BLOCK_FLAG_PROCESSED ) ) ) {
    rc = FD_STORE_SLOT_PREPARE_NEED_PARENT_EXEC;
    // FD_LOG_WARNING(("NEED PARENT EXEC %lu %lu", slot, parent_slot));
    if( FD_UNLIKELY( !fd_uchar_extract_bit( parent_block_map_entry->flags, FD_BLOCK_FLAG_REPLAYING ) ) ) {
      /* ... but it is not prepared */
      re_add_delays[re_adds_cnt] = (long)5e6;
      re_adds[re_adds_cnt++] = slot;
    }
    re_add_delays[re_adds_cnt] = (long)5e6;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

  /* The parent is executed, but the block is still incomplete. Ask for more shreds. */
  if( FD_UNLIKELY( !block ) ) {
    rc = FD_STORE_SLOT_PREPARE_NEED_REPAIR;
    *repair_slot_out = slot;
    re_add_delays[re_adds_cnt] = FD_REPAIR_BACKOFF_TIME;
    re_adds[re_adds_cnt++] = slot;
    goto end;
  }

  /* Prepare the replay_slot struct. */
  *block_out    = fd_blockstore_block_data_laddr( store->blockstore, block );
  *block_sz_out = block->data_sz;

  /* Mark the block as prepared, and thus unsafe to remove. */
  block_map_entry->flags = fd_uchar_set_bit( block_map_entry->flags, FD_BLOCK_FLAG_REPLAYING );

end:
  /* Block data ptr remains valid outside of the rw lock for the lifetime of the block alloc. */
  fd_blockstore_end_read( store->blockstore );

  for (uint i = 0; i < re_adds_cnt; ++i)
    fd_store_add_pending( store, re_adds[i], re_add_delays[i], 0, 0 );

  return rc;
}

int
fd_store_shred_insert( fd_store_t * store,
                       fd_shred_t const * shred ) {

  if( FD_UNLIKELY( store->expected_shred_version && shred->version != store->expected_shred_version ) ) {
    FD_LOG_DEBUG(( "received shred version %lu instead of %lu", (ulong)shred->version, store->expected_shred_version ));
    return FD_BLOCKSTORE_OK;
  }

  fd_blockstore_t * blockstore = store->blockstore;

  if (shred->slot < blockstore->smr) {
    return FD_BLOCKSTORE_OK;
  }
  uchar shred_type = fd_shred_type( shred->variant );
  // FD_LOG_INFO(("is chained: %u", fd_shred_is_chained(shred_type) ));
  if( shred_type != FD_SHRED_TYPE_LEGACY_DATA
      && shred_type != FD_SHRED_TYPE_MERKLE_DATA
      && shred_type != FD_SHRED_TYPE_MERKLE_DATA_CHAINED
      && shred_type != FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED ) {
    return FD_BLOCKSTORE_OK;
  }

  if( store->root!=FD_SLOT_NULL && shred->slot<store->root ) {
    FD_LOG_WARNING(( "shred slot is behind root, dropping shred - root: %lu, shred_slot: %lu", store->root, shred->slot ));
    return FD_BLOCKSTORE_OK;
  }

  fd_blockstore_start_write( blockstore );
  /* TODO remove this check when we can handle duplicate shreds and blocks */
  if( fd_blockstore_block_query( blockstore, shred->slot ) != NULL ) {
    fd_blockstore_end_write( blockstore );
    return FD_BLOCKSTORE_OK;
  }
  int rc = fd_buf_shred_insert( blockstore, shred );
  fd_blockstore_end_write( blockstore );

  /* FIXME */
  if( FD_UNLIKELY( rc < FD_BLOCKSTORE_OK ) ) {
    FD_LOG_ERR( ( "failed to insert shred. reason: %d", rc ) );
  } else if ( rc == FD_BLOCKSTORE_OK_SLOT_COMPLETE ) {
    fd_store_add_pending( store, shred->slot, (long)5e6, 0, 1 );
  } else {
    fd_store_add_pending( store, shred->slot, FD_REPAIR_BACKOFF_TIME, 0, 0 );
    fd_repair_backoff_t * backoff = fd_repair_backoff_map_query( store->repair_backoff_map, shred->slot, NULL );
    if( FD_LIKELY( backoff==NULL ) ) {
      /* new backoff entry */
      backoff = fd_repair_backoff_map_insert( store->repair_backoff_map, shred->slot );
      backoff->last_backoff_duration = FD_REPAIR_BACKOFF_TIME;
      backoff->last_repair_time = store->now;
    } else if( ( backoff->last_repair_time+backoff->last_backoff_duration )
        >( store->now + FD_REPAIR_BACKOFF_TIME ) ) {
      backoff->last_backoff_duration = FD_REPAIR_BACKOFF_TIME;
      backoff->last_repair_time = store->now;
    }
  }
  return rc;
}

void
fd_store_shred_update_with_shred_from_turbine( fd_store_t * store,
                                               fd_shred_t const * shred ) {
  if( FD_UNLIKELY( store->first_turbine_slot == FD_SLOT_NULL ) ) {
    FD_LOG_NOTICE(("first turbine slot: %lu", shred->slot));
    // ulong slot = shred->slot;
    // while ( slot > store->snapshot_slot ) {
    //   fd_store_add_pending( store, slot, 0 );
    //   slot -= 10;
    // }
    store->first_turbine_slot = shred->slot;
    store->curr_turbine_slot = shred->slot;
  }

  store->curr_turbine_slot = fd_ulong_max(shred->slot, store->curr_turbine_slot);
}

void
fd_store_add_pending( fd_store_t * store,
                      ulong slot,
                      long delay,
                      int should_backoff,
                      int reset_backoff ) {
                        (void)should_backoff;
                        (void)reset_backoff;
  // fd_repair_backoff_t * backoff = fd_repair_backoff_map_query( store->repair_backoff_map, slot, NULL );
  // long existing_when = fd_pending_slots_get( store->pending_slots, slot );
  // if( existing_when!=0L && existing_when!=LONG_MAX ) {
  //   if( !should_backoff && delay > ( existing_when-store->now ) ) {
  //     return;
  //   }
  // }
  // // if( existing_when!=0L && existing_when!=LONG_MAX ) {
  // //   if( !should_backoff && delay < ( existing_when-store->now ) ) {
  // //     FD_LOG_WARNING(( "hey! %lu %ld %ld ", slot, delay, ( existing_when-store->now )));
  // //   } else {
  // //     FD_LOG_WARNING(( "eep %lu %lu %lu %d %lu", slot, delay/1000000, (existing_when - store->now)/1000000, should_backoff ));
  //     //  return;
  // //   }
  // // }
  // if( backoff==NULL ) {
  //   backoff = fd_repair_backoff_map_insert( store->repair_backoff_map, slot );
  //   backoff->slot = slot;
  //   backoff->last_backoff = delay;
  // } else if( reset_backoff ) {
  //   backoff->last_backoff = delay;
  // } else if( should_backoff ) {
  //   ulong backoff->last_backoff + (backoff->last_backoff>>3);
  //   backoff->last_backoff =
  //   delay = backoff->last_backoff;
  // } else {
  //   delay = backoff->last_backoff;
  // }
  // if( should_backoff ) FD_LOG_INFO(("PENDING %lu %d %lu %ld", slot, should_backoff, delay/1000000, (existing_when-store->now)/1000000L));
  if( store->root!=FD_SLOT_NULL && slot<store->root) {
    FD_LOG_WARNING(( "slot is older than root, skipping adding slot to pending queue - root: %lu, slot: %lu",
        store->root, slot ));
    return;
  }
  fd_pending_slots_add( store->pending_slots, slot, store->now + (long)delay );
}

void
fd_store_set_root( fd_store_t * store,
                   ulong        root ) {
  store->root = root;
  fd_pending_slots_set_lo_wmark( store->pending_slots, root );

  /* remove old roots */
  for( ulong i = 0; i<fd_repair_backoff_map_slot_cnt(); i++ ) {
    if( store->repair_backoff_map[ i ].slot <= root ) {
      fd_repair_backoff_map_remove( store->repair_backoff_map, &store->repair_backoff_map[ i ] );
    }
  }
}

ulong
fd_store_slot_repair( fd_store_t * store,
                      ulong slot,
                      fd_repair_request_t * out_repair_reqs,
                      ulong out_repair_reqs_sz ) {
  if( out_repair_reqs_sz==0UL ) {
    return 0UL;
  }

  fd_repair_backoff_t * backoff = fd_repair_backoff_map_query( store->repair_backoff_map, slot, NULL );
  if( FD_LIKELY( backoff!=NULL ) ) {
    if( store->now<( backoff->last_repair_time+backoff->last_backoff_duration ) ) {
      return 0UL;
    }
  } else {
    /* new backoff entry */
    backoff = fd_repair_backoff_map_insert( store->repair_backoff_map, slot );
    backoff->last_backoff_duration = FD_REPAIR_BACKOFF_TIME;
  }
  backoff->last_repair_time = store->now;

  ulong repair_req_cnt = 0;
  fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( store->blockstore, slot );

  if( FD_LIKELY( !block_map_entry ) ) {
    /* We haven't received any shreds for this slot yet */

    fd_repair_request_t * repair_req = &out_repair_reqs[repair_req_cnt++];
    repair_req->shred_index = 0;
    repair_req->slot = slot;
    repair_req->type = FD_REPAIR_REQ_TYPE_NEED_HIGHEST_WINDOW_INDEX;
  } else {
    /* We've received at least one shred, so fill in what's missing */

    uint complete_idx = block_map_entry->complete_idx;

    /* We don't know the last index yet */
    if( FD_UNLIKELY( complete_idx == UINT_MAX ) ) {
      complete_idx = block_map_entry->received_idx - 1;
      fd_repair_request_t * repair_req = &out_repair_reqs[repair_req_cnt++];
      repair_req->shred_index = complete_idx;
      repair_req->slot = slot;
      repair_req->type = FD_REPAIR_REQ_TYPE_NEED_HIGHEST_WINDOW_INDEX;
    }

    if( repair_req_cnt==out_repair_reqs_sz ) {
      backoff->last_backoff_duration += backoff->last_backoff_duration>>2;
      FD_LOG_INFO( ( "[repair] MAX need %lu [%u, %u], sent %lu requests (backoff: %ld ms)", slot, block_map_entry->consumed_idx + 1, complete_idx, repair_req_cnt, backoff->last_backoff_duration/(long)1e6 ) );
      return repair_req_cnt;
    }

    /* First make sure we are ready to execute this block soon. Look for an ancestor that was executed. */
    ulong anc_slot = slot;
    int good = 0;
    for( uint i = 0; i < 6; ++i ) {
      anc_slot  = fd_blockstore_parent_slot_query( store->blockstore, anc_slot );
      fd_block_t * anc_block = fd_blockstore_block_query( store->blockstore, anc_slot );
      fd_block_map_t * anc_block_map_entry = fd_blockstore_block_map_query( store->blockstore, anc_slot );
      if( anc_block && fd_uchar_extract_bit( anc_block_map_entry->flags, FD_BLOCK_FLAG_PROCESSED ) ) {
        good = 1;
        out_repair_reqs_sz /= (i>>1)+1U; /* Slow roll blocks that are further out */
        break;
      }
    }

    if( !good ) {
      return repair_req_cnt;
    }

    /* Fill in what's missing */
    for( uint i = block_map_entry->consumed_idx + 1; i <= complete_idx; i++ ) {
      if( fd_buf_shred_query( store->blockstore, slot, i ) != NULL ) continue;

      fd_repair_request_t * repair_req = &out_repair_reqs[repair_req_cnt++];
      repair_req->shred_index = i;
      repair_req->slot = slot;
      repair_req->type = FD_REPAIR_REQ_TYPE_NEED_WINDOW_INDEX;

      if( repair_req_cnt == out_repair_reqs_sz ) {
        backoff->last_backoff_duration += backoff->last_backoff_duration>>2;
        FD_LOG_INFO( ( "[repair] MAX need %lu [%u, %u], sent %lu requests (backoff: %ld ms)", slot, block_map_entry->consumed_idx + 1, complete_idx, repair_req_cnt, backoff->last_backoff_duration/(long)1e6 ) );
        return repair_req_cnt;
      }
    }
    if( repair_req_cnt ) {
      backoff->last_backoff_duration += backoff->last_backoff_duration>>2;
      FD_LOG_INFO( ( "[repair] need %lu [%u, %u], sent %lu requests (backoff: %ld ms)", slot, block_map_entry->consumed_idx + 1, complete_idx, repair_req_cnt, backoff->last_backoff_duration/(long)1e6 ) );
    }
  }
  return repair_req_cnt;
}
