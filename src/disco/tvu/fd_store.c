#include "fd_store.h"

void *
fd_store_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_store_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  fd_memset( mem, 0, fd_store_footprint() );

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
                       uchar const ** block_out,
                       ulong *        block_sz_out ) {
  fd_blockstore_start_read( store->blockstore );

  ulong re_adds[2];
  uint re_adds_cnt = 0;

  int rc = FD_STORE_SLOT_PREPARE_CONTINUE;

  fd_block_t * block = fd_blockstore_block_query( store->blockstore, slot );

  /* We already executed this block */
  if( FD_UNLIKELY( block && fd_uint_extract_bit( block->flags, FD_BLOCK_FLAG_EXECUTED ) ) ) goto end;

  fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( store->blockstore, slot );

  if( FD_UNLIKELY( !slot_meta ) ) {
    /* I know nothing about this block yet */
    rc = FD_STORE_SLOT_PREPARE_NEED_REPAIR;
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
    re_adds[re_adds_cnt++] = slot;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

  fd_block_t * parent_block = fd_blockstore_block_query( store->blockstore, parent_slot );

  /* We have a parent slot meta, and therefore have at least one shred of the parent block, so we
     have the ancestry and need to repair that block directly (as opposed to calling repair orphan).
  */
  if( FD_UNLIKELY( !parent_block ) ) {
    rc = FD_STORE_SLOT_PREPARE_NEED_PARENT_REPAIR;
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
