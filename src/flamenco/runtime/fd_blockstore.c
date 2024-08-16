#include "fd_blockstore.h"

ulong
fd_blockstore_align( void ) {
  return alignof( fd_blockstore_t );
}

ulong
fd_blockstore_footprint( void ) {
  return sizeof( fd_blockstore_t );
}

void *
fd_blockstore_new( void * shmem,
                   ulong  wksp_tag,
                   ulong  seed,
                   ulong  shred_max,
                   ulong  slot_max,
                   int    lg_txn_max ) {
  fd_blockstore_t * blockstore = (fd_blockstore_t *)shmem;

  if( FD_UNLIKELY( !blockstore ) ) {
    FD_LOG_WARNING( ( "NULL blockstore" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)blockstore, fd_blockstore_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned blockstore" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !wksp_tag ) ) {
    FD_LOG_WARNING( ( "bad wksp_tag" ) );
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( blockstore );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING( ( "shmem must be part of a workspace" ) );
    return NULL;
  }

  void * shred_pool_shmem = fd_wksp_alloc_laddr( wksp,
                                                 fd_buf_shred_pool_align(),
                                                 fd_buf_shred_pool_footprint( shred_max ),
                                                 wksp_tag );
  if( FD_UNLIKELY( !shred_pool_shmem ) ) {
    FD_LOG_WARNING( ( "shred_max too large for workspace" ) );
    return NULL;
  }

  void * shred_shpool = fd_buf_shred_pool_new( shred_pool_shmem, shred_max );
  if( FD_UNLIKELY( !shred_shpool ) ) {
    FD_LOG_WARNING( ( "fd_buf_shred_pool_new failed" ) );
    fd_wksp_free_laddr( shred_pool_shmem );
    return NULL;
  }

  fd_buf_shred_t * shred_pool = fd_buf_shred_pool_join( shred_shpool );
  if( FD_UNLIKELY( !shred_pool ) ) {
    FD_LOG_WARNING( ( "fd_buf_shred_pool_join failed" ) );
    goto buf_shred_pool_delete;
    return NULL;
  }

  void * shred_map_shmem = fd_wksp_alloc_laddr( wksp,
                                                fd_buf_shred_map_align(),
                                                fd_buf_shred_map_footprint( shred_max ),
                                                wksp_tag );
  if( FD_UNLIKELY( !shred_map_shmem ) ) {
    FD_LOG_WARNING( ( "shred_max too large for workspace" ) );
    goto buf_shred_pool_delete;
    return NULL;
  }

  void * shred_shmap = fd_buf_shred_map_new( shred_map_shmem, shred_max, seed );
  if( FD_UNLIKELY( !shred_shmap ) ) {
    FD_LOG_WARNING( ( "fd_buf_shred_map_new failed" ) );
    fd_wksp_free_laddr( shred_map_shmem );
    goto buf_shred_pool_delete;
    return NULL;
  }

  fd_buf_shred_map_t * shred_map = fd_buf_shred_map_join( shred_shmap );
  if( FD_UNLIKELY( !shred_map ) ) {
    FD_LOG_WARNING( ( "fd_buf_shred_map_join failed" ) );
    goto buf_shred_map_delete;
    return NULL;
  }

  void * block_map_shmem    = fd_wksp_alloc_laddr( wksp,
                                                   fd_block_map_align(),
                                                   fd_block_map_footprint( slot_max ),
                                                   wksp_tag );
  if( FD_UNLIKELY( !block_map_shmem ) ) {
    FD_LOG_WARNING( ( "lg_slot_max too large for workspace" ) );
    goto buf_shred_map_delete;
    return NULL;
  }

  void * block_map_shmap = fd_block_map_new( block_map_shmem, slot_max, 0 );
  if( FD_UNLIKELY( !block_map_shmap ) ) {
    FD_LOG_WARNING( ( "fd_block_map_new failed" ) );
    fd_wksp_free_laddr( block_map_shmem );
    goto buf_shred_map_delete;
    return NULL;
  }

  fd_block_map_t * block_map = fd_block_map_join( block_map_shmap );
  if( FD_UNLIKELY( !block_map_shmap ) ) {
    FD_LOG_WARNING( ( "fd_block_map_join failed" ) );
    goto slot_map_delete;
    return NULL;
  }

  void * slot_deque_shmem = fd_wksp_alloc_laddr( wksp,
                                                 fd_blockstore_slot_deque_align(),
                                                 fd_blockstore_slot_deque_footprint( slot_max ),
                                                 wksp_tag );
  if( FD_UNLIKELY( !slot_deque_shmem ) ) {
    FD_LOG_WARNING( ( "slot_max too large for workspace" ) );
    goto slot_map_delete;
    return NULL;
  }

  void * slot_prune_shdeque = fd_blockstore_slot_deque_new( slot_deque_shmem, slot_max );
  if( FD_UNLIKELY( !slot_prune_shdeque ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_slot_deque_new failed" ) );
    fd_wksp_free_laddr( slot_deque_shmem );
    goto slot_map_delete;
    return NULL;
  }

  ulong * slot_deque = fd_blockstore_slot_deque_join( slot_prune_shdeque );
  if( FD_UNLIKELY( !slot_deque ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_slot_deque_join failed" ) );
    goto slot_deque_delete;
    return NULL;
  }

  void * txn_shmem = fd_wksp_alloc_laddr( wksp,
                                          fd_blockstore_txn_map_align(),
                                          fd_blockstore_txn_map_footprint( 1LU << lg_txn_max ),
                                          wksp_tag );
  if( FD_UNLIKELY( !txn_shmem ) ) {
    FD_LOG_WARNING( ( "lg_txn_max too large for workspace" ) );
    goto slot_deque_delete;
    return NULL;
  }

  void * txn_shmap = fd_blockstore_txn_map_new( txn_shmem, 1LU << lg_txn_max, 0 );
  if( FD_UNLIKELY( !txn_shmap ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_txn_map_new failed" ) );
    fd_wksp_free_laddr( txn_shmem );
    goto slot_deque_delete;
    return NULL;
  }

  fd_blockstore_txn_map_t * txn_map = fd_blockstore_txn_map_join( txn_shmap );
  if( FD_UNLIKELY( !txn_map ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_txn_map_join failed" ) );
    goto txn_map_delete;
    return NULL;
  }

  void * alloc_shmem = fd_wksp_alloc_laddr( wksp,
                                            fd_alloc_align(),
                                            fd_alloc_footprint(),
                                            FD_BLOCKSTORE_MAGIC );
  if( FD_UNLIKELY( !alloc_shmem ) ) {
    FD_LOG_WARNING( ( "fd_alloc too large for workspace" ) );
    goto txn_map_delete;
    return NULL;
  }

  void * alloc_shalloc = fd_alloc_new( alloc_shmem, FD_BLOCKSTORE_MAGIC );
  if( FD_UNLIKELY( !alloc_shalloc ) ) {
    FD_LOG_WARNING( ( "fd_allow_new failed" ) );
    fd_wksp_free_laddr( alloc_shalloc );
    goto txn_map_delete;
    return NULL;
  }

  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 0UL ); /* TODO: pass through cgroup hint */
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_WARNING( ( "fd_alloc_join failed" ) );
    fd_wksp_free_laddr( fd_alloc_delete( alloc_shalloc ) );
    goto txn_map_delete;
    return NULL;
  }

  fd_memset( blockstore, 0, fd_blockstore_footprint() );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( blockstore->magic ) = FD_BLOCKSTORE_MAGIC;
  FD_COMPILER_MFENCE();
  blockstore->blockstore_gaddr = fd_wksp_gaddr_fast( wksp, blockstore );
  blockstore->wksp_tag         = wksp_tag;
  blockstore->seed             = seed;

  FD_COMPILER_MFENCE();
  fd_readwrite_new( &blockstore->lock );
  FD_COMPILER_MFENCE();

  blockstore->smr              = 0;
  blockstore->min              = 0;
  blockstore->max              = 0;

  blockstore->shred_max        = shred_max;
  blockstore->shred_pool_gaddr = fd_wksp_gaddr_fast( wksp, shred_pool );
  blockstore->shred_map_gaddr  = fd_wksp_gaddr_fast( wksp, shred_map );

  blockstore->slot_max         = slot_max;
  blockstore->slot_map_gaddr   = fd_wksp_gaddr_fast( wksp, block_map );
  blockstore->slot_deque_gaddr = fd_wksp_gaddr_fast( wksp, slot_deque );

  blockstore->lg_txn_max       = lg_txn_max;
  blockstore->txn_map_gaddr    = fd_wksp_gaddr_fast( wksp, txn_map );

  blockstore->alloc_gaddr      = fd_wksp_gaddr_fast( wksp, alloc );

  return (void *)blockstore;

txn_map_delete:
  fd_wksp_free_laddr(
      fd_blockstore_txn_map_delete( txn_map ) );
slot_deque_delete:
  fd_wksp_free_laddr( fd_blockstore_slot_deque_delete( slot_deque ) );
slot_map_delete:
  fd_wksp_free_laddr( fd_block_map_delete( block_map ) );
buf_shred_map_delete:
  fd_wksp_free_laddr( fd_buf_shred_map_delete( shred_map ) );
buf_shred_pool_delete:
  fd_wksp_free_laddr( fd_buf_shred_pool_delete( shred_pool ) );
  return NULL;
}

fd_blockstore_t *
fd_blockstore_join( void * shblockstore ) {
  fd_blockstore_t * blockstore = (fd_blockstore_t *)shblockstore;

  if( FD_UNLIKELY( !blockstore ) ) {
    FD_LOG_WARNING( ( "NULL shblockstore" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)blockstore, fd_blockstore_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned shblockstore" ) );
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( blockstore );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING( ( "shblockstore must be part of a workspace" ) );
    return NULL;
  }

  if( FD_UNLIKELY( blockstore->magic != FD_BLOCKSTORE_MAGIC ) ) {
    FD_LOG_WARNING( ( "bad magic" ) );
    return NULL;
  }

  return blockstore;
}

void *
fd_blockstore_leave( fd_blockstore_t * blockstore ) {

  if( FD_UNLIKELY( !blockstore ) ) {
    FD_LOG_WARNING( ( "NULL blockstore" ) );
    return NULL;
  }

  return (void *)blockstore;
}

void *
fd_blockstore_delete( void * shblockstore ) {
  fd_blockstore_t * blockstore = (fd_blockstore_t *)shblockstore;

  if( FD_UNLIKELY( !blockstore ) ) {
    FD_LOG_WARNING( ( "NULL shblockstore" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)blockstore, fd_blockstore_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned shblockstore" ) );
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( blockstore );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING( ( "shblockstore must be part of a workspace" ) );
    return NULL;
  }

  if( FD_UNLIKELY( blockstore->magic != FD_BLOCKSTORE_MAGIC ) ) {
    FD_LOG_WARNING( ( "bad magic" ) );
    return NULL;
  }

  /* Free all blocks. */

  ulong * q = fd_wksp_laddr_fast( wksp, blockstore->slot_deque_gaddr );
  fd_blockstore_slot_deque_remove_all( q );
  fd_blockstore_slot_deque_push_tail( q, blockstore->smr );
  while( !fd_blockstore_slot_deque_empty( q ) ) {
    ulong curr = fd_blockstore_slot_deque_pop_head( q );

    ulong * child_slots    = NULL;
    ulong   child_slot_cnt = 0;
    int rc = fd_blockstore_child_slots_query( blockstore, curr, &child_slots, &child_slot_cnt );
    if( FD_UNLIKELY( rc != FD_BLOCKSTORE_OK ) ) {
      FD_LOG_ERR( ( "[fd_blockstore_delete] failed to query children in slot %lu", curr ) );
    }

    for( ulong i = 0; i < FD_BLOCKSTORE_CHILD_SLOT_MAX; i++ ) {
      if( FD_LIKELY( child_slots[i] != FD_SLOT_NULL  ) ) {
        fd_blockstore_slot_deque_push_tail( q, child_slots[i] );
      }
    }

    fd_blockstore_slot_remove( blockstore, curr );
    if( FD_UNLIKELY( rc != FD_BLOCKSTORE_OK ) ) {
      FD_LOG_ERR( ( "[fd_blockstore_remove] failed to remove slot %lu", curr ) );
    }
  }

  /* Free all structures. */

  fd_wksp_free_laddr( fd_alloc_delete( fd_wksp_laddr_fast( wksp, blockstore->alloc_gaddr ) ) );
  fd_wksp_free_laddr( fd_blockstore_txn_map_delete( fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr ) ) );
  fd_wksp_free_laddr( fd_block_map_delete( fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr ) ) );
  fd_wksp_free_laddr( fd_blockstore_slot_deque_delete( fd_wksp_laddr_fast( wksp, blockstore->slot_deque_gaddr ) ) );
  fd_wksp_free_laddr( fd_buf_shred_map_delete( fd_wksp_laddr_fast( wksp, blockstore->shred_map_gaddr ) ) );
  fd_wksp_free_laddr( fd_buf_shred_pool_delete( fd_wksp_laddr_fast( wksp, blockstore->shred_pool_gaddr ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( blockstore->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return blockstore;
}

/* txn map helpers */

int
fd_blockstore_txn_key_equal( fd_blockstore_txn_key_t const * k0, fd_blockstore_txn_key_t const * k1 ) {
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    if( k0->v[i] != k1->v[i] ) return 0;
  return 1;
}

ulong
fd_blockstore_txn_key_hash( fd_blockstore_txn_key_t const * k, ulong seed ) {
  ulong h = seed;
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    h ^= k->v[i];
  return h;
}

static void
fd_blockstore_scan_block( fd_blockstore_t * blockstore, ulong slot, fd_block_t * block ) {

#define MAX_MICROS ( 16 << 10 )
  fd_block_micro_t micros[MAX_MICROS];
  ulong            micros_cnt = 0;
#define MAX_TXNS ( 1 << 18 )
  fd_block_txn_ref_t txns[MAX_TXNS];
  ulong              txns_cnt = 0;

  uchar * data = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->data_gaddr );
  ulong   sz   = block->data_sz;
  FD_LOG_DEBUG( ( "scanning slot %lu, ptr %p, sz %lu", slot, (void *)data, sz ) );

  ulong blockoff = 0;
  while( blockoff < sz ) {
    if( blockoff + sizeof( ulong ) > sz ) FD_LOG_ERR( ( "premature end of block" ) );
    ulong mcount = FD_LOAD( ulong, (const uchar *)data + blockoff );
    blockoff += sizeof( ulong );

    /* Loop across microblocks */
    for( ulong mblk = 0; mblk < mcount; ++mblk ) {
      if( blockoff + sizeof( fd_microblock_hdr_t ) > sz )
        FD_LOG_ERR( ( "premature end of block" ) );
      if( micros_cnt < MAX_MICROS ) {
        fd_block_micro_t * m = micros + ( micros_cnt++ );
        m->off               = blockoff;
      }
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)( (const uchar *)data + blockoff );
      blockoff += sizeof( fd_microblock_hdr_t );

      /* Loop across transactions */
      for( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar         txn_out[FD_TXN_MAX_SZ];
        uchar const * raw    = (uchar const *)data + blockoff;
        ulong         pay_sz = 0;
        ulong         txn_sz = fd_txn_parse_core( (uchar const *)raw,
                                          fd_ulong_min( sz - blockoff, FD_TXN_MTU ),
                                          txn_out,
                                          NULL,
                                          &pay_sz );
        if( txn_sz == 0 || txn_sz > FD_TXN_MTU ) {
          FD_LOG_ERR( ( "failed to parse transaction %lu in microblock %lu in slot %lu. txn size: %lu",
                        txn_idx,
                        mblk,
                        slot,
                        txn_sz ) );
        }
        fd_txn_t const * txn = (fd_txn_t const *)txn_out;

        if( pay_sz == 0UL )
          FD_LOG_ERR( ( "failed to parse transaction %lu in microblock %lu in slot %lu",
                        txn_idx,
                        mblk,
                        slot ) );

        fd_blockstore_txn_key_t const * sigs =
            (fd_blockstore_txn_key_t const *)( (ulong)raw + (ulong)txn->signature_off );
        fd_blockstore_txn_map_t * txn_map = fd_blockstore_txn_map( blockstore );
        for( ulong j = 0; j < txn->signature_cnt; j++ ) {
          if( FD_UNLIKELY( fd_blockstore_txn_map_key_cnt( txn_map ) ==
                           fd_blockstore_txn_map_key_max( txn_map ) ) ) {
            break;
          }
          fd_blockstore_txn_key_t sig;
          fd_memcpy( &sig, sigs + j, sizeof( sig ) );
          fd_blockstore_txn_map_t * elem = fd_blockstore_txn_map_insert( txn_map, &sig );
          if( elem == NULL ) { break; }
          elem->slot       = slot;
          elem->offset     = blockoff;
          elem->sz         = pay_sz;
          elem->meta_gaddr = 0;
          elem->meta_sz    = 0;
          elem->meta_owned = 0;

          if( txns_cnt < MAX_TXNS ) {
            fd_block_txn_ref_t * ref = &txns[txns_cnt++];
            ref->txn_off                  = blockoff;
            ref->id_off                   = (ulong)( sigs + j ) - (ulong)data;
            ref->sz                       = pay_sz;
          }
        }

        blockoff += pay_sz;
      }
    }
  }

  fd_block_micro_t * micros_laddr =
      fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                       alignof( fd_block_micro_t ),
                       sizeof( fd_block_micro_t ) * micros_cnt );
  fd_memcpy( micros_laddr, micros, sizeof( fd_block_micro_t ) * micros_cnt );
  block->micros_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), micros_laddr );
  block->micros_cnt   = micros_cnt;

  fd_block_txn_ref_t * txns_laddr =
      fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                       alignof( fd_block_txn_ref_t ),
                       sizeof( fd_block_txn_ref_t ) * txns_cnt );
  fd_memcpy( txns_laddr, txns, sizeof( fd_block_txn_ref_t ) * txns_cnt );
  block->txns_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), txns_laddr );
  block->txns_cnt   = txns_cnt;
}

/* Remove a slot from blockstore */
void
fd_blockstore_slot_remove( fd_blockstore_t * blockstore, ulong slot ) {
  FD_LOG_DEBUG(( "[%s] slot %lu", __func__, slot ));
  fd_block_map_t * block_map_entry = fd_block_map_remove( fd_blockstore_block_map( blockstore ), &slot );
  if( FD_UNLIKELY( !block_map_entry ) ) return;

  /* It is not safe to remove a replaying block. */

  if( FD_UNLIKELY( fd_uchar_extract_bit( block_map_entry->flags, FD_BLOCK_FLAG_REPLAYING ) ) ) {
    FD_LOG_WARNING(( "[%s] slot %lu has replay in progress. not removing.", __func__, slot ));
  }

  /* Unlink slot from its parent only if it is not published. */

  fd_block_map_t * parent_block_map_entry =
      fd_blockstore_block_map_query( blockstore, block_map_entry->parent_slot );
  if( FD_LIKELY( parent_block_map_entry ) ) {
    for( ulong i = 0; i < parent_block_map_entry->child_slot_cnt; i++ ) {
      if( FD_LIKELY( parent_block_map_entry->child_slots[i] == slot ) ) {
        parent_block_map_entry->child_slots[i] =
            parent_block_map_entry->child_slots[--parent_block_map_entry->child_slot_cnt];
      }
    }
  }

  /* block_gaddr 0 indicates it hasn't received all shreds yet.
  
     TODO refactor to use FD_BLOCK_FLAG_COMPLETED. */

  if( FD_LIKELY( block_map_entry->block_gaddr == 0 ) ) {

    /* Remove buf_shreds if there's no block yet (we haven't received all shreds). */

    fd_buf_shred_map_t * map  = fd_blockstore_buf_shred_map( blockstore );
    fd_buf_shred_t *     pool = fd_blockstore_buf_shred_pool( blockstore );
    for( uint idx = 0; idx < block_map_entry->received_idx; idx++ ) {
      fd_shred_key_t key = { .slot = slot, .idx = idx };
      fd_buf_shred_t * buf_shred = fd_buf_shred_map_ele_remove( map, &key, NULL, pool );
      if ( FD_LIKELY( buf_shred ) ) {
        fd_buf_shred_pool_ele_release( pool, buf_shred );
      }
    }

    /* Return early because there are no allocations without a block. */

    return;
  }

  /* Remove all the allocations relating to a block. */

  fd_wksp_t *  wksp  = fd_blockstore_wksp( blockstore );
  fd_alloc_t * alloc = fd_blockstore_alloc( blockstore );

  fd_blockstore_txn_map_t * txn_map = fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr );
  fd_block_t *              block   = fd_wksp_laddr_fast( wksp, block_map_entry->block_gaddr );

  /* DO THIS FIRST FOR THREAD SAFETY */
  FD_COMPILER_MFENCE();
  block_map_entry->block_gaddr = 0;

  uchar *              data = fd_wksp_laddr_fast( wksp, block->data_gaddr );
  fd_block_txn_ref_t * txns = fd_wksp_laddr_fast( wksp, block->txns_gaddr );
  for( ulong j = 0; j < block->txns_cnt; ++j ) {
    fd_blockstore_txn_key_t sig;
    fd_memcpy( &sig, data + txns[j].id_off, sizeof( sig ) );
    fd_blockstore_txn_map_t * txn_map_entry = fd_blockstore_txn_map_query( txn_map, &sig, NULL );
    if( FD_LIKELY( txn_map_entry ) ) {
      if( txn_map_entry->meta_gaddr && txn_map_entry->meta_owned ) {
        fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, txn_map_entry->meta_gaddr ) );
      }
      fd_blockstore_txn_map_remove( txn_map, &sig );
    }
  }
  if( block->micros_gaddr ) fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, block->micros_gaddr ) );
  if( block->txns_gaddr ) fd_alloc_free( alloc, txns );
  fd_alloc_free( alloc, block );
  return;
}

/* Remove all the unassembled shreds for a slot */
int
fd_blockstore_buffered_shreds_remove( fd_blockstore_t * blockstore, ulong slot ) {
  fd_wksp_t *                wksp       = fd_blockstore_wksp( blockstore );
  fd_block_map_t * slot_map   = fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr );
  fd_block_map_t * block_map_entry = fd_block_map_query( slot_map, &slot, NULL );
  if( FD_UNLIKELY( !block_map_entry ) ) return FD_BLOCKSTORE_OK;
  fd_buf_shred_t *     shred_pool = fd_blockstore_buf_shred_pool( blockstore );
  fd_buf_shred_map_t * shred_map  = fd_blockstore_buf_shred_map( blockstore );
  ulong                       shred_cnt  = block_map_entry->complete_idx + 1;
  for( uint i = 0; i < shred_cnt; i++ ) {
    fd_shred_key_t          key = { .slot = slot, .idx = i };
    fd_buf_shred_t * ele;
    while( FD_UNLIKELY(
        ele = fd_buf_shred_map_ele_remove( shred_map, &key, NULL, shred_pool ) ) )
      fd_buf_shred_pool_ele_release( shred_pool, ele );
  }
  fd_block_map_remove( slot_map, &slot );
  return FD_BLOCKSTORE_OK;
}

int
fd_blockstore_publish( fd_blockstore_t * blockstore, ulong smr ) {
  long  prune_time_ns    = -fd_log_wallclock();
  ulong prune_cnt  = 0UL;

  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  ulong *     q    = fd_wksp_laddr_fast( wksp, blockstore->slot_deque_gaddr );

  /* If root is missing, return an error. */

  if( FD_UNLIKELY( !fd_blockstore_block_map_query( blockstore, smr ) ) ) {
    return FD_BLOCKSTORE_ERR_SLOT_MISSING;
  }

  /* If trying to re-publish current root, return an error. */

  if( FD_UNLIKELY( smr == blockstore->smr ) ) {
    FD_LOG_WARNING(( "[fd_blockstore_publish] attempting to re-publish current blockstore root %lu", blockstore->smr ));
    return FD_BLOCKSTORE_ERR_UNKNOWN;
  }

  /* If trying to publish a root older than current, return an error. */

  if( FD_UNLIKELY( smr < blockstore->smr ) ) {
    FD_LOG_WARNING(( "[fd_blockstore_publish] attempting to publish a root older than the current root. new: %lu, curr: %lu", smr, blockstore->smr ));
    return FD_BLOCKSTORE_ERR_UNKNOWN;
  }

  /* Clear the deque, preparing it to be reused. */

  fd_blockstore_slot_deque_remove_all( q );

  /* Push the root onto the queue. */

  fd_blockstore_slot_deque_push_tail( q, blockstore->smr );

  /* Conduct a BFS, stopping the search at the new root. */

  while( !fd_blockstore_slot_deque_empty( q ) ) {
    ulong slot = fd_blockstore_slot_deque_pop_head( q );

    fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( blockstore, slot );

    /* Add slot's children to the queue. */

    for( ulong i = 0; i < block_map_entry->child_slot_cnt; i++ ) {
      if( FD_LIKELY( block_map_entry->child_slots[i] != smr ) ) {
        fd_blockstore_slot_deque_push_tail( q, block_map_entry->child_slots[i] );
      }
    }

    if( !fd_uchar_extract_bit( block_map_entry->flags, FD_BLOCK_FLAG_FINALIZED ) ) {

      /* Remove the slot only if it is not finalized. */

      FD_LOG_NOTICE(( "[%s] pruning slot %lu", __func__, slot ));
      fd_blockstore_slot_remove( blockstore, slot );
      prune_cnt++;
    }
  }

  prune_time_ns += fd_log_wallclock();

  FD_LOG_NOTICE( ( "[fd_blockstore_publish] new root: %lu, old root: %lu, prune cnt: %lu, took: %6.6f ms",
                   smr,
                   blockstore->smr,
                   prune_cnt,
                   (double)prune_time_ns * 1e-6 ) );

  blockstore->smr = smr;

  return FD_BLOCKSTORE_OK;
}

/* Deshred into a block once we've received all shreds for a slot. */

static int
deshred( fd_blockstore_t * blockstore, ulong slot ) {
  FD_LOG_DEBUG(( "[%s] slot %lu", __func__, slot ));

  fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( blockstore, slot );
  FD_TEST( block_map_entry->block_gaddr == 0 ); /* FIXME duplicate blocks are not supported */

  block_map_entry->ts         = fd_log_wallclock();


  fd_buf_shred_t *     shred_pool = fd_blockstore_buf_shred_pool( blockstore );
  fd_buf_shred_map_t * shred_map  = fd_blockstore_buf_shred_map( blockstore );

  ulong block_sz   = 0;
  ulong shred_cnt = block_map_entry->complete_idx + 1;
  for( uint idx = 0; idx < shred_cnt; idx++ ) {
    fd_shred_key_t key = { .slot = slot, .idx = idx };
    fd_buf_shred_t const * query = fd_buf_shred_map_ele_query_const( shred_map, &key, NULL, shred_pool );
    if( FD_UNLIKELY( !query ) ) {
      FD_LOG_ERR(( "[%s] missing shred slot: %lu idx: %u while deshredding", __func__, slot, idx ));
    }
    block_sz += fd_shred_payload_sz( &query->hdr );
  }

  // alloc mem for the block
  ulong data_off = fd_ulong_align_up( sizeof(fd_block_t), 128UL );
  ulong shred_off = fd_ulong_align_up( data_off + block_sz, alignof( fd_block_shred_t ) );
  ulong tot_sz = shred_off + sizeof( fd_block_shred_t ) * shred_cnt;

  fd_alloc_t *       alloc        = fd_blockstore_alloc( blockstore );
  fd_wksp_t *        wksp         = fd_blockstore_wksp( blockstore );
  fd_block_t *       block        = fd_alloc_malloc( alloc, 128UL, tot_sz );
  if( FD_UNLIKELY( block == NULL ) ) {
    return FD_BLOCKSTORE_ERR_SLOT_FULL;
  }

  fd_memset( block, 0, sizeof(fd_block_t) );

  uchar * data_laddr  = (uchar *)((ulong)block + data_off);
  block->data_gaddr   = fd_wksp_gaddr_fast( wksp, data_laddr );
  block->data_sz      = block_sz;
  fd_block_shred_t * shreds_laddr = (fd_block_shred_t *)((ulong)block + shred_off);
  block->shreds_gaddr = fd_wksp_gaddr_fast( wksp, shreds_laddr );
  block->shreds_cnt   = shred_cnt;

  /* deshred the shreds into the block mem */
  fd_deshredder_t    deshredder = { 0 };
  fd_shred_t const * shreds[1]  = { 0 };
  fd_deshredder_init( &deshredder, data_laddr, block->data_sz, shreds, 0 );
  long  rc  = -FD_SHRED_EPIPE;
  ulong off = 0;
  for( uint i = 0; i < shred_cnt; i++ ) {
    // TODO can do this in one iteration with block sz loop... massage with deshredder API
    fd_shred_key_t                key = { .slot = slot, .idx = i };
    fd_buf_shred_t const * query =
        fd_buf_shred_map_ele_query_const( shred_map, &key, NULL, shred_pool );
    if( FD_UNLIKELY( !query ) ) FD_LOG_ERR( ( "missing shred idx %u during deshred. slot %lu.", i, slot ) );
    fd_shred_t const * shred = &query->hdr;
    deshredder.shreds        = &shred;
    deshredder.shred_cnt     = 1;
    rc                       = fd_deshredder_next( &deshredder );
    FD_TEST( rc >= 0 );

    shreds_laddr[i].hdr = *shred;
    ulong merkle_sz = shreds_laddr[i].merkle_sz = fd_shred_merkle_sz( shred->variant );
    FD_TEST( merkle_sz <= sizeof(shreds_laddr[i].merkle) );
    if( merkle_sz ) {
      fd_memcpy( shreds_laddr[i].merkle, (uchar const*)shred + fd_shred_merkle_off( shred ), merkle_sz );
    }
    shreds_laddr[i].off = off;

    FD_TEST( !memcmp( &shreds_laddr[i].hdr, shred, sizeof( fd_shred_t ) ) );
    FD_TEST( !memcmp( data_laddr + shreds_laddr[i].off,
                      fd_shred_data_payload( shred ),
                      fd_shred_payload_sz( shred ) ) );

    off += fd_shred_payload_sz( shred );
    fd_buf_shred_t * ele = NULL;
    while( FD_UNLIKELY( ele = fd_buf_shred_map_ele_remove( shred_map, &key, NULL, shred_pool ) ) ) {
      fd_buf_shred_pool_ele_release( shred_pool, ele );
    }
  }

  /* deshredder error handling */
  int err;
  switch( rc ) {
  case -FD_SHRED_EINVAL:
    err = FD_BLOCKSTORE_ERR_SHRED_INVALID;
    goto fail_deshred;
  case -FD_SHRED_ENOMEM:
    FD_LOG_ERR(
        ( "should have alloc'd enough memory above. likely indicates memory corruption." ) );
  }

  switch( deshredder.result ) {
  case FD_SHRED_ESLOT:
    fd_blockstore_scan_block( blockstore, slot, block );

    /* Do this last when it's safe */
    FD_COMPILER_MFENCE();
    block_map_entry->block_gaddr     = fd_wksp_gaddr_fast( wksp, block );
    fd_block_micro_t *    micros     = fd_wksp_laddr_fast( wksp, block->micros_gaddr );
    uchar *               data       = fd_wksp_laddr_fast( wksp, block->data_gaddr );
    fd_microblock_hdr_t * last_micro = (fd_microblock_hdr_t *)( data +
                                                                micros[block->micros_cnt - 1].off );
    memcpy( &block_map_entry->block_hash, last_micro->hash, sizeof( fd_hash_t ) );

    block_map_entry->flags = fd_uchar_clear_bit( block_map_entry->flags, FD_BLOCK_FLAG_SHREDDING );
    block_map_entry->flags = fd_uchar_set_bit( block_map_entry->flags, FD_BLOCK_FLAG_COMPLETED );

    return FD_BLOCKSTORE_OK;
  case FD_SHRED_EBATCH:
  case FD_SHRED_EPIPE:
    FD_LOG_WARNING( ( "deshredding slot %lu produced invalid block", slot ) );
    err = FD_BLOCKSTORE_ERR_DESHRED_INVALID;
    goto fail_deshred;
  case FD_SHRED_EINVAL:
    err = FD_BLOCKSTORE_ERR_SHRED_INVALID;
    goto fail_deshred;
  case FD_SHRED_ENOMEM:
    err = FD_BLOCKSTORE_ERR_NO_MEM;
    goto fail_deshred;
  default:
    err = FD_BLOCKSTORE_ERR_UNKNOWN;
  }

fail_deshred:
  /* We failed to deshred the block. Throw it away, and try again from scratch. */
  FD_LOG_WARNING(( "[%s] failed to deshred slot %lu. err: %d", __func__, slot, err ));
  fd_alloc_free( alloc, block );
  fd_blockstore_slot_remove( blockstore, slot );
  for( uint i = 0; i < shred_cnt; i++ ) {
    fd_shred_key_t key = { .slot = slot, .idx = i };
    fd_buf_shred_map_ele_remove( shred_map, &key, NULL, shred_pool );
  }
  return err;
}

int
fd_buf_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred ) {
  FD_LOG_DEBUG(( "[%s] slot %lu idx %u", __func__, shred->slot, shred->idx ));

  /* Check this shred > SMR. We ignore shreds before the SMR because by
     it is invariant that we must have a connected, linear chain for the
     SMR and its ancestors. */

  if( FD_UNLIKELY( shred->slot <= blockstore->smr ) ) {  
    return FD_BLOCKSTORE_OK;
  }
   
  /* Check if we already have this shred */

  fd_buf_shred_t *     shred_pool = fd_blockstore_buf_shred_pool( blockstore );
  fd_buf_shred_map_t * shred_map  = fd_blockstore_buf_shred_map( blockstore );
  fd_shred_key_t       shred_key  = { .slot = shred->slot, .idx = shred->idx };
  fd_buf_shred_t const * shred_   = fd_buf_shred_map_ele_query_const( shred_map, &shred_key, NULL, shred_pool );
  if( FD_UNLIKELY( shred_ ) ) {

    /* Check if we're seeing a different payload for the same shred key,
       which indicates equivocation. */

    if( FD_UNLIKELY( fd_shred_payload_sz( &shred_->hdr ) != fd_shred_payload_sz( shred ) ) ) {
      FD_LOG_ERR(( "equivocating shred detected %lu %u. halting.", shred->slot, shred->idx ));
    }

    if( FD_UNLIKELY( 0 != memcmp( fd_shred_data_payload( &shred_->hdr ), fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) ) ) ) {
      FD_LOG_ERR(( "equivocating shred detected %lu %u. halting.", shred->slot, shred->idx ));
    }

    /* Short-circuit if we already have the shred. */

    return FD_BLOCKSTORE_OK;
  }

  /* Insert the shred */

  if( FD_UNLIKELY( !fd_buf_shred_pool_free( shred_pool ) ) ) {
    FD_LOG_ERR(( "shred pool is full. halting." ));
  }
  fd_buf_shred_t * ele = fd_buf_shred_pool_ele_acquire( shred_pool ); /* always non-NULL */
  ele->key             = shred_key;
  ele->hdr             = *shred;
  fd_memcpy( &ele->raw, shred, fd_shred_sz( shred ) );
  fd_buf_shred_map_ele_insert( shred_map, ele, shred_pool ); /* always non-NULL */

  /* Update shred's associated slot meta */

  ulong slot = shred->slot;
  fd_block_map_t * block_map = fd_blockstore_block_map( blockstore );
  fd_block_map_t * block_map_entry = fd_block_map_query( block_map, &slot, NULL );
  if( FD_UNLIKELY( !block_map_entry ) ) {

    if( FD_UNLIKELY( fd_block_map_key_cnt( block_map ) == fd_block_map_key_max( block_map ) ) ) {

      if( FD_UNLIKELY( blockstore->min == blockstore->smr ) ) {
        FD_LOG_ERR(( "[%s] blockstore->min %lu is smr %lu. unable to evict full blockstore.", __func__, blockstore->min, blockstore->smr ));
      }

      /* If block_map is full, evict everything through the SMR. */

      for( ulong slot = blockstore->min; slot < blockstore->smr; slot++ ) {
        FD_LOG_NOTICE(("[%s] evicting slot %lu", __func__, slot ));
        fd_blockstore_slot_remove( blockstore, slot );
      }
    }

    /* Try to insert slot into block_map */

    block_map_entry = fd_block_map_insert( block_map, &slot );
    if( FD_UNLIKELY( !block_map_entry ) ) return FD_BLOCKSTORE_ERR_SLOT_FULL;

    /* Initialize the block_map_entry. Note some fields are initialized
       to dummy values because we do not have all the necessary metadata
       yet. */

    block_map_entry->slot = block_map_entry->slot;

    block_map_entry->parent_slot = shred->slot - shred->data.parent_off;
    memset( block_map_entry->child_slots,
            UCHAR_MAX,
            FD_BLOCKSTORE_CHILD_SLOT_MAX * sizeof( ulong ) );
    block_map_entry->child_slot_cnt = 0;

    block_map_entry->height         = 0;
    block_map_entry->block_hash     = ( fd_hash_t ){ 0 };
    block_map_entry->bank_hash      = ( fd_hash_t ){ 0 };
    block_map_entry->flags          = fd_uchar_set_bit( 0, FD_BLOCK_FLAG_SHREDDING );
    block_map_entry->ts             = 0;
    block_map_entry->reference_tick = (uchar)( (int)shred->data.flags &
                                               (int)FD_SHRED_DATA_REF_TICK_MASK );
    block_map_entry->consumed_idx   = UINT_MAX;
    block_map_entry->received_idx   = 0;
    block_map_entry->complete_idx   = UINT_MAX;

    block_map_entry->block_gaddr    = 0;
  }

  FD_LOG_DEBUG( ( "slot_meta->consumed_idx: %u, shred->slot: %lu, slot_meta->received_idx: %u, "
                  "shred->idx: %u, shred->complete_idx: %u",
                  block_map_entry->consumed_idx,
                  shred->slot,
                  block_map_entry->received_idx,
                  shred->idx,
                  block_map_entry->complete_idx ) );

  /* Update shred windowing metadata: consumed, received, shred_cnt */

  while( fd_buf_shred_query( blockstore, shred->slot, (uint)( block_map_entry->consumed_idx + 1U ) ) ) {
    block_map_entry->consumed_idx++;
  }
  block_map_entry->received_idx = fd_uint_max( block_map_entry->received_idx, shred->idx + 1 );
  if( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) block_map_entry->complete_idx = shred->idx;

  /* update ancestry metadata: parent_slot, is_connected, next_slot */

  fd_block_map_t * parent_block_map_entry =
      fd_blockstore_block_map_query( blockstore, block_map_entry->parent_slot );

  /* Add this slot to its parent's child slots if not already there. */

  if( FD_LIKELY( parent_block_map_entry ) ) {
    int found = 0;
    for( ulong i = 0; i < parent_block_map_entry->child_slot_cnt; i++ ) {
      if( FD_LIKELY( parent_block_map_entry->child_slots[i] == slot ) ) {
        found = 1;
      }
    }
    if( FD_UNLIKELY( !found ) ) {
      if( parent_block_map_entry->child_slot_cnt == FD_BLOCKSTORE_CHILD_SLOT_MAX ) {
        FD_LOG_ERR( ( "failed to add slot %lu to parent %lu's children. exceeding child slot max",
                      slot,
                      parent_block_map_entry->slot ) );
      }
      parent_block_map_entry->child_slots[parent_block_map_entry->child_slot_cnt++] = slot;
    }
  }

  if( FD_LIKELY( block_map_entry->consumed_idx == UINT_MAX ||
                 block_map_entry->consumed_idx != block_map_entry->complete_idx ) ) {
    return FD_BLOCKSTORE_OK;
  }

  /* Received all shreds, so try to assemble a block. */
  FD_LOG_DEBUG( ( "received all shreds for slot %lu - now building a block", shred->slot ) );

  int rc = deshred( blockstore, shred->slot );
  switch( rc ) {
  case FD_BLOCKSTORE_OK:
    return FD_BLOCKSTORE_OK_SLOT_COMPLETE;
  case FD_BLOCKSTORE_ERR_SLOT_FULL:
    FD_LOG_DEBUG( ( "already deshredded slot %lu. ignoring.", shred->slot ) );
    return FD_BLOCKSTORE_OK;
  case FD_BLOCKSTORE_ERR_DESHRED_INVALID:
    FD_LOG_DEBUG( ( "failed to deshred slot %lu. ignoring.", shred->slot ) );
    return FD_BLOCKSTORE_OK;
  default:
    /* FIXME */
    FD_LOG_ERR( ( "deshred err %d", rc ) );
  }
}

fd_shred_t *
fd_buf_shred_query( fd_blockstore_t * blockstore, ulong slot, uint shred_idx ) {
  fd_buf_shred_t *     shred_pool = fd_blockstore_buf_shred_pool( blockstore );
  fd_buf_shred_map_t * shred_map  = fd_blockstore_buf_shred_map( blockstore );
  fd_shred_key_t              key        = { .slot = slot, .idx = shred_idx };
  fd_buf_shred_t *     query =
      fd_buf_shred_map_ele_query( shred_map, &key, NULL, shred_pool );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->hdr;
}

long
fd_buf_shred_query_copy_data( fd_blockstore_t * blockstore, ulong slot, uint shred_idx, void * buf, ulong buf_max ) {
  if( buf_max < FD_SHRED_MAX_SZ ) return -1;

  fd_buf_shred_t *     shred_pool = fd_blockstore_buf_shred_pool( blockstore );
  fd_buf_shred_map_t * shred_map  = fd_blockstore_buf_shred_map( blockstore );
  fd_shred_key_t              key        = { .slot = slot, .idx = shred_idx };
  fd_buf_shred_t *     shred =
      fd_buf_shred_map_ele_query( shred_map, &key, NULL, shred_pool );
  if( shred ) {
    ulong sz = fd_shred_sz( &shred->hdr );
    if( sz > buf_max ) return -1;
    fd_memcpy( buf, shred->raw, sz);
    return (long)sz;
  }

  fd_block_map_t * query =
      fd_block_map_query( fd_blockstore_block_map( blockstore ), &slot, NULL );
  if( FD_UNLIKELY( !query || query->block_gaddr == 0 ) ) return -1;
  if( shred_idx > query->complete_idx ) return -1;
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  fd_block_t * blk = fd_wksp_laddr_fast( wksp, query->block_gaddr );
  fd_block_shred_t * shreds = fd_wksp_laddr_fast( wksp, blk->shreds_gaddr );
  ulong sz = fd_shred_payload_sz( &shreds[shred_idx].hdr );
  if( FD_SHRED_DATA_HEADER_SZ + sz > buf_max ) return -1L;
  fd_memcpy( buf, &shreds[shred_idx].hdr, FD_SHRED_DATA_HEADER_SZ );
  fd_memcpy( (uchar*)buf + FD_SHRED_DATA_HEADER_SZ, (uchar*)fd_wksp_laddr_fast( wksp, blk->data_gaddr ) + shreds[shred_idx].off, sz );
  ulong tot_sz = FD_SHRED_DATA_HEADER_SZ + sz;
  ulong merkle_sz = shreds[shred_idx].merkle_sz;
  if( merkle_sz ) {
    if( tot_sz + merkle_sz > buf_max ) return -1;
    fd_memcpy( (uchar*)buf + tot_sz, shreds[shred_idx].merkle, merkle_sz );
    tot_sz += merkle_sz;
  }
  if( tot_sz >= FD_SHRED_MIN_SZ ) return (long)tot_sz;
  /* Zero pad */
  fd_memset( (uchar*)buf + tot_sz, 0, FD_SHRED_MIN_SZ - tot_sz );
  return (long)FD_SHRED_MIN_SZ;
}

fd_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_map_t * query =
      fd_block_map_query( fd_blockstore_block_map( blockstore ), &slot, NULL );
  if( FD_UNLIKELY( !query || query->block_gaddr == 0 ) ) return NULL;
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), query->block_gaddr );
}

fd_hash_t const *
fd_blockstore_block_hash_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_map_t * query =
      fd_block_map_query( fd_blockstore_block_map( blockstore ), &slot, NULL );
  if( FD_UNLIKELY( !query || query->block_gaddr == 0 ) ) return NULL;
  return &query->block_hash;
}

fd_hash_t const *
fd_blockstore_bank_hash_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( blockstore, slot );
  if( FD_UNLIKELY( !block_map_entry ) ) return NULL;
  return &block_map_entry->bank_hash;
}

fd_block_map_t *
fd_blockstore_block_map_query( fd_blockstore_t * blockstore, ulong slot ) {
  return fd_block_map_query( fd_blockstore_block_map( blockstore ), &slot, NULL );
}

ulong
fd_blockstore_parent_slot_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_map_t * query = fd_blockstore_block_map_query( blockstore, slot );
  if( FD_UNLIKELY( !query ) ) return FD_SLOT_NULL;
  return query->parent_slot;
}

int
fd_blockstore_child_slots_query( fd_blockstore_t * blockstore, ulong slot, ulong ** slots_out, ulong * slot_cnt_out ) {
  fd_block_map_t * query = fd_blockstore_block_map_query( blockstore, slot );
  if( FD_UNLIKELY( !query ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
  *slots_out    = query->child_slots;
  *slot_cnt_out = query->child_slot_cnt;
  return FD_BLOCKSTORE_OK;
}

int
fd_blockstore_block_data_query_volatile( fd_blockstore_t * blockstore, ulong slot, fd_block_map_t * block_map_entry_out, fd_valloc_t alloc, uchar ** block_data_out, ulong * block_data_out_sz ) {
  /* WARNING: this code is extremely delicate. Do NOT modify without
     understanding all the invariants. In particular, we must never
     dereference through a corrupt pointer. It's OK for the
     destination data to be overwritten/invalid as long as the memory
     location is valid. As long as we don't crash, we can validate the
     data after it is read. */
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  fd_block_map_t const * block_map = fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr );
  for(;;) {
    uint seqnum;
    if( FD_UNLIKELY( fd_readwrite_start_concur_read( &blockstore->lock, &seqnum ) ) ) continue;

    fd_block_map_t const * query = fd_block_map_query_safe( block_map, &slot, NULL );
    if( FD_UNLIKELY( !query ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    memcpy( block_map_entry_out, query, sizeof( fd_block_map_t ) );
    ulong blk_gaddr = query->block_gaddr;
    if( FD_UNLIKELY( !blk_gaddr ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

    if( FD_UNLIKELY( fd_readwrite_check_concur_read( &blockstore->lock, seqnum ) ) ) continue;

    fd_block_t * blk = fd_wksp_laddr_fast( wksp, blk_gaddr );
    ulong blk_data_gaddr = blk->data_gaddr;
    if( FD_UNLIKELY( !blk_data_gaddr ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    ulong sz = *block_data_out_sz = blk->data_sz;
    if( sz >= FD_SHRED_MAX_PER_SLOT * FD_SHRED_MAX_SZ ) continue;

    if( FD_UNLIKELY( fd_readwrite_check_concur_read( &blockstore->lock, seqnum ) ) ) continue;

    uchar * data_out = fd_valloc_malloc( alloc, 128UL, sz );
    if( FD_UNLIKELY( data_out == NULL ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    fd_memcpy( data_out, fd_wksp_laddr_fast( wksp, blk_data_gaddr ), sz );

    if( FD_UNLIKELY( fd_readwrite_check_concur_read( &blockstore->lock, seqnum ) ) ) {
      fd_valloc_free( alloc, data_out );
      continue;
    }

    *block_data_out = data_out;
    return FD_BLOCKSTORE_OK;
  }
}

int
fd_blockstore_block_map_query_volatile( fd_blockstore_t * blockstore, ulong slot, fd_block_map_t * block_map_entry_out ) {
  /* WARNING: this code is extremely delicate. Do NOT modify without
     understanding all the invariants. In particular, we must never
     dereference through a corrupt pointer. It's OK for the
     destination data to be overwritten/invalid as long as the memory
     location is valid. As long as we don't crash, we can validate the
     data after it is read. */
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  fd_block_map_t const * slot_map = fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr );
  for(;;) {
    uint seqnum;
    if( FD_UNLIKELY( fd_readwrite_start_concur_read( &blockstore->lock, &seqnum ) ) ) continue;

    fd_block_map_t const * query = fd_block_map_query_safe( slot_map, &slot, NULL );
    if( FD_UNLIKELY( !query ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    memcpy( block_map_entry_out, query, sizeof( fd_block_map_t ) );
    ulong blk_gaddr = query->block_gaddr;
    if( FD_UNLIKELY( !blk_gaddr ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

    if( FD_UNLIKELY( fd_readwrite_check_concur_read( &blockstore->lock, seqnum ) ) ) continue;

    return FD_BLOCKSTORE_OK;
  }
}

fd_blockstore_txn_map_t *
fd_blockstore_txn_query( fd_blockstore_t * blockstore, uchar const sig[FD_ED25519_SIG_SZ] ) {
  fd_blockstore_txn_key_t key;
  fd_memcpy( &key, sig, sizeof( key ) );
  return fd_blockstore_txn_map_query(
      fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->txn_map_gaddr ),
      &key,
      NULL );
}

int
fd_blockstore_txn_query_volatile( fd_blockstore_t * blockstore, uchar const sig[FD_ED25519_SIG_SZ], fd_blockstore_txn_map_t * txn_out, long * blk_ts, uchar * blk_flags, uchar txn_data_out[FD_TXN_MTU] ) {
  /* WARNING: this code is extremely delicate. Do NOT modify without
     understanding all the invariants. In particular, we must never
     dereference through a corrupt pointer. It's OK for the
     destination data to be overwritten/invalid as long as the memory
     location is valid. As long as we don't crash, we can validate the
     data after it is read. */
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  fd_block_map_t const * slot_map = fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr );
  fd_blockstore_txn_map_t * txn_map = fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr );
  for(;;) {
    uint seqnum;
    if( FD_UNLIKELY( fd_readwrite_start_concur_read( &blockstore->lock, &seqnum ) ) ) continue;

    fd_blockstore_txn_key_t key;
    fd_memcpy( &key, sig, sizeof( key ) );
    fd_blockstore_txn_map_t const * txn_map_entry = fd_blockstore_txn_map_query_safe( txn_map, &key, NULL );
    if( FD_UNLIKELY( txn_map_entry == NULL ) ) return FD_BLOCKSTORE_ERR_TXN_MISSING;
    fd_memcpy( txn_out, txn_map_entry, sizeof(fd_blockstore_txn_map_t) );

    if( FD_UNLIKELY( fd_readwrite_check_concur_read( &blockstore->lock, seqnum ) ) ) continue;

    fd_block_map_t const * query = fd_block_map_query_safe( slot_map, &txn_out->slot, NULL );
    if( FD_UNLIKELY( !query ) ) return FD_BLOCKSTORE_ERR_TXN_MISSING;
    ulong blk_gaddr = query->block_gaddr;
    if( FD_UNLIKELY( !blk_gaddr ) ) return FD_BLOCKSTORE_ERR_TXN_MISSING;

    if( FD_UNLIKELY( fd_readwrite_check_concur_read( &blockstore->lock, seqnum ) ) ) continue;

    fd_block_t * blk = fd_wksp_laddr_fast( wksp, blk_gaddr );
    if( blk_ts ) *blk_ts = query->ts;
    if( blk_flags ) *blk_flags = query->flags;
    ulong ptr = blk->data_gaddr;
    ulong sz = blk->data_sz;
    if( txn_out->offset + txn_out->sz > sz || txn_out->sz > FD_TXN_MTU ) continue;

    if( FD_UNLIKELY( fd_readwrite_check_concur_read( &blockstore->lock, seqnum ) ) ) continue;

    if( txn_data_out == NULL ) return FD_BLOCKSTORE_OK;
    uchar const * data = fd_wksp_laddr_fast( wksp, ptr );
    fd_memcpy( txn_data_out, data + txn_out->offset, txn_out->sz );

    if( FD_UNLIKELY( fd_readwrite_check_concur_read( &blockstore->lock, seqnum ) ) ) continue;

    return FD_BLOCKSTORE_OK;
  }
}

void
fd_blockstore_block_height_update( fd_blockstore_t * blockstore, ulong slot, ulong height ) {
  fd_block_map_t * query = fd_blockstore_block_map_query( blockstore, slot );
  if( FD_LIKELY( query )) query->height = height;
}

void
fd_blockstore_log_block_status( fd_blockstore_t * blockstore, ulong around_slot ) {
  for( ulong i = around_slot - 5; i < around_slot + 20; ++i ) {
    fd_block_map_t * slot_entry =
        fd_block_map_query( fd_blockstore_block_map( blockstore ), &i, NULL );
    if( !slot_entry ) continue;
    FD_LOG_NOTICE( ( "%sslot=%lu received=%u consumed=%u finished=%u",
                     ( i == around_slot ? "*" : " " ),
                     i,
                     slot_entry->received_idx,
                     slot_entry->consumed_idx,
                     slot_entry->complete_idx ) );
  }
}

static char *
fd_smart_size( ulong sz, char * tmp, size_t tmpsz ) {
  if( sz <= (1UL<<7) )
    snprintf( tmp, tmpsz, "%lu B", sz );
  else if( sz <= (1UL<<17) )
    snprintf( tmp, tmpsz, "%.3f KB", ((double)sz/((double)(1UL<<10))) );
  else if( sz <= (1UL<<27) )
    snprintf( tmp, tmpsz, "%.3f MB", ((double)sz/((double)(1UL<<20))) );
  else
    snprintf( tmp, tmpsz, "%.3f GB", ((double)sz/((double)(1UL<<30))) );
  return tmp;
}

void
fd_blockstore_log_mem_usage( fd_blockstore_t * blockstore ) {
  char tmp1[100];
  char tmp2[100];
  char tmp3[100];

  FD_LOG_NOTICE(( "blockstore base footprint: %s",
                  fd_smart_size( fd_blockstore_footprint(), tmp1, sizeof(tmp1) ) ));
  fd_buf_shred_t * shred_pool = fd_blockstore_buf_shred_pool( blockstore );
  ulong shred_used = fd_buf_shred_pool_used( shred_pool );
  ulong shred_max = fd_buf_shred_pool_max( shred_pool );
  FD_LOG_NOTICE(( "shred pool footprint: %s (%lu entries used out of %lu, %lu%%)",
                  fd_smart_size( fd_buf_shred_pool_footprint( shred_max ), tmp1, sizeof(tmp1) ),
                  shred_used,
                  shred_max,
                  (100U*shred_used) / shred_max ));
  fd_buf_shred_map_t * shred_map = fd_blockstore_buf_shred_map( blockstore );
  ulong shred_map_cnt = fd_buf_shred_map_chain_cnt( shred_map );
  FD_LOG_NOTICE(( "shred map footprint: %s (%lu chains, load is %.3f)",
                  fd_smart_size( fd_buf_shred_map_footprint( shred_map_cnt ), tmp1, sizeof(tmp1) ),
                  shred_map_cnt,
                  ((double)shred_used)/((double)shred_map_cnt) ));
  fd_block_map_t * slot_map = fd_blockstore_block_map( blockstore );
  ulong slot_map_cnt = fd_block_map_key_cnt( slot_map );
  ulong slot_map_max = fd_block_map_key_max( slot_map );
  FD_LOG_NOTICE(( "slot map footprint: %s (%lu entries used out of %lu, %lu%%)",
                  fd_smart_size( fd_block_map_footprint( slot_map_max ), tmp1, sizeof(tmp1) ),
                  slot_map_cnt,
                  slot_map_max,
                  (100U*slot_map_cnt)/slot_map_max ));
  fd_blockstore_txn_map_t * txn_map = fd_blockstore_txn_map( blockstore );
  ulong txn_map_cnt = fd_blockstore_txn_map_key_cnt( txn_map );
  ulong txn_map_max = fd_blockstore_txn_map_key_max( txn_map );
  FD_LOG_NOTICE(( "txn map footprint: %s (%lu entries used out of %lu, %lu%%)",
                  fd_smart_size( fd_blockstore_txn_map_footprint( txn_map_max ), tmp1, sizeof(tmp1) ),
                  txn_map_cnt,
                  txn_map_max,
                  (100U*txn_map_cnt)/txn_map_max ));
  ulong block_cnt = 0;
  ulong data_tot = 0;
  ulong data_max = 0;
  ulong txn_tot = 0;
  ulong txn_max = 0;

  ulong * q = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->slot_deque_gaddr );
  fd_blockstore_slot_deque_remove_all( q );
  fd_blockstore_slot_deque_push_tail( q, blockstore->smr );
  while( !fd_blockstore_slot_deque_empty( q ) ) {
    ulong curr = fd_blockstore_slot_deque_pop_head( q );

    fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( blockstore, curr );
    if( FD_UNLIKELY( !block_map_entry || !block_map_entry->block_gaddr ) ) continue;
    fd_block_t * block = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block_map_entry->block_gaddr );
    if( block->data_gaddr ) {
      block_cnt++;
      data_tot += block->data_sz;
      data_max = fd_ulong_max( data_max, block->data_sz );
      txn_tot += block->txns_cnt;
      txn_max = fd_ulong_max( txn_max, block->txns_cnt );
    }

    ulong * child_slots    = NULL;
    ulong   child_slot_cnt = 0;
    int     rc = fd_blockstore_child_slots_query( blockstore, curr, &child_slots, &child_slot_cnt );
    if( FD_UNLIKELY( rc != FD_BLOCKSTORE_OK ) ) {
      continue;
    }

    for( ulong i = 0; i < child_slot_cnt; i++ ) {
      fd_blockstore_slot_deque_push_tail( q, child_slots[i] );
    }
  }

  if( block_cnt )
    FD_LOG_NOTICE(( "block cnt: %lu, total size: %s, avg size: %s, max size: %s, avg txns per block: %lu, max txns: %lu",
                    block_cnt,
                    fd_smart_size( data_tot, tmp1, sizeof(tmp1) ),
                    fd_smart_size( data_tot/block_cnt, tmp2, sizeof(tmp2) ),
                    fd_smart_size( data_max, tmp3, sizeof(tmp3) ),
                    txn_tot/block_cnt,
                    txn_max ));
}

fd_blockstore_t *
fd_blockstore_init( fd_blockstore_t * blockstore, fd_slot_bank_t const * slot_bank ) {
  ulong slot      = slot_bank->slot;

  blockstore->min = slot;
  blockstore->max = slot;
  blockstore->hcs = slot;
  blockstore->smr = slot;

  fd_block_map_t * block_map_entry = fd_block_map_insert( fd_blockstore_block_map( blockstore ),
                                                          &slot );

  block_map_entry->parent_slot     = slot_bank->prev_slot;
  memset( block_map_entry->child_slots, UCHAR_MAX, FD_BLOCKSTORE_CHILD_SLOT_MAX * sizeof( ulong ) );
  block_map_entry->child_slot_cnt  = 0;

  block_map_entry->height          = slot_bank->block_height;
  block_map_entry->bank_hash       = slot_bank->banks_hash;
  block_map_entry->flags           = fd_uchar_set_bit(
                                     fd_uchar_set_bit(
                                     fd_uchar_set_bit(
                                     fd_uchar_set_bit(
                                     fd_uchar_set_bit( block_map_entry->flags,
                                       FD_BLOCK_FLAG_COMPLETED ),
                                       FD_BLOCK_FLAG_PROCESSED ),
                                       FD_BLOCK_FLAG_EQVOCSAFE ),
                                       FD_BLOCK_FLAG_CONFIRMED ),
                                       FD_BLOCK_FLAG_FINALIZED );
  block_map_entry->reference_tick  = 0;
  block_map_entry->ts              = 0;

  block_map_entry->consumed_idx    = 0;
  block_map_entry->received_idx    = 0;
  block_map_entry->complete_idx    = 0;

  /* This creates an empty allocation for a block, to "facade" that we
     have this particular block (even though we don't).  This is useful
     to avoid special-casing various blockstore APIs.

     This should only ever be done for the snapshot slot, after booting
     up from the snapshot. */

  fd_block_t * block = fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                                        alignof( fd_block_t ),
                                        sizeof( fd_block_t ) );

  /* Point to the fake block. */

  block_map_entry->block_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), block );

  /* Set all fields to 0. Caller's responsibility to check gaddr and sz != 0. */

  memset( block, 0, sizeof( fd_block_t ) );

  return blockstore;
}
