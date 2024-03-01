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
                                                 fd_blockstore_shred_pool_align(),
                                                 fd_blockstore_shred_pool_footprint( shred_max ),
                                                 wksp_tag );
  if( FD_UNLIKELY( !shred_pool_shmem ) ) {
    FD_LOG_WARNING( ( "shred_max too large for workspace" ) );
    return NULL;
  }

  void * shred_shpool = fd_blockstore_shred_pool_new( shred_pool_shmem, shred_max );
  if( FD_UNLIKELY( !shred_shpool ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_shred_pool_new failed" ) );
    fd_wksp_free_laddr( shred_pool_shmem );
    return NULL;
  }

  fd_blockstore_shred_t * shred_pool = fd_blockstore_shred_pool_join( shred_shpool );
  if( FD_UNLIKELY( !shred_pool ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_shred_pool_join failed" ) );
    goto blockstore_shred_pool_delete;
    return NULL;
  }

  void * shred_map_shmem = fd_wksp_alloc_laddr( wksp,
                                                fd_blockstore_shred_map_align(),
                                                fd_blockstore_shred_map_footprint( shred_max ),
                                                wksp_tag );
  if( FD_UNLIKELY( !shred_map_shmem ) ) {
    FD_LOG_WARNING( ( "shred_max too large for workspace" ) );
    goto blockstore_shred_pool_delete;
    return NULL;
  }

  void * shred_shmap = fd_blockstore_shred_map_new( shred_map_shmem, shred_max, seed );
  if( FD_UNLIKELY( !shred_shmap ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_shred_map_new failed" ) );
    fd_wksp_free_laddr( shred_map_shmem );
    goto blockstore_shred_pool_delete;
    return NULL;
  }

  fd_blockstore_shred_map_t * shred_map = fd_blockstore_shred_map_join( shred_shmap );
  if( FD_UNLIKELY( !shred_map ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_shred_map_join failed" ) );
    goto blockstore_shred_map_delete;
    return NULL;
  }

  ulong slot_max_with_slop = slot_max + ( slot_max >> 4U );
  int   lg_slot_max        = 1U;
  while( ( 1U << lg_slot_max ) < slot_max_with_slop )
    lg_slot_max++;

  void * slot_shmem = fd_wksp_alloc_laddr( wksp,
                                           fd_blockstore_slot_map_align(),
                                           fd_blockstore_slot_map_footprint( lg_slot_max ),
                                           wksp_tag );
  if( FD_UNLIKELY( !slot_shmem ) ) {
    FD_LOG_WARNING( ( "lg_slot_max too large for workspace" ) );
    goto blockstore_shred_map_delete;
    return NULL;
  }

  void * slot_shmap = fd_blockstore_slot_map_new( slot_shmem, lg_slot_max );
  if( FD_UNLIKELY( !slot_shmap ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_slot_map_new failed" ) );
    fd_wksp_free_laddr( slot_shmem );
    goto blockstore_shred_map_delete;
    return NULL;
  }

  fd_blockstore_slot_map_t * slot_map = fd_blockstore_slot_map_join( slot_shmap );
  if( FD_UNLIKELY( !slot_shmap ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_slot_map_join failed" ) );
    goto slot_map_delete;
    return NULL;
  }

  void * txn_shmem = fd_wksp_alloc_laddr( wksp,
                                          fd_blockstore_txn_map_align(),
                                          fd_blockstore_txn_map_footprint( lg_txn_max ),
                                          wksp_tag );
  if( FD_UNLIKELY( !txn_shmem ) ) {
    FD_LOG_WARNING( ( "lg_txn_max too large for workspace" ) );
    goto slot_map_delete;
    return NULL;
  }

  void * txn_shmap = fd_blockstore_txn_map_new( txn_shmem, lg_txn_max );
  if( FD_UNLIKELY( !txn_shmap ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_txn_map_new failed" ) );
    fd_wksp_free_laddr( txn_shmem );
    goto slot_map_delete;
    return NULL;
  }

  fd_blockstore_txn_map_t * txn_map = fd_blockstore_txn_map_join( txn_shmap );
  if( FD_UNLIKELY( !txn_map ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_txn_map_join failed" ) );
    goto txn_map_delete;
    return NULL;
  }

  void * alloc_shmem =
      fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), wksp_tag );
  if( FD_UNLIKELY( !alloc_shmem ) ) {
    FD_LOG_WARNING( ( "fd_alloc too large for workspace" ) );
    goto txn_map_delete;
    return NULL;
  }

  void * alloc_shalloc = fd_alloc_new( alloc_shmem, wksp_tag );
  if( FD_UNLIKELY( !alloc_shalloc ) ) {
    FD_LOG_WARNING( ( "fd_allow_new failed" ) );
    fd_wksp_free_laddr( alloc_shalloc );
    goto txn_map_delete;
    return NULL;
  }

  fd_alloc_t * alloc =
      fd_alloc_join( alloc_shalloc, 0UL ); /* TODO: Consider letting user pass the cgroup hint? */
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_WARNING( ( "fd_alloc_join failed" ) );
    fd_wksp_free_laddr( fd_alloc_delete( alloc_shalloc ) );
    goto txn_map_delete;
    return NULL;
  }

  fd_memset( blockstore, 0, fd_blockstore_footprint() );

  blockstore->blockstore_gaddr = fd_wksp_gaddr_fast( wksp, blockstore );
  blockstore->wksp_tag         = wksp_tag;
  blockstore->seed             = seed;

  blockstore->root = 0;
  blockstore->min  = ULONG_MAX;
  blockstore->max  = 0;

  blockstore->shred_max        = shred_max;
  blockstore->shred_pool_gaddr = fd_wksp_gaddr_fast( wksp, shred_pool );
  blockstore->shred_map_gaddr  = fd_wksp_gaddr_fast( wksp, shred_map );

  blockstore->lg_slot_max        = lg_slot_max;
  blockstore->slot_map_gaddr     = fd_wksp_gaddr_fast( wksp, slot_map );
  blockstore->slot_max           = slot_max;
  blockstore->slot_max_with_slop = slot_max_with_slop;

  blockstore->lg_txn_max    = lg_txn_max;
  blockstore->txn_map_gaddr = fd_wksp_gaddr_fast( wksp, txn_map );

  blockstore->alloc_gaddr = fd_wksp_gaddr_fast( wksp, alloc );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( blockstore->magic ) = FD_BLOCKSTORE_MAGIC;
  fd_readwrite_new( &blockstore->lock );
  FD_COMPILER_MFENCE();

  return (void *)blockstore;

txn_map_delete:
  fd_wksp_free_laddr(
      fd_blockstore_txn_map_delete( fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr ) ) );
slot_map_delete:
  fd_wksp_free_laddr(
      fd_blockstore_slot_map_delete( fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr ) ) );
blockstore_shred_map_delete:
  fd_wksp_free_laddr( fd_blockstore_shred_map_delete( shred_map ) );
blockstore_shred_pool_delete:
  fd_wksp_free_laddr( fd_blockstore_shred_pool_delete( shred_pool ) );
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

  /* Free all value resources here */

  for( ulong i = blockstore->min; i <= blockstore->max; i++ )
    fd_blockstore_slot_remove( blockstore, i );

  fd_wksp_free_laddr( fd_alloc_delete( fd_wksp_laddr_fast( wksp, blockstore->alloc_gaddr ) ) );
  fd_wksp_free_laddr(
      fd_blockstore_txn_map_delete( fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr ) ) );
  fd_wksp_free_laddr(
      fd_blockstore_slot_map_delete( fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr ) ) );
  fd_wksp_free_laddr(
      fd_blockstore_shred_map_delete( fd_wksp_laddr_fast( wksp, blockstore->shred_map_gaddr ) ) );
  fd_wksp_free_laddr(
      fd_blockstore_shred_pool_delete( fd_wksp_laddr_fast( wksp, blockstore->shred_pool_gaddr ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( blockstore->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return blockstore;
}

/* txn map helpers */

fd_blockstore_txn_key_t
fd_blockstore_txn_key_null( void ) {
  static fd_blockstore_txn_key_t k = { .v = { 0 } };
  return k;
}

int
fd_blockstore_txn_key_inval( fd_blockstore_txn_key_t k ) {
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    if( k.v[i] ) return 0;
  return 1;
}

int
fd_blockstore_txn_key_equal( fd_blockstore_txn_key_t k0, fd_blockstore_txn_key_t k1 ) {
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    if( k0.v[i] != k1.v[i] ) return 0;
  return 1;
}

uint
fd_blockstore_txn_key_hash( fd_blockstore_txn_key_t k ) {
  ulong h = 0;
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    h ^= k.v[i];
  return (uint)( h ^ ( h >> 32U ) );
}

static void
fd_blockstore_scan_block( fd_blockstore_t * blockstore, ulong slot, fd_block_t * block ) {
  if( blockstore->min > slot ) blockstore->min = slot;
  if( blockstore->max < slot ) blockstore->max = slot;

#define MAX_MICROS ( 16 << 10 )
  fd_block_micro_t micros[MAX_MICROS];
  ulong                 micros_cnt = 0;
#define MAX_TXNS ( 1 << 18 )
  fd_block_txn_ref_t txns[MAX_TXNS];
  ulong                   txns_cnt = 0;

  uchar * data = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->data_gaddr );
  ulong   sz   = block->sz;
  FD_LOG_DEBUG( ( "scanning slot %lu, ptr 0x%lx, sz %lu", slot, data, sz ) );

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
        m->off                    = blockoff;
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
                                          &pay_sz,
                                          0 );
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
          fd_blockstore_txn_map_t * elem = fd_blockstore_txn_map_insert( txn_map, sig );
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
int
fd_blockstore_slot_remove( fd_blockstore_t * blockstore, ulong slot ) {
  fd_wksp_t *                wksp       = fd_blockstore_wksp( blockstore );
  fd_blockstore_slot_map_t * slot_map   = fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr );
  fd_blockstore_slot_map_t * slot_entry = fd_blockstore_slot_map_query( slot_map, slot, NULL );
  if( FD_UNLIKELY( !slot_entry ) ) return FD_BLOCKSTORE_OK;
  if( FD_LIKELY( slot_entry->slot_meta.consumed != ULONG_MAX &&
                 slot_entry->slot_meta.consumed == slot_entry->slot_meta.last_index ) ) {
    fd_alloc_t *              alloc   = fd_wksp_laddr_fast( wksp, blockstore->alloc_gaddr );
    fd_blockstore_txn_map_t * txn_map = fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr );
    fd_block_t *              block   = &slot_entry->block;
    int                       bit = fd_uint_extract_bit( block->flags, FD_BLOCK_FLAG_PREPARED ) |
              fd_uint_extract_bit( block->flags, FD_BLOCK_FLAG_SNAPSHOT );
    if( FD_LIKELY( !bit ) ) {
      uchar *              data = fd_wksp_laddr_fast( wksp, block->data_gaddr );
      fd_block_txn_ref_t * txns = fd_wksp_laddr_fast( wksp, block->txns_gaddr );
      for( ulong j = 0; j < block->txns_cnt; ++j ) {
        fd_blockstore_txn_key_t sig;
        fd_memcpy( &sig, data + txns[j].id_off, sizeof( sig ) );
        fd_blockstore_txn_map_t * txn_map_entry = fd_blockstore_txn_map_query( txn_map, sig, NULL );
        if( FD_LIKELY( txn_map_entry ) ) {
          if( txn_map_entry->meta_gaddr && txn_map_entry->meta_owned )
            fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, txn_map_entry->meta_gaddr ) );
          fd_blockstore_txn_map_remove( txn_map, txn_map_entry );
        }
      }
      if( block->shreds_gaddr ) fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, block->shreds_gaddr ) );
      if( block->micros_gaddr ) fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, block->micros_gaddr ) );
      if( block->txns_gaddr )   fd_alloc_free( alloc, txns );
      if( block->data_gaddr && block->data_gaddr != ULONG_MAX )
        fd_alloc_free( alloc, data );
    }
  }
  fd_blockstore_slot_map_remove( slot_map, slot_entry );
  return FD_BLOCKSTORE_OK;
}

/* Remove all the unassembled shreds for a slot */
int
fd_blockstore_shreds_remove( fd_blockstore_t * blockstore, ulong slot ) {
  fd_wksp_t *                wksp       = fd_blockstore_wksp( blockstore );
  fd_blockstore_slot_map_t * slot_map   = fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr );
  fd_blockstore_slot_map_t * slot_entry = fd_blockstore_slot_map_query( slot_map, slot, NULL );
  if( FD_UNLIKELY( !slot_entry ) ) return FD_BLOCKSTORE_OK;
  fd_blockstore_shred_t *     shred_pool = fd_blockstore_shred_pool( blockstore );
  fd_blockstore_shred_map_t * shred_map  = fd_blockstore_shred_map( blockstore );
  ulong                       shred_cnt  = slot_entry->slot_meta.last_index + 1;
  for( uint i = 0; i < shred_cnt; i++ ) {
    fd_shred_key_t          key = { .slot = slot, .idx = i };
    fd_blockstore_shred_t * ele;
    while( FD_UNLIKELY(
        ele = fd_blockstore_shred_map_ele_remove( shred_map, &key, NULL, shred_pool ) ) )
      fd_blockstore_shred_pool_ele_release( shred_pool, ele );
  }
  fd_blockstore_slot_map_remove( slot_map, slot_entry );
  return FD_BLOCKSTORE_OK;
}

/* Remove the all slots less than min_slots from blockstore by
   removing them from all relevant internal structures. Used to maintain
   invariant `min_slot = max_slot - FD_BLOCKSTORE_SLOT_HISTORY_MAX`. */
int
fd_blockstore_slot_history_remove( fd_blockstore_t * blockstore, ulong min_slot ) {
  if( blockstore->min >= min_slot ) return FD_BLOCKSTORE_OK;

  /* Find next minimum that exists */
  fd_wksp_t *                wksp     = fd_blockstore_wksp( blockstore );
  fd_blockstore_slot_map_t * slot_map = fd_wksp_laddr_fast( wksp, blockstore->slot_map_gaddr );
  while( min_slot < blockstore->max && !fd_blockstore_slot_map_query( slot_map, min_slot, NULL ) )
    ++min_slot;
  ulong old_min_slot = blockstore->min;
  blockstore->min    = min_slot;

  /* Scrub slot_meta and block map */
  for( ulong i = old_min_slot; i < min_slot; ++i ) {
    int err = fd_blockstore_slot_remove( blockstore, i );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BLOCKSTORE_OK;
}

/* Deshred and construct a block once we've received all shreds for a slot. */
static int
fd_blockstore_deshred( fd_blockstore_t * blockstore, ulong slot ) {

  /* TODO add duplicate block logic */
  FD_LOG_DEBUG( ( "deshredding %lu", slot ) );

  // calculate the size of the block
  ulong                      block_sz   = 0;
  fd_blockstore_slot_map_t * slot_map   = fd_blockstore_slot_map( blockstore );
  fd_blockstore_slot_map_t * slot_entry = fd_blockstore_slot_map_query( slot_map, slot, NULL );

  FD_TEST( slot_entry->block.data_gaddr == 0 ); /* FIXME duplicate blocks are not supported */

  fd_blockstore_shred_t *     shred_pool = fd_blockstore_shred_pool( blockstore );
  fd_blockstore_shred_map_t * shred_map  = fd_blockstore_shred_map( blockstore );

  ulong shreds_cnt = slot_entry->slot_meta.last_index + 1;
  for( uint idx = 0; idx < shreds_cnt; idx++ ) {
    fd_shred_key_t key = { .slot = slot, .idx = idx };
    // explicitly query the shred map here because the payload should immediately follow the header
    fd_blockstore_shred_t const * query =
        fd_blockstore_shred_map_ele_query_const( shred_map, &key, NULL, shred_pool );

    // we already deshredded
    if( FD_UNLIKELY( !query ) ) {
      FD_LOG_WARNING( ( "missing shred when blockstore said slot was complete." ) );
      return FD_BLOCKSTORE_OK;
    }
    block_sz += fd_shred_payload_sz( &query->hdr );
  }

  if( FD_UNLIKELY( fd_blockstore_slot_map_key_cnt( slot_map ) ==
                   fd_blockstore_slot_map_key_max( slot_map ) ) ) {
    return FD_BLOCKSTORE_ERR_SLOT_FULL;
  }

  // alloc mem for the block
  fd_block_t *       block        = &slot_entry->block;
  fd_alloc_t *       alloc        = fd_blockstore_alloc( blockstore );
  fd_wksp_t *        wksp         = fd_blockstore_wksp( blockstore );
  fd_block_shred_t * shreds_laddr = fd_alloc_malloc(
      alloc, alignof( fd_block_shred_t ), sizeof( fd_block_shred_t ) * shreds_cnt );
  // FD_TEST( shreds_laddr );
  block->shreds_gaddr = fd_wksp_gaddr_fast( wksp, shreds_laddr );
  block->shreds_cnt   = shreds_cnt;
  block->ts           = fd_log_wallclock();
  uchar * data_laddr  = fd_alloc_malloc( alloc, 128UL, block_sz );
  block->data_gaddr   = fd_wksp_gaddr_fast( wksp, data_laddr );
  block->sz           = block_sz;
  block->micros_gaddr = 0;
  block->micros_cnt   = 0;
  block->txns_gaddr   = 0;
  block->txns_cnt     = 0;
  block->height       = 0;
  block->flags        = 0;
  fd_memset( block->bank_hash.hash, 0, 32U );

  // deshred the shreds into the block mem
  fd_deshredder_t    deshredder = { 0 };
  fd_shred_t const * shreds[1]  = { 0 };
  fd_deshredder_init( &deshredder, data_laddr, block->sz, shreds, 0 );
  long  rc  = -FD_SHRED_EPIPE;
  ulong off = 0;
  for( uint i = 0; i < shreds_cnt; i++ ) {
    // TODO can do this in one iteration with block sz loop... massage with deshredder API
    fd_shred_key_t                key = { .slot = slot, .idx = i };
    fd_blockstore_shred_t const * query =
        fd_blockstore_shred_map_ele_query_const( shred_map, &key, NULL, shred_pool );
    if( FD_UNLIKELY( !query ) ) FD_LOG_ERR( ( "missing shred when slot is complete." ) );
    fd_shred_t const * shred = &query->hdr;
    deshredder.shreds        = &shred;
    deshredder.shred_cnt     = 1;
    rc                       = fd_deshredder_next( &deshredder );

    shreds_laddr[i].hdr = *shred;
    shreds_laddr[i].off = off;

    FD_TEST( !memcmp( &shreds_laddr[i].hdr, shred, sizeof( fd_shred_t ) ) );
    FD_TEST( !memcmp( data_laddr + shreds_laddr[i].off,
                      fd_shred_data_payload( shred ),
                      fd_shred_payload_sz( shred ) ) );

    off += fd_shred_payload_sz( shred );
    fd_blockstore_shred_t * ele;
    while( FD_UNLIKELY(
        ele = fd_blockstore_shred_map_ele_remove( shred_map, &key, NULL, shred_pool ) ) )
      fd_blockstore_shred_pool_ele_release( shred_pool, ele );
  }

  // deshredder error handling
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
  FD_LOG_WARNING( ( "removing slot %lu due to error %d", slot, err ) );
  fd_alloc_free( alloc, shreds_laddr );
  fd_alloc_free( alloc, data_laddr );
  fd_blockstore_slot_remove( blockstore, slot );
  for( uint i = 0; i < shreds_cnt; i++ ) {
    fd_shred_key_t          key = { .slot = slot, .idx = i };
    fd_blockstore_shred_t * ele;
    while( FD_UNLIKELY(
        ele = fd_blockstore_shred_map_ele_remove( shred_map, &key, NULL, shred_pool ) ) ) {
      fd_blockstore_shred_pool_ele_release( shred_pool, ele );
    }
  }
  return err;
}

int
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred ) {
  /* Check if we already have this shred */
  fd_blockstore_shred_t *     shred_pool = fd_blockstore_shred_pool( blockstore );
  fd_blockstore_shred_map_t * shred_map  = fd_blockstore_shred_map( blockstore );
  fd_shred_key_t              shred_key  = { .slot = shred->slot, .idx = shred->idx };
  for( const fd_blockstore_shred_t * query =
           fd_blockstore_shred_map_ele_query_const( shred_map, &shred_key, NULL, shred_pool );
       query;
       query = fd_blockstore_shred_map_ele_next_const( query, NULL, shred_pool ) ) {
    if( memcmp( &query->raw, shred, fd_shred_sz( shred ) ) == 0 ) return FD_BLOCKSTORE_OK;
  }

  /* Insert the shred */

  if( fd_blockstore_shred_pool_free( shred_pool ) == 0 ) { return FD_BLOCKSTORE_ERR_SHRED_FULL; }

  fd_blockstore_shred_t * ele = fd_blockstore_shred_pool_ele_acquire( shred_pool );
  if( FD_UNLIKELY( !ele ) ) return FD_BLOCKSTORE_ERR_SHRED_FULL;
  ele->key = shred_key;
  ele->hdr = *shred;
  fd_memcpy( &ele->raw, shred, fd_shred_sz( shred ) );
  fd_blockstore_shred_map_t * insert =
      fd_blockstore_shred_map_ele_insert( shred_map, ele, shred_pool );
  if( FD_UNLIKELY( !insert ) ) return FD_BLOCKSTORE_ERR_SHRED_FULL;

  /* Update shred's associated slot meta */

  fd_blockstore_slot_map_t * slot_entry =
      fd_blockstore_slot_map_query( fd_blockstore_slot_map( blockstore ), shred->slot, NULL );
  if( FD_UNLIKELY( !slot_entry ) ) {
    slot_entry = fd_blockstore_slot_map_insert( fd_blockstore_slot_map( blockstore ), shred->slot );
    if( FD_UNLIKELY( !slot_entry ) ) return FD_BLOCKSTORE_ERR_SLOT_FULL;

    /* zero-out the block */
    fd_memset( &slot_entry->block, 0, sizeof( fd_block_t ) );

    /* zero-out the slot meta */
    fd_slot_meta_t * slot_meta = &slot_entry->slot_meta;
    fd_memset( slot_meta, 0, sizeof( fd_slot_meta_t ) );

    /* the "reference tick" is the tick at the time the leader prepared the entry batch */
    ulong reference_tick             = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;
    ulong ms                         = reference_tick * FD_MS_PER_TICK;
    ulong now                        = (ulong)fd_log_wallclock() / 1000000UL;
    slot_meta->slot                  = slot_entry->slot;
    slot_meta->consumed              = ULONG_MAX;
    slot_meta->received              = 0;
    slot_meta->first_shred_timestamp = now - ms;
    slot_meta->last_index            = ULONG_MAX;
  }
  fd_slot_meta_t * slot_meta = &slot_entry->slot_meta;

  /* update shred window metadata: consumed, received, last_index */

  FD_LOG_DEBUG( ( "slot_meta->consumed: %lu, shred->slot: %lu, slot_meta->received: %lu, "
                  "shred->idx: %lu, slot_meta->last_index: %lu",
                  slot_meta->consumed,
                  shred->slot,
                  slot_meta->received,
                  shred->idx,
                  slot_meta->last_index ) );
  while(
      fd_blockstore_shred_query( blockstore, shred->slot, (uint)( slot_meta->consumed + 1U ) ) ) {
    slot_meta->consumed++;
  }
  slot_meta->received = fd_ulong_max( slot_meta->received, shred->idx + 1 );
  if( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) slot_meta->last_index = shred->idx;

  /* update ancestry metadata: parent_slot, is_connected, next_slots */

  slot_meta->parent_slot = shred->slot - shred->data.parent_off;
  fd_slot_meta_t * parent_slot_meta =
      fd_blockstore_slot_meta_query( blockstore, slot_meta->parent_slot );
  if( FD_UNLIKELY( !parent_slot_meta ) ) {
    slot_meta->is_connected = 0;
  } else {
    slot_meta->is_connected = 1;
    // FIXME initialize the vectors hdr region
    // parent_slot_meta->next_slot[parent_slot_meta->next_slot_len++] = slot_meta->slot;
  }

  /* entry_end_indexes is unused, and tracks contiguous shred windows */

  if( FD_LIKELY( slot_meta->consumed == ULONG_MAX ||
                 slot_meta->consumed != slot_meta->last_index ) ) {
    return FD_BLOCKSTORE_OK;
  }

  /* Received all shreds, so try to assemble a block. */
  FD_LOG_DEBUG( ( "received all shreds for slot %lu - now building a block", shred->slot ) );

  if( FD_UNLIKELY( blockstore->min != FD_SLOT_NULL &&
                   blockstore->max >= blockstore->slot_max_with_slop &&
                   blockstore->max - blockstore->min >= blockstore->slot_max_with_slop ) ) {
    FD_LOG_WARNING( ( "evicting oldest slot: %lu max: %lu - exceeds slot history max %lu",
                      blockstore->min,
                      blockstore->max,
                      blockstore->slot_max ) );
    if( FD_UNLIKELY( fd_blockstore_slot_history_remove( blockstore,
                                                        blockstore->max - blockstore->slot_max ) !=
                     FD_BLOCKSTORE_OK ) ) {
      FD_LOG_WARNING( ( "failed to find and remove min slot. likely programming error." ) );
    }
  }

  int rc = fd_blockstore_deshred( blockstore, shred->slot );
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
fd_blockstore_shred_query( fd_blockstore_t * blockstore, ulong slot, uint shred_idx ) {
  fd_blockstore_shred_t *     shred_pool = fd_blockstore_shred_pool( blockstore );
  fd_blockstore_shred_map_t * shred_map  = fd_blockstore_shred_map( blockstore );
  fd_shred_key_t              key        = { .slot = slot, .idx = shred_idx };
  fd_blockstore_shred_t *     query =
      fd_blockstore_shred_map_ele_query( shred_map, &key, NULL, shred_pool );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->hdr;
}

fd_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_slot_map_t * query =
      fd_blockstore_slot_map_query( fd_blockstore_slot_map( blockstore ), slot, NULL );
  if( FD_UNLIKELY( !query || query->block.data_gaddr == 0 ) ) return NULL;
  return &query->block;
}

/* Get the final poh hash for a given slot */
fd_hash_t const *
fd_blockstore_block_hash_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_slot_map_t * query =
      fd_blockstore_slot_map_query( fd_blockstore_slot_map( blockstore ), slot, NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  if( FD_UNLIKELY( query->block.micros_gaddr == 0 ) ) return NULL;
  fd_wksp_t *             wksp   = fd_blockstore_wksp( blockstore );
  fd_block_micro_t * micros = fd_wksp_laddr_fast( wksp, query->block.micros_gaddr );
  uchar *                 data   = fd_wksp_laddr_fast( wksp, query->block.data_gaddr );
  fd_microblock_hdr_t *   last_micro =
      (fd_microblock_hdr_t *)( data + micros[query->block.micros_cnt - 1].off );
  return (fd_hash_t *)fd_type_pun( last_micro->hash );
}

/* Get the bank hash for a given slot */
fd_hash_t const *
fd_blockstore_bank_hash_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_slot_map_t * query =
      fd_blockstore_slot_map_query( fd_blockstore_slot_map( blockstore ), slot, NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->block.bank_hash;
}

fd_slot_meta_t *
fd_blockstore_slot_meta_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_slot_map_t * query =
      fd_blockstore_slot_map_query( fd_blockstore_slot_map( blockstore ), slot, NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->slot_meta;
}

/* Return the slot of the parent block */
ulong
fd_blockstore_slot_parent_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_slot_map_t * query =
      fd_blockstore_slot_map_query( fd_blockstore_slot_map( blockstore ), slot, NULL );
  if( FD_UNLIKELY( !query ) ) return FD_SLOT_NULL;
  return query->slot_meta.parent_slot;
}

/* Returns the transaction data for the given signature */
fd_blockstore_txn_map_t *
fd_blockstore_txn_query( fd_blockstore_t * blockstore, uchar const sig[FD_ED25519_SIG_SZ] ) {
  fd_blockstore_txn_key_t key;
  fd_memcpy( &key, sig, sizeof( key ) );
  return fd_blockstore_txn_map_query(
      fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->txn_map_gaddr ),
      key,
      NULL );
}

/* Update the height for a block */
void
fd_blockstore_block_height_update( fd_blockstore_t * blockstore, ulong slot, ulong block_height ) {
  fd_block_t * query = fd_blockstore_block_query( blockstore, slot );
  if( query ) query->height = block_height;
}

void
fd_blockstore_log_block_status( fd_blockstore_t * blockstore, ulong around_slot ) {
  for( ulong i = around_slot - 5; i < around_slot + 20; ++i ) {
    fd_blockstore_slot_map_t * slot_entry =
        fd_blockstore_slot_map_query( fd_blockstore_slot_map( blockstore ), i, NULL );
    if( !slot_entry ) continue;
    FD_LOG_NOTICE( ( "%sslot=%lu received=%ld consumed=%ld last=%ld size=%ld",
                     ( i == around_slot ? "*" : " " ),
                     i,
                     (long)slot_entry->slot_meta.received,
                     (long)slot_entry->slot_meta.consumed,
                     (long)slot_entry->slot_meta.last_index,
                     (long)slot_entry->block.sz ) );
  }
}
