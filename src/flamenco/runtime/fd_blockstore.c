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
                   ulong  tmp_shred_max,
                   int    lg_txn_max,
                   ulong  slot_history_max ) {
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

  void * tmp_shred_pool_shmem =
      fd_wksp_alloc_laddr( wksp,
                           fd_blockstore_tmp_shred_pool_align(),
                           fd_blockstore_tmp_shred_pool_footprint( tmp_shred_max ),
                           wksp_tag );
  if( FD_UNLIKELY( !tmp_shred_pool_shmem ) ) {
    FD_LOG_WARNING( ( "tmp_shred_max too large for workspace" ) );
    return NULL;
  }

  void * tmp_shred_shpool = fd_blockstore_tmp_shred_pool_new( tmp_shred_pool_shmem, tmp_shred_max );
  if( FD_UNLIKELY( !tmp_shred_shpool ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_tmp_shred_pool_new failed" ) );
    fd_wksp_free_laddr( tmp_shred_pool_shmem );
    return NULL;
  }

  fd_blockstore_tmp_shred_t * tmp_shred_pool =
      fd_blockstore_tmp_shred_pool_join( tmp_shred_shpool );
  if( FD_UNLIKELY( !tmp_shred_pool ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_tmp_shred_pool_join failed" ) );
    goto tmp_shred_pool_delete;
    return NULL;
  }

  void * tmp_shred_map_shmem =
      fd_wksp_alloc_laddr( wksp,
                           fd_blockstore_tmp_shred_map_align(),
                           fd_blockstore_tmp_shred_map_footprint( tmp_shred_max ),
                           wksp_tag );
  if( FD_UNLIKELY( !tmp_shred_map_shmem ) ) {
    FD_LOG_WARNING( ( "tmp_shred_max too large for workspace" ) );
    goto tmp_shred_pool_delete;
    return NULL;
  }

  void * tmp_shred_shmap =
      fd_blockstore_tmp_shred_map_new( tmp_shred_map_shmem, tmp_shred_max, seed );
  if( FD_UNLIKELY( !tmp_shred_shmap ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_tmp_shred_map_new failed" ) );
    fd_wksp_free_laddr( tmp_shred_map_shmem );
    goto tmp_shred_pool_delete;
    return NULL;
  }

  fd_blockstore_tmp_shred_map_t * tmp_shred_map =
      fd_blockstore_tmp_shred_map_join( tmp_shred_shmap );
  if( FD_UNLIKELY( !tmp_shred_map ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_tmp_shred_map_join failed" ) );
    goto tmp_shred_map_delete;
    return NULL;
  }

  ulong slot_history_max_with_slop = slot_history_max + (slot_history_max>>4U);
  int lg_slot_max = 1U;
  while ( (1U<<lg_slot_max) < slot_history_max_with_slop ) lg_slot_max++;
  void * slot_meta_shmem =
      fd_wksp_alloc_laddr( wksp,
                           fd_blockstore_slot_meta_map_align(),
                           fd_blockstore_slot_meta_map_footprint( lg_slot_max ),
                           wksp_tag );
  if( FD_UNLIKELY( !slot_meta_shmem ) ) {
    FD_LOG_WARNING( ( "lg_slot_max too large for workspace" ) );
    goto tmp_shred_map_delete;
    return NULL;
  }

  void * slot_meta_shmap = fd_blockstore_slot_meta_map_new( slot_meta_shmem, lg_slot_max );
  if( FD_UNLIKELY( !slot_meta_shmap ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_slot_meta_map_new failed" ) );
    fd_wksp_free_laddr( slot_meta_shmem );
    goto tmp_shred_map_delete;
    return NULL;
  }

  fd_blockstore_slot_meta_map_t * slot_meta_map =
      fd_blockstore_slot_meta_map_join( slot_meta_shmap );
  if( FD_UNLIKELY( !slot_meta_map ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_slot_meta_map_join failed" ) );
    goto slot_meta_map_delete;
    return NULL;
  }

  void * block_shmem = fd_wksp_alloc_laddr( wksp,
                                            fd_blockstore_block_map_align(),
                                            fd_blockstore_block_map_footprint( lg_slot_max ),
                                            wksp_tag );
  if( FD_UNLIKELY( !block_shmem ) ) {
    FD_LOG_WARNING( ( "lg_slot_max too large for workspace" ) );
    goto slot_meta_map_delete;
    return NULL;
  }

  void * block_shmap = fd_blockstore_block_map_new( block_shmem, lg_slot_max );
  if( FD_UNLIKELY( !block_shmap ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_block_map_new failed" ) );
    fd_wksp_free_laddr( block_shmem );
    goto slot_meta_map_delete;
    return NULL;
  }

  fd_blockstore_block_map_t * block_map = fd_blockstore_block_map_join( block_shmap );
  if( FD_UNLIKELY( !block_map ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_block_map_join failed" ) );
    goto block_map_delete;
    return NULL;
  }

  void * txn_shmem = fd_wksp_alloc_laddr( wksp,
                                          fd_blockstore_txn_map_align(),
                                          fd_blockstore_txn_map_footprint( lg_txn_max ),
                                          wksp_tag );
  if( FD_UNLIKELY( !txn_shmem ) ) {
    FD_LOG_WARNING( ( "lg_txn_max too large for workspace" ) );
    goto block_map_delete;
    return NULL;
  }

  void * txn_shmap = fd_blockstore_txn_map_new( txn_shmem, lg_txn_max );
  if( FD_UNLIKELY( !txn_shmap ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_txn_map_new failed" ) );
    fd_wksp_free_laddr( txn_shmem );
    goto block_map_delete;
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

  blockstore->tmp_shred_max        = tmp_shred_max;
  blockstore->tmp_shred_pool_gaddr = fd_wksp_gaddr_fast( wksp, tmp_shred_pool );
  blockstore->tmp_shred_map_gaddr  = fd_wksp_gaddr_fast( wksp, tmp_shred_map );

  blockstore->lg_slot_max         = lg_slot_max;
  blockstore->slot_meta_map_gaddr = fd_wksp_gaddr_fast( wksp, slot_meta_map );
  blockstore->block_map_gaddr     = fd_wksp_gaddr_fast( wksp, block_map );
  blockstore->slot_history_max    = slot_history_max;
  blockstore->slot_history_max_with_slop = slot_history_max_with_slop;

  blockstore->lg_txn_max    = lg_txn_max;
  blockstore->txn_map_gaddr = fd_wksp_gaddr_fast( wksp, txn_map );

  blockstore->alloc_gaddr = fd_wksp_gaddr_fast( wksp, alloc );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( blockstore->magic ) = FD_BLOCKSTORE_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)blockstore;

txn_map_delete:
  fd_wksp_free_laddr(
      fd_blockstore_txn_map_delete( fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr ) ) );
block_map_delete:
  fd_wksp_free_laddr( fd_blockstore_block_map_delete( block_map ) );
slot_meta_map_delete:
  fd_wksp_free_laddr( fd_blockstore_slot_meta_map_delete(
      fd_wksp_laddr_fast( wksp, blockstore->slot_meta_map_gaddr ) ) );
tmp_shred_map_delete:
  fd_wksp_free_laddr( fd_blockstore_tmp_shred_map_delete( tmp_shred_map ) );
tmp_shred_pool_delete:
  fd_wksp_free_laddr( fd_blockstore_tmp_shred_pool_delete( tmp_shred_pool ) );
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

static int
fd_blockstore_remove_slot( fd_blockstore_t * blockstore, ulong slot );

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
    fd_blockstore_remove_slot(blockstore, i);

  fd_wksp_free_laddr( fd_alloc_delete( fd_wksp_laddr_fast( wksp, blockstore->alloc_gaddr ) ) );
  fd_wksp_free_laddr(
      fd_blockstore_txn_map_delete( fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr ) ) );
  fd_wksp_free_laddr(
      fd_blockstore_block_map_delete( fd_wksp_laddr_fast( wksp, blockstore->block_map_gaddr ) ) );
  fd_wksp_free_laddr( fd_blockstore_slot_meta_map_delete(
      fd_wksp_laddr_fast( wksp, blockstore->slot_meta_map_gaddr ) ) );
  fd_wksp_free_laddr( fd_blockstore_tmp_shred_map_delete(
      fd_wksp_laddr_fast( wksp, blockstore->tmp_shred_map_gaddr ) ) );
  fd_wksp_free_laddr( fd_blockstore_tmp_shred_pool_delete(
      fd_wksp_laddr_fast( wksp, blockstore->tmp_shred_pool_gaddr ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( blockstore->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return blockstore;
}

/* Accessors (private) */

/* fd_blockstore_tmp_shred_pool returns a pointer in the caller's address space to the blockstore's
 * tmp shred pool. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
 * local join. */
FD_FN_PURE static inline fd_blockstore_tmp_shred_t *
fd_blockstore_tmp_shred_pool( fd_blockstore_t * blockstore ) {
  return (fd_blockstore_tmp_shred_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                          blockstore->tmp_shred_pool_gaddr );
}

/* fd_blockstore_tmp_shred_map returns a pointer in the caller's address space to the blockstore's
 * tmp shred map. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
 * local join. */
FD_FN_PURE static inline fd_blockstore_tmp_shred_map_t *
fd_blockstore_tmp_shred_map( fd_blockstore_t * blockstore ) {
  return (fd_blockstore_tmp_shred_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                              blockstore->tmp_shred_map_gaddr );
}

/* fd_blockstore_slot_meta_map returns a pointer in the caller's address space to the blockstore's
 * slot meta map. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
 * local join. */
FD_FN_PURE static inline fd_blockstore_slot_meta_map_t *
fd_blockstore_slot_meta_map( fd_blockstore_t * blockstore ) {
  return (fd_blockstore_slot_meta_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                              blockstore->slot_meta_map_gaddr );
}

/* fd_blockstore_block_map returns a pointer in the caller's address space to the blockstore's
 * block map. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
 * local join. */
FD_FN_PURE static inline fd_blockstore_block_map_t *
fd_blockstore_block_map( fd_blockstore_t * blockstore ) {
  return (fd_blockstore_block_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                          blockstore->block_map_gaddr );
}

/* fd_blockstore_txn_map returns a pointer in the caller's address space to the blockstore's
 * block map. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
 * local join. */
FD_FN_PURE static inline fd_blockstore_txn_map_t *
fd_blockstore_txn_map( fd_blockstore_t * blockstore ) {
  return (fd_blockstore_txn_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                        blockstore->txn_map_gaddr );
}

/* fd_blockstore_alloc returns a pointer in the caller's address space to
   the blockstore's allocator. */

FD_FN_PURE static inline fd_alloc_t * /* Lifetime is that of the local join */
fd_blockstore_alloc( fd_blockstore_t * blockstore ) {
  return (fd_alloc_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                           blockstore->alloc_gaddr );
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
fd_blockstore_scan_block( fd_blockstore_t *           blockstore,
                          ulong                       slot,
                          fd_blockstore_block_map_t * blk ) {
  if( blockstore->min > slot ) blockstore->min = slot;
  if( blockstore->max < slot ) blockstore->max = slot;

#define MAX_MICROS ( 16 << 10 )
  fd_blockstore_micro_t micros[MAX_MICROS];
  ulong                 micros_cnt = 0;
#define MAX_TXNS ( 1 << 18 )
  fd_blockstore_txn_ref_t txns[MAX_TXNS];
  ulong                   txns_cnt = 0;

  uchar * data = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blk->block.data_gaddr );
  ulong   sz   = blk->block.sz;
  FD_LOG_DEBUG( ( "scanning slot %lu, ptr 0x%lx, sz %lu", slot, data, sz ) );

  ulong blockoff = 0;
  while( blockoff < sz ) {
    if( blockoff + sizeof( ulong ) > sz ) FD_LOG_ERR( ( "premature end of block" ) );
    ulong mcount = *(const ulong *)( (const uchar *)data + blockoff );
    blockoff += sizeof( ulong );

    /* Loop across microblocks */
    for( ulong mblk = 0; mblk < mcount; ++mblk ) {
      if( blockoff + sizeof( fd_microblock_hdr_t ) > sz )
        FD_LOG_ERR( ( "premature end of block" ) );
      if( micros_cnt < MAX_MICROS ) {
        fd_blockstore_micro_t * m = micros + ( micros_cnt++ );
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
          FD_LOG_ERR( ( "failed to parse transaction %lu in microblock %lu in slot %lu",
                        txn_idx,
                        mblk,
                        slot ) );
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
            return;
          }
          fd_blockstore_txn_key_t sig;
          fd_memcpy( &sig, sigs + j, sizeof( sig ) );
          fd_blockstore_txn_map_t * elem = fd_blockstore_txn_map_insert( txn_map, sig );
          if( elem == NULL ) return;
          elem->slot       = slot;
          elem->offset     = blockoff;
          elem->sz         = pay_sz;
          elem->meta_gaddr = 0;
          elem->meta_sz    = 0;
          elem->meta_owned = 0;

          if( txns_cnt < MAX_TXNS ) {
            fd_blockstore_txn_ref_t * ref = &txns[txns_cnt++];
            ref->txn_off = blockoff;
            ref->id_off = (ulong)(sigs + j) - (ulong)data;
            ref->sz = pay_sz;
          }
        }

        blockoff += pay_sz;
      }
    }
  }

  fd_blockstore_micro_t * micros_laddr =
      fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                       alignof(fd_blockstore_micro_t),
                       sizeof( fd_blockstore_micro_t ) * micros_cnt );
  fd_memcpy( micros_laddr, micros, sizeof( fd_blockstore_micro_t ) * micros_cnt );
  blk->block.micros_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), micros_laddr );
  blk->block.micros_cnt   = micros_cnt;

  fd_blockstore_txn_ref_t * txns_laddr =
      fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                       alignof(fd_blockstore_txn_ref_t),
                       sizeof( fd_blockstore_txn_ref_t ) * txns_cnt );
  fd_memcpy( txns_laddr, txns, sizeof( fd_blockstore_txn_ref_t ) * txns_cnt );
  blk->block.txns_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), txns_laddr );
  blk->block.txns_cnt   = txns_cnt;
}

/* Private function for deleting a block slot */
static int
fd_blockstore_remove_slot( fd_blockstore_t * blockstore, ulong slot ) {
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  fd_blockstore_slot_meta_map_t * slot_meta_map = fd_wksp_laddr_fast( wksp, blockstore->slot_meta_map_gaddr );
  fd_blockstore_slot_meta_map_t * slot_meta_entry = fd_blockstore_slot_meta_map_query( slot_meta_map, slot, NULL );
  if( FD_LIKELY( slot_meta_entry ) )
    fd_blockstore_slot_meta_map_remove( slot_meta_map, slot_meta_entry );

  fd_alloc_t *                alloc     = fd_wksp_laddr_fast( wksp, blockstore->alloc_gaddr );
  fd_blockstore_block_map_t * block_map = fd_wksp_laddr_fast( wksp, blockstore->block_map_gaddr );
  fd_blockstore_txn_map_t *   txn_map   = fd_wksp_laddr_fast( wksp, blockstore->txn_map_gaddr );
  fd_blockstore_block_map_t * block_entry = fd_blockstore_block_map_query( block_map, slot, NULL );
  if( FD_LIKELY( block_entry ) ) {
    uchar * data = fd_wksp_laddr_fast( wksp, block_entry->block.data_gaddr );
    fd_blockstore_txn_ref_t * txns = fd_wksp_laddr_fast( wksp, block_entry->block.txns_gaddr );
    for ( ulong j = 0; j < block_entry->block.txns_cnt; ++j ) {
      fd_blockstore_txn_key_t sig;
      fd_memcpy( &sig, data + txns[j].id_off, sizeof( sig ) );
      fd_blockstore_txn_map_t * txn_map_entry = fd_blockstore_txn_map_query( txn_map, sig, NULL );
      if( FD_LIKELY( txn_map_entry ) ) {
        if ( txn_map_entry->meta_gaddr && txn_map_entry->meta_owned )
          fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, txn_map_entry->meta_gaddr ) );
        fd_blockstore_txn_map_remove( txn_map, txn_map_entry );
      }
    }
    fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, block_entry->block.shreds_gaddr ) );
    fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, block_entry->block.micros_gaddr ) );
    fd_alloc_free( alloc, txns );
    fd_alloc_free( alloc, data );
  }
  return FD_BLOCKSTORE_OK;
}

/* Remove the all slots less than min_slots from blockstore by
   removing them from all relevant internal structures. Used to maintain
   invariant `min_slot = max_slot - FD_BLOCKSTORE_SLOT_HISTORY_MAX`. */
int
fd_blockstore_remove_before( fd_blockstore_t * blockstore, ulong min_slot ) {
  if ( blockstore->min >= min_slot )
    return FD_BLOCKSTORE_OK;

  /* Find next minimum that exists */
  fd_wksp_t * wksp = fd_wksp_containing( blockstore );
  fd_blockstore_slot_meta_map_t * slot_meta_map = fd_wksp_laddr_fast( wksp, blockstore->slot_meta_map_gaddr );
  while ( min_slot < blockstore->max &&
          !fd_blockstore_slot_meta_map_query( slot_meta_map, min_slot, NULL ) )
    ++min_slot;
  ulong old_min_slot = blockstore->min;
  blockstore->min = min_slot;

  /* Scrub slot_meta and block map */
  for ( ulong i = old_min_slot; i < min_slot; ++i ) {
    int err = fd_blockstore_remove_slot(blockstore, i);
    if( FD_UNLIKELY(err) )
      return err;
  }
  return FD_BLOCKSTORE_OK;
}

/* Deshred and construct a block once we've received all shreds for a slot. */
static int
fd_blockstore_deshred( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_block_map_t * block_map = fd_blockstore_block_map( blockstore );
  if( FD_UNLIKELY( fd_blockstore_block_map_query( block_map, slot, NULL ) ) ) {
    FD_LOG_ERR( ( "duplicate blocks not supported" ) );
  }

  // calculate the size of the block
  ulong                           block_sz      = 0;
  fd_blockstore_slot_meta_map_t * slot_meta_map = fd_blockstore_slot_meta_map( blockstore );
  fd_blockstore_slot_meta_map_t * slot_meta_entry =
      fd_blockstore_slot_meta_map_query( slot_meta_map, slot, NULL );

  fd_blockstore_tmp_shred_t *     tmp_shred_pool = fd_blockstore_tmp_shred_pool( blockstore );
  fd_blockstore_tmp_shred_map_t * tmp_shred_map  = fd_blockstore_tmp_shred_map( blockstore );

  ulong shred_cnt = slot_meta_entry->slot_meta.last_index + 1;
  for( uint idx = 0; idx < shred_cnt; idx++ ) {
    fd_blockstore_tmp_shred_key_t key = { .slot = slot, .idx = idx };
    // explicitly query the shred map here because the payload should immediately follow the header
    fd_blockstore_tmp_shred_t const * query =
        fd_blockstore_tmp_shred_map_ele_query_const( tmp_shred_map, &key, NULL, tmp_shred_pool );
    if( FD_UNLIKELY( !query ) )
      FD_LOG_ERR( ( "missing shred when blockstore said slot was complete." ) );
    block_sz += fd_shred_payload_sz( &query->hdr );
  }

  if( FD_UNLIKELY( fd_blockstore_block_map_key_cnt( block_map ) ==
                   fd_blockstore_block_map_key_max( block_map ) ) ) {
    return FD_BLOCKSTORE_ERR_SLOT_FULL;
  }

  // alloc mem for the block
  fd_blockstore_block_map_t * insert = fd_blockstore_block_map_insert( block_map, slot );
  FD_TEST( insert );
  fd_alloc_t *            alloc        = fd_blockstore_alloc( blockstore );
  fd_wksp_t *             wksp         = fd_blockstore_wksp( blockstore );
  fd_blockstore_shred_t * shreds_laddr = fd_alloc_malloc(
      alloc, alignof( fd_blockstore_shred_t ), sizeof( fd_blockstore_shred_t ) * shred_cnt );
  // FD_TEST( shreds_laddr );
  insert->block.shreds_gaddr = fd_wksp_gaddr_fast( wksp, shreds_laddr );
  insert->block.shreds_cnt   = shred_cnt;
  insert->block.ts           = fd_log_wallclock();
  uchar * data_laddr         = fd_alloc_malloc( alloc, 128UL, block_sz );
  insert->block.data_gaddr   = fd_wksp_gaddr_fast( wksp, data_laddr );
  insert->block.sz           = block_sz;
  insert->block.micros_gaddr = 0;
  insert->block.micros_cnt   = 0;
  insert->block.txns_gaddr   = 0;
  insert->block.txns_cnt     = 0;
  insert->block.height       = 0;
  fd_memset(insert->block.bank_hash.hash, 0, 32U);

  // deshred the shreds into the block mem
  fd_deshredder_t    deshredder = { 0 };
  fd_shred_t const * shreds[1]  = { 0 };
  fd_deshredder_init( &deshredder, data_laddr, insert->block.sz, shreds, 0 );
  long  rc  = -FD_SHRED_EPIPE;
  ulong off = 0;
  for( uint i = 0; i < shred_cnt; i++ ) {
    // TODO can do this in one iteration with block sz loop... massage with deshredder API
    fd_blockstore_tmp_shred_key_t     key = { .slot = slot, .idx = i };
    fd_blockstore_tmp_shred_t const * query =
        fd_blockstore_tmp_shred_map_ele_query_const( tmp_shred_map, &key, NULL, tmp_shred_pool );
    if( FD_UNLIKELY( !query ) ) FD_LOG_ERR( ( "missing shred when slot is complete." ) );
    fd_shred_t const * shred = &query->hdr;
    deshredder.shreds        = &shred;
    // FD_LOG_NOTICE(("shred slot %lu idx %lu flags 0x%02X", shred->slot, shred->idx,
    // shred->data.flags));
    deshredder.shred_cnt = 1;
    rc                   = fd_deshredder_next( &deshredder );

    shreds_laddr[i].hdr = *shred;
    shreds_laddr[i].off = off;

    FD_TEST( !memcmp( &shreds_laddr[i].hdr, shred, sizeof( fd_shred_t ) ) );
    FD_TEST( !memcmp( data_laddr + shreds_laddr[i].off,
                      fd_shred_data_payload( shred ),
                      fd_shred_payload_sz( shred ) ) );

    off += fd_shred_payload_sz( shred );
    while( FD_UNLIKELY(
        fd_blockstore_tmp_shred_map_ele_remove( tmp_shred_map, &key, NULL, tmp_shred_pool ) ) )
      ;
  }

  // deshredder error handling
  switch( rc ) {
  case -FD_SHRED_EINVAL:
    return FD_BLOCKSTORE_ERR_INVALID_SHRED;
  case -FD_SHRED_ENOMEM:
    FD_LOG_ERR(
        ( "should have alloc'd enough memory above. likely indicates memory corruption." ) );
  }

  switch( deshredder.result ) {
  case FD_SHRED_ESLOT:
    fd_blockstore_scan_block( blockstore, slot, insert );
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
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_slot_meta_t * slot_meta_opt, fd_shred_t const * shred ) {
  fd_blockstore_slot_meta_map_t * slot_meta_map =
      fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->slot_meta_map_gaddr );
  fd_blockstore_slot_meta_map_t * slot_meta_entry =
      fd_blockstore_slot_meta_map_query( slot_meta_map, shred->slot, NULL );
  if( FD_UNLIKELY( !slot_meta_entry ) ) {
    slot_meta_entry      = fd_blockstore_slot_meta_map_insert( slot_meta_map, shred->slot );
    if (slot_meta_opt) {
      slot_meta_entry->slot_meta = *slot_meta_opt;
      slot_meta_entry->slot_meta.consumed = (ulong)-1L;
      slot_meta_entry->slot_meta.received = 0;
    } else {
      fd_memset(&slot_meta_entry->slot_meta, 0, sizeof(slot_meta_entry->slot_meta));
      slot_meta_entry->slot_meta.consumed = (ulong)-1L;
      ulong reference_tick = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;
      ulong ms             = reference_tick * FD_MS_PER_TICK;
      // the "reference tick" is the tick at the point the entry batch is being prepared
      ulong now                                        = (ulong)fd_log_wallclock() / 1000000UL;
      slot_meta_entry->slot_meta.slot                  = slot_meta_entry->slot;
      slot_meta_entry->slot_meta.first_shred_timestamp = now - ms;
    }
  }
  fd_slot_meta_t * slot_meta = &slot_meta_entry->slot_meta;
  slot_meta->last_index      = fd_ulong_max( slot_meta->last_index, shred->idx );
  slot_meta->received        = fd_ulong_max( slot_meta->received, shred->idx );
  slot_meta->parent_slot     = shred->slot - shred->data.parent_off;
  if( FD_UNLIKELY( shred->idx == slot_meta->consumed + 1U ) ) slot_meta->consumed++;
  while( fd_blockstore_shred_query( blockstore, slot_meta->slot, (uint)slot_meta->consumed + 1U ) ) {
    slot_meta->consumed++;
  }

  // TODO forking stuff: parents, children (next slots), is_connected
  // TODO indexes of contiguous shred window -- if we even want to do it that way

  fd_blockstore_tmp_shred_t *     tmp_shred_pool = fd_blockstore_tmp_shred_pool( blockstore );
  fd_blockstore_tmp_shred_map_t * tmp_shred_map  = fd_blockstore_tmp_shred_map( blockstore );
  fd_blockstore_tmp_shred_key_t   insert_key     = { .slot = shred->slot, .idx = shred->idx };
  if( fd_blockstore_tmp_shred_pool_free( tmp_shred_pool ) == 0 ) {
    return FD_BLOCKSTORE_ERR_SHRED_FULL;
  }

  fd_blockstore_tmp_shred_t * ele = fd_blockstore_tmp_shred_pool_ele_acquire( tmp_shred_pool );
  if( FD_UNLIKELY( !ele ) ) return FD_BLOCKSTORE_ERR_SHRED_FULL;
  ele->key = insert_key;
  ele->hdr = *shred;
  fd_memcpy( &ele->raw, shred, fd_shred_sz( shred ) );
  fd_blockstore_tmp_shred_map_t * insert =
      fd_blockstore_tmp_shred_map_ele_insert( tmp_shred_map, ele, tmp_shred_pool );

  if( FD_UNLIKELY( slot_meta->consumed == slot_meta->last_index ) ) {
    FD_LOG_DEBUG( ( "received all shreds for slot %lu - now building a block", slot_meta->slot ) );
    if( FD_UNLIKELY( !insert ) ) return FD_BLOCKSTORE_ERR_SHRED_FULL;

    if( FD_UNLIKELY( blockstore->min != ULONG_MAX &&
                     blockstore->max >= blockstore->slot_history_max_with_slop &&
                     blockstore->max - blockstore->min >= blockstore->slot_history_max_with_slop ) ) {
      FD_LOG_WARNING( ( "evicting oldest slot: %lu max: %lu - exceeds slot history max %lu",
                        blockstore->min,
                        blockstore->max,
                        blockstore->slot_history_max ) );
      if( FD_UNLIKELY( fd_blockstore_remove_before( blockstore, blockstore->max - blockstore->slot_history_max ) != FD_BLOCKSTORE_OK ) ) {
        FD_LOG_WARNING( ( "failed to find and remove min slot. likely programming error." ) );
      }
    }

    int rc = fd_blockstore_deshred( blockstore, slot_meta->slot );
    switch( rc ) {
    case FD_BLOCKSTORE_OK:
      break;
    case FD_BLOCKSTORE_ERR_SLOT_FULL:
      FD_LOG_DEBUG( ( "already deshredded slot %lu. ignoring.", slot_meta->slot ) );
      break;
    default:
      FD_LOG_ERR( ( "deshred err %d", rc ) );
    }
  }

  return FD_BLOCKSTORE_OK;
}

fd_shred_t *
fd_blockstore_shred_query( fd_blockstore_t * blockstore, ulong slot, uint shred_idx ) {
  fd_blockstore_tmp_shred_t *     tmp_shred_pool = fd_blockstore_tmp_shred_pool( blockstore );
  fd_blockstore_tmp_shred_map_t * tmp_shred_map  = fd_blockstore_tmp_shred_map( blockstore );
  fd_blockstore_tmp_shred_key_t   key            = { .slot = slot, .idx = shred_idx };
  fd_blockstore_tmp_shred_t *     query =
      fd_blockstore_tmp_shred_map_ele_query( tmp_shred_map, &key, NULL, tmp_shred_pool );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->hdr;
}

fd_blockstore_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_block_map_t * query =
      fd_blockstore_block_map_query( fd_blockstore_block_map( blockstore ), slot, NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->block;
}

/* Get the final poh hash for a given slot */
uchar const *
fd_blockstore_block_query_hash( fd_blockstore_t * blockstore, ulong slot ) {
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  fd_blockstore_block_map_t * map = fd_wksp_laddr_fast( wksp, blockstore->block_map_gaddr );
  fd_blockstore_block_map_t * query = fd_blockstore_block_map_query( map, slot, NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  fd_blockstore_micro_t * micros = fd_wksp_laddr_fast( wksp, query->block.micros_gaddr );
  uchar * data = fd_wksp_laddr_fast( wksp, query->block.data_gaddr );
  fd_microblock_hdr_t * last_micro = (fd_microblock_hdr_t *)( data + micros[query->block.micros_cnt - 1].off );
  return last_micro->hash;
}

/* Get the bank hash for a given slot */
uchar const *
fd_blockstore_block_query_bank_hash( fd_blockstore_t * blockstore, ulong slot ) {
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  fd_blockstore_block_map_t * map = fd_wksp_laddr_fast( wksp, blockstore->block_map_gaddr );
  fd_blockstore_block_map_t * query = fd_blockstore_block_map_query( map, slot, NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return query->block.bank_hash.hash;
}

fd_slot_meta_t *
fd_blockstore_slot_meta_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_slot_meta_map_t * query = fd_blockstore_slot_meta_map_query(
      fd_wksp_laddr_fast( fd_wksp_containing( blockstore ), blockstore->slot_meta_map_gaddr ),
      slot,
      NULL );
  if( FD_UNLIKELY( !query ) ) return NULL;
  return &query->slot_meta;
}

/* Return the slot of the parent block */
ulong
fd_blockstore_slot_parent_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_blockstore_slot_meta_map_t * query = fd_blockstore_slot_meta_map_query(
      fd_wksp_laddr_fast( fd_wksp_containing( blockstore ), blockstore->slot_meta_map_gaddr ),
      slot,
      NULL );
  if( FD_UNLIKELY( !query ) ) return ULONG_MAX;
  return query->slot_meta.parent_slot;
}

/* Returns the transaction data for the given signature */
fd_blockstore_txn_map_t *
fd_blockstore_txn_query( fd_blockstore_t * blockstore, uchar const sig[FD_ED25519_SIG_SZ] ) {
  fd_blockstore_txn_key_t key;
  fd_memcpy( &key, sig, sizeof( key ) );
  return fd_blockstore_txn_map_query(
      fd_wksp_laddr_fast( fd_wksp_containing( blockstore ), blockstore->txn_map_gaddr ),
      key,
      NULL );
}

/* Set the height for a block */
void
fd_blockstore_set_height( fd_blockstore_t * blockstore,
                          ulong slot,
                          ulong block_height ) {
  fd_blockstore_block_t * query = fd_blockstore_block_query( blockstore, slot );
  if( query )
    query->height = block_height;
}
