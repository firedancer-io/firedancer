#include "fd_progcache.h"
#include "fd_progcache_evict.h"
#include "fd_prog_load.h"
#include "../runtime/fd_bank.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "fd_progcache_rec.h"

FD_TL fd_progcache_metrics_t   fd_progcache_metrics_default;
FD_TL fd_progcache_metrics_t * fd_progcache_metrics_cur;

__attribute__((constructor)) static void
init_progcache( void ) {
  fd_progcache_metrics_cur = &fd_progcache_metrics_default;
}

/* Algorithm to estimate size of cache metadata structures (rec_pool
   object pool and rec_map hashchain table).

   FIXME Carefully balance this */

static ulong
fd_progcache_est_rec_max1( ulong wksp_footprint,
                           ulong mean_cache_entry_size ) {
  return wksp_footprint / mean_cache_entry_size;
}

ulong
fd_progcache_est_rec_max( ulong wksp_footprint,
                          ulong mean_cache_entry_size ) {
  ulong est = fd_progcache_est_rec_max1( wksp_footprint, mean_cache_entry_size );
  if( FD_UNLIKELY( est>(1UL<<31) ) ) FD_LOG_ERR(( "fd_progcache_est_rec_max(wksp_footprint=%lu,mean_cache_entry_size=%lu) failed: invalid parameters", wksp_footprint, mean_cache_entry_size ));
  return fd_ulong_max( est, 2048UL );
}

fd_progcache_t *
fd_progcache_join( fd_progcache_t * ljoin,
                   void *           shfunk ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shfunk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
    return NULL;
  }

  memset( ljoin, 0, sizeof(fd_progcache_t) );
  if( FD_UNLIKELY( !fd_funk_join( ljoin->funk, shfunk ) ) ) return NULL;
  return ljoin;
}

void *
fd_progcache_leave( fd_progcache_t * cache,
                    void **          opt_shfunk ) {
  if( FD_UNLIKELY( !cache ) ) {
    FD_LOG_WARNING(( "NULL cache" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_funk_leave( cache->funk, opt_shfunk ) ) ) return NULL;
  return cache;
}

fd_progcache_rec_t const *
fd_progcache_peek( fd_progcache_t const *    cache,
                   fd_funk_txn_xid_t const * xid,
                   void const *              prog_addr ) {
  if( FD_UNLIKELY( !cache || !cache->funk->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  fd_funk_rec_key_t key[1]; memcpy( key->uc, prog_addr, 32UL );
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( cache->funk, xid, key, NULL, query );
  if( FD_UNLIKELY( !rec ) ) return NULL;
  return fd_funk_val_const( rec, fd_funk_wksp( cache->funk ) );
}

static void
fd_progcache_publish_prepare( fd_funk_rec_prepare_t *   prepare,
                              fd_funk_rec_t *           rec,
                              fd_funk_txn_map_query_t * txn_query,
                              fd_funk_t const *         funk,
                              fd_funk_txn_xid_t const * xid ) {
  prepare->rec = rec;
  int query_err = fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, txn_query, 0 );
  if( query_err==FD_MAP_ERR_KEY ) {
    if( FD_UNLIKELY( !fd_funk_txn_xid_eq( xid, fd_funk_last_publish( funk ) ) ) ) {
      FD_LOG_CRIT(( "fd_funk_txn_map_query_try failed: xid %lu:%lu not found", xid->ul[0], xid->ul[1] ));
    }
  } else if( query_err==FD_MAP_SUCCESS ) {
    fd_funk_txn_t * txn = fd_funk_txn_map_query_ele( txn_query );
    prepare->rec_head_idx = &txn->rec_head_idx;
    prepare->rec_tail_idx = &txn->rec_tail_idx;
  } else {
    FD_LOG_CRIT(( "fd_funk_txn_map_query_try failed (%i-%s)", query_err, fd_map_strerror( query_err ) ));
  }
}

static void
fd_progcache_publish( fd_progcache_t *          cache,
                      fd_funk_txn_xid_t const * xid,
                      fd_funk_rec_t *           rec,
                      void const *              prog_addr ) {
  fd_funk_t * funk = cache->funk;

  fd_funk_txn_map_query_t query[1];
  fd_funk_rec_prepare_t prepare[1] = {{0}};
  fd_progcache_publish_prepare( prepare, rec, query, funk, xid );

  int is_rooted = !prepare->rec_head_idx;
  if( is_rooted ) fd_funk_txn_xid_set_root( rec->pair.xid );
  else            fd_funk_txn_xid_copy( rec->pair.xid, xid );
  memcpy( rec->pair.key, prog_addr, 32UL );

  rec->tag      = 0;
  rec->prev_idx = FD_FUNK_REC_IDX_NULL;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;

  fd_funk_rec_publish( funk, prepare );

  if( !is_rooted ) {
    int query_err = fd_funk_txn_map_query_test( query );
    if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_txn_map_query_test failed (%i-%s)", query_err, fd_map_strerror( query_err ) ));
  }
}

static fd_progcache_rec_t const *
fd_progcache_insert( fd_progcache_t *          cache,
                     fd_funk_t *               accdb,
                     fd_funk_txn_xid_t const * xid,
                     void const *              prog_addr,
                     ulong                     gen,
                     fd_bank_t const *         bank,
                     ulong const               last_slot_modified ) {

  /* Acquire reference to ELF binary data */

  fd_funk_txn_xid_t modify_xid;
  ulong progdata_sz;
  uchar const * progdata = fd_prog_load_elf( accdb, xid, prog_addr, &progdata_sz, &modify_xid );
  if( FD_UNLIKELY( !progdata ) ) return NULL;

  /* Prevent cache entry from crossing epoch boundary */

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  ulong load_epoch   = fd_bank_epoch_get( bank );
  ulong modify_epoch = fd_slot_to_epoch( epoch_schedule, modify_xid.ul[0], NULL );
  if( FD_UNLIKELY( modify_epoch<load_epoch ) ) {
    ulong target_slot = fd_epoch_slot0( epoch_schedule, load_epoch );
    /* Walk up funk txn chain until we find a slot >= target_slot */
    fd_funk_txn_map_query_t query[1];
    FD_TEST( fd_funk_txn_map_query_try( cache->funk->txn_map, xid, NULL, query, 0 ) != FD_MAP_ERR_KEY );
    fd_funk_txn_t const * candidate = fd_funk_txn_map_query_ele_const( query );
    for(;;) {
      ulong parent_idx = fd_funk_txn_idx( candidate->parent_cidx );
      if( fd_funk_txn_idx_is_null( parent_idx ) ) break;
      fd_funk_txn_t const * parent = &cache->funk->txn_pool->ele[ parent_idx ];
      if( parent->xid.ul[0]<target_slot ) break;
      if( FD_UNLIKELY( parent->xid.ul[0]>=candidate->xid.ul[0] ) ) {
        /* prevent cycles and other forms of corruption */
        FD_LOG_CRIT(( "fd_progcache_insert failed: funk txn tree is malformed (txn %lu:%lu has parent %lu:%lu)",
                      candidate->xid.ul[0], candidate->xid.ul[1],
                      parent   ->xid.ul[0], parent   ->xid.ul[1] ));
      }
      candidate = parent;
    }
    modify_xid = candidate->xid;
  }

  /* Peek ELF header to determine allocation size */

  fd_features_t const * features  = fd_bank_features_query( bank );
  ulong         const   load_slot = fd_bank_slot_get( bank );
  fd_prog_versions_t versions = fd_prog_versions( features, load_slot );
  fd_sbpf_loader_config_t config = {
    .sbpf_min_version = versions.min_sbpf_version,
    .sbpf_max_version = versions.max_sbpf_version,
  };
  fd_sbpf_elf_info_t elf_info[1];
  if( FD_UNLIKELY( fd_sbpf_elf_peek( elf_info, progdata, progdata_sz, &config ) ) ) return NULL;

  /* Allocate cache entry */

  fd_funk_t *     funk          = cache->funk;
  ulong           rec_footprint = fd_progcache_rec_footprint( elf_info );
  fd_funk_rec_t * funk_rec      = fd_progcache_rec_acquire( cache, rec_footprint, gen );
  void *          rec_mem       = fd_wksp_laddr_fast( funk->wksp, funk_rec->val_gaddr );

  /* Load cache entry */

  fd_progcache_rec_t * rec = fd_progcache_rec_new( rec_mem, elf_info, load_slot, features, progdata, progdata_sz );
  if( FD_UNLIKELY( !rec ) ) {  /* load failed? */
    fd_progcache_rec_tombstone( cache, funk_rec );
    rec_mem = fd_wksp_laddr_fast( funk->wksp, funk_rec->val_gaddr );
    rec     = fd_progcache_rec_new_nx( rec_mem, load_slot, last_slot_modified );
  }
  rec->last_slot_modified = last_slot_modified;

  /* Publish cache entry to funk index */

  fd_progcache_publish( cache, &modify_xid, funk_rec, prog_addr );
  return rec;
}

fd_progcache_rec_t const *
fd_progcache_pull( fd_progcache_t *          cache,
                   fd_funk_t *               accdb,
                   fd_funk_txn_xid_t const * xid,
                   void const *              prog_addr,
                   ulong                     gen,
                   fd_bank_t const *         bank ) {
  if( FD_UNLIKELY( !cache || !cache->funk->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));

  fd_progcache_rec_t const * found_rec = fd_progcache_peek( cache, xid, prog_addr );
  ulong last_slot_modified = 0UL;
  if( found_rec ) {

    fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
    ulong current_slot                         = fd_bank_slot_get( bank );
    ulong current_epoch                        = fd_bank_epoch_get( bank );
    ulong last_epoch_verified                  = fd_slot_to_epoch( epoch_schedule, found_rec->last_slot_verified, NULL );
    /* */ last_slot_modified                   = found_rec->last_slot_modified;
    if( FD_LIKELY( last_epoch_verified==current_epoch &&
                  ( last_slot_modified<found_rec->last_slot_verified ||
                    current_slot==found_rec->last_slot_verified ) ) ) {
      return found_rec;
    }

  }

  return fd_progcache_insert( cache, accdb, xid, prog_addr, gen, bank, last_slot_modified );
}

fd_progcache_rec_t const *
fd_progcache_invalidate( fd_progcache_t *          cache,
                         fd_funk_txn_xid_t const * xid,
                         void const *              prog_addr,
                         ulong                     slot,
                         ulong                     gen ) {
  if( FD_UNLIKELY( !cache || !cache->funk->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  fd_funk_rec_key_t key[1]; memcpy( key->uc, prog_addr, 32UL );
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * prev_rec = fd_funk_rec_query_try_global( cache->funk, xid, prog_addr, NULL, query );
  if( FD_UNLIKELY( !prev_rec ) ) return NULL; /* nothing to invalidate */

  ulong                rec_footprint = fd_progcache_rec_footprint( NULL );
  fd_funk_rec_t *      funk_rec      = fd_progcache_rec_acquire( cache, rec_footprint, gen );
  void *               rec_mem       = fd_wksp_laddr_fast( cache->funk->wksp, funk_rec->val_gaddr );
  fd_progcache_rec_t * rec           = fd_progcache_rec_new_nx( rec_mem, slot, slot );
  fd_progcache_publish( cache, xid, funk_rec, prog_addr );
  return rec;
}

/* reset_txn_list does a depth-first traversal of the txn tree.
   Detaches all recs from txns by emptying rec linked lists. */

static void
reset_txn_list( fd_funk_t * funk,
                ulong       txn_head_idx ) {
  fd_funk_txn_pool_t * txn_pool = funk->txn_pool;
  for( ulong idx = txn_head_idx;
       !fd_funk_txn_idx_is_null( idx );
  ) {
    fd_funk_txn_t * txn = &txn_pool->ele[ idx ];
    fd_funk_txn_state_assert( txn, FD_FUNK_TXN_STATE_ACTIVE );
    txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
    txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;
    reset_txn_list( funk, txn->child_head_cidx );
    idx = fd_funk_txn_idx( txn->sibling_next_cidx );
  }
}

/* reset_rec_map frees all records in a funk instance. */

static void
reset_rec_map( fd_funk_t * funk ) {
  fd_wksp_t *          wksp     = funk->wksp;
  fd_alloc_t *         alloc    = funk->alloc;
  fd_funk_rec_map_t *  rec_map  = funk->rec_map;
  fd_funk_rec_pool_t * rec_pool = funk->rec_pool;

  ulong chain_cnt = fd_funk_rec_map_chain_cnt( rec_map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    for(
        fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter( rec_map, chain_idx );
        !fd_funk_rec_map_iter_done( iter );
    ) {
      fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( iter );
      ulong next = fd_funk_rec_map_private_idx( rec->map_next );;

      /* Remove rec object from map */
      fd_funk_rec_map_query_t rec_query[1];
      int err = fd_funk_rec_map_remove( rec_map, fd_funk_rec_pair( rec ), NULL, rec_query, FD_MAP_FLAG_BLOCKING );
      fd_funk_rec_key_t key; fd_funk_rec_key_copy( &key, rec->pair.key );
      if( FD_UNLIKELY( err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", err, fd_map_strerror( err ) ));

      /* Free rec resources */
      fd_funk_val_flush( rec, alloc, wksp );
      fd_funk_rec_pool_release( rec_pool, rec, 1 );
      iter.ele_idx = next;
    }
  }
}

void
fd_progcache_reset( fd_progcache_t * cache ) {
  fd_funk_t * funk = cache->funk;
  reset_txn_list( funk, fd_funk_txn_idx( funk->shmem->child_head_cidx ) );
  reset_rec_map( funk );
}

void
fd_progcache_clear( fd_progcache_t * cache ) {
  /* FIXME this descends the progcache txn tree multiple times */
  fd_progcache_reset( cache );
  fd_funk_txn_cancel_all( cache->funk );
}
