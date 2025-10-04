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
    rec->txn_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  } else if( query_err==FD_MAP_SUCCESS ) {
    fd_funk_txn_t * txn = fd_funk_txn_map_query_ele( txn_query );
    prepare->rec_head_idx = &txn->rec_head_idx;
    prepare->rec_tail_idx = &txn->rec_tail_idx;
    rec->txn_cidx = fd_funk_txn_cidx( (ulong)( txn - funk->txn_pool->ele ) );
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
  fd_funk_txn_xid_t actual_xid = *xid;
  if( is_rooted ) {
    fd_funk_txn_xid_set_root( &actual_xid );
  }
  fd_funk_txn_xid_copy( rec->pair.xid, xid );
  memcpy( rec->pair.key, prog_addr, 32UL );

  rec->tag      = 0;
  rec->flags    = 0;
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
