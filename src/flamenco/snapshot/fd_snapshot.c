#include "fd_snapshot.h"
#include "fd_snapshot_loader.h"
#include "fd_snapshot_restore.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/fd_hashes.h"
#include "../runtime/fd_runtime_init.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../rewards/fd_rewards.h"
#include "../runtime/fd_runtime.h"

#include <assert.h>
#include <errno.h>

/* FIXME: don't hardcode this param */
#define ZSTD_WINDOW_SZ (33554432UL)

struct fd_snapshot_load_ctx {
  /* User-defined parameters. */
  const char *           snapshot_file;
  fd_exec_slot_ctx_t *   slot_ctx;
  fd_tpool_t *           tpool;
  uint                   verify_hash;
  uint                   check_hash;
  int                    snapshot_type;

  /* Internal state. */
  fd_funk_txn_t *        par_txn;
  fd_funk_txn_t *        child_txn;

  fd_snapshot_loader_t *  loader;
  fd_snapshot_restore_t * restore;

  fd_spad_t *             runtime_spad;
};
typedef struct fd_snapshot_load_ctx fd_snapshot_load_ctx_t;

static void
fd_hashes_load( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  FD_TXN_ACCOUNT_DECL( block_hashes_rec );
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_recent_block_hashes_id, block_hashes_rec );

  if( err != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_ERR(( "missing recent block hashes account" ));
  }

  /* FIXME: Do not hardcode the number of vote accounts */

  slot_ctx->slot_bank.stake_account_keys.account_keys_root = NULL;
  uchar * pool_mem = fd_spad_alloc( runtime_spad, fd_account_keys_pair_t_map_align(), fd_account_keys_pair_t_map_footprint( 100000UL ) );

  slot_ctx->slot_bank.stake_account_keys.account_keys_pool = fd_account_keys_pair_t_map_join( fd_account_keys_pair_t_map_new( pool_mem, 100000UL ) );

  slot_ctx->slot_bank.vote_account_keys.account_keys_root = NULL;
  pool_mem = fd_spad_alloc( runtime_spad, fd_account_keys_pair_t_map_align(), fd_account_keys_pair_t_map_footprint( 100000UL ) );
  slot_ctx->slot_bank.vote_account_keys.account_keys_pool = fd_account_keys_pair_t_map_join( fd_account_keys_pair_t_map_new( pool_mem, 100000UL ) );

  slot_ctx->slot_bank.collected_execution_fees = 0UL;
  slot_ctx->slot_bank.collected_priority_fees  = 0UL;
  slot_ctx->slot_bank.collected_rent           = 0UL;

  fd_runtime_save_slot_bank( slot_ctx );
  fd_runtime_save_epoch_bank( slot_ctx );
}

static int
restore_manifest( void *                 ctx,
                  fd_solana_manifest_t * manifest,
                  fd_spad_t *            spad ) {
  return (!!fd_exec_slot_ctx_recover( ctx, manifest, spad ) ? 0 : EINVAL);
}

static int
restore_status_cache( void *                  ctx,
                      fd_bank_slot_deltas_t * slot_deltas,
                      fd_spad_t *             spad ) {
  return (!!fd_exec_slot_ctx_recover_status_cache( ctx, slot_deltas, spad ) ? 0 : EINVAL);
}

static int
restore_rent_fresh_account( fd_exec_slot_ctx_t * slot_ctx,
                            fd_pubkey_t const  * pubkey ) {
  fd_runtime_register_new_fresh_account( slot_ctx, pubkey );
  return 0;
}

ulong
fd_snapshot_load_ctx_align( void ) {
  return alignof(fd_snapshot_load_ctx_t);
}

ulong
fd_snapshot_load_ctx_footprint( void ) {
  return sizeof(fd_snapshot_load_ctx_t);
}

fd_snapshot_load_ctx_t *
fd_snapshot_load_new( uchar *                mem,
                      const char *           snapshot_file,
                      fd_exec_slot_ctx_t *   slot_ctx,
                      fd_tpool_t *           tpool,
                      uint                   verify_hash,
                      uint                   check_hash,
                      int                    snapshot_type,
                      fd_spad_t * *          exec_spads,
                      ulong                  exec_spad_cnt,
                      fd_spad_t *            runtime_spad ) {

  (void)exec_spads;
  (void)exec_spad_cnt;

  fd_snapshot_load_ctx_t * ctx = (fd_snapshot_load_ctx_t *)mem;
  ctx->snapshot_file = snapshot_file;
  ctx->slot_ctx      = slot_ctx;
  ctx->tpool         = tpool;
  ctx->verify_hash   = verify_hash;
  ctx->check_hash    = check_hash;
  ctx->snapshot_type = snapshot_type;
  ctx->runtime_spad  = runtime_spad;
  return ctx;
}

void
fd_snapshot_load_init( fd_snapshot_load_ctx_t * ctx ) {
  switch( ctx->snapshot_type ) {
    case FD_SNAPSHOT_TYPE_UNSPECIFIED:
      FD_LOG_ERR(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_UNSPECIFIED)", ctx->snapshot_file, ctx->verify_hash ? "true" : "false", ctx->check_hash ? "true" : "false"));
      break;
    case FD_SNAPSHOT_TYPE_FULL:
      FD_LOG_NOTICE(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_FULL)", ctx->snapshot_file, ctx->verify_hash ? "true" : "false", ctx->check_hash ? "true" : "false"));
      break;
    case FD_SNAPSHOT_TYPE_INCREMENTAL:
      FD_LOG_NOTICE(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_INCREMENTAL)", ctx->snapshot_file, ctx->verify_hash ? "true" : "false", ctx->check_hash ? "true" : "false"));
      break;
    default:
      FD_LOG_ERR(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, huh?)", ctx->snapshot_file, ctx->verify_hash ? "true" : "false", ctx->check_hash ? "true" : "false"));
      break;
  }

  fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );

  ctx->par_txn   = ctx->slot_ctx->funk_txn;
  ctx->child_txn = ctx->slot_ctx->funk_txn;
  if( ctx->verify_hash && FD_FEATURE_ACTIVE( ctx->slot_ctx->slot_bank.slot, ctx->slot_ctx->epoch_ctx->features, incremental_snapshot_only_incremental_hash_calculation ) ) {
    fd_funk_txn_xid_t xid;
    memset( &xid, 0xc3, sizeof(xid) );
    ctx->child_txn = fd_funk_txn_prepare( ctx->slot_ctx->acc_mgr->funk, ctx->child_txn, &xid, 0 );
    ctx->slot_ctx->funk_txn = ctx->child_txn;
    }
}

void
fd_snapshot_load_manifest_and_status_cache( fd_snapshot_load_ctx_t * ctx,
                                            ulong *                  base_slot_override,
                                            int                      restore_manifest_flags ) {

  size_t slen = strlen( ctx->snapshot_file );
  char * snapshot_cstr = fd_spad_alloc( ctx->runtime_spad, 8UL, slen + 1 );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( snapshot_cstr ), ctx->snapshot_file, slen ) );

  fd_snapshot_src_t src[1];
  if( FD_UNLIKELY( !fd_snapshot_src_parse( src, snapshot_cstr ) ) ) {
    FD_LOG_ERR(( "Failed to load snapshot" ));
  }

  fd_exec_epoch_ctx_bank_mem_clear( ctx->slot_ctx->epoch_ctx );

  fd_acc_mgr_t *  acc_mgr  = ctx->slot_ctx->acc_mgr;
  fd_funk_txn_t * funk_txn = ctx->slot_ctx->funk_txn;

  void * restore_mem = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );
  void * loader_mem  = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_loader_align(),  fd_snapshot_loader_footprint( ZSTD_WINDOW_SZ ) );

  ctx->restore = fd_snapshot_restore_new( restore_mem,
                                          acc_mgr,
                                          funk_txn,
                                          ctx->runtime_spad,
                                          ctx->slot_ctx,
                                          (restore_manifest_flags & FD_SNAPSHOT_RESTORE_MANIFEST) ? restore_manifest : NULL,
                                          (restore_manifest_flags & FD_SNAPSHOT_RESTORE_STATUS_CACHE) ? restore_status_cache : NULL,
                                          restore_rent_fresh_account );

  ctx->loader  = fd_snapshot_loader_new ( loader_mem, ZSTD_WINDOW_SZ );

  if( FD_UNLIKELY( !ctx->restore || !ctx->loader ) ) {
    FD_LOG_ERR(( "Failed to load snapshot" ));
  }

  if( FD_UNLIKELY( !fd_snapshot_loader_init( ctx->loader,
                                            ctx->restore,
                                                    src,
                                                    base_slot_override ? *base_slot_override : ctx->slot_ctx->slot_bank.slot,
                                                    1 ) ) ) {
    FD_LOG_ERR(( "Failed to init snapshot loader" ));
  }

  /* First load in the manifest. */
  for(;;) {
    int err = fd_snapshot_loader_advance( ctx->loader );
    if( err==MANIFEST_DONE ) break; /* We have finished loading in the manifest. */
    if( FD_LIKELY( !err ) ) continue; /* Keep going. */

    /* If we have reached the end of the snapshot(err==-1), throw an error because
       this is not expected. */
    FD_LOG_ERR(( "Failed to load snapshot (%d-%s)", err, fd_io_strerror( err ) ));
  }

}

void
fd_snapshot_load_accounts( fd_snapshot_load_ctx_t * ctx ) {

  /* Now, that the manifest is done being read in. Read in the rest of the accounts. */
  for(;;) {
    int err = fd_snapshot_loader_advance( ctx->loader );
    if( err==-1 ) break; /* We have finished loading in the snapshot. */
    if( FD_LIKELY( err==0 ) ) continue; /* Keep going. */

    FD_LOG_ERR(( "Failed to load snapshot (%d-%s)", err, fd_io_strerror( err ) ));
  }

  fd_snapshot_name_t const * name = fd_snapshot_loader_get_name( ctx->loader );
  if( FD_UNLIKELY( !name ) ) FD_LOG_ERR(( "name is NULL" ));

  FD_LOG_NOTICE(( "Done loading accounts" ));

  FD_LOG_NOTICE(( "Finished reading snapshot %s", ctx->snapshot_file ));
}

void
fd_snapshot_load_fini( fd_snapshot_load_ctx_t * ctx ) {

  fd_snapshot_name_t const * name  = fd_snapshot_loader_get_name( ctx->loader );
  fd_hash_t          const * fhash = &name->fhash;

  if( name->type != ctx->snapshot_type ) {
    FD_LOG_ERR(( "snapshot %s is wrong type", ctx->snapshot_file ));
  }

  // In order to calculate the snapshot hash, we need to know what features are active...
  fd_features_restore( ctx->slot_ctx, ctx->runtime_spad );
  fd_calculate_epoch_accounts_hash_values( ctx->slot_ctx );

  // https://github.com/anza-xyz/agave/blob/766cd682423b8049ddeac3c0ec6cebe0a1356e9e/runtime/src/bank.rs#L1831
  if( FD_FEATURE_ACTIVE( ctx->slot_ctx->slot_bank.slot, ctx->slot_ctx->epoch_ctx->features, accounts_lt_hash ) ) {
    ulong *p = (ulong *) ctx->slot_ctx->slot_bank.lthash.lthash;
    ulong *e = (ulong *) &ctx->slot_ctx->slot_bank.lthash.lthash[sizeof(ctx->slot_ctx->slot_bank.lthash.lthash)];
    while (p < e) {
      if ( 0 != *(p++) )
        break;
    }
    if (p >= e)
      FD_LOG_ERR(( "snapshot must have an accounts lt hash if the feature is enabled" ));
  }

  if( ctx->verify_hash ) {
    if( ctx->snapshot_type==FD_SNAPSHOT_TYPE_FULL ) {
      fd_hash_t accounts_hash;
      FD_SPAD_FRAME_BEGIN( ctx->runtime_spad ) {
        fd_snapshot_hash( ctx->slot_ctx, ctx->tpool, &accounts_hash, ctx->check_hash, ctx->runtime_spad );
      } FD_SPAD_FRAME_END;

      if( memcmp( fhash->uc, accounts_hash.uc, sizeof(fd_hash_t) ) ) {
        FD_LOG_ERR(( "snapshot accounts_hash (calculated) %s != (expected) %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ), FD_BASE58_ENC_32_ALLOCA( fhash->uc ) ));
      } else {
        FD_LOG_NOTICE(( "snapshot accounts_hash %s verified successfully", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ) ));
      }
    } else if( ctx->snapshot_type == FD_SNAPSHOT_TYPE_INCREMENTAL ) {
      fd_hash_t accounts_hash;

      if( FD_FEATURE_ACTIVE( ctx->slot_ctx->slot_bank.slot, ctx->slot_ctx->epoch_ctx->features, incremental_snapshot_only_incremental_hash_calculation ) ) {
        FD_LOG_NOTICE(( "hashing incremental snapshot with only deltas" ));
        fd_snapshot_inc_hash( ctx->slot_ctx, &accounts_hash, ctx->child_txn, ctx->check_hash, ctx->runtime_spad );
      } else {
        FD_LOG_NOTICE(( "hashing incremental snapshot with all accounts" ));
        fd_snapshot_hash( ctx->slot_ctx, ctx->tpool, &accounts_hash, ctx->check_hash, ctx->runtime_spad );
      }

      if( memcmp( fhash->uc, accounts_hash.uc, sizeof(fd_hash_t) ) ) {
        FD_LOG_ERR(( "incremental accounts_hash %s != %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ), FD_BASE58_ENC_32_ALLOCA( fhash->uc ) ));
      } else {
        FD_LOG_NOTICE(( "incremental accounts_hash %s verified successfully", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ) ));
      }
    } else {
      FD_LOG_ERR(( "invalid snapshot type %d", ctx->snapshot_type ));
    }
  }

  if( ctx->child_txn != ctx->par_txn ) {
    fd_funk_txn_publish( ctx->slot_ctx->acc_mgr->funk, ctx->child_txn, 0 );
    ctx->slot_ctx->funk_txn = ctx->par_txn;
  }

  fd_hashes_load( ctx->slot_ctx, ctx->runtime_spad );

  /* We don't need to free any of the loader memory since it is allocated
     from a spad. */

  fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );
}

void
fd_snapshot_load_all( const char *         source_cstr,
                      fd_exec_slot_ctx_t * slot_ctx,
                      ulong *              base_slot_override,
                      fd_tpool_t *         tpool,
                      uint                 verify_hash,
                      uint                 check_hash,
                      int                  snapshot_type,
                      fd_spad_t * *        exec_spads,
                      ulong                exec_spad_cnt,
                      fd_spad_t *          runtime_spad ) {

  uchar *                  mem = fd_spad_alloc( runtime_spad, fd_snapshot_load_ctx_align(), fd_snapshot_load_ctx_footprint() );
  fd_snapshot_load_ctx_t * ctx = fd_snapshot_load_new( mem,
                                                       source_cstr,
                                                       slot_ctx,
                                                       tpool,
                                                       verify_hash,
                                                       check_hash,
                                                       snapshot_type,
                                                       exec_spads,
                                                       exec_spad_cnt,
                                                       runtime_spad );

  fd_snapshot_load_init( ctx );
  fd_runtime_update_slots_per_epoch( slot_ctx, 432000UL, runtime_spad );
  fd_snapshot_load_manifest_and_status_cache( ctx, base_slot_override,
    FD_SNAPSHOT_RESTORE_STATUS_CACHE | FD_SNAPSHOT_RESTORE_MANIFEST );
  fd_snapshot_load_accounts( ctx );
  fd_snapshot_load_fini( ctx );

}

void
fd_snapshot_load_prefetch_manifest( fd_snapshot_load_ctx_t * ctx ) {

  fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );

  size_t slen = strlen( ctx->snapshot_file );
  char * snapshot_cstr = fd_spad_alloc( ctx->runtime_spad, 8UL, slen + 1 );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( snapshot_cstr ), ctx->snapshot_file, slen ) );

  fd_snapshot_src_t src[1];
  if( FD_UNLIKELY( !fd_snapshot_src_parse( src, snapshot_cstr ) ) ) {
    FD_LOG_ERR(( "Failed to load snapshot" ));
  }

  fd_acc_mgr_t *  acc_mgr  = ctx->slot_ctx->acc_mgr;
  fd_funk_txn_t * funk_txn = ctx->slot_ctx->funk_txn;

  void * restore_mem = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );
  void * loader_mem  = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_loader_align(),  fd_snapshot_loader_footprint( ZSTD_WINDOW_SZ ) );

  ctx->restore = fd_snapshot_restore_new( restore_mem, acc_mgr, funk_txn, ctx->runtime_spad, ctx->slot_ctx, restore_manifest, restore_status_cache, restore_rent_fresh_account );
  ctx->loader  = fd_snapshot_loader_new( loader_mem, ZSTD_WINDOW_SZ );

  if( FD_UNLIKELY( !fd_snapshot_loader_init( ctx->loader, ctx->restore, src, ctx->slot_ctx->slot_bank.slot, 0 ) ) ) {
    FD_LOG_ERR(( "Failed to init snapshot loader" ));
  }

  /* First load in the manifest. */
  for(;;) {
    int err = fd_snapshot_loader_advance( ctx->loader );
    if( err==MANIFEST_DONE ) break; /* We have finished loading in the manifest. */
    if( FD_LIKELY( !err ) ) continue; /* Keep going. */

    /* If we have reached the end of the snapshot(err==-1), throw an error because
       this is not expected. */
    FD_LOG_ERR(( "Failed to load snapshot (%d-%s)", err, fd_io_strerror( err ) ));
  }

  fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );
}

ulong
fd_snapshot_get_slot( fd_snapshot_load_ctx_t * ctx ) {
  return fd_snapshot_restore_get_slot( ctx->restore );
}
