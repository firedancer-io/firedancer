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
}; 
typedef struct fd_snapshot_load_ctx fd_snapshot_load_ctx_t;

static void
fd_hashes_load( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_BORROWED_ACCOUNT_DECL( block_hashes_rec );
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_recent_block_hashes_id, block_hashes_rec );

  if( err != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_ERR(( "missing recent block hashes account" ));
  }

  fd_bincode_decode_ctx_t ctx = {
    .data       = block_hashes_rec->const_data,
    .dataend    = block_hashes_rec->const_data + block_hashes_rec->const_meta->dlen,
    .valloc     = slot_ctx->valloc
  };

  fd_recent_block_hashes_decode( &slot_ctx->slot_bank.recent_block_hashes, &ctx );

  /* FIXME: Do not hardcode the number of vote accounts */

  slot_ctx->slot_bank.stake_account_keys.stake_accounts_root = NULL;
  slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool = fd_stake_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000UL );

  slot_ctx->slot_bank.vote_account_keys.vote_accounts_root = NULL;
  slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool = fd_vote_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000UL );

  slot_ctx->slot_bank.collected_execution_fees = 0UL;
  slot_ctx->slot_bank.collected_priority_fees  = 0UL;
  slot_ctx->slot_bank.collected_rent           = 0UL;

  fd_runtime_save_slot_bank( slot_ctx );
  fd_runtime_save_epoch_bank( slot_ctx );
}

static int
restore_manifest( void *                 ctx,
                  fd_solana_manifest_t * manifest ) {
  return (!!fd_exec_slot_ctx_recover( ctx, manifest ) ? 0 : EINVAL);
}

static int
restore_status_cache( void *                 ctx,
                      fd_bank_slot_deltas_t * slot_deltas ) {
  return (!!fd_exec_slot_ctx_recover_status_cache( ctx, slot_deltas ) ? 0 : EINVAL);
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
                      int                    snapshot_type ) {

  fd_snapshot_load_ctx_t * ctx = (fd_snapshot_load_ctx_t *)mem;
  ctx->snapshot_file = snapshot_file;
  ctx->slot_ctx      = slot_ctx;
  ctx->tpool         = tpool;
  ctx->verify_hash   = verify_hash;
  ctx->check_hash    = check_hash;
  ctx->snapshot_type = snapshot_type;
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
  if( ctx->verify_hash && FD_FEATURE_ACTIVE( ctx->slot_ctx, incremental_snapshot_only_incremental_hash_calculation ) ) {
    fd_funk_txn_xid_t xid;
    memset( &xid, 0xc3, sizeof(xid) );
    ctx->child_txn = fd_funk_txn_prepare( ctx->slot_ctx->acc_mgr->funk, ctx->child_txn, &xid, 0 );
    ctx->slot_ctx->funk_txn = ctx->child_txn;
    }
}

void
fd_snapshot_load_manifest_and_status_cache( fd_snapshot_load_ctx_t * ctx ) {

  fd_scratch_push();
  size_t slen = strlen( ctx->snapshot_file );
  char * snapshot_cstr = fd_scratch_alloc( 1UL, slen + 1 );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( snapshot_cstr ), ctx->snapshot_file, slen ) );

  fd_snapshot_src_t src[1];
  if( FD_UNLIKELY( !fd_snapshot_src_parse( src, snapshot_cstr ) ) ) {
    FD_LOG_ERR(( "Failed to load snapshot" ));
  }

  fd_exec_epoch_ctx_bank_mem_clear( ctx->slot_ctx->epoch_ctx );

  fd_valloc_t     valloc   = ctx->slot_ctx->valloc;
  fd_acc_mgr_t *  acc_mgr  = ctx->slot_ctx->acc_mgr;
  fd_funk_txn_t * funk_txn = ctx->slot_ctx->funk_txn;

  void * restore_mem = fd_valloc_malloc( valloc, fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );
  void * loader_mem  = fd_valloc_malloc( valloc, fd_snapshot_loader_align(),  fd_snapshot_loader_footprint( ZSTD_WINDOW_SZ ) );

  ctx->restore = fd_snapshot_restore_new( restore_mem, acc_mgr, funk_txn, valloc, ctx->slot_ctx, restore_manifest, restore_status_cache );
  ctx->loader  = fd_snapshot_loader_new ( loader_mem, ZSTD_WINDOW_SZ );

  if( FD_UNLIKELY( !ctx->restore || !ctx->loader ) ) {
    fd_valloc_free( valloc, fd_snapshot_loader_delete ( ctx->loader  ) );
    fd_valloc_free( valloc, fd_snapshot_restore_delete( ctx->restore ) );
    FD_LOG_ERR(( "Failed to load snapshot" ));
  }

  if( FD_UNLIKELY( !fd_snapshot_loader_init( ctx->loader, ctx->restore, src, ctx->slot_ctx->slot_bank.slot, 1 ) ) ) {
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

  fd_valloc_free( ctx->slot_ctx->valloc, fd_snapshot_loader_delete ( ctx->loader ) );
  fd_valloc_free( ctx->slot_ctx->valloc, fd_snapshot_restore_delete( ctx->restore ) );

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
  fd_features_restore( ctx->slot_ctx );
  fd_calculate_epoch_accounts_hash_values( ctx->slot_ctx );

  if( ctx->verify_hash ) {
    if( ctx->snapshot_type==FD_SNAPSHOT_TYPE_FULL ) {
      fd_hash_t accounts_hash;
      fd_snapshot_hash(ctx->slot_ctx, ctx->tpool, &accounts_hash, ctx->check_hash );

      if( memcmp( fhash->uc, accounts_hash.uc, sizeof(fd_hash_t) ) ) {
        FD_LOG_ERR(( "snapshot accounts_hash (calculated) %s != (expected) %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ), FD_BASE58_ENC_32_ALLOCA( fhash->uc ) ));
      } else {
        FD_LOG_NOTICE(( "snapshot accounts_hash %s verified successfully", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ) ));
      }
    } else if( ctx->snapshot_type == FD_SNAPSHOT_TYPE_INCREMENTAL) {
      fd_hash_t accounts_hash;

      if( FD_FEATURE_ACTIVE( ctx->slot_ctx, incremental_snapshot_only_incremental_hash_calculation ) ) {
        FD_LOG_NOTICE(( "hashing incremental snapshot with only deltas" ));
        fd_accounts_hash_inc_only( ctx->slot_ctx, &accounts_hash, ctx->child_txn, ctx->check_hash );
      } else {
        FD_LOG_NOTICE(( "hashing incremental snapshot with all accounts" ));
        fd_snapshot_hash( ctx->slot_ctx, ctx->tpool, &accounts_hash, ctx->check_hash );
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

  fd_hashes_load( ctx->slot_ctx );

  fd_rewards_recalculate_partitioned_rewards( ctx->slot_ctx );

  fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );
}

void
fd_snapshot_load_all( const char *         source_cstr,
                      fd_exec_slot_ctx_t * slot_ctx,
                      fd_tpool_t *         tpool,
                      uint                 verify_hash,
                      uint                 check_hash,
                      int                  snapshot_type ) {

  FD_SCRATCH_SCOPE_BEGIN {

  uchar *                  mem = fd_scratch_alloc( fd_snapshot_load_ctx_align(), fd_snapshot_load_ctx_footprint() );
  fd_snapshot_load_ctx_t * ctx = fd_snapshot_load_new( mem, source_cstr, slot_ctx, tpool, verify_hash, check_hash, snapshot_type );

  fd_snapshot_load_init( ctx );
  fd_snapshot_load_manifest_and_status_cache( ctx );
  fd_snapshot_load_accounts( ctx );
  fd_snapshot_load_fini( ctx );

  } FD_SCRATCH_SCOPE_END;
}

void
fd_snapshot_load_prefetch_manifest( fd_snapshot_load_ctx_t * ctx ) {

  fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );

  size_t slen = strlen( ctx->snapshot_file );
  char * snapshot_cstr = fd_scratch_alloc( 8UL, slen + 1 );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( snapshot_cstr ), ctx->snapshot_file, slen ) );

  fd_snapshot_src_t src[1];
  if( FD_UNLIKELY( !fd_snapshot_src_parse( src, snapshot_cstr ) ) ) {
    FD_LOG_ERR(( "Failed to load snapshot" ));
  }

  fd_valloc_t     valloc   = ctx->slot_ctx->valloc;
  fd_acc_mgr_t *  acc_mgr  = ctx->slot_ctx->acc_mgr;
  fd_funk_txn_t * funk_txn = ctx->slot_ctx->funk_txn;

  void * restore_mem = fd_valloc_malloc( valloc, fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );
  void * loader_mem  = fd_valloc_malloc( valloc, fd_snapshot_loader_align(),  fd_snapshot_loader_footprint( ZSTD_WINDOW_SZ ) );

  ctx->restore = fd_snapshot_restore_new( restore_mem, acc_mgr, funk_txn, valloc, ctx->slot_ctx, restore_manifest, restore_status_cache );
  ctx->loader  = fd_snapshot_loader_new ( loader_mem, ZSTD_WINDOW_SZ );

  if( FD_UNLIKELY( !ctx->restore || !ctx->loader ) ) {
    fd_valloc_free( valloc, fd_snapshot_loader_delete ( ctx->loader  ) );
    fd_valloc_free( valloc, fd_snapshot_restore_delete( ctx->restore ) );
    FD_LOG_ERR(( "Failed to load snapshot" ));
  }

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
