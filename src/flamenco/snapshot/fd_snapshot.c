#include "fd_snapshot.h"
#include "fd_snapshot_loader.h"
#include "fd_snapshot_restore.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/fd_hashes.h"
#include "../runtime/fd_runtime_init.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/fd_runtime.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../rewards/fd_rewards.h"

#include <assert.h>
#include <errno.h>

/* FIXME: don't hardcode this param */
#define ZSTD_WINDOW_SZ (33554432UL)

struct fd_snapshot_load_ctx {
  /* User-defined parameters. */
  const char *           snapshot_dir;
  const char *           snapshot_src;
  int                    snapshot_src_type;
  fd_exec_slot_ctx_t *   slot_ctx;
  uint                   verify_hash;
  uint                   check_hash;
  int                    snapshot_type;

  /* Internal state. */
  fd_funk_txn_t *        par_txn;
  fd_funk_txn_t *        child_txn;

  fd_snapshot_loader_t *  loader;
  fd_snapshot_restore_t * restore;

  fd_spad_t *             runtime_spad;

  fd_exec_para_cb_ctx_t * exec_para_ctx;
};
typedef struct fd_snapshot_load_ctx fd_snapshot_load_ctx_t;

static void
fd_hashes_load( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_TXN_ACCOUNT_DECL( block_hashes_rec );
  int err = fd_txn_account_init_from_funk_readonly( block_hashes_rec, &fd_sysvar_recent_block_hashes_id, slot_ctx->funk, slot_ctx->funk_txn );

  if( err != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_ERR(( "missing recent block hashes account" ));
  }

  fd_bank_execution_fees_set( slot_ctx->bank, 0UL );
}

static int
restore_manifest( void *                              ctx,
                  fd_solana_manifest_global_t const * manifest,
                  fd_spad_t *                         spad ) {
  return (!!fd_exec_slot_ctx_recover( ctx, manifest, spad ) ? 0 : EINVAL);
}

static int
restore_status_cache( void *                  ctx,
                      fd_bank_slot_deltas_t * slot_deltas,
                      fd_spad_t *             spad ) {
  return (!!fd_exec_slot_ctx_recover_status_cache( ctx, slot_deltas, spad ) ? 0 : EINVAL);
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
                      const char *           snapshot_src,
                      int                    snapshot_src_type,
                      const char *           snapshot_dir,
                      fd_exec_slot_ctx_t *   slot_ctx,
                      uint                   verify_hash,
                      uint                   check_hash,
                      int                    snapshot_type,
                      fd_spad_t * *          exec_spads,
                      ulong                  exec_spad_cnt,
                      fd_spad_t *            runtime_spad,
                      fd_exec_para_cb_ctx_t * exec_para_ctx ) {

  (void)exec_spads;
  (void)exec_spad_cnt;

  fd_snapshot_load_ctx_t * ctx = (fd_snapshot_load_ctx_t *)mem;

  ctx->snapshot_dir      = snapshot_dir;
  ctx->snapshot_src      = snapshot_src;
  ctx->snapshot_src_type = snapshot_src_type;
  ctx->slot_ctx          = slot_ctx;
  ctx->verify_hash       = verify_hash;
  ctx->check_hash        = check_hash;
  ctx->snapshot_type     = snapshot_type;
  ctx->runtime_spad      = runtime_spad;
  ctx->exec_para_ctx     = exec_para_ctx;

  return ctx;
}

void
fd_snapshot_load_init( fd_snapshot_load_ctx_t * ctx ) {
  switch( ctx->snapshot_type ) {
    case FD_SNAPSHOT_TYPE_UNSPECIFIED:
      FD_LOG_ERR(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_UNSPECIFIED)", ctx->snapshot_src, ctx->verify_hash ? "true" : "false", ctx->check_hash ? "true" : "false"));
      break;
    case FD_SNAPSHOT_TYPE_FULL:
      FD_LOG_NOTICE(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_FULL)", ctx->snapshot_src, ctx->verify_hash ? "true" : "false", ctx->check_hash ? "true" : "false"));
      break;
    case FD_SNAPSHOT_TYPE_INCREMENTAL:
      FD_LOG_NOTICE(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_INCREMENTAL)", ctx->snapshot_src, ctx->verify_hash ? "true" : "false", ctx->check_hash ? "true" : "false"));
      break;
    default:
      FD_LOG_ERR(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, huh?)", ctx->snapshot_src, ctx->verify_hash ? "true" : "false", ctx->check_hash ? "true" : "false"));
      break;
  }

  ctx->par_txn   = ctx->slot_ctx->funk_txn;
  ctx->child_txn = ctx->slot_ctx->funk_txn;

  // the hash in the incremental snapshot of an lt_hash contains all the accounts.  This means we don't need a sub-txn for the incremental
  if( ctx->verify_hash &&
    (FD_FEATURE_ACTIVE_BANK( ctx->slot_ctx->bank, incremental_snapshot_only_incremental_hash_calculation )
      && !FD_FEATURE_ACTIVE_BANK( ctx->slot_ctx->bank, snapshots_lt_hash ) )) {
    fd_funk_txn_xid_t xid;
    memset( &xid, 0xc3, sizeof(xid) );
    fd_funk_txn_start_write( ctx->slot_ctx->funk );
    ctx->child_txn = fd_funk_txn_prepare( ctx->slot_ctx->funk, ctx->child_txn, &xid, 0 );
    fd_funk_txn_end_write( ctx->slot_ctx->funk );
    ctx->slot_ctx->funk_txn = ctx->child_txn;
  }
}

void
fd_snapshot_load_manifest_and_status_cache( fd_snapshot_load_ctx_t * ctx,
                                            ulong *                  base_slot_override,
                                            int                      restore_manifest_flags ) {

  size_t slen = strlen( ctx->snapshot_src );
  char * snapshot_cstr = fd_spad_alloc( ctx->runtime_spad, 8UL, slen + 1 );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( snapshot_cstr ), ctx->snapshot_src, slen ) );

  fd_snapshot_src_t src[1];
  if( FD_UNLIKELY( !fd_snapshot_src_parse( src, snapshot_cstr, ctx->snapshot_src_type ) ) ) {
    FD_LOG_ERR(( "Failed to parse snapshot src" ));
  }
  src->snapshot_dir = ctx->snapshot_dir;

  fd_funk_t *     funk     = ctx->slot_ctx->funk;
  fd_funk_txn_t * funk_txn = ctx->slot_ctx->funk_txn;

  void * restore_mem = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );
  void * loader_mem  = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_loader_align(),  fd_snapshot_loader_footprint( ZSTD_WINDOW_SZ ) );

  ctx->restore = fd_snapshot_restore_new( restore_mem,
                                          funk,
                                          funk_txn,
                                          ctx->runtime_spad,
                                          ctx->slot_ctx,
                                          (restore_manifest_flags & FD_SNAPSHOT_RESTORE_MANIFEST) ? restore_manifest : NULL,
                                          (restore_manifest_flags & FD_SNAPSHOT_RESTORE_STATUS_CACHE) ? restore_status_cache : NULL );
  if( FD_UNLIKELY( !ctx->restore ) ) {
    FD_LOG_ERR(( "Failed to fd_snapshot_restore_new" ));
  }

  ctx->loader  = fd_snapshot_loader_new ( loader_mem, ZSTD_WINDOW_SZ );

  if( FD_UNLIKELY( !ctx->loader ) ) {
    FD_LOG_ERR(( "Failed to fd_snapshot_loader_new" ));
  }

  if( FD_UNLIKELY( !fd_snapshot_loader_init( ctx->loader,
                                             ctx->restore,
                                             src,
                                             base_slot_override ? *base_slot_override : fd_bank_slot_get( ctx->slot_ctx->bank ),
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

  FD_LOG_NOTICE(( "Finished reading snapshot %s", ctx->snapshot_src ));
}

#define FD_LTHASH_SNAPSHOT_HACK
void
fd_snapshot_load_fini( fd_snapshot_load_ctx_t * ctx ) {
  fd_snapshot_name_t const * name  = fd_snapshot_loader_get_name( ctx->loader );
  fd_hash_t          const * fhash = &name->fhash;

  if( name->type != ctx->snapshot_type ) {
    FD_LOG_ERR(( "snapshot %s is wrong type", ctx->snapshot_src ));
  }

  // In order to calculate the snapshot hash, we need to know what features are active...
  fd_features_restore( ctx->slot_ctx, ctx->runtime_spad );
  fd_calculate_epoch_accounts_hash_values( ctx->slot_ctx );

  int snapshots_lt_hash = FD_FEATURE_ACTIVE_BANK( ctx->slot_ctx->bank, snapshots_lt_hash );
  int accounts_lt_hash = FD_FEATURE_ACTIVE_BANK( ctx->slot_ctx->bank, accounts_lt_hash );
  int incremental_snapshot_only_incremental_hash_calculation = FD_FEATURE_ACTIVE_BANK( ctx->slot_ctx->bank,
    incremental_snapshot_only_incremental_hash_calculation );

  // https://github.com/anza-xyz/agave/blob/766cd682423b8049ddeac3c0ec6cebe0a1356e9e/runtime/src/bank.rs#L1831
  if( accounts_lt_hash ) {
    fd_slot_lthash_t const * lthash = fd_bank_lthash_query( ctx->slot_ctx->bank );
    ulong *p = (ulong *) lthash->lthash;
    ulong *e = (ulong *) &lthash->lthash[sizeof(lthash->lthash)];
    while (p < e) {
      if ( 0 != *(p++) )
        break;
    }
    if (p >= e) {
      if( ctx->snapshot_type==FD_SNAPSHOT_TYPE_FULL ) {
        FD_LOG_WARNING(( "re-calculating accounts lt hash for full snapshot" ));
        fd_lthash_value_t lthash_buf;
        fd_lthash_zero(&lthash_buf);
        fd_hash_t accounts_hash;
        fd_snapshot_hash( ctx->slot_ctx, &accounts_hash, ctx->check_hash, ctx->runtime_spad, ctx->exec_para_ctx, &lthash_buf );
        fd_slot_lthash_t * lthash_val = fd_bank_lthash_modify( ctx->slot_ctx->bank );
        fd_memcpy( (fd_lthash_value_t *)fd_type_pun(lthash_val->lthash), &lthash_buf, sizeof(lthash_buf) );
        FD_LOG_NOTICE(( "re-calculated accounts_lthash for full snapshot %s", FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *)fd_type_pun(lthash_val->lthash)  ) ));
      }
    } else {
      FD_LOG_NOTICE(( "accounts_lthash found %s", FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *)lthash->lthash ) ));
    }
  }

  if( ctx->verify_hash ) {
    fd_hash_t accounts_hash;
    fd_lthash_value_t *lthash = NULL;
    fd_lthash_value_t lthash_buf;
    if ( snapshots_lt_hash ) {
      fd_lthash_zero(&lthash_buf);
      lthash = &lthash_buf;
    }

    if( ctx->snapshot_type==FD_SNAPSHOT_TYPE_FULL ) {
      FD_SPAD_FRAME_BEGIN( ctx->runtime_spad ) {
        fd_snapshot_hash( ctx->slot_ctx, &accounts_hash, ctx->check_hash, ctx->runtime_spad, ctx->exec_para_ctx, lthash );
      } FD_SPAD_FRAME_END;

      if ( snapshots_lt_hash ) {
        fd_slot_lthash_t const * lthash_val = fd_bank_lthash_query( ctx->slot_ctx->bank );
        if( memcmp( (fd_lthash_value_t *)lthash_val->lthash, lthash, sizeof(lthash_buf) ) ) {
          FD_LOG_ERR(( "snapshot accounts_hash (calculated) %s != (expected) %s",
              FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *)lthash_val->lthash ), FD_LTHASH_ENC_32_ALLOCA( lthash ) ));
        } else {
          FD_LOG_NOTICE(( "accounts_lthash found %s verified successfully", FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *)lthash_val->lthash ) ));
        }
      } else {
        if( memcmp( fhash->uc, accounts_hash.uc, sizeof(fd_hash_t) ) ) {
          FD_LOG_ERR(( "snapshot accounts_hash (calculated) %s != (expected) %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ), FD_BASE58_ENC_32_ALLOCA( fhash->uc ) ));
        } else {
          FD_LOG_NOTICE(( "snapshot accounts_hash %s verified successfully", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ) ));
        }
      }
    } else if( ctx->snapshot_type == FD_SNAPSHOT_TYPE_INCREMENTAL ) {
      fd_hash_t accounts_hash;

      if( incremental_snapshot_only_incremental_hash_calculation && !snapshots_lt_hash ) {
        FD_LOG_NOTICE(( "hashing incremental snapshot with only deltas" ));
        fd_snapshot_inc_hash( ctx->slot_ctx, &accounts_hash, ctx->child_txn, ctx->check_hash, ctx->runtime_spad, NULL);
      } else {
        FD_LOG_NOTICE(( "hashing incremental snapshot with all accounts" ));
        fd_snapshot_hash( ctx->slot_ctx, &accounts_hash, ctx->check_hash, ctx->runtime_spad, ctx->exec_para_ctx, lthash );
      }

      if ( snapshots_lt_hash ) {
        fd_slot_lthash_t const * lthash_val = fd_bank_lthash_query( ctx->slot_ctx->bank );
        if( memcmp( (fd_lthash_value_t *)lthash_val->lthash, lthash, sizeof(lthash_buf) ) ) {
          FD_LOG_ERR(( "snapshot accounts_hash (calculated) %s != (expected) %s",
              FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *)lthash_val->lthash ), FD_LTHASH_ENC_32_ALLOCA( lthash ) ));
        } else {
          FD_LOG_NOTICE(( "accounts_lthash found %s verified successfully", FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *)lthash_val->lthash ) ));
        }
      } else {
        if( memcmp( fhash->uc, accounts_hash.uc, sizeof(fd_hash_t) ) ) {
          FD_LOG_ERR(( "incremental accounts_hash %s != %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ), FD_BASE58_ENC_32_ALLOCA( fhash->uc ) ));
        } else {
          FD_LOG_NOTICE(( "incremental accounts_hash %s verified successfully", FD_BASE58_ENC_32_ALLOCA( accounts_hash.hash ) ));
        }
      }
    } else {
      FD_LOG_ERR(( "invalid snapshot type %d", ctx->snapshot_type ));
    }

  }
  if( ctx->child_txn != ctx->par_txn ) {
    fd_funk_txn_start_write( ctx->slot_ctx->funk );
    fd_funk_txn_publish( ctx->slot_ctx->funk, ctx->child_txn, 0 );
    fd_funk_txn_end_write( ctx->slot_ctx->funk );
    ctx->slot_ctx->funk_txn = ctx->par_txn;
  }

  fd_hashes_load( ctx->slot_ctx );

  /* We don't need to free any of the loader memory since it is allocated
     from a spad. */
}

void
fd_snapshot_load_all( const char *         source_cstr,
                      int                  source_type,
                      const char *         snapshot_dir,
                      fd_exec_slot_ctx_t * slot_ctx,
                      ulong *              base_slot_override,
                      fd_tpool_t *         tpool,
                      uint                 verify_hash,
                      uint                 check_hash,
                      int                  snapshot_type,
                      fd_spad_t * *        exec_spads,
                      ulong                exec_spad_cnt,
                      fd_spad_t *          runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  fd_exec_para_cb_ctx_t exec_para_ctx = {
    .func       = fd_accounts_hash_counter_and_gather_tpool_cb,
    .para_arg_1 = tpool
  };

  uchar *                  mem = fd_spad_alloc( runtime_spad, fd_snapshot_load_ctx_align(), fd_snapshot_load_ctx_footprint() );
  fd_snapshot_load_ctx_t * ctx = fd_snapshot_load_new( mem,
                                                       source_cstr,
                                                       source_type,
                                                       snapshot_dir,
                                                       slot_ctx,
                                                       verify_hash,
                                                       check_hash,
                                                       snapshot_type,
                                                       exec_spads,
                                                       exec_spad_cnt,
                                                       runtime_spad,
                                                       &exec_para_ctx );

  fd_snapshot_load_init( ctx );
  fd_runtime_update_slots_per_epoch( slot_ctx->bank, FD_DEFAULT_SLOTS_PER_EPOCH );
  fd_snapshot_load_manifest_and_status_cache( ctx, base_slot_override,
    FD_SNAPSHOT_RESTORE_STATUS_CACHE | FD_SNAPSHOT_RESTORE_MANIFEST );
  fd_snapshot_load_accounts( ctx );
  fd_snapshot_load_fini( ctx );

  } FD_SPAD_FRAME_END;

}

void
fd_snapshot_load_prefetch_manifest( fd_snapshot_load_ctx_t * ctx ) {

  size_t slen = strlen( ctx->snapshot_src );
  char * snapshot_cstr = fd_spad_alloc( ctx->runtime_spad, 8UL, slen + 1 );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( snapshot_cstr ), ctx->snapshot_src, slen ) );

  fd_snapshot_src_t src[1];
  if( FD_UNLIKELY( !fd_snapshot_src_parse( src, snapshot_cstr, ctx->snapshot_src_type ) ) ) {
    FD_LOG_ERR(( "Failed to parse snapshot src" ));
  }
  src->snapshot_dir = ctx->snapshot_dir;

  fd_funk_t *     funk     = ctx->slot_ctx->funk;
  fd_funk_txn_t * funk_txn = ctx->slot_ctx->funk_txn;

  void * restore_mem = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );
  void * loader_mem  = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_loader_align(),  fd_snapshot_loader_footprint( ZSTD_WINDOW_SZ ) );

  ctx->restore = fd_snapshot_restore_new( restore_mem, funk, funk_txn, ctx->runtime_spad, ctx->slot_ctx, restore_manifest, restore_status_cache );
  if( FD_UNLIKELY( !ctx->restore ) ) {
    FD_LOG_ERR(( "Failed to fd_snapshot_restore_new" ));
  }
  ctx->loader  = fd_snapshot_loader_new( loader_mem, ZSTD_WINDOW_SZ );
  if( FD_UNLIKELY( !ctx->loader ) ) {
    FD_LOG_ERR(( "Failed to fd_snapshot_loader_new" ));
  }

  if( FD_UNLIKELY( !fd_snapshot_loader_init( ctx->loader, ctx->restore, src, 0UL, 0 ) ) ) {
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

  fd_snapshot_loader_delete( ctx->loader );
  fd_snapshot_restore_delete( ctx->restore );
}

static int
fd_should_snapshot_include_epoch_accounts_hash(fd_exec_slot_ctx_t * slot_ctx) {
  if( FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, snapshots_lt_hash ) ) {
    return 0;
  }

  // We need to find the correct logic
  if( fd_bank_eah_start_slot_get( slot_ctx->bank ) != ULONG_MAX ) {
    return 0;
  }
  if( fd_bank_eah_stop_slot_get( slot_ctx->bank ) == ULONG_MAX ) {
    return 0;
  }
  return 1;
}

ulong
fd_snapshot_get_slot( fd_snapshot_load_ctx_t * ctx ) {
  return fd_snapshot_restore_get_slot( ctx->restore );
}

int
fd_snapshot_hash( fd_exec_slot_ctx_t *    slot_ctx,
                  fd_hash_t *             accounts_hash,
                  uint                    check_hash,
                  fd_spad_t *             runtime_spad,
                  fd_exec_para_cb_ctx_t * exec_para_ctx,
                  fd_lthash_value_t *     lt_hash ) {
  (void)check_hash;

  if( fd_should_snapshot_include_epoch_accounts_hash( slot_ctx ) ) {
    FD_LOG_NOTICE(( "snapshot is including epoch account hash" ));
    fd_sha256_t h;
    fd_hash_t   hash;
    fd_accounts_hash( slot_ctx->funk,
                      fd_bank_slot_get( slot_ctx->bank ),
                      &hash,
                      runtime_spad,
                      fd_bank_features_query( slot_ctx->bank ),
                      exec_para_ctx,
                      lt_hash );

    fd_sha256_init( &h );
    fd_sha256_append( &h, (uchar const *) hash.hash, sizeof( fd_hash_t ) );
    fd_sha256_append( &h, (uchar const *) fd_bank_epoch_account_hash_query( slot_ctx->bank ), sizeof( fd_hash_t ) );
    fd_sha256_fini( &h, accounts_hash );
    return 0;
  }

  return fd_accounts_hash( slot_ctx->funk,
                           fd_bank_slot_get( slot_ctx->bank ),
                           accounts_hash,
                           runtime_spad,
                           fd_bank_features_query( slot_ctx->bank ),
                           exec_para_ctx,
                           lt_hash );
}

int
fd_snapshot_inc_hash( fd_exec_slot_ctx_t * slot_ctx,
                      fd_hash_t *          accounts_hash,
                      fd_funk_txn_t *      child_txn,
                      uint                 do_hash_verify,
                      fd_spad_t *          spad,
                      fd_lthash_value_t *  lt_hash ) {

  (void) lt_hash;

  if( fd_should_snapshot_include_epoch_accounts_hash( slot_ctx ) ) {
    fd_sha256_t h;
    fd_hash_t   hash;
    fd_accounts_hash_inc_only( slot_ctx, &hash, child_txn, do_hash_verify, spad );

    fd_sha256_init( &h );
    fd_sha256_append( &h, (uchar const *) hash.hash, sizeof( fd_hash_t ) );
    //fd_sha256_append( &h, (uchar const *) slot_ctx->slot_bank.epoch_account_hash.hash, sizeof( fd_hash_t ) );
    fd_sha256_fini( &h, accounts_hash );

    return 0;
  }
  return fd_accounts_hash_inc_only( slot_ctx, accounts_hash, child_txn, do_hash_verify, spad );
}
