#include "fd_snapshot.h"
#include "fd_snapshot_loader.h"
#include "fd_snapshot_restore.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/fd_hashes.h"
#include "../runtime/fd_runtime.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../runtime/context/fd_exec_slot_ctx.h"

#include <assert.h>
#include <errno.h>

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

static void
fd_hashes_load(fd_exec_slot_ctx_t * slot_ctx) {
  FD_BORROWED_ACCOUNT_DECL(block_hashes_rec);
  int err = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_recent_block_hashes_id, block_hashes_rec);

  if( err != FD_ACC_MGR_SUCCESS )
    FD_LOG_ERR(( "missing recent block hashes account" ));

  fd_bincode_decode_ctx_t ctx = {
    .data       = block_hashes_rec->const_data,
    .dataend    = block_hashes_rec->const_data + block_hashes_rec->const_meta->dlen,
    .valloc     = slot_ctx->valloc
  };

  fd_recent_block_hashes_decode( &slot_ctx->slot_bank.recent_block_hashes, &ctx );

  slot_ctx->slot_bank.stake_account_keys.stake_accounts_root = NULL;
  slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool = fd_stake_accounts_pair_t_map_alloc(slot_ctx->valloc, 100000);

  slot_ctx->slot_bank.vote_account_keys.vote_accounts_root = NULL;
  slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool = fd_vote_accounts_pair_t_map_alloc(slot_ctx->valloc, 100000);

  slot_ctx->slot_bank.collected_fees = 0;
  slot_ctx->slot_bank.collected_rent = 0;

  fd_runtime_save_slot_bank( slot_ctx );
  fd_runtime_save_epoch_bank( slot_ctx );
}


static int
restore_manifest( void *                 ctx,
                  fd_solana_manifest_t * manifest ) {
  return (!!fd_exec_slot_ctx_recover( ctx, manifest ) ? 0 : EINVAL);
}

static void
load_one_snapshot( fd_exec_slot_ctx_t * slot_ctx,
                   char *               source_cstr ) {

  /* FIXME don't hardcode this param */
  static ulong const zstd_window_sz = 33554432UL;

  fd_snapshot_src_t src[1];
  if( FD_UNLIKELY( !fd_snapshot_src_parse( src, source_cstr ) ) ) {
    FD_LOG_ERR(( "Failed to load snapshot" ));
  }

  fd_valloc_t     valloc   = slot_ctx->valloc;
  fd_acc_mgr_t *  acc_mgr  = slot_ctx->acc_mgr;
  fd_funk_txn_t * funk_txn = slot_ctx->funk_txn;

  void * restore_mem = fd_valloc_malloc( valloc, fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );
  void * loader_mem  = fd_valloc_malloc( valloc, fd_snapshot_loader_align(),  fd_snapshot_loader_footprint( zstd_window_sz ) );

  fd_snapshot_restore_t * restore = fd_snapshot_restore_new( restore_mem, acc_mgr, funk_txn, valloc, slot_ctx, restore_manifest );
  fd_snapshot_loader_t *  loader  = fd_snapshot_loader_new ( loader_mem, zstd_window_sz );

  if( FD_UNLIKELY( !restore || !loader ) ) {
    fd_valloc_free( valloc, fd_snapshot_loader_delete ( loader_mem  ) );
    fd_valloc_free( valloc, fd_snapshot_restore_delete( restore_mem ) );
    FD_LOG_ERR(( "Failed to load snapshot" ));
  }

  if( FD_UNLIKELY( !fd_snapshot_loader_init( loader, restore, src ) ) ) {
    FD_LOG_ERR(( "Failed to init snapshot loader" ));
  }

  for(;;) {
    int err = fd_snapshot_loader_advance( loader );
    if( FD_LIKELY( err == 0 ) ) continue;
    if( err == -1 ) break;

    FD_LOG_ERR(( "Failed to load snapshot (%d-%s)", err, fd_io_strerror( err ) ));
  }

  fd_valloc_free( valloc, fd_snapshot_loader_delete ( loader_mem  ) );
  fd_valloc_free( valloc, fd_snapshot_restore_delete( restore_mem ) );

  FD_LOG_NOTICE(( "Finished reading snapshot %s", source_cstr ));
}


void
fd_snapshot_load( const char *         snapshotfile,
                  fd_exec_slot_ctx_t * slot_ctx,
                  uint                 verify_hash,
                  uint                 check_hash,
                  int                  snapshot_type ) {

  switch (snapshot_type) {
  case FD_SNAPSHOT_TYPE_UNSPECIFIED:
    FD_LOG_ERR(("fd_snapshot_load(%s, verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_UNSPECIFIED)", snapshotfile, verify_hash ? "true" : "false", check_hash ? "true" : "false"));
    break;
  case FD_SNAPSHOT_TYPE_FULL:
    FD_LOG_NOTICE(("fd_snapshot_load(%s, verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_FULL)", snapshotfile, verify_hash ? "true" : "false", check_hash ? "true" : "false"));
    break;
  case FD_SNAPSHOT_TYPE_INCREMENTAL:
    FD_LOG_NOTICE(("fd_snapshot_load(%s, verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_INCREMENTAL)", snapshotfile, verify_hash ? "true" : "false", check_hash ? "true" : "false"));
    break;
  default:
    FD_LOG_ERR(("fd_snapshot_load(%s, verify-hash=%s, check-hash=%s, huh?)", snapshotfile, verify_hash ? "true" : "false", check_hash ? "true" : "false"));
    break;
  }

  ulong const slen = strlen(snapshotfile);
  const char *hptr = &snapshotfile[slen - 1];
  while ((hptr >= snapshotfile) && (*hptr != '-'))
    hptr--;
  hptr++;
  char hash[100];
  ulong const hlen = (size_t) ((&snapshotfile[slen - 1] - hptr) - 7);
  if( hlen > sizeof(hash)-1U )
    FD_LOG_ERR(( "invalid snapshot file %s", snapshotfile ));
  memcpy(hash, hptr, hlen);
  hash[hlen] = '\0';

  fd_hash_t fhash;
  if( FD_UNLIKELY( !fd_base58_decode_32( hash, fhash.uc ) ) )
    FD_LOG_ERR(( "invalid snapshot hash" ));

  fd_funk_speed_load_mode( slot_ctx->acc_mgr->funk, 1 );
  fd_funk_start_write( slot_ctx->acc_mgr->funk );

  fd_funk_txn_t * child_txn = slot_ctx->funk_txn;

  fd_scratch_push();
  char * snapshot_cstr = fd_scratch_alloc( 1UL, slen + 1 );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( snapshot_cstr ), snapshotfile, slen ) );
  load_one_snapshot( slot_ctx, snapshot_cstr );
  fd_scratch_pop();

  // In order to calculate the snapshot hash, we need to know what features are active...
  fd_features_restore( slot_ctx );
  fd_calculate_epoch_accounts_hash_values( slot_ctx );

  if( verify_hash ) {
    if (snapshot_type == FD_SNAPSHOT_TYPE_FULL) {
      fd_hash_t accounts_hash;
      fd_snapshot_hash(slot_ctx, &accounts_hash, child_txn, check_hash, 0);

      if (memcmp(fhash.uc, accounts_hash.uc, 32) != 0)
        FD_LOG_ERR(("snapshot accounts_hash %32J != %32J", accounts_hash.hash, fhash.uc));
      else
        FD_LOG_NOTICE(("snapshot accounts_hash %32J verified successfully", accounts_hash.hash));
    } else if (snapshot_type == FD_SNAPSHOT_TYPE_INCREMENTAL) {
      fd_hash_t accounts_hash;

      if (FD_FEATURE_ACTIVE(slot_ctx, incremental_snapshot_only_incremental_hash_calculation)) {
        FD_LOG_NOTICE(( "hashing incremental snapshot with only deltas" ));
        fd_snapshot_hash(slot_ctx, &accounts_hash, child_txn, check_hash, 1);
      } else {
        FD_LOG_NOTICE(( "hashing incremental snapshot with all accounts" ));
        fd_snapshot_hash(slot_ctx, &accounts_hash, NULL, check_hash, 0);
      }

      if (memcmp(fhash.uc, accounts_hash.uc, 32) != 0)
        FD_LOG_ERR(("incremental accounts_hash %32J != %32J", accounts_hash.hash, fhash.uc));
      else
        FD_LOG_NOTICE(("incremental accounts_hash %32J verified successfully", accounts_hash.hash));
    } else {
      FD_LOG_ERR(( "invalid snapshot type %u", snapshot_type ));
    }
  }

  fd_hashes_load(slot_ctx);

  fd_funk_end_write( slot_ctx->acc_mgr->funk );
  fd_funk_speed_load_mode( slot_ctx->acc_mgr->funk, 0 );
}
