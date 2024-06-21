#include "fd_snapshot.h"
#include "fd_snapshot_loader.h"
#include "fd_snapshot_restore.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/fd_hashes.h"
#include "../runtime/fd_runtime_init.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../runtime/context/fd_exec_slot_ctx.h"

#include <assert.h>
#include <errno.h>

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

fd_snapshot_name_t *
fd_snapshot_name_from_buf( fd_snapshot_name_t * id,
                           char const *         str,
                           ulong                str_len,
                           ulong                base_slot ) {
  char buf[ 4096 ];
  str_len = fd_ulong_min( sizeof(buf)-1, str_len );
  fd_memcpy( buf, str, str_len );

  return fd_snapshot_name_from_cstr( id, buf, base_slot );
}

fd_snapshot_name_t *
fd_snapshot_name_from_cstr( fd_snapshot_name_t * id,
                            char const *         cstr,
                            ulong                base_slot ) {

  fd_memset( id, 0, sizeof(fd_snapshot_name_t) );

  const char * orig_cstr = cstr;

  char * last_slash = strrchr( cstr, '/' );
  if( last_slash && last_slash[0]=='/' ) cstr = last_slash + 1;

  if( 0==strncmp( cstr, "snapshot-", sizeof("snapshot-")-1 ) ) {
    cstr += sizeof("snapshot-")-1;
    id->type = FD_SNAPSHOT_TYPE_FULL;
  } else if( 0==strncmp( cstr, "incremental-snapshot-", sizeof("incremental-snapshot-")-1 ) ) {
    cstr += sizeof("incremental-snapshot-")-1;
    id->type = FD_SNAPSHOT_TYPE_INCREMENTAL;
  } else {
    FD_LOG_WARNING(( "unrecognized snapshot type: \"%s\"", orig_cstr ));
    return NULL;
  }

  char const * endptr = NULL;
  id->slot = strtoul( cstr, fd_type_pun( &endptr ), 10 );
  if( !endptr || endptr[0]!='-' ) {
    FD_LOG_WARNING(( "invalid snapshot file name: \"%s\"", orig_cstr ));
    return NULL;
  }
  cstr = endptr+1;

  if( id->type == FD_SNAPSHOT_TYPE_INCREMENTAL ) {
    id->incremental_slot = strtoul( cstr, fd_type_pun( &endptr ), 10 );
    if( !endptr || endptr[0]!='-' ) {
      FD_LOG_WARNING(( "invalid snapshot file name: \"%s\"", orig_cstr ));
      return NULL;
    }
    cstr = endptr+1;

    if( base_slot != id->slot ) {
      FD_LOG_WARNING(( "failed to load snapshot: \"%s\"", orig_cstr ));
      FD_LOG_WARNING(( "expected base slot %lu but got %lu, incremental snapshot does not match full snapshot", base_slot, id->slot ));
      return NULL;
    }
  }

  char const * file_ext = strchr( cstr, '.' );
  ulong        file_ext_off = (ulong)( file_ext - cstr );

  char hash_cstr[ FD_BASE58_ENCODED_32_SZ ] = {0};
  strncpy( hash_cstr, cstr, sizeof(hash_cstr)-1 );
  if( file_ext_off < sizeof(hash_cstr) ) {
    hash_cstr[ file_ext_off ] = '\0';
  }
  strncpy( id->file_ext, file_ext, sizeof(id->file_ext)-1 );

  if( FD_UNLIKELY( !fd_base58_decode_32( hash_cstr, id->fhash.hash ) ) ) {
    FD_LOG_WARNING(( "invalid snapshot file name: \"%s\"", orig_cstr ));
    return NULL;
  }
  return id;
}

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
                   char *               source_cstr,
                   fd_snapshot_name_t * name_out ) {

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

  if( FD_UNLIKELY( !fd_snapshot_loader_init( loader, restore, src, slot_ctx->slot_bank.slot ) ) ) {
    FD_LOG_ERR(( "Failed to init snapshot loader" ));
  }

  for(;;) {
    int err = fd_snapshot_loader_advance( loader );
    if( FD_LIKELY( err == 0 ) ) continue;
    if( err == -1 ) break;

    FD_LOG_ERR(( "Failed to load snapshot (%d-%s)", err, fd_io_strerror( err ) ));
  }

  fd_snapshot_name_t const * name = fd_snapshot_loader_get_name( loader );
  if( FD_UNLIKELY( !name ) ) FD_LOG_ERR(( "name is NULL" ));
  *name_out = *name;

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
    FD_LOG_ERR(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_UNSPECIFIED)", snapshotfile, verify_hash ? "true" : "false", check_hash ? "true" : "false"));
    break;
  case FD_SNAPSHOT_TYPE_FULL:
    FD_LOG_NOTICE(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_FULL)", snapshotfile, verify_hash ? "true" : "false", check_hash ? "true" : "false"));
    break;
  case FD_SNAPSHOT_TYPE_INCREMENTAL:
    FD_LOG_NOTICE(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, FD_SNAPSHOT_TYPE_INCREMENTAL)", snapshotfile, verify_hash ? "true" : "false", check_hash ? "true" : "false"));
    break;
  default:
    FD_LOG_ERR(("fd_snapshot_load(\"%s\", verify-hash=%s, check-hash=%s, huh?)", snapshotfile, verify_hash ? "true" : "false", check_hash ? "true" : "false"));
    break;
  }

  fd_funk_speed_load_mode( slot_ctx->acc_mgr->funk, 1 );
  fd_funk_start_write( slot_ctx->acc_mgr->funk );

  fd_funk_txn_t * child_txn = slot_ctx->funk_txn;

  fd_scratch_push();
  size_t slen = strlen( snapshotfile );
  char * snapshot_cstr = fd_scratch_alloc( 1UL, slen + 1 );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( snapshot_cstr ), snapshotfile, slen ) );
  fd_snapshot_name_t name = {0};
  load_one_snapshot( slot_ctx, snapshot_cstr, &name );
  fd_hash_t const * fhash = &name.fhash;
  fd_scratch_pop();

  if( name.type != snapshot_type ) {
    FD_LOG_ERR(( "snapshot %s is wrong type", snapshotfile ));
  }

  // In order to calculate the snapshot hash, we need to know what features are active...
  fd_features_restore( slot_ctx );
  fd_calculate_epoch_accounts_hash_values( slot_ctx );

  if( verify_hash ) {
    if (snapshot_type == FD_SNAPSHOT_TYPE_FULL) {
      fd_hash_t accounts_hash;
      fd_snapshot_hash(slot_ctx, &accounts_hash, child_txn, check_hash, 0);

      if (memcmp(fhash->uc, accounts_hash.uc, 32) != 0)
        FD_LOG_ERR(("snapshot accounts_hash %32J != %32J", accounts_hash.hash, fhash->uc));
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

      if (memcmp(fhash->uc, accounts_hash.uc, 32) != 0)
        FD_LOG_ERR(("incremental accounts_hash %32J != %32J", accounts_hash.hash, fhash->uc));
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
