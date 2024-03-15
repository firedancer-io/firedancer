#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "context/fd_exec_slot_ctx.h"
#include "fd_hashes.h"
#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "fd_system_ids.h"
#include "../../util/fd_util.h"
#include "fd_snapshot_loader.h"
#include "../snapshot/fd_snapshot_restore.h"
#include "../../ballet/zstd/fd_zstd.h"
#include <assert.h>

extern void
fd_write_builtin_bogus_account( fd_exec_slot_ctx_t * slot_ctx,
                                uchar const          pubkey[ static 32 ],
                                char const *         data,
                                ulong                sz );

static int
restore_manifest( void *                 ctx,
                  fd_solana_manifest_t * manifest ) {
  return (!!fd_exec_slot_ctx_recover( ctx, manifest ) ? 0 : EINVAL);
}

/* TODO make this function gracefully handle errors ? */

static int
load_one_snapshot( fd_exec_slot_ctx_t * slot_ctx,
                   char const *         snapshotfile ) {

  FD_LOG_NOTICE(("fd_snapshot_restore_footprint: %lu", fd_snapshot_restore_footprint()));
  if( !fd_scratch_alloc_is_safe( fd_snapshot_restore_align(), fd_snapshot_restore_footprint() ) )
    FD_LOG_ERR(( "insufficient scratch space for snapshot restore" ));
  uchar * restore_mem = fd_scratch_alloc( fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );

  ulong max_window_sz = 10000000;
  if( !fd_scratch_alloc_is_safe( fd_zstd_dstream_align(), fd_zstd_dstream_footprint( max_window_sz ) ) )
    FD_LOG_ERR(( "insufficient scratch space for snapshot restore" ));
  uchar * zstd_mem = fd_scratch_alloc( fd_zstd_dstream_align(), fd_zstd_dstream_footprint( max_window_sz ) );

  fd_snapshot_restore_t * restore = fd_snapshot_restore_new( restore_mem, slot_ctx->acc_mgr, slot_ctx->funk_txn, fd_libc_alloc_virtual(), slot_ctx, restore_manifest );
  assert( restore );

  fd_tar_reader_t reader_[1];
  fd_tar_reader_t * reader = fd_tar_reader_new( reader_, &fd_snapshot_restore_tar_vt, restore );
  assert( reader );

  fd_zstd_dstream_t * dstream = fd_zstd_dstream_new( zstd_mem, max_window_sz );
  assert( dstream );

  FD_LOG_NOTICE(( "reading %s", snapshotfile ));
  int fd = open( snapshotfile, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) )
    FD_LOG_ERR(( "open(%s) failed (%d-%s)", snapshotfile, errno, fd_io_strerror( errno ) ));

  for(;;) {

    uchar   in_buf [ 8192 ];
    uchar * in     = in_buf;

    ulong in_sz = 0UL;
    int read_err = fd_io_read( fd, in, 1UL, sizeof(in_buf), &in_sz );
    if( FD_LIKELY( read_err==0 ) ) { /* ok */ }
    else if( read_err<0 ) { /* EOF */ break; }
    else {
      FD_LOG_ERR(( "fd_io_read failed (%d-%s)", read_err, fd_io_strerror( read_err ) ));
      return 0;
    }
    uchar * in_end = in_buf + in_sz;

    do {
      uchar   out_buf[ 16384 ];
      uchar * out;
      uchar * out_end = out_buf + sizeof(out_buf);

      do {
        out = out_buf;

        int zstd_err = fd_zstd_dstream_read( dstream, (uchar const **)&in, in_end, &out, out_end, NULL );
        if( FD_UNLIKELY( zstd_err>0 ) ) {
          FD_LOG_ERR(( "fd_zstd_dstream_read failed" ));
          return 0;
        }

        ulong out_sz = (ulong)( out-out_buf );
        int tar_err = fd_tar_read( reader, out_buf, out_sz );
        if( FD_UNLIKELY( tar_err>0 ) ) {
          FD_LOG_ERR(( "fd_tar_read failed (%d-%s)", tar_err, fd_io_strerror( tar_err ) ));
          return 0;
        }
      } while( out==out_end );
    } while( in<in_end );
  }

  /* TODO: Check at this point that zstd, tar, restore have all
           completed gracefully */

  if( FD_UNLIKELY( 0!=close(fd) ) )
    FD_LOG_ERR(( "close(%s) failed (%d-%s)", snapshotfile, errno, fd_io_strerror( errno ) ));

  fd_snapshot_restore_discard_buf( restore );

  return 0;
}

void
fd_snapshot_load( const char *         snapshotfile,
                  fd_exec_slot_ctx_t * slot_ctx,
                  uint                 verify_hash,
                  uint                 check_hash,
                  fd_snapshot_type_t   snapshot_type ) {


  fd_funk_txn_t * parent_txn = slot_ctx->funk_txn;
  fd_funk_txn_xid_t xid;

  size_t slen = strlen(snapshotfile);
  const char *hptr = &snapshotfile[slen - 1];
  while ((hptr >= snapshotfile) && (*hptr != '-'))
    hptr--;
  hptr++;
  char hash[100];
  size_t hlen = (size_t) ((&snapshotfile[slen - 1] - hptr) - 7);
  if( hlen > sizeof(hash)-1U )
    FD_LOG_ERR(( "invalid snapshot file %s", snapshotfile ));
  memcpy(hash, hptr, hlen);
  hash[hlen] = '\0';

  fd_hash_t fhash;
  if( FD_UNLIKELY( !fd_base58_decode_32( hash, fhash.uc ) ) )
    FD_LOG_ERR(( "invalid snapshot hash" ));

  FD_TEST(sizeof(xid) == sizeof(fhash));
  memcpy(&xid, &fhash.ul[0], sizeof(xid));

  fd_funk_txn_t * child_txn = fd_funk_txn_prepare( slot_ctx->acc_mgr->funk, parent_txn, &xid, 1 );
  slot_ctx->funk_txn = child_txn;

  fd_scratch_push();
  load_one_snapshot( slot_ctx, snapshotfile );
  fd_scratch_pop();

  // In order to calculate the snapshot hash, we need to know what features are active...
  fd_features_restore( slot_ctx );
  fd_calculate_epoch_accounts_hash_values( slot_ctx );

  if (!FD_FEATURE_ACTIVE(slot_ctx, incremental_snapshot_only_incremental_hash_calculation)) {
    /* We need to flush the incremental snapshot's changes if we are
        using the OLD verification method.  Otherwise, iterating over
        the root would only see the base snapshot's records. */
    fd_funk_txn_publish( slot_ctx->acc_mgr->funk, child_txn, 0 );
    slot_ctx->funk_txn = parent_txn;
    child_txn = NULL;
  }

  if( verify_hash ) {
    if (snapshot_type == FD_SNAPSHOT_TYPE_FULL) {
      fd_hash_t accounts_hash;
      fd_snapshot_hash(slot_ctx, &accounts_hash, child_txn, check_hash, 0);

      if (memcmp(fhash.uc, accounts_hash.uc, 32) != 0)
        FD_LOG_ERR(("snapshot accounts_hash %32J != %32J", accounts_hash.hash, fhash.uc));
      else
        FD_LOG_INFO(("snapshot accounts_hash %32J verified successfully", accounts_hash.hash));
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
        FD_LOG_INFO(("incremental accounts_hash %32J verified successfully", accounts_hash.hash));
    } else {
      FD_LOG_ERR(( "invalid snapshot type %u", snapshot_type ));
    }
  }

  /* flush if we haven't done so already */
  if( child_txn ) {
    fd_funk_txn_publish( slot_ctx->acc_mgr->funk, child_txn, 0 );
    slot_ctx->funk_txn = parent_txn;
    child_txn = NULL;
  }
  fd_hashes_load(slot_ctx);
}

void
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

  fd_runtime_save_slot_bank( slot_ctx );
  fd_runtime_save_epoch_bank( slot_ctx );
}
