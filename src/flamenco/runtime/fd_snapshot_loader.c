#define OLD_TAR

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "fd_hashes.h"
#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "fd_system_ids.h"
#include "../../util/fd_util.h"
#ifdef OLD_TAR
#include "../../util/archive/fd_tar_old.h"
#else
#include "../../util/archive/fd_tar.h"
#endif /* OLD_TAR */
#include "../../util/compress/fd_compress.h"
#include "fd_snapshot_loader.h"

extern void fd_write_builtin_bogus_account( fd_exec_slot_ctx_t * slot_ctx,
                                            uchar const          pubkey[ static 32 ],
                                            char const *         data,
                                            ulong                sz );

struct SnapshotParser {
#ifdef OLD_TAR
  struct fd_tar_old_stream  tarreader_;
#else
  struct fd_tar_stream  tarreader_;
#endif /* OLD_TAR */
  char*                 tmpstart_;
  char*                 tmpcur_;
  char*                 tmpend_;

  fd_exec_slot_ctx_t *  slot_ctx_;

  fd_solana_manifest_t* manifest_;
};

static void
SnapshotParser_init(struct SnapshotParser* self, fd_exec_slot_ctx_t * slot_ctx) {
#ifdef OLD_TAR
  fd_tar_old_stream_init( &self->tarreader_, slot_ctx->valloc );
#else
  fd_tar_stream_init( &self->tarreader_, slot_ctx->valloc );
#endif /* OLD_TAR */
  size_t tmpsize = 1<<30;
  self->tmpstart_ = self->tmpcur_ = (char*)malloc(tmpsize);
  self->tmpend_ = self->tmpstart_ + tmpsize;

  self->slot_ctx_ = slot_ctx;

  self->manifest_ = NULL;
}

static void
SnapshotParser_destroy(struct SnapshotParser* self) {
  if (self->manifest_) {
    fd_exec_slot_ctx_t * slot_ctx = self->slot_ctx_;
    fd_bincode_destroy_ctx_t ctx = { .valloc = slot_ctx->valloc };
    fd_solana_manifest_destroy(self->manifest_, &ctx);
    fd_valloc_free( slot_ctx->valloc, self->manifest_ );
    self->manifest_ = NULL;
  }

#ifdef OLD_TAR
  fd_tar_old_stream_delete(&self->tarreader_);
#else
  fd_tar_stream_delete(&self->tarreader_);
#endif /* OLD_TAR */
  free(self->tmpstart_);
}

/* why is this creatively named "parse" if it actually loads the
   snapshot into the database? */

static void
SnapshotParser_parsefd_solana_accounts(struct SnapshotParser* self, char const * name, const void* data, size_t datalen) {
  ulong id, slot;
  if (sscanf(name, "accounts/%lu.%lu", &slot, &id) != 2)
    return;

  fd_slot_account_pair_t_mapnode_t key1;
  key1.elem.slot = slot;
  fd_slot_account_pair_t_mapnode_t* node1 = fd_slot_account_pair_t_map_find(
    self->manifest_->accounts_db.storages_pool, self->manifest_->accounts_db.storages_root, &key1);
  if (node1 == NULL)
    return;

  fd_serializable_account_storage_entry_t_mapnode_t key2;
  key2.elem.id = id;
  fd_serializable_account_storage_entry_t_mapnode_t* node2 = fd_serializable_account_storage_entry_t_map_find(
    node1->elem.accounts_pool, node1->elem.accounts_root, &key2);
  if (node2 == NULL)
    return;

  if (node2->elem.accounts_current_len < datalen)
    datalen = node2->elem.accounts_current_len;

  fd_acc_mgr_t *  acc_mgr = self->slot_ctx_->acc_mgr;
  fd_funk_txn_t * txn     = self->slot_ctx_->funk_txn;

  while (datalen) {
    size_t roundedlen = (sizeof(fd_solana_account_hdr_t)+7UL)&~7UL;
    if (roundedlen > datalen)
      return;

    fd_solana_account_hdr_t const * hdr = (fd_solana_account_hdr_t const *)data;
    uchar const * acc_data = (uchar const *)hdr + sizeof(fd_solana_account_hdr_t);

    fd_pubkey_t const * acc_key = (fd_pubkey_t const *)&hdr->meta.pubkey;

    do {
      /* Check existing account */
      FD_BORROWED_ACCOUNT_DECL(rec);

      int read_result = FD_ACC_MGR_SUCCESS;
      fd_account_meta_t const * acc_meta = fd_acc_mgr_view_raw( acc_mgr, txn, acc_key, &rec->const_rec, &read_result);

      /* Skip if we previously inserted a newer version */
      if( read_result == FD_ACC_MGR_SUCCESS ) {
        if( acc_meta->slot > slot )
          break;
      } else if( FD_UNLIKELY( read_result != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
        FD_LOG_ERR(( "database error while loading snapshot: %d", read_result ));
      }

      if( FD_UNLIKELY( hdr->meta.data_len > MAX_ACC_SIZE ) )
        FD_LOG_ERR(("account too large: %lu bytes", hdr->meta.data_len));

      /* Write account */
      int write_result = fd_acc_mgr_modify(acc_mgr, txn, acc_key, /* do_create */ 1, hdr->meta.data_len, rec);
      if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) )
        FD_LOG_ERR(("writing account failed"));

      rec->meta->dlen = hdr->meta.data_len;
      rec->meta->slot = slot;
      memcpy( &rec->meta->hash, hdr->hash.value, 32UL );
      memcpy( &rec->meta->info, &hdr->info, sizeof(fd_solana_account_meta_t) );
      if( hdr->meta.data_len )
        memcpy( rec->data, acc_data, hdr->meta.data_len );

      /* TODO Check if calculated hash fails to match account hash from snapshot. */
    } while (0);

    roundedlen = (sizeof(fd_solana_account_hdr_t)+hdr->meta.data_len+7UL)&~7UL;
    if (roundedlen > datalen)
      return;
    data = (char const *)data + roundedlen;
    datalen -= roundedlen;
  }
}

static void
SnapshotParser_parseSnapshots(struct SnapshotParser* self, const void* data, size_t datalen) {
  fd_exec_slot_ctx_t * slot_ctx = self->slot_ctx_;

  self->manifest_ = fd_valloc_malloc( slot_ctx->valloc, FD_SOLANA_MANIFEST_ALIGN, FD_SOLANA_MANIFEST_FOOTPRINT );
  fd_bincode_decode_ctx_t ctx;
  ctx.data = data;
  ctx.dataend = (char const *)data + datalen;
  ctx.valloc  = slot_ctx->valloc;
  if ( fd_solana_manifest_decode(self->manifest_, &ctx) )
    FD_LOG_ERR(("fd_solana_manifest_decode failed"));

  if ( fd_global_import_solana_manifest(slot_ctx, self->manifest_) )
    FD_LOG_ERR(("fd_global_import_solana_manifest failed"));
}

static void
SnapshotParser_tarEntry(void* arg, char const * name, const void* data, size_t datalen) {
  if (datalen == 0)
    return;
  if (strncmp(name, "accounts/", sizeof("accounts/")-1) == 0)
    SnapshotParser_parsefd_solana_accounts((struct SnapshotParser*)arg, name, data, datalen);
  if (strncmp(name, "snapshots/", sizeof("snapshots/")-1) == 0 &&
      strcmp(name, "snapshots/status_cache") != 0)
    SnapshotParser_parseSnapshots((struct SnapshotParser*)arg, data, datalen);
}

// Return non-zero on end of tarball
static int
SnapshotParser_moreData( void *        arg,
                         uchar const * data,
                         ulong         datalen ) {
  struct SnapshotParser* self = (struct SnapshotParser*)arg;
#ifdef OLD_TAR
  return fd_tar_old_stream_moreData(&self->tarreader_, data, datalen, SnapshotParser_tarEntry, self);
#else
  return fd_tar_stream_moreData(&self->tarreader_, data, datalen, SnapshotParser_tarEntry, self);
#endif /* OLD_TAR */
}

void
fd_snapshot_load(const char ** snapshotfiles, fd_exec_slot_ctx_t * slot_ctx, uint verify_hash) {
  for (uint i = 0; snapshotfiles[i] != NULL; ++i) {
    fd_funk_txn_t * parent_txn = slot_ctx->funk_txn;
    fd_funk_txn_xid_t xid;

    const char * snapshotfile = snapshotfiles[i];

    size_t slen = strlen(snapshotfile);
    const char *hptr = &snapshotfile[slen - 1];
    while ((hptr >= snapshotfile) && (*hptr != '-'))
      hptr--;
    hptr++;
    char hash[100];
    size_t hlen = (size_t) ((&snapshotfile[slen - 1] - hptr) - 7);
    memcpy(hash, hptr, hlen);
    hash[hlen] = '\0';

    fd_hash_t fhash;
    fd_base58_decode_32( hash, fhash.uc);

    FD_TEST(sizeof(xid) == sizeof(fhash));
    memcpy(&xid, &fhash.ul[0], sizeof(xid));

    fd_funk_txn_t * child_txn = fd_funk_txn_prepare( slot_ctx->acc_mgr->funk, parent_txn, &xid, 1 );
    slot_ctx->funk_txn = child_txn;

    struct SnapshotParser parser;
    SnapshotParser_init(&parser, slot_ctx);

    FD_LOG_NOTICE(( "reading %s", snapshotfile ));
    int fd = open( snapshotfile, O_RDONLY );
    if( FD_UNLIKELY( fd<0 ) )
      FD_LOG_ERR(( "open(%s) failed (%d-%s)", snapshotfile, errno, fd_io_strerror( errno ) ));

    int err = 0;
    if( 0==strcmp( snapshotfile + strlen(snapshotfile) - 4, ".zst" ) )
      err = fd_decompress_zstd( fd, SnapshotParser_moreData, &parser );
#if FD_HAS_BZ2
    else if( 0==strcmp( snapshotfile + strlen(snapshotfile) - 4, ".bz2" ) )
      err = fd_decompress_bz2( fd, SnapshotParser_moreData, &parser );
#endif
    else
      FD_LOG_ERR(( "unknown snapshot compression suffix" ));

    if( err ) FD_LOG_ERR(( "failed to load snapshot (%d-%s)", err, fd_io_strerror( err ) ));

    err = close(fd);
    if( FD_UNLIKELY( err ) )
      FD_LOG_ERR(( "close(%s) failed (%d-%s)", snapshotfile, errno, fd_io_strerror( errno ) ));

    SnapshotParser_destroy(&parser);

    // In order to calculate the snapshot hash, we need to know what features are active...
    fd_features_restore( slot_ctx );
    fd_calculate_epoch_accounts_hash_values( slot_ctx );

    if( verify_hash ) {
      if (0 == i) {
        fd_hash_t accounts_hash;
        fd_snapshot_hash(slot_ctx, &accounts_hash, child_txn);

        if (memcmp(fhash.uc, accounts_hash.uc, 32) != 0)
          FD_LOG_ERR(("snapshot accounts_hash %32J != %32J", accounts_hash.hash, fhash.uc));
        else
          FD_LOG_WARNING(("snapshot accounts_hash %32J == %32J", accounts_hash.hash, fhash.uc));
      } else if (1 == i) {
        fd_hash_t accounts_hash;

        if (FD_FEATURE_ACTIVE(slot_ctx, incremental_snapshot_only_incremental_hash_calculation))
          fd_snapshot_hash(slot_ctx, &accounts_hash, child_txn);
        else
          fd_snapshot_hash(slot_ctx, &accounts_hash, NULL);

        if (memcmp(fhash.uc, accounts_hash.uc, 32) != 0)
          FD_LOG_ERR(("incremental accounts_hash %32J != %32J", accounts_hash.hash, fhash.uc));
        else
          FD_LOG_WARNING(("incremental accounts_hash %32J == %32J", accounts_hash.hash, fhash.uc));
      }
    }

    FD_LOG_WARNING(("txn_publish_start"));
    fd_funk_txn_publish( slot_ctx->acc_mgr->funk, child_txn, 0 );
    FD_LOG_WARNING(("txn_publish_stop"));
    slot_ctx->funk_txn = parent_txn;
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
