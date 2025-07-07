#include "fd_snapshot_restore.h"
#include "fd_snapshot_restore_private.h"
#include "../runtime/fd_acc_mgr.h"
#include <errno.h>

static void
_set_accv_sz( fd_snapshot_restore_t * restore,
              ulong                   slot,
              ulong                   id,
              ulong                   sz ) {
  fd_snapshot_accv_key_t key = { .slot = slot, .id = id };
  fd_snapshot_accv_map_t * rec = fd_snapshot_accv_map_insert( restore->accv_map, key );
  FD_TEST( rec );
  rec->sz = sz;
  FD_TEST( fd_snapshot_accv_map_query( restore->accv_map, key, NULL ) == rec );
}

static int                                 _cb_retcode    = 0;
static fd_solana_manifest_global_t const * _cb_v_manifest = NULL;
static fd_bank_slot_deltas_t *             _cb_v_cache    = NULL;
static void *                              _cb_v_ctx      = NULL;

int
cb_manifest( void *                              ctx,
             fd_solana_manifest_global_t const * manifest,
             fd_spad_t *                         spad ) {
  (void)spad;
  _cb_v_manifest = manifest;
  _cb_v_ctx      = ctx;
  return _cb_retcode;
}

int
cb_status_cache( void *                  ctx,
                 fd_bank_slot_deltas_t * cache,
                 fd_spad_t *             spad ) {
  (void)spad;
  _cb_v_cache = cache;
  _cb_v_ctx   = ctx;
  return _cb_retcode;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",  NULL,      "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt", NULL,             3UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong ( &argc, &argv, "--near-cpu", NULL, fd_log_cpu_id() );

  /* Setup workspace */

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s)", page_cnt, _page_sz ));

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  FD_TEST( wksp );
  ulong const static_tag = 1UL;

  /* Setup slot context */

  ulong const txn_max =  16UL;
  uint const rec_max = 512UL;

  ulong const funk_seed = 0xeffb398d4552afbcUL;
  ulong const funk_tag  = 42UL;
  void * funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), funk_tag );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, fd_funk_new( funk_mem, funk_tag, funk_seed, txn_max, rec_max ) );
  FD_TEST( funk );

  void * restore_mem = fd_wksp_alloc_laddr( wksp, fd_snapshot_restore_align(), fd_snapshot_restore_footprint(), static_tag );

  fd_spad_t * _spad = fd_spad_new( fd_wksp_alloc_laddr( wksp, FD_SPAD_ALIGN, FD_SPAD_FOOTPRINT( 1000000000UL ), static_tag ), 1000000000UL );
  fd_spad_push( _spad );

  fd_funk_txn_xid_t xid[1] = {{ .ul = {4} }};
  ulong             restore_slot = 999UL;

  uchar _dummy_ctx[1];  /* memory address to serve as the callback context pointer */

  /* NEW_RESTORE is a convenience macro to create a new snapshot restore
     context that is waiting for a manifest. */

# define NEW_RESTORE() \
    fd_snapshot_restore_new( restore_mem, funk, NULL, _spad, _dummy_ctx, cb_manifest, cb_status_cache )

  /* NEW_RESTORE_POST_MANIFEST is a convenience macro to create a new
     snapshot restore context that pretends that the manifest has
     already been restored. */

# define NEW_RESTORE_POST_MANIFEST() __extension__({ \
    fd_snapshot_restore_t * restore = fd_snapshot_restore_new( restore_mem, funk, NULL, _spad, _dummy_ctx, cb_manifest, cb_status_cache ); \
    restore->manifest_done = MANIFEST_DONE_SEEN; \
    restore->slot          = restore_slot; \
    restore; \
  })

  /* Test invalid params */
  fd_spad_push( _spad );
  FD_TEST( !fd_snapshot_restore_new( NULL,        funk, NULL, _spad, NULL, cb_manifest, cb_status_cache ) );  /* NULL mem */
  FD_TEST( !fd_snapshot_restore_new( restore_mem, NULL, NULL, _spad, NULL, cb_manifest, cb_status_cache ) );  /* NULL funk */
  fd_spad_pop( _spad );

  /* Reject accounts before manifest */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = fd_snapshot_restore_new( restore_mem, funk, NULL, _spad, NULL, cb_manifest, cb_status_cache );
    FD_TEST( restore );
    FD_TEST( restore->failed        == 0 );
    FD_TEST( restore->manifest_done == 0 );
    fd_tar_meta_t meta = { .name = "accounts/1.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( EINVAL==fd_snapshot_restore_file( restore, &meta, 128UL ) );
    FD_TEST( restore->failed == 1 );

    /* Public API should resturn EINVAL if restore->failed */
    FD_TEST( EINVAL==fd_snapshot_restore_file( restore, &meta, 128UL ) );
    FD_TEST( EINVAL==fd_snapshot_restore_chunk( restore, "A", 1UL ) );

    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Reject invalid status cache */

  do {
    fd_spad_push( _spad );
    FD_LOG_WARNING(("SPAD %lu", _spad->mem_max));
    fd_snapshot_restore_t * restore = fd_snapshot_restore_new( restore_mem, funk, NULL, _spad, NULL, cb_manifest, cb_status_cache );
    FD_TEST( restore );
    fd_tar_meta_t meta = { .name = "snapshots/status_cache", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( 0==fd_snapshot_restore_file( restore, &meta, 18UL ) );
    FD_TEST( restore->buf );
    FD_TEST( EINVAL==fd_snapshot_restore_chunk( restore, "AAAAAAAAAAAAAAAAAA", 18UL ) );
    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Reject invalid manifest */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = fd_snapshot_restore_new( restore_mem, funk, NULL, _spad, NULL, cb_manifest, cb_status_cache );
    FD_TEST( restore );
    fd_tar_meta_t meta = { .name = "snapshots/123/123", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( 0==fd_snapshot_restore_file( restore, &meta, 18UL ) );
    FD_TEST( restore->buf );
    FD_TEST( EINVAL==fd_snapshot_restore_chunk( restore, "AAAAAAAAAAAAAAAAAA", 18UL ) );
    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test status cache with size exceeding buffer size (out of memory) */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = fd_snapshot_restore_new( restore_mem, funk, NULL, _spad, NULL, cb_manifest, cb_status_cache );
    FD_TEST( restore );
    fd_tar_meta_t meta = { .name = "snapshots/status_cache", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( ENOMEM==fd_snapshot_restore_file( restore, &meta, ULONG_MAX ) );
    FD_TEST( restore->failed == 1 );
    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test manifest with size exceeding buffer size (out of memory) */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = fd_snapshot_restore_new( restore_mem, funk, NULL, _spad, NULL, cb_manifest, cb_status_cache );
    FD_TEST( restore );
    fd_tar_meta_t meta = { .name = "snapshots/123/123", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( ENOMEM==fd_snapshot_restore_file( restore, &meta, ULONG_MAX ) );
    FD_TEST( restore->failed == 1 );
    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test basic manifest */

  do {
    fd_spad_push( _spad );
    fd_solana_manifest_t manifest[1] = {{ .bank = { .slot = 3UL } }};
    ulong manifest_sz = fd_solana_manifest_size( manifest );

    ulong   data_sz = manifest_sz;
    uchar * data    = fd_spad_alloc( _spad, 8UL, data_sz );
    fd_bincode_encode_ctx_t encode =
      { .data    = data,
        .dataend = data + manifest_sz + 1 };
    FD_TEST( 0==fd_solana_manifest_encode( manifest, &encode ) );

    fd_snapshot_restore_t * restore = NEW_RESTORE();
    FD_TEST( restore );
    FD_TEST( restore->manifest_done == 0 );

    fd_tar_meta_t meta = { .name = "snapshots/123/123", .typeflag = FD_TAR_TYPE_REGULAR };
    _cb_v_ctx      = NULL;
    _cb_v_manifest = NULL;
    _cb_retcode = 0;
    FD_TEST( 0==fd_snapshot_restore_file( restore, &meta, data_sz ) );
    FD_TEST( MANIFEST_DONE==fd_snapshot_restore_chunk( restore, data, data_sz ) );
    FD_TEST( _cb_v_ctx              == _dummy_ctx         );
    FD_TEST( _cb_v_manifest         != NULL               );
    FD_TEST( restore->manifest_done == MANIFEST_DONE_SEEN );
    FD_TEST( restore->slot          == 3UL                );

    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test basic status cache */

  do {
    fd_spad_push( _spad );
    /* Create basic slot delta */
    fd_bank_slot_deltas_t cache[1];
    cache->slot_deltas_len = 1;
    cache->slot_deltas = fd_spad_alloc( _spad, alignof(fd_slot_delta_t), 1UL*sizeof(fd_slot_delta_t) );
    cache->slot_deltas->is_root = 0;
    cache->slot_deltas->slot = 10;
    cache->slot_deltas->slot_delta_vec_len = 1;
    cache->slot_deltas->slot_delta_vec = fd_spad_alloc( _spad, alignof(fd_status_pair_t), 1UL*sizeof(fd_status_pair_t) );

    fd_status_pair_t * pair = cache->slot_deltas->slot_delta_vec;
    fd_memset( pair->hash.uc, 1UL, sizeof(fd_hash_t) );
    pair->value.txn_idx = 2;
    pair->value.statuses_len = 1;
    pair->value.statuses = fd_spad_alloc( _spad, alignof(fd_cache_status_t), 1UL*sizeof(fd_cache_status_t) );

    fd_cache_status_t * status = pair->value.statuses;
    status->result.discriminant = 0;
    fd_memset(status->key_slice, 2, 20);

    ulong sz = fd_bank_slot_deltas_size( cache );

    ulong   data_sz = sz;
    uchar * data    = fd_spad_alloc( _spad, 8UL, data_sz );
    fd_bincode_encode_ctx_t encode =
      { .data    = data,
        .dataend = data + sz + 1 };
    FD_TEST( 0==fd_bank_slot_deltas_encode( cache, &encode ) );

    fd_snapshot_restore_t * restore = NEW_RESTORE();
    FD_TEST( restore );
    FD_TEST( restore->status_cache_done == 0) ;

    fd_tar_meta_t meta = { .name = "snapshots/status_cache", .typeflag = FD_TAR_TYPE_REGULAR };
    _cb_v_ctx      = NULL;
    _cb_v_cache = NULL;
    _cb_retcode = 0;
    FD_TEST( 0==fd_snapshot_restore_file( restore, &meta, data_sz ) );
    FD_TEST( 0==fd_snapshot_restore_chunk( restore, data, data_sz ) );
    FD_TEST( _cb_v_ctx      == _dummy_ctx  );
    FD_TEST( _cb_v_cache    != NULL        );
    FD_TEST( restore->status_cache_done == 1   );

    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Ignore trailing data after manifest */

  do {
    fd_spad_push( _spad );
    fd_solana_manifest_t manifest[1] = {0};
    ulong manifest_sz = fd_solana_manifest_size( manifest );

    ulong   data_sz = manifest_sz + 16UL;
    uchar * data    = fd_spad_alloc( _spad, 8UL, data_sz );
    fd_bincode_encode_ctx_t encode =
      { .data    = data,
        .dataend = data + manifest_sz + 1 };
    FD_TEST( 0==fd_solana_manifest_encode( manifest, &encode ) );
    fd_memset( data + manifest_sz, 'A', 16UL );

    fd_snapshot_restore_t * restore = NEW_RESTORE();
    FD_TEST( restore );

    fd_tar_meta_t meta = { .name = "snapshots/123/123", .typeflag = FD_TAR_TYPE_REGULAR };
    _cb_v_ctx = NULL;
    _cb_v_manifest = NULL;
    _cb_retcode = 0;
    FD_TEST( 0==fd_snapshot_restore_file( restore, &meta, manifest_sz + 1 ) );
    FD_TEST( MANIFEST_DONE==fd_snapshot_restore_chunk( restore, data, manifest_sz + 1 ) );
    FD_TEST( _cb_v_ctx      == _dummy_ctx );  /* callback must have been successful */
    FD_TEST( _cb_v_manifest != NULL       );
    FD_TEST( 0==fd_snapshot_restore_chunk( restore, data, manifest_sz + 1 ) );

    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test empty file */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    _set_accv_sz( restore, /* slot */ 1UL, /* id */ 1UL, /* sz */ 0UL );
    fd_tar_meta_t meta = { .name = "accounts/1.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( 0==fd_snapshot_restore_file( restore, &meta, 0UL ) );
    FD_TEST( restore->state == STATE_IGNORE );
    FD_TEST( 0==fd_snapshot_restore_chunk( restore, NULL, 0UL ) );
    FD_TEST( restore->state == STATE_IGNORE );
    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test undersz AppendVec (torn header) */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    restore->manifest_done = 1;

    _set_accv_sz( restore, /* slot */ 1UL, /* id */ 1UL, /* sz */ 1UL );
    fd_tar_meta_t meta1 = { .name = "accounts/1.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( EINVAL==fd_snapshot_restore_file( restore, &meta1, 1UL ) );
    FD_TEST( restore->failed == 1 );

    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test undersz AppendVec (no body) */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    restore->manifest_done = 1;

    _set_accv_sz( restore, /* slot */ 1UL, /* id */ 1UL, /* sz */ sizeof(fd_solana_account_hdr_t) );
    fd_tar_meta_t accv_meta = { .name = "accounts/1.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( 0==fd_snapshot_restore_file( restore, &accv_meta, sizeof(fd_solana_account_hdr_t) ) );
    FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );

    do {
      fd_solana_account_hdr_t hdr = { .meta = { .data_len = 4UL } };
      FD_TEST( EINVAL==fd_snapshot_restore_chunk( restore, (uchar const *)&hdr, sizeof(fd_solana_account_hdr_t) ) );
      FD_TEST( restore->failed == 1 );
    } while(0);

    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test undersz AppendVec (torn body) */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    restore->manifest_done = 1;

    _set_accv_sz( restore, /* slot */ 1UL, /* id */ 1UL, /* sz */ sizeof(fd_solana_account_hdr_t) + 2UL );
    fd_tar_meta_t accv_meta = { .name = "accounts/1.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( 0==fd_snapshot_restore_file( restore, &accv_meta, sizeof(fd_solana_account_hdr_t) + 2UL ) );
    FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );

    do {
      fd_solana_account_hdr_t hdr = { .meta = { .data_len = 4UL } };
      FD_TEST( EINVAL==fd_snapshot_restore_chunk( restore, (uchar const *)&hdr, sizeof(fd_solana_account_hdr_t) ) );
      FD_TEST( restore->failed == 1 );
    } while(0);

    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Reject account with too high slot number */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    restore->manifest_done = 1;

    _set_accv_sz( restore, /* slot */ 100000UL, /* id */ 1UL, /* sz */ sizeof(fd_solana_account_hdr_t) );
    fd_tar_meta_t accv_meta = { .name = "accounts/100000.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( EINVAL==fd_snapshot_restore_file( restore, &accv_meta, sizeof(fd_solana_account_hdr_t) ) );
    FD_TEST( restore->failed == 1 );
    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Dead accounts must be inserted into database too */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    restore->manifest_done = MANIFEST_DONE_SEEN;
    restore->funk_txn      = fd_funk_txn_prepare( funk, NULL, xid, 0 );
    FD_TEST( restore->funk_txn );

    _set_accv_sz( restore, /* slot */ 1UL, /* id */ 1UL, /* sz */ sizeof(fd_solana_account_hdr_t) );
    fd_tar_meta_t accv_meta = { .name = "accounts/1.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( 0==fd_snapshot_restore_file( restore, &accv_meta, sizeof(fd_solana_account_hdr_t) ) );
    FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );

    do {
      fd_solana_account_hdr_t hdr = {0};
      FD_TEST( 0==fd_snapshot_restore_chunk( restore, (uchar const *)&hdr, sizeof(fd_solana_account_hdr_t) ) );

      /* Query loaded account */
      fd_pubkey_t pubkey[1]; memcpy( pubkey, hdr.meta.pubkey, 32 );
      fd_account_meta_t const * acc = fd_funk_get_acc_meta_readonly( funk, restore->funk_txn, pubkey, NULL, NULL, NULL );
      FD_TEST( acc );
      FD_TEST( !fd_account_meta_exists( acc ) );
    } while(0);

    fd_funk_txn_cancel( funk, restore->funk_txn, 0 );
    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Old revision must not overrule dead account */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    restore->manifest_done = MANIFEST_DONE_SEEN;
    restore->funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 0 );

    /* Insert a dead account (slot 9) */
    fd_pubkey_t key[1] = {{ .ul = {9} }};
    do {
      fd_funk_rec_key_t id   = fd_funk_acc_key( key );
      fd_wksp_t *          wksp = fd_funk_wksp(funk);
      fd_funk_rec_prepare_t prepare[1];
      int err;
      fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, restore->funk_txn, &id, prepare, &err );
      fd_account_meta_t * meta = fd_funk_val_truncate(
          rec,
          fd_funk_alloc( funk ),
          wksp,
          0UL,
          sizeof(fd_account_meta_t),
          &err );
      FD_TEST( meta );
      fd_account_meta_init( meta );
      meta->dlen          = 0UL;
      meta->info.lamports = 0UL;
      meta->slot          = 9UL;
      fd_funk_rec_publish( funk, prepare );
      FD_TEST( !fd_account_meta_exists( meta ) );
    } while(0);

    /* Restore the snapshot */
    _set_accv_sz( restore, /* slot */ 8UL, /* id */ 1UL, /* sz */ sizeof(fd_solana_account_hdr_t) );
    fd_tar_meta_t accv_meta = { .name = "accounts/8.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( 0==fd_snapshot_restore_file( restore, &accv_meta, sizeof(fd_solana_account_hdr_t) ) );
    FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );

    do {
      fd_solana_account_hdr_t hdr = {0};
      memcpy( &hdr.meta.pubkey, key->uc, 32 );
      FD_TEST( 0==fd_snapshot_restore_chunk( restore, (uchar const *)&hdr, sizeof(fd_solana_account_hdr_t) ) );
      FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );  /* expecting next account */

      /* Query loaded account */
      fd_pubkey_t pubkey[1]; memcpy( pubkey, hdr.meta.pubkey, 32 );
      fd_account_meta_t const * acc = fd_funk_get_acc_meta_readonly( funk, restore->funk_txn, pubkey, NULL, NULL, NULL );
      FD_TEST( acc );
      FD_TEST( !fd_account_meta_exists( acc ) );
      FD_TEST( acc->slot == 9UL );
    } while(0);

    fd_funk_txn_cancel( funk, restore->funk_txn, 0 );
    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* When an old revision is encountered, only that revision should be
     ignored.  Test that we are still loading other accounts in the
     database. */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    restore->manifest_done = MANIFEST_DONE_SEEN;
    restore->funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 0 );

    /* Insert an account (key 9, slot 9) */
    fd_pubkey_t key[1] = {{ .ul = {9} }};
    do {
      fd_funk_rec_key_t id   = fd_funk_acc_key( key );
      fd_wksp_t *          wksp = fd_funk_wksp(funk);
      fd_funk_rec_prepare_t prepare[1];
      int err;
      fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, restore->funk_txn, &id, prepare, &err );
      fd_account_meta_t * meta = fd_funk_val_truncate(
          rec,
          fd_funk_alloc( funk ),
          wksp,
          0UL,
          sizeof(fd_account_meta_t)+4,
          &err );
      FD_TEST( meta );
      fd_account_meta_init( meta );
      meta->dlen          =  4UL;
      meta->info.lamports = 90UL;
      meta->slot          =  9UL;
      fd_funk_rec_publish( funk, prepare );
      FD_TEST( fd_account_meta_exists( meta ) );
      memcpy( (uchar *)meta + meta->hlen, "ABCD", 4UL );
    } while(0);

    /* Restore the snapshot */
    ulong accv_sz = 2 * sizeof(fd_solana_account_hdr_t) + 16UL;
    _set_accv_sz( restore, /* slot */ 8UL, /* id */ 1UL, /* sz */ accv_sz );
    fd_tar_meta_t accv_meta = { .name = "accounts/8.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( 0==fd_snapshot_restore_file( restore, &accv_meta, accv_sz ) );
    FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );

    do {
      /* Account (key 9, slot 8) */
      fd_solana_account_hdr_t hdr1 = { .meta = { .data_len = 4UL } };
      memcpy( &hdr1.meta.pubkey, key->uc, 32 );
      FD_TEST( 0==fd_snapshot_restore_chunk( restore, (uchar const *)&hdr1, sizeof(fd_solana_account_hdr_t) ) );
      FD_TEST( restore->state == STATE_READ_ACCOUNT_DATA );
      FD_TEST( 0==fd_snapshot_restore_chunk( restore, (uchar const *)"....PPPP", 8UL ) );
      FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );  /* expecting next account */

      /* Account (key 10, slot 8) */
      fd_solana_account_hdr_t hdr2 = { .meta = { .pubkey = {10}, .data_len = 4UL } };
      FD_TEST( 0==fd_snapshot_restore_chunk( restore, (uchar const *)&hdr2, sizeof(fd_solana_account_hdr_t) ) );
      FD_TEST( restore->state == STATE_READ_ACCOUNT_DATA );
      /* Special case: We have padding at the end of the account, but
         still within the AppendVec (not considered garbage) */
      FD_TEST( 0==fd_snapshot_restore_chunk( restore, (uchar const *)"Hi :)....", 8UL ) );
      FD_TEST( restore->state == STATE_IGNORE );

      /* Verify key 9 */
      fd_pubkey_t pubkey1[1]; memcpy( pubkey1, hdr1.meta.pubkey, 32 );
      fd_account_meta_t const * acc1 = fd_funk_get_acc_meta_readonly( funk, restore->funk_txn, pubkey1, NULL, NULL, NULL );
      FD_TEST( acc1 );
      FD_TEST( fd_account_meta_exists( acc1 ) );
      FD_TEST( acc1->slot == 9UL );
      FD_TEST( acc1->dlen            ==  4UL );
      FD_TEST( acc1->info.lamports   == 90UL );
      FD_TEST( acc1->info.rent_epoch ==  0UL );
      FD_TEST( acc1->info.executable ==  0   );
      FD_TEST( 0==memcmp( (uchar const *)acc1 + acc1->hlen, "ABCD", 4UL ) );

      /* Verify key 10 */
      fd_pubkey_t pubkey2[1]; memcpy( pubkey2, hdr2.meta.pubkey, 32 );
      fd_account_meta_t const * acc2 = fd_funk_get_acc_meta_readonly( funk, restore->funk_txn, pubkey2, NULL, NULL, NULL );
      FD_TEST( acc2 );
      FD_TEST( fd_account_meta_exists( acc2 ) );
      FD_TEST( acc2->slot == 8UL );
      FD_TEST( acc2->dlen            == hdr2.meta.data_len   );
      FD_TEST( acc2->info.lamports   == hdr2.info.lamports   );
      FD_TEST( acc2->info.rent_epoch == hdr2.info.rent_epoch );
      FD_TEST( acc2->info.executable == hdr2.info.executable );
      FD_TEST( 0==memcmp( (uchar const *)acc2 + acc2->hlen, "Hi :)", 4UL ) );
    } while(0);

    fd_funk_txn_cancel( funk, restore->funk_txn, 0 );
    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test undersz AppendVec (real sz smaller than indicated sz) */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    restore->manifest_done = 1;

    _set_accv_sz( restore, /* slot */ 1UL, /* id */ 1UL, /* sz */ sizeof(fd_solana_account_hdr_t) + 2UL );
    fd_tar_meta_t accv_meta = { .name = "accounts/1.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( EINVAL==fd_snapshot_restore_file( restore, &accv_meta, sizeof(fd_solana_account_hdr_t) ) );
    FD_TEST( restore->failed == 1 );

    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

  /* Test accounts */

  do {
    fd_spad_push( _spad );
    fd_snapshot_restore_t * restore = NEW_RESTORE_POST_MANIFEST();
    FD_TEST( restore );
    restore->manifest_done = MANIFEST_DONE_SEEN;

    ulong accv_sz = 2 * sizeof(fd_solana_account_hdr_t) + 2UL;
    _set_accv_sz( restore, /* slot */ 1UL, /* id */ 1UL, accv_sz );

    fd_tar_meta_t meta = { .name = "accounts/1.1", .typeflag = FD_TAR_TYPE_REGULAR };
    FD_TEST( 0==fd_snapshot_restore_file( restore, &meta, accv_sz + 4UL ) );
    FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );

    FD_TEST( restore->accv_sz == (2 * sizeof(fd_solana_account_hdr_t) + 2UL) );

    /* Empty account */

    do {
      fd_solana_account_hdr_t hdr = {0};
      for( ulong j=0UL; j < sizeof(fd_solana_account_hdr_t); j++ ) {
        FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );
        FD_TEST( 0==fd_snapshot_restore_chunk( restore, ((uchar const *)&hdr) + j, 1UL ) );
      }
      FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );  /* expecting next account */
      FD_TEST( restore->acc_sz  == 0UL );
      FD_TEST( restore->acc_pad == 0UL );
    } while(0);

    FD_TEST( restore->accv_sz == (sizeof(fd_solana_account_hdr_t) + 2UL) );

    /* Account with one byte */

    do {
      fd_solana_account_hdr_t hdr = {
        .meta = {
          .data_len = 2UL,
          .pubkey   = {1}
        },
        .info = {
          .lamports   = 1234,
          .rent_epoch = ULONG_MAX,
          .owner      = {2},
          .executable = 1
        },
        .hash = { .uc = {3} }
      };
      for( ulong j=0UL; j < sizeof(fd_solana_account_hdr_t); j++ ) {
        FD_TEST( restore->state == STATE_READ_ACCOUNT_HDR );
        FD_TEST( 0==fd_snapshot_restore_chunk( restore, ((uchar const *)&hdr) + j, 1UL ) );
      }

      FD_TEST( restore->state == STATE_READ_ACCOUNT_DATA );
      FD_TEST( restore->accv_sz == 2UL );
      FD_TEST( restore->acc_sz  == 2UL );
      FD_TEST( restore->acc_pad == 6UL );
      FD_TEST( 0==fd_snapshot_restore_chunk( restore, "A", 1UL ) );

      FD_TEST( restore->state == STATE_READ_ACCOUNT_DATA );
      FD_TEST( restore->accv_sz == 1UL );
      FD_TEST( restore->acc_sz  == 1UL );
      FD_TEST( restore->acc_pad == 6UL );
      FD_TEST( 0==fd_snapshot_restore_chunk( restore, "B", 1UL ) );

      FD_TEST( restore->state == STATE_IGNORE );
      FD_TEST( restore->accv_sz == 0UL );
      FD_TEST( restore->acc_sz  == 0UL );
      FD_TEST( restore->acc_pad == 6UL );

      /* Query loaded account */
      fd_pubkey_t pubkey[1]; memcpy( pubkey, hdr.meta.pubkey, 32 );
      fd_account_meta_t const * acc = fd_funk_get_acc_meta_readonly( funk, restore->funk_txn, pubkey, NULL, NULL, NULL );
      FD_TEST( acc );
      FD_TEST( acc->dlen            ==       2UL );
      FD_TEST( acc->info.lamports   ==    1234UL );
      FD_TEST( acc->info.rent_epoch == ULONG_MAX );
      FD_TEST( acc->info.executable ==       1UL );
      FD_TEST( 0==memcmp( acc->info.owner, hdr.info.owner, 32UL ) );
      FD_TEST( 0==memcmp( acc->hash,       hdr.hash.uc,    32UL ) );

      uchar const * acc_data = (uchar const *)acc + acc->hlen;
      FD_TEST( 0==memcmp( acc_data, "AB", 2UL ) );
    } while(0);

    FD_TEST( restore->accv_sz == 0UL );

    /* Trailing garbage */

    FD_TEST( 0== fd_snapshot_restore_chunk( restore, "ABCD", 4UL ) );

    fd_snapshot_restore_delete( restore );
    fd_spad_pop( _spad );
  } while(0);

# undef NEW_RESTORE_POST_MANIFEST

  /* Clean up */

  fd_wksp_free_laddr( fd_spad_delete( fd_spad_leave( _spad ) ) );
  fd_wksp_free_laddr( restore_mem );
  fd_funk_leave( funk, NULL );
  fd_wksp_free_laddr( fd_funk_delete( funk_mem ) );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
