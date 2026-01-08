/* fd_snapin_tile_funk.c contains APIs to load accounts into funk. */

#include "fd_snapin_tile_private.h"
#include "../../flamenco/accdb/fd_accdb_sync.h"

int
fd_snapin_process_account_header_funk( fd_snapin_tile_t *            ctx,
                                       fd_ssparse_advance_result_t * result ) {
  fd_funk_t * funk = ctx->accdb_admin->funk;

  fd_funk_rec_key_t id = FD_LOAD( fd_funk_rec_key_t, result->account_header.pubkey );
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t * rec = fd_funk_rec_query_try( funk, ctx->xid, &id, query );
  fd_funk_rec_t const * existing_rec = rec;

  ctx->metrics.accounts_loaded++;

  int early_exit = 0;
  if( !ctx->full && !existing_rec ) {
    fd_accdb_peek_t peek[1];
    if( fd_accdb_peek( ctx->accdb, peek, ctx->xid, result->account_header.pubkey ) ) {
      existing_rec = (fd_funk_rec_t *)peek->acc->user_data;
    }
  }
  if( FD_UNLIKELY( existing_rec ) ) {
    fd_account_meta_t * meta = fd_funk_val( existing_rec, funk->wksp );
    if( FD_UNLIKELY( meta ) ) {
      if( FD_LIKELY( meta->slot>result->account_header.slot ) ) {
        ctx->acc_data = NULL;
        ctx->metrics.accounts_ignored++;
        fd_snapin_send_duplicate_account( ctx, result->account_header.lamports, NULL, result->account_header.data_len, (uchar)result->account_header.executable, result->account_header.owner, result->account_header.pubkey, 0, &early_exit );
        return early_exit;
      }
      ctx->metrics.accounts_replaced++;
      fd_snapin_send_duplicate_account( ctx, meta->lamports, (uchar const *)meta + sizeof(fd_account_meta_t), meta->dlen, meta->executable, meta->owner, result->account_header.pubkey, 1, &early_exit);
    }
  }

  int should_publish = 0;
  fd_funk_rec_prepare_t prepare[1];
  if( FD_LIKELY( !rec ) ) {
    should_publish = 1;
    rec = fd_funk_rec_prepare( funk, ctx->xid, &id, prepare, NULL );
    FD_TEST( rec );
  }

  fd_account_meta_t * meta = fd_funk_val( rec, funk->wksp );
  /* Allocate data space from heap, free old value (if any) */
  fd_funk_val_flush( rec, funk->alloc, funk->wksp );
  ulong const alloc_sz = sizeof(fd_account_meta_t)+result->account_header.data_len;
  ulong       alloc_max;
  meta = fd_alloc_malloc_at_least( funk->alloc, 16UL, alloc_sz, &alloc_max );
  if( FD_UNLIKELY( !meta ) ) FD_LOG_ERR(( "Ran out of heap memory while loading snapshot (increase [funk.heap_size_gib])" ));
  memset( meta, 0, sizeof(fd_account_meta_t) );
  rec->val_gaddr = fd_wksp_gaddr_fast( funk->wksp, meta );
  rec->val_max   = (uint)( fd_ulong_min( alloc_max, FD_FUNK_REC_VAL_MAX ) & FD_FUNK_REC_VAL_MAX );
  rec->val_sz    = (uint)( alloc_sz  & FD_FUNK_REC_VAL_MAX );

  meta->dlen       = (uint)result->account_header.data_len;
  meta->slot       = result->account_header.slot;
  memcpy( meta->owner, result->account_header.owner, sizeof(fd_pubkey_t) );
  meta->lamports   = result->account_header.lamports;
  meta->executable = (uchar)result->account_header.executable;

  ctx->acc_data = (uchar*)meta + sizeof(fd_account_meta_t);

  if( FD_LIKELY( should_publish ) ) fd_funk_rec_publish( funk, prepare );
  return early_exit;
}

int
fd_snapin_process_account_data_funk( fd_snapin_tile_t *            ctx,
                                     fd_ssparse_advance_result_t * result ) {
  int early_exit = 0;
  if( FD_UNLIKELY( !ctx->acc_data ) ) {
    fd_snapin_send_duplicate_account_data( ctx, result->account_data.data, result->account_data.data_sz, &early_exit );
    return early_exit;
  }

  fd_memcpy( ctx->acc_data, result->account_data.data, result->account_data.data_sz );
  ctx->acc_data += result->account_data.data_sz;
  return 0;
}

/* streamlined_insert inserts an unfragmented account.
   Only used while loading a full snapshot, not an incremental. */

static void
streamlined_insert( fd_snapin_tile_t * ctx,
                    fd_funk_rec_t *    rec,
                    uchar const *      frame,
                    ulong              slot ) {
  ulong data_len   = fd_ulong_load_8_fast( frame+0x08UL );
  ulong lamports   = fd_ulong_load_8_fast( frame+0x30UL );
  ulong rent_epoch = fd_ulong_load_8_fast( frame+0x38UL ); (void)rent_epoch;
  uchar owner[32];   memcpy( owner, frame+0x40UL, 32UL );
  _Bool executable = !!frame[ 0x60UL ];

  fd_funk_t * funk = ctx->accdb_admin->funk;
  if( FD_UNLIKELY( data_len > FD_RUNTIME_ACC_SZ_MAX ) ) FD_LOG_ERR(( "Found unusually large account (data_sz=%lu), aborting", data_len ));
  fd_funk_val_flush( rec, funk->alloc, funk->wksp );
  ulong const alloc_sz = sizeof(fd_account_meta_t)+data_len;
  ulong       alloc_max;
  fd_account_meta_t * meta = fd_alloc_malloc_at_least( funk->alloc, 16UL, alloc_sz, &alloc_max );
  if( FD_UNLIKELY( !meta ) ) FD_LOG_ERR(( "Ran out of heap memory while loading snapshot (increase [funk.heap_size_gib])" ));
  memset( meta, 0, sizeof(fd_account_meta_t) );
  rec->val_gaddr = fd_wksp_gaddr_fast( funk->wksp, meta );
  rec->val_max   = (uint)( fd_ulong_min( alloc_max, FD_FUNK_REC_VAL_MAX ) & FD_FUNK_REC_VAL_MAX );
  rec->val_sz    = (uint)( alloc_sz  & FD_FUNK_REC_VAL_MAX );

  /* Write metadata */
  meta->dlen = (uint)data_len;
  meta->slot = slot;
  memcpy( meta->owner, owner, sizeof(fd_pubkey_t) );
  meta->lamports   = lamports;
  meta->executable = (uchar)executable;

  /* Write data */
  uchar * acc_data = (uchar *)( meta+1 );
  fd_memcpy( acc_data, frame+0x88UL, data_len );
}

/* process_account_batch is a happy path performance optimization
   handling insertion of lots of small accounts.

   The main optimization implemented for funk is doing hash map memory
   accesses in parallel to amortize DRAM latency. */

int
fd_snapin_process_account_batch_funk( fd_snapin_tile_t *            ctx,
                                      fd_ssparse_advance_result_t * result,
                                      buffered_account_batch_t *    buffered_batch ) {
  int early_exit  = 0;
  ulong start_idx = result ? 0 : buffered_batch->remaining_idx;
  fd_funk_t *         funk    = ctx->accdb_admin->funk;
  fd_funk_rec_map_t * rec_map = funk->rec_map;
  fd_funk_rec_t *     rec_tbl = funk->rec_pool->ele;
  fd_funk_rec_map_shmem_private_chain_t * chain_tbl = fd_funk_rec_map_shmem_private_chain( rec_map->map, 0UL );

  /* Derive map chains */
  uint chain_idx[ FD_SSPARSE_ACC_BATCH_MAX ];
  ulong chain_mask = rec_map->map->chain_cnt-1UL;
  for( ulong i=start_idx; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    uchar const * frame  = result ? result->account_batch.batch[ i ] : buffered_batch->batch[ i ];
    uchar const * pubkey = frame+0x10UL;
    ulong         memo   = fd_funk_rec_key_hash1( pubkey, rec_map->map->seed );
    chain_idx[ i ] = (uint)( memo&chain_mask );
  }

  /* Parallel load hash chain heads */
  uint map_node [ FD_SSPARSE_ACC_BATCH_MAX ];
  uint chain_cnt[ FD_SSPARSE_ACC_BATCH_MAX ];
  for( ulong i=start_idx; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    map_node [ i ] =       chain_tbl[ chain_idx[ i ] ].head_cidx;
    chain_cnt[ i ] = (uint)chain_tbl[ chain_idx[ i ] ].ver_cnt;
  }
  uint chain_max = 0U;
  for( ulong i=start_idx; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    chain_max = fd_uint_max( chain_max, chain_cnt[ i ] );
  }

  /* Parallel walk hash chains */
  static fd_funk_rec_t dummy_rec = { .map_next = UINT_MAX };
  fd_funk_rec_t * rec[ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  for( ulong j=0UL; j<chain_max; j++ ) {
    for( ulong i=start_idx; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
      uchar const *   frame     = result ? result->account_batch.batch[ i ] : buffered_batch->batch[ i ];
      uchar const *   pubkey    = frame+0x10UL;
      int const       has_node  = j<chain_cnt[ i ];
      fd_funk_rec_t * node      = has_node ? rec_tbl+map_node[ i ] : &dummy_rec;
      int const       key_match = 0==memcmp( node->pair.key, pubkey, sizeof(fd_funk_rec_key_t) );
      if( has_node && key_match ) rec[ i ] = node;
      map_node[ i ] = node->map_next;
    }
  }

  /* Create map entries */
  ulong insert_limit = FD_SSPARSE_ACC_BATCH_MAX;
  for( ulong i=start_idx; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    ulong         slot       = result ? result->account_batch.slot : buffered_batch->slot;
    uchar const * frame      = result ? result->account_batch.batch[ i ] : buffered_batch->batch[ i ];
    uchar const * pubkey     = frame+0x10UL;
    ulong         data_len   = fd_ulong_load_8_fast( frame+0x08UL );
    ulong         lamports   = fd_ulong_load_8_fast( frame+0x30UL );
    ulong         rent_epoch = fd_ulong_load_8_fast( frame+0x38UL ); (void)rent_epoch;
    _Bool         executable = !!frame[ 0x60UL ];
    uchar const * data       = frame+0x88UL;
    uchar owner[32];   memcpy( owner, frame+0x40UL, 32UL );
    fd_funk_rec_key_t key = FD_LOAD( fd_funk_rec_key_t, pubkey );

    ctx->metrics.accounts_loaded++;
    fd_funk_rec_t * r = rec[ i ];
    if( FD_LIKELY( !r ) ) {  /* optimize for new account */
      r = fd_funk_rec_pool_acquire( funk->rec_pool, NULL, 0, NULL );
      FD_TEST( r );
      memset( r, 0, sizeof(fd_funk_rec_t) );
      fd_funk_txn_xid_copy( r->pair.xid, ctx->xid );
      fd_funk_rec_key_copy( r->pair.key, &key );
      r->prev_idx = UINT_MAX;
      r->next_idx = UINT_MAX;

      /* Insert to hash map.  In theory, a key could appear twice in the
         same batch.  All accounts in a batch are guaranteed to be from
         the same slot though, so this is fine, assuming that accdb code
         gracefully handles duplicate hash map entries. */
      fd_funk_rec_map_shmem_private_chain_t * chain = &chain_tbl[ chain_idx[ i ] ];
      ulong ver_cnt    = chain->ver_cnt;
      uint  head_cidx  = chain->head_cidx;
      chain->ver_cnt   = fd_funk_rec_map_private_vcnt( fd_funk_rec_map_private_vcnt_ver( ver_cnt ), fd_funk_rec_map_private_vcnt_cnt( ver_cnt )+1UL );
      chain->head_cidx = (uint)( r-rec_tbl );
      r->map_next      = head_cidx;
      rec[ i ]         = r;
    } else {  /* existing record for key found */
      fd_account_meta_t const * existing = fd_funk_val( r, funk->wksp );
      if( FD_UNLIKELY( !existing ) ) FD_LOG_HEXDUMP_NOTICE(( "r", r, sizeof(fd_funk_rec_t) ));
      FD_TEST( existing );
      if( existing->slot > slot ) {
        rec[ i ] = NULL;  /* skip record if existing value is newer */
        /* send the skipped account to the subtracting hash tile */
        ctx->metrics.accounts_ignored++;
        fd_snapin_send_duplicate_account( ctx, lamports, data, data_len, executable, owner, pubkey, 1, &early_exit );
      } else if( slot > existing->slot) {
        /* send the to-be-replaced account to the subtracting hash tile */
        ctx->metrics.accounts_replaced++;
        fd_snapin_send_duplicate_account( ctx, existing->lamports, (uchar const *)existing + sizeof(fd_account_meta_t), existing->dlen, existing->executable, existing->owner, pubkey, 1, &early_exit );
      } else { /* slot==existing->slot */
        FD_TEST( 0 );
      }

      if( FD_LIKELY( early_exit ) ) {
        /* buffer account batch if not already buffered */
        if( FD_LIKELY( result && i<FD_SSPARSE_ACC_BATCH_MAX-1UL ) ) {
          FD_TEST( ctx->buffered_batch.batch_cnt==0UL );
          fd_memcpy( ctx->buffered_batch.batch, result->account_batch.batch, sizeof(uchar const*)*FD_SSPARSE_ACC_BATCH_MAX );
          ctx->buffered_batch.slot          = result->account_batch.slot;
          ctx->buffered_batch.batch_cnt     = result->account_batch.batch_cnt;
          ctx->buffered_batch.remaining_idx = i + 1UL;
        }

        insert_limit = i+1UL;
        break;
      }
    }
  }

  /* Actually insert accounts */
  for( ulong i=start_idx; i<insert_limit; i++ ) {
    uchar const * frame = result ? result->account_batch.batch[ i ] : buffered_batch->batch[ i ];
    ulong slot = result ? result->account_batch.slot : buffered_batch->slot;
    if( rec[ i ] ) {
      streamlined_insert( ctx, rec[ i ], frame, slot );
    }
  }

  if( FD_LIKELY( buffered_batch ) ) {
    if( FD_LIKELY( insert_limit==FD_SSPARSE_ACC_BATCH_MAX ) ) {
      buffered_batch->batch_cnt     = 0UL;
      buffered_batch->remaining_idx = 0UL;
    } else {
      buffered_batch->remaining_idx = insert_limit;
    }
  }

  return early_exit;
}

void
fd_snapin_read_account_funk( fd_snapin_tile_t *  ctx,
                             void const *        acct_addr,
                             fd_account_meta_t * meta,
                             uchar *             data,
                             ulong               data_max ) {
  memset( meta, 0, sizeof(fd_account_meta_t) );

  /* Start a speculative database query.
     It is assumed that no conflicting database accesses take place
     while the account is being read from funk. */

  fd_accdb_peek_t peek_[1];
  fd_accdb_peek_t * peek = fd_accdb_peek( ctx->accdb, peek_, ctx->xid, acct_addr );
  if( FD_UNLIKELY( !peek ) ) return;

  ulong data_sz = fd_accdb_ref_data_sz( peek->acc );
  if( FD_UNLIKELY( data_sz>data_max ) ) {
    FD_BASE58_ENCODE_32_BYTES( acct_addr, acct_addr_b58 );
    FD_LOG_WARNING(( "failed to read account %s: account data size (%lu bytes) exceeds buffer size (%lu bytes)",
                     acct_addr_b58, (ulong)meta->dlen, data_max ));
  }

  memcpy( meta->owner, fd_accdb_ref_owner( peek->acc ), sizeof(fd_pubkey_t) );
  meta->lamports   = fd_accdb_ref_lamports( peek->acc );
  meta->slot       = fd_accdb_ref_slot( peek->acc );
  meta->dlen       = (uint)data_sz;
  meta->executable = !!fd_accdb_ref_exec_bit( peek->acc );
  fd_memcpy( data, fd_accdb_ref_data_const( peek->acc ), data_sz );

  FD_CRIT( fd_accdb_peek_test( peek ), "invalid read" );
  fd_accdb_peek_drop( peek );
}
