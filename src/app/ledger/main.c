#include <errno.h>
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_runtime_public.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/rewards/fd_rewards.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/shredcap/fd_shredcap.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/snapshot/fd_snapshot.h"

struct fd_ledger_args {
  fd_wksp_t *           wksp;                    /* wksp for blockstore */
  fd_wksp_t *           funk_wksp;               /* wksp for funk */
  fd_wksp_t *           status_cache_wksp;       /* wksp for status cache. */
  fd_blockstore_t       blockstore_ljoin;
  fd_blockstore_t *     blockstore;              /* blockstore for replay */
  fd_funk_t             funk[1];                 /* handle to funk */
  fd_alloc_t *          alloc;                   /* handle to alloc */
  char const *          cmd;                     /* user passed command to fd_ledger */
  ulong                 start_slot;              /* start slot for offline replay */
  ulong                 end_slot;                /* end slot for offline replay */
  uint                  hashseed;                /* hashseed */
  char const *          checkpt;                 /* wksp checkpoint */
  char const *          checkpt_funk;            /* wksp checkpoint for a funk wksp */
  char const *          checkpt_status_cache;    /* status cache checkpoint */
  char const *          restore;                 /* wksp restore */
  char const *          allocator;               /* allocator used during replay (libc/wksp) */
  ulong                 shred_max;               /* maximum number of shreds*/
  ulong                 slot_history_max;        /* number of slots stored by blockstore*/
  ulong                 txns_max;                /* txns_max*/
  uint                  index_max;               /* size of funk index (same as rec max) */
  ulong                 funk_page_cnt;
  char const *          snapshot;                /* path to agave snapshot */
  char const *          incremental;             /* path to agave incremental snapshot */
  char const *          genesis;                 /* path to agave genesis */
  char const *          mini_db_dir;             /* path to minifed rocksdb that's to be created */
  int                   copy_txn_status;         /* determine if txns should be copied to the blockstore during minify/replay */
  int                   funk_only;               /* determine if only funk should be ingested */
  char const *          shredcap;                /* path to replay using shredcap instead of rocksdb */
  int                   abort_on_mismatch;       /* determine if execution should abort on mismatch*/
  char const *          capture_fpath;           /* solcap: path for solcap file to be created */
  ulong                 solcap_start_slot;       /* solcap capture start slot */
  int                   capture_txns;            /* solcap: determine if transaction results should be captured for solcap*/
  char const *          checkpt_path;            /* path to dump funk wksp checkpoints during execution*/
  ulong                 checkpt_freq;            /* how often funk wksp checkpoints will be dumped (defaults to never) */
  int                   checkpt_mismatch;        /* determine if a funk wksp checkpoint should be dumped on a mismatch*/

  int                   dump_instr_to_pb;        /* instruction dumping: should insns be dumped */
  int                   dump_txn_to_pb;          /* txn dumping: should txns be dumped */
  int                   dump_block_to_pb;        /* block dumping: should blocks be dumped */
  int                   dump_syscall_to_pb;      /* syscall dumping: should syscalls be dumped */
  int                   dump_elf_to_pb;          /* elf dumping: should elfs be dumped */
  ulong                 dump_proto_start_slot;   /* instruction / txn dumping: what slot to start dumping*/
  char const *          dump_proto_sig_filter;   /* instruction / txn dumping: specify txn sig to dump at */
  char const *          dump_proto_output_dir;   /* instruction / txn dumping: output directory for protobuf messages */

  int                   verify_funk;             /* verify funk before execution starts */
  uint                  verify_acc_hash;         /* verify account hash from the snapshot */
  uint                  check_acc_hash;          /* check account hash by reconstructing with data */
  ulong                 trash_hash;              /* trash hash to be used for negative cases*/
  ulong                 vote_acct_max;           /* max number of vote accounts */
  char const *          rocksdb_list[32];        /* max number of rocksdb dirs that can be passed in */
  ulong                 rocksdb_list_slot[32];   /* start slot for each rocksdb dir that's passed in assuming there are mulitple */
  ulong                 rocksdb_list_cnt;        /* number of rocksdb dirs passed in */
  char *                rocksdb_list_strdup;
  uint                  cluster_version[3];      /* What version of solana is the genesis block? */
  char const *          one_off_features[32];    /* List of one off feature pubkeys to enable for execution agnostic of cluster version */
  uint                  one_off_features_cnt;    /* Number of one off features */
  char *                one_off_features_strdup;
  double                allowed_mem_delta;       /* Percent of memory in the blockstore wksp that can be
                                                    used and not freed between the start of end of execution.
                                                    If the difference in usage exceeds this value, error out. */

  /* These values are setup and maintained before replay */
  fd_capture_ctx_t *    capture_ctx;             /* capture_ctx is used in runtime_replay for various debugging tasks */
  fd_exec_slot_ctx_t *  slot_ctx;                /* slot_ctx */
  fd_tpool_t *          tpool;                   /* thread pool for execution */
  uchar                 tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );

  fd_spad_t *           exec_spads[ 128UL ];          /* bump allocators that are eventually assigned to each txn_ctx */
  ulong                 exec_spad_cnt;                /* number of bump allocators, bounded by number of threads */
  fd_spad_t *           runtime_spad;            /* bump allocator used for runtime scoped allocations */
  ulong                 thread_mem_bound;        /* how much spad is allocated by a tpool thread. The default
                                                    value is the full runtime bound. If a value of 0 is passed
                                                    in, then a reduced bound will be used. */
  ulong                 runtime_mem_bound;       /* how much to allocate for a runtime-scoped spad */

  fd_valloc_t           valloc; /* wksp valloc that should NOT be used for runtime allocations */

  char const *          lthash;
};
typedef struct fd_ledger_args fd_ledger_args_t;

/* Allocations ****************************************************************/

static void
init_exec_spads( fd_ledger_args_t * args, int has_tpool ) {

  FD_LOG_NOTICE(( "setting up exec_spads" ));

  /* Allocate memory for the account mem space. In live execution, each of
     the spad allocations should be tied to its respective execution thread.
     In the future, the spad should be allocated from its tiles' workspace.
     It is important that the exec_spads are only allocated on startup for
     performance reasons to avoid dynamic allocation in the critical path. */

  if( has_tpool ) {
    args->exec_spad_cnt = fd_tpool_worker_cnt( args->tpool );
    for( ulong i=0UL; i<fd_tpool_worker_cnt( args->tpool ); i++ ) {
      ulong       total_mem_sz = args->thread_mem_bound;
      uchar *     mem          = fd_wksp_alloc_laddr( args->wksp, FD_SPAD_ALIGN, FD_SPAD_FOOTPRINT( total_mem_sz ), 999UL );
      fd_spad_t * spad         = fd_spad_join( fd_spad_new( mem, total_mem_sz ) );
      if( FD_UNLIKELY( !spad ) ) {
        FD_LOG_ERR(( "failed to allocate spad" ));
      }
      args->exec_spads[ i ] = spad;
    }
  }
}

/* Runtime Replay *************************************************************/
static int
init_tpool( fd_ledger_args_t * ledger_args ) {

  ulong tcnt = fd_tile_cnt();
  fd_tpool_t * tpool = NULL;

  ulong start_idx = 1UL;
  if( tcnt>=1UL ) {
    tpool = fd_tpool_init( ledger_args->tpool_mem, tcnt, 0UL );
    if( tpool == NULL ) {
      FD_LOG_ERR(( "failed to create thread pool" ));
    }
    for( ulong i=1UL; i<tcnt; ++i ) {
      if( fd_tpool_worker_push( tpool, start_idx++ ) == NULL ) {
        FD_LOG_ERR(( "failed to launch worker" ));
      }
      else {
        FD_LOG_INFO(( "launched worker %lu", start_idx - 1UL ));
      }
    }
  }

  ledger_args->tpool = tpool;

  return 0;
}

void
args_cleanup( fd_ledger_args_t * ledger_args ) {
  if( ledger_args->rocksdb_list_strdup )     free( ledger_args->rocksdb_list_strdup );
  if( ledger_args->one_off_features_strdup ) free( ledger_args->one_off_features_strdup );
}

int
runtime_replay( fd_ledger_args_t * ledger_args ) {
  int ret = 0;

  fd_features_restore( ledger_args->slot_ctx, ledger_args->runtime_spad );

  fd_runtime_update_leaders( ledger_args->slot_ctx->bank, ledger_args->slot_ctx->slot, ledger_args->runtime_spad );

  fd_calculate_epoch_accounts_hash_values( ledger_args->slot_ctx );

  long              replay_time = -fd_log_wallclock();
  ulong             txn_cnt     = 0;
  ulong             slot_cnt    = 0;
  fd_blockstore_t * blockstore  = ledger_args->blockstore;

  ulong prev_slot  = ledger_args->slot_ctx->slot;
  ulong start_slot = ledger_args->slot_ctx->slot + 1;

  /* On demand rocksdb ingest */
  fd_rocksdb_t           rocks_db         = {0};
  fd_rocksdb_root_iter_t iter             = {0};
  fd_slot_meta_t         slot_meta        = {0};
  ulong                  curr_rocksdb_idx = 0UL;

  char * err = fd_rocksdb_init( &rocks_db, ledger_args->rocksdb_list[ 0UL ] );
  if( FD_UNLIKELY( err!=NULL ) ) {
    FD_LOG_ERR(( "fd_rocksdb_init at path=%s returned error=%s", ledger_args->rocksdb_list[ 0UL ], err ));
  }
  fd_rocksdb_root_iter_new( &iter );

  int block_found = -1;
  while ( block_found!=0 && start_slot<=ledger_args->end_slot ) {
    block_found = fd_rocksdb_root_iter_seek( &iter, &rocks_db, start_slot, &slot_meta, ledger_args->valloc );
    if ( block_found!=0 ) {
      start_slot++;
    }
  }

  /* Setup trash_hash */
  uchar trash_hash_buf[32];
  memset( trash_hash_buf, 0xFE, sizeof(trash_hash_buf) );

  /* Calculate and store wksp free size before execution. */
  fd_wksp_usage_t init_usage = {0};
  fd_wksp_usage( fd_blockstore_wksp( ledger_args->blockstore ), NULL, 0UL, &init_usage );

  ulong block_slot = start_slot;
  uchar aborted = 0U;

  // set up to let us easily jump to the end of execution
  do {

  if( FD_UNLIKELY( block_found!=0 ) ) {
    if( 0 == ledger_args->end_slot )
      break; // special case just letting us do the genesis block
    FD_LOG_ERR(( "unable to seek to any slot" ));
  }

  for( ulong slot = start_slot; slot<=ledger_args->end_slot && !aborted; ++slot ) {

    fd_bank_prev_slot_set( ledger_args->slot_ctx->bank, prev_slot );

    FD_LOG_DEBUG(( "reading slot %lu", slot ));

    /* If we have reached a new block, load one in from rocksdb to the blockstore */
    bool block_exists = fd_blockstore_shreds_complete( blockstore, slot);
    if( !block_exists && slot_meta.slot == slot ) {
      int err = fd_rocksdb_import_block_blockstore( &rocks_db,
                                                    &slot_meta, blockstore,
                                                    slot == (ledger_args->trash_hash) ? trash_hash_buf : NULL,
                                                    ledger_args->valloc );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "Failed to import block %lu", start_slot ));
      }

      /* Remove the previous block from the blockstore */
      if( FD_LIKELY( block_slot < slot ) ) {
        /* Mark the block as successfully processed */

        fd_block_map_query_t query[1] = {0};
        int err = fd_block_map_prepare( blockstore->block_map, &block_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
        fd_block_info_t * block_info = fd_block_map_query_ele( query );

        if( FD_UNLIKELY( err || block_info->slot != block_slot ) ) FD_LOG_ERR(( "failed to prepare block map query" ));

        block_info->flags = fd_uchar_clear_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING );
        block_info->flags = fd_uchar_set_bit( block_info->flags, FD_BLOCK_FLAG_PROCESSED );

        fd_block_map_publish( query );

        /* Remove the old block from the blockstore */
        /*for( uint idx = 0; idx <= slot_complete_idx; idx++ ) {
          fd_blockstore_shred_remove( blockstore, block_slot, idx );
        }*/
        fd_blockstore_block_allocs_remove( blockstore, block_slot );
        fd_blockstore_slot_remove( blockstore, block_slot );
      }
      /* Mark the new block as replaying */
      fd_block_map_query_t query[1] = {0};
      err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
      fd_block_info_t * block_info = fd_block_map_query_ele( query );
      if( FD_UNLIKELY( err || block_info->slot != slot ) ) FD_LOG_ERR(( "failed to prepare block map query" ));
      block_info->flags = fd_uchar_set_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING );
      fd_block_map_publish( query );

      block_slot = slot;
    }

    fd_block_t * blk = fd_blockstore_block_query( blockstore, slot );
    if( blk == NULL ) {
      FD_LOG_WARNING(( "failed to read slot %lu", slot ));
      continue;
    }

    fd_bank_tick_height_set( ledger_args->slot_ctx->bank, fd_bank_max_tick_height_get( ledger_args->slot_ctx->bank ) );

    ulong * max_tick_height = fd_bank_max_tick_height_modify( ledger_args->slot_ctx->bank );
    ulong ticks_per_slot = fd_bank_ticks_per_slot_get( ledger_args->slot_ctx->bank );
    if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_compute_max_tick_height( ticks_per_slot, slot, max_tick_height ) ) ) {
      FD_LOG_ERR(( "couldn't compute max tick height slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
    }

    ledger_args->slot_ctx->bank = fd_banks_clone_from_parent( ledger_args->slot_ctx->banks, slot, prev_slot );

    ulong blk_txn_cnt = 0UL;
    FD_LOG_NOTICE(( "Used memory in spad before slot=%lu %lu", slot, ledger_args->runtime_spad->mem_used ));
    FD_TEST( fd_runtime_block_eval_tpool( ledger_args->slot_ctx,
                                          slot,
                                          blk,
                                          ledger_args->capture_ctx,
                                          ledger_args->tpool,
                                          1,
                                          &blk_txn_cnt,
                                          ledger_args->exec_spads,
                                          ledger_args->exec_spad_cnt,
                                          ledger_args->runtime_spad,
                                          ledger_args->blockstore ) == FD_RUNTIME_EXECUTE_SUCCESS );
    txn_cnt += blk_txn_cnt;
    slot_cnt++;

    fd_hash_t expected;
    int err = fd_blockstore_block_hash_query( blockstore, slot, &expected );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR( ( "slot %lu is missing its hash", slot ) );
    else if( FD_UNLIKELY( 0 != memcmp( fd_bank_poh_query( ledger_args->slot_ctx->bank ), expected.hash, sizeof(fd_hash_t) ) ) ) {
      char expected_hash[ FD_BASE58_ENCODED_32_SZ ];
      fd_acct_addr_cstr( expected_hash, expected.hash );
      char poh_hash[ FD_BASE58_ENCODED_32_SZ ];
      fd_acct_addr_cstr( poh_hash, fd_bank_poh_query( ledger_args->slot_ctx->bank )->hash );
      FD_LOG_WARNING(( "PoH hash mismatch! slot=%lu expected=%s, got=%s",
                        slot,
                        expected_hash,
                        poh_hash ));

      if( ledger_args->checkpt_mismatch ) {
        fd_runtime_checkpt( ledger_args->capture_ctx, ledger_args->slot_ctx, ULONG_MAX );
      }
      if( ledger_args->abort_on_mismatch ) {
        ret = 1;
        aborted = 1U;
        break;
      }
    }

    fd_hash_t const * bank_hash_bm = fd_bank_bank_hash_query( ledger_args->slot_ctx->bank );
    err = fd_blockstore_bank_hash_query( blockstore, slot, &expected );
    if( FD_UNLIKELY( err) ) {
      FD_LOG_ERR(( "slot %lu is missing its bank hash", slot ));
    } else if( FD_UNLIKELY( 0 != memcmp( bank_hash_bm,
                                         expected.hash,
                                         32UL ) ) ) {

      char expected_hash[ FD_BASE58_ENCODED_32_SZ ];
      fd_acct_addr_cstr( expected_hash, expected.hash );
      char bank_hash[ FD_BASE58_ENCODED_32_SZ ];
      fd_acct_addr_cstr( bank_hash, bank_hash_bm->hash );

      FD_LOG_WARNING(( "Bank hash mismatch! slot=%lu expected=%s, got=%s",
                        slot,
                        expected_hash,
                        bank_hash ));

      if( ledger_args->checkpt_mismatch ) {
        fd_runtime_checkpt( ledger_args->capture_ctx, ledger_args->slot_ctx, ULONG_MAX );
      }
      if( ledger_args->abort_on_mismatch ) {
        ret = 1;
        break;
      }
    }

    prev_slot = slot;

    if( slot<ledger_args->end_slot ) {
      /* TODO: This currently doesn't support switching over on slots that occur on a fork */
      /* If need to go to next rocksdb, switch over */
      if( FD_UNLIKELY( ledger_args->rocksdb_list_cnt>1UL &&
                       slot+1UL==ledger_args->rocksdb_list_slot[curr_rocksdb_idx] ) ) {
        curr_rocksdb_idx++;
        FD_LOG_WARNING(( "Switching to next rocksdb=%s", ledger_args->rocksdb_list[curr_rocksdb_idx] ));
        fd_rocksdb_root_iter_destroy( &iter );
        fd_rocksdb_destroy( &rocks_db );

        fd_memset( &rocks_db,  0, sizeof(fd_rocksdb_t)           );
        fd_memset( &iter,      0, sizeof(fd_rocksdb_root_iter_t) );
        fd_memset( &slot_meta, 0, sizeof(fd_slot_meta_t)         );

        char * err = fd_rocksdb_init( &rocks_db, ledger_args->rocksdb_list[curr_rocksdb_idx] );
        if( FD_UNLIKELY( err!=NULL ) ) {
          FD_LOG_ERR(( "fd_rocksdb_init at path=%s returned error=%s", ledger_args->rocksdb_list[curr_rocksdb_idx], err ));
        }
        fd_rocksdb_root_iter_new( &iter );
        int ret = fd_rocksdb_root_iter_seek( &iter, &rocks_db, slot+1UL, &slot_meta, ledger_args->valloc );
        if( ret<0 ) {
          FD_LOG_ERR(( "Failed to seek to slot %lu", slot+1UL ));
        }
      } else {
        /* Otherwise look for next slot in current rocksdb */
        int ret = fd_rocksdb_root_iter_next( &iter, &slot_meta, ledger_args->valloc );
        if( ret<0 ) {
          ret = fd_rocksdb_get_meta( &rocks_db, slot+1UL, &slot_meta, ledger_args->valloc );
          if( ret<0 ) {
            FD_LOG_ERR(( "Failed to get meta for slot %lu", slot+1UL ));
          }
        }
      }
    }
  }

  } while(0);

  /* Throw an error if the blockstore wksp has a usage which exceeds the allowed
     threshold. This likely indicates that a memory leak was introduced. */

  fd_wksp_usage_t final_usage = {0};
  fd_wksp_usage( fd_blockstore_wksp( ledger_args->blockstore ), NULL, 0UL, &final_usage );

  ulong  mem_delta      = fd_ulong_sat_sub( init_usage.free_sz, final_usage.free_sz );
  double pcnt_mem_delta = (double)mem_delta / (double)init_usage.free_sz;
  if( pcnt_mem_delta > ledger_args->allowed_mem_delta ) {
    FD_LOG_ERR(( "Memory usage delta (%4f%%) exceeded allowed limit (%4f%%)", 100UL * pcnt_mem_delta, 100UL * ledger_args->allowed_mem_delta ));
  } else {
    FD_LOG_NOTICE(( "Memory usage delta (%4f%%) within allowed limit (%4f%%)", 100UL * pcnt_mem_delta, 100UL * ledger_args->allowed_mem_delta ));
  }

#if FD_SPAD_TRACK_USAGE
  for( ulong i=0UL; i<ledger_args->exec_spad_cnt; i++ ) {
    fd_spad_t * spad = ledger_args->exec_spads[ i ];
    double pcnt_mem_wmark = (double)fd_spad_mem_wmark( spad ) / (double)fd_spad_mem_max( spad );
    pcnt_mem_wmark *= 100;
    FD_LOG_NOTICE(( "spad %2lu mem_wmark %10lu (%6.2f%%) mem_max %10lu", i, fd_spad_mem_wmark( spad ), pcnt_mem_wmark, fd_spad_mem_max( spad ) ));
  }
#endif

  if( ledger_args->tpool ) {
    fd_tpool_fini( ledger_args->tpool );
  }

  fd_rocksdb_root_iter_destroy( &iter );
  fd_rocksdb_destroy( &rocks_db );

  replay_time += fd_log_wallclock();
  double replay_time_s = (double)replay_time * 1e-9;
  double tps           = (double)txn_cnt / replay_time_s;
  double sec_per_slot  = replay_time_s / (double)slot_cnt;
  FD_LOG_NOTICE((
        "replay completed - slots: %lu, elapsed: %6.6f s, txns: %lu, tps: %6.6f, sec/slot: %6.6f",
        slot_cnt,
        replay_time_s,
        txn_cnt,
        tps,
        sec_per_slot ));

  if( slot_cnt == 0 ) {
    if( 0 != ledger_args->end_slot )
      FD_LOG_ERR(( "No slots replayed" ));
    else
      FD_LOG_WARNING(( "No slots replayed" ));
  }

  args_cleanup( ledger_args );

  return ret;
}

/***************************** Helpers ****************************************/
static fd_valloc_t
allocator_setup( fd_wksp_t * wksp ) {

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_ERR(( "workspace is NULL" ));
  }

  void * alloc_shmem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); }
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { FD_LOG_ERR( ( "fd_alloc_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) { FD_LOG_ERR( ( "fd_alloc_join failed" ) ); }
  fd_valloc_t valloc = fd_alloc_virtual( alloc );
  return valloc;

  /* NOTE: Enable this if leak hunting */
  //return fd_backtracing_alloc_virtual( &valloc );

}

void
fd_ledger_capture_setup( fd_ledger_args_t * args ) {
  fd_flamenco_boot( NULL, NULL );

  /* Setup capture context */
  int has_solcap           = args->capture_fpath && args->capture_fpath[0] != '\0';
  int has_checkpt          = args->checkpt_path && args->checkpt_path[0] != '\0';
  int has_checkpt_funk     = args->checkpt_funk && args->checkpt_funk[0] != '\0';
  int has_dump_to_protobuf = args->dump_instr_to_pb || args->dump_txn_to_pb || args->dump_block_to_pb || args->dump_syscall_to_pb || args->dump_elf_to_pb;

  if( has_solcap || has_checkpt || has_checkpt_funk || has_dump_to_protobuf ) {
    FILE * capture_file = NULL;

    void * capture_ctx_mem = fd_valloc_malloc( args->valloc, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
    FD_TEST( capture_ctx_mem );
    fd_memset( capture_ctx_mem, 0, sizeof( fd_capture_ctx_t ) );
    args->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );

    args->capture_ctx->checkpt_freq = ULONG_MAX;
    args->capture_ctx->solcap_start_slot = args->solcap_start_slot;

    if( has_solcap ) {
      capture_file = fopen( args->capture_fpath, "w+" );
      if( FD_UNLIKELY( !capture_file ) ) {
        FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", args->capture_fpath, errno, strerror( errno ) ));
      }
      fd_solcap_writer_init( args->capture_ctx->capture, capture_file );
      args->capture_ctx->capture_txns = args->capture_txns;
    } else {
      args->capture_ctx->capture = NULL;
    }

    if( has_checkpt || has_checkpt_funk ) {
      args->capture_ctx->checkpt_path = ( has_checkpt ? args->checkpt_path : args->checkpt_funk );
      args->capture_ctx->checkpt_freq = args->checkpt_freq;
    }
    if( has_dump_to_protobuf ) {
      args->capture_ctx->dump_instr_to_pb      = args->dump_instr_to_pb;
      args->capture_ctx->dump_txn_to_pb        = args->dump_txn_to_pb;
      args->capture_ctx->dump_block_to_pb      = args->dump_block_to_pb;
      args->capture_ctx->dump_syscall_to_pb    = args->dump_syscall_to_pb;
      args->capture_ctx->dump_elf_to_pb        = args->dump_elf_to_pb;
      args->capture_ctx->dump_proto_sig_filter = args->dump_proto_sig_filter;
      args->capture_ctx->dump_proto_output_dir = args->dump_proto_output_dir;
      args->capture_ctx->dump_proto_start_slot = args->dump_proto_start_slot;
    }
  }
}

void
fd_ledger_main_setup( fd_ledger_args_t * args ) {
  fd_flamenco_boot( NULL, NULL );

  /* Finish other runtime setup steps */
  fd_features_restore( args->slot_ctx, args->runtime_spad );
  fd_runtime_update_leaders( args->slot_ctx->bank, args->slot_ctx->slot, args->runtime_spad );
  fd_calculate_epoch_accounts_hash_values( args->slot_ctx );

  /* After both snapshots have been loaded in, we can determine if we should
      start distributing rewards. */

  fd_rewards_recalculate_partitioned_rewards( args->slot_ctx,
                                              args->tpool,
                                              args->exec_spads,
                                              args->exec_spad_cnt,
                                              args->runtime_spad );

}

void
fd_ledger_main_teardown( fd_ledger_args_t * args ) {
  /* Flush solcap file and cleanup */
  if( args->capture_ctx && args->capture_ctx->capture ) {
    fd_solcap_writer_flush( args->capture_ctx->capture );
    fd_solcap_writer_delete( args->capture_ctx->capture );
  }

  fd_exec_slot_ctx_delete( fd_exec_slot_ctx_leave( args->slot_ctx ) );
}

void
ingest_rocksdb( char const *      file,
                ulong             start_slot,
                ulong             end_slot,
                fd_blockstore_t * blockstore,
                ulong             trash_hash,
                fd_valloc_t       valloc ) {

  fd_rocksdb_t rocks_db;
  char * err = fd_rocksdb_init( &rocks_db, file );
  if( FD_UNLIKELY( err!=NULL ) ) {
    FD_LOG_ERR(( "fd_rocksdb_init returned %s", err ));
  }

  ulong last_slot = fd_rocksdb_last_slot( &rocks_db, &err );
  if( FD_UNLIKELY( err!=NULL ) ) {
    FD_LOG_ERR(( "fd_rocksdb_last_slot returned %s", err ));
  }

  if( last_slot < start_slot ) {
    FD_LOG_ERR(( "rocksdb blocks are older than snapshot. first=%lu last=%lu wanted=%lu",
                 fd_rocksdb_first_slot(&rocks_db, &err), last_slot, start_slot ));
  }

  FD_LOG_NOTICE(( "ingesting rocksdb from start=%lu to end=%lu", start_slot, end_slot ));

  fd_rocksdb_root_iter_t iter = {0};
  fd_rocksdb_root_iter_new( &iter );

  fd_slot_meta_t slot_meta = {0};
  fd_memset( &slot_meta, 0, sizeof(slot_meta) );

  int block_found = -1;
  while ( block_found!=0 && start_slot<=end_slot ) {
    block_found = fd_rocksdb_root_iter_seek( &iter, &rocks_db, start_slot, &slot_meta, valloc );
    if ( block_found!=0 ) {
      start_slot++;
    }
  }
  if( FD_UNLIKELY( block_found!=0 ) ) {
    FD_LOG_ERR(( "unable to seek to any slot" ));
  }

  uchar trash_hash_buf[32];
  memset( trash_hash_buf, 0xFE, sizeof(trash_hash_buf) );

  ulong blk_cnt = 0;
  do {
    ulong slot = slot_meta.slot;
    if( slot > end_slot ) {
      break;
    }

    /* Read and deshred block from RocksDB */
    if( blk_cnt % 100 == 0 ) {
      FD_LOG_WARNING(( "imported %lu blocks", blk_cnt ));
    }

    int err = fd_rocksdb_import_block_blockstore( &rocks_db,
                                                  &slot_meta,
                                                  blockstore,
                                                  (slot == trash_hash) ? trash_hash_buf : NULL,
                                                  valloc );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_rocksdb_get_block failed" ));
    }

    ++blk_cnt;

    memset( &slot_meta, 0, sizeof(fd_slot_meta_t) );

    int ret = fd_rocksdb_root_iter_next( &iter, &slot_meta, valloc );
    if( ret < 0 ) {
      // FD_LOG_WARNING(("Failed for slot %lu", slot + 1));
      ret = fd_rocksdb_get_meta( &rocks_db, slot + 1, &slot_meta, valloc );
      if( ret < 0 ) {
        break;
      }
    }
      // FD_LOG_ERR(("fd_rocksdb_root_iter_seek returned %d", ret));
  } while (1);

  fd_rocksdb_root_iter_destroy( &iter );
  fd_rocksdb_destroy( &rocks_db );

  FD_LOG_NOTICE(( "ingested %lu blocks", blk_cnt ));
}

void
parse_one_off_features( fd_ledger_args_t * args, char const * one_off_features ) {
  if( !one_off_features ) {
    FD_LOG_NOTICE(( "No one-off features passed in" ));
    return;
  }

  char * one_off_features_str = strdup( one_off_features );
  args->one_off_features_strdup = one_off_features_str;
  char * token = NULL;
  token = strtok( one_off_features_str, "," );
  while( token ) {
    args->one_off_features[ args->one_off_features_cnt++ ] = token;
    token = strtok( NULL, "," );
  }

  FD_LOG_NOTICE(( "Found %u one off features to include", args->one_off_features_cnt ));
}

void
parse_rocksdb_list( fd_ledger_args_t * args,
                    char const *       rocksdb_list,
                    char const *       rocksdb_start_slots ) {
  /* First parse the paths to the different rocksdb */
  if( FD_UNLIKELY( !rocksdb_list ) ) {
    FD_LOG_NOTICE(( "No rocksdb list passed in" ));
    return;
  }

  char * rocksdb_str = strdup( rocksdb_list );
  args->rocksdb_list_strdup = rocksdb_str;
  char * token       = NULL;
  token = strtok( rocksdb_str, "," );
  while( token ) {
    args->rocksdb_list[ args->rocksdb_list_cnt++ ] = token;
    token = strtok( NULL, "," );
  }

  /* Now repeat for the start slots assuming there are multiple */
  if( rocksdb_start_slots == NULL && args->rocksdb_list_cnt > 1 ) {
    FD_LOG_ERR(( "Multiple rocksdb dirs passed in but no start slots" ));
  }
  ulong index = 0UL;
  if( rocksdb_start_slots ) {
    char * rocksdb_start_slot_str = strdup( rocksdb_start_slots );
    token = NULL;
    token = strtok( rocksdb_start_slot_str, "," );
    while( token ) {
      args->rocksdb_list_slot[ index++ ] = strtoul( token, NULL, 10 );
      token = strtok( NULL, "," );
    }
  }

  if( index != args->rocksdb_list_cnt - 1UL ) {
    FD_LOG_ERR(( "Number of rocksdb dirs passed in doesn't match number of start slots" ));
  }
}

void
init_funk( fd_ledger_args_t * args ) {
  ulong funk_tag = 42UL;
  void * funk_shmem = fd_funk_new( fd_wksp_alloc_laddr(
      args->funk_wksp,
      fd_funk_align(),
      fd_funk_footprint( args->txns_max, args->index_max ),
      funk_tag
    ),
    funk_tag,
    args->hashseed,
    args->txns_max,
    args->index_max
  );
  if( FD_UNLIKELY( !funk_shmem ) ) {
    FD_LOG_ERR(( "Failed to allocate shmem for funk" ));
  }
  fd_funk_join( args->funk, funk_shmem );
  FD_LOG_NOTICE(( "Funk database is at %s:0x%lx", fd_wksp_name( args->wksp ), fd_wksp_gaddr_fast( args->funk_wksp, args->funk ) ));
}

void
init_blockstore( fd_ledger_args_t * args ) {
  fd_wksp_tag_query_info_t info;
  ulong blockstore_tag = FD_BLOCKSTORE_MAGIC;
  void * shmem;
  if( fd_wksp_tag_query( args->wksp, &blockstore_tag, 1, &info, 1 ) > 0 ) {
    shmem = fd_wksp_laddr_fast( args->wksp, info.gaddr_lo );
    args->blockstore = fd_blockstore_join( &args->blockstore_ljoin, shmem );
    if( args->blockstore->shmem->magic != FD_BLOCKSTORE_MAGIC ) {
      FD_LOG_ERR(( "failed to join a blockstore" ));
    }
    FD_LOG_NOTICE(( "joined blockstore" ));
  } else {
    shmem = fd_wksp_alloc_laddr( args->wksp, fd_blockstore_align(), fd_blockstore_footprint( args->shred_max, args->slot_history_max, 16 ), blockstore_tag );
    if( shmem == NULL ) {
      FD_LOG_ERR(( "failed to allocate a blockstore" ));
    }
    args->blockstore = fd_blockstore_join( &args->blockstore_ljoin, fd_blockstore_new( shmem, 1, args->hashseed, args->shred_max, args->slot_history_max, 16 ) );
    if( args->blockstore->shmem->magic != FD_BLOCKSTORE_MAGIC ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR(( "failed to allocate a blockstore" ));
    }
    FD_LOG_NOTICE(( "allocating a new blockstore" ));
  }
}

void
checkpt( fd_ledger_args_t * args ) {
  if( !args->checkpt && !args->checkpt_funk && !args->checkpt_status_cache ) {
    FD_LOG_WARNING(( "No checkpt argument specified" ));
  }

  if( args->checkpt_funk ) {
    if( args->funk_wksp == NULL ) {
      FD_LOG_ERR(( "funk_wksp is NULL" ));
    }
    FD_LOG_NOTICE(( "writing funk checkpt %s", args->checkpt_funk ));
    unlink( args->checkpt_funk );
    int err = fd_wksp_checkpt( args->funk_wksp, args->checkpt_funk, 0666, 0, NULL );
    if( err ) {
      FD_LOG_ERR(( "funk checkpt failed: error %d", err ));
    }
  }
  if( args->checkpt ) {
    FD_LOG_NOTICE(( "writing %s", args->checkpt ));
    unlink( args->checkpt );
    int err = fd_wksp_checkpt( args->wksp, args->checkpt, 0666, 0, NULL );
    if( err ) {
      FD_LOG_ERR(( "checkpt failed: error %d", err ));
    }
  }
  if( args->checkpt_status_cache ) {
    FD_LOG_NOTICE(( "writing %s", args->checkpt_status_cache ));
    unlink( args->checkpt_status_cache );
    int err = fd_wksp_checkpt( args->status_cache_wksp, args->checkpt_status_cache, 0666, 0, NULL );
    if( err ) {
      FD_LOG_ERR(( "status cache checkpt failed: error %d", err ));
    }
  }
}

void
wksp_restore( fd_ledger_args_t * args ) {
  if( args->restore != NULL ) {
    FD_LOG_NOTICE(( "restoring wksp %s", args->restore ));
    fd_wksp_restore( args->wksp, args->restore, args->hashseed );
  }
}

/********************* Main Command Functions and Setup ***********************/
void
minify( fd_ledger_args_t * args ) {
    /* Example commmand:
    fd_ledger --cmd minify --rocksdb <LARGE_ROCKSDB> --minified-rocksdb <MINI_ROCKSDB>
              --start-slot <START_SLOT> --end-slot <END_SLOT> --copy-txn-status 1
  */
  if( args->rocksdb_list[ 0UL ] == NULL ) {
    FD_LOG_ERR(( "rocksdb path is NULL" ));
  }
  if( args->mini_db_dir == NULL ) {
    FD_LOG_ERR(( "minified rocksdb path is NULL" ));
  }

  args->valloc = allocator_setup( args->wksp );
  init_exec_spads( args, 0 );

  fd_rocksdb_t big_rocksdb;
  char * err = fd_rocksdb_init( &big_rocksdb, args->rocksdb_list[ 0UL ] );
  if( FD_UNLIKELY( err!=NULL ) ) {
    FD_LOG_ERR(( "fd_rocksdb_init at path=%s returned error=%s", args->rocksdb_list[ 0UL ], err ));
  }

  /* If the directory for the minified rocksdb already exists, error out */
  struct stat statbuf;
  if( stat( args->mini_db_dir, &statbuf ) == 0 ) {
    FD_LOG_ERR(( "path for mini_db_dir=%s already exists", args->mini_db_dir ));
  }

  /* Create a new smaller rocksdb */
  fd_rocksdb_t mini_rocksdb;
  fd_rocksdb_new( &mini_rocksdb, args->mini_db_dir );

  /* Correctly bound off start and end slot */
  ulong first_slot = fd_rocksdb_first_slot( &big_rocksdb, &err );
  ulong last_slot  = fd_rocksdb_last_slot( &big_rocksdb, &err );
  if( args->start_slot < first_slot ) { args->start_slot = first_slot; }
  if( args->end_slot > last_slot )    { args->end_slot = last_slot; }

  FD_LOG_NOTICE(( "copying over rocks db for range [%lu, %lu]", args->start_slot, args->end_slot ));

  /* Copy over all slot indexed columns */
  for( ulong cf_idx = 1; cf_idx < FD_ROCKSDB_CF_CNT; ++cf_idx ) {
    fd_rocksdb_copy_over_slot_indexed_range( &big_rocksdb, &mini_rocksdb, cf_idx,
                                              args->start_slot, args->end_slot );
  }
  FD_LOG_NOTICE(("copied over all slot indexed columns"));

  /* Copy over transactions. This is more complicated because first, a temporary
      blockstore will be populated. This will be used to look up transactions
      which can be quickly queried */
  if( args->copy_txn_status ) {
    init_blockstore( args );
    /* Ingest block range into blockstore */
    ingest_rocksdb( args->rocksdb_list[ 0UL ],
                    args->start_slot,
                    args->end_slot,
                    args->blockstore,
                    ULONG_MAX,
                    args->valloc );

  } else {
    FD_LOG_NOTICE(( "skipping copying of transaction statuses" ));
  }

  /* TODO: Currently, the address signatures column family isn't copied as it
           is indexed on the pubkey. */

  fd_rocksdb_destroy( &big_rocksdb );
  fd_rocksdb_destroy( &mini_rocksdb );
}

void
ingest( fd_ledger_args_t * args ) {
  /* Setup funk, blockstore, and slot_ctx */
  wksp_restore( args );
  init_funk( args );
  if( !args->funk_only ) {
    init_blockstore( args );
  }

  init_tpool( args );
  init_exec_spads( args, 1 );

  fd_funk_t * funk = args->funk;

  args->valloc = allocator_setup( args->wksp );

  uchar slot_ctx_mem[FD_EXEC_SLOT_CTX_FOOTPRINT] __attribute__((aligned(FD_EXEC_SLOT_CTX_ALIGN)));
  fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem ) );
  args->slot_ctx = slot_ctx;

  slot_ctx->funk = funk;

  // if( args->status_cache_wksp ) {
  //   void * status_cache_mem = fd_spad_alloc_check( spad,
  //                                                  fd_txncache_align(),
  //                                                  fd_txncache_footprint( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
  //                                                                             FD_TXNCACHE_DEFAULT_MAX_LIVE_SLOTS,
  //                                                                             MAX_CACHE_TXNS_PER_SLOT ) );
  //   FD_TEST( status_cache_mem );
  //   slot_ctx->status_cache  = fd_txncache_join( fd_txncache_new( status_cache_mem,
  //                                                                FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
  //                                                                FD_TXNCACHE_DEFAULT_MAX_LIVE_SLOTS,
  //                                                                MAX_CACHE_TXNS_PER_SLOT ) );
  //   FD_TEST( slot_ctx->status_cache );
  // }

  /* Load in snapshot(s) */
  if( args->snapshot ) {
    fd_snapshot_load_all( args->snapshot,
                          FD_SNAPSHOT_SRC_FILE,
                          NULL,
                          slot_ctx,
                          NULL,
                          args->tpool,
                          args->verify_acc_hash,
                          args->check_acc_hash ,
                          FD_SNAPSHOT_TYPE_FULL,
                          args->exec_spads,
                          args->exec_spad_cnt,
                          args->runtime_spad );
    FD_LOG_NOTICE(( "imported records from snapshot" ));
  }
  if( args->incremental ) {
    fd_snapshot_load_all( args->incremental,
                          FD_SNAPSHOT_SRC_FILE,
                          NULL,
                          slot_ctx,
                          NULL,
                          args->tpool,
                          args->verify_acc_hash,
                          args->check_acc_hash,
                          FD_SNAPSHOT_TYPE_INCREMENTAL,
                          args->exec_spads,
                          args->exec_spad_cnt,
                          args->runtime_spad );
    FD_LOG_NOTICE(( "imported records from incremental snapshot" ));
  }

  if( args->genesis ) {
    fd_runtime_read_genesis( slot_ctx, args->genesis, args->snapshot != NULL, NULL, args->runtime_spad );
  }

  /* At this point the account state has been ingested into funk. Intake rocksdb */
  if( args->start_slot == 0 ) {
    args->start_slot = slot_ctx->slot + 1;
  }
  fd_blockstore_t * blockstore = args->blockstore;
  if( blockstore ) {
    blockstore->shmem->lps = blockstore->shmem->hcs = blockstore->shmem->wmk = slot_ctx->slot;
  }

  if( args->funk_only ) {
    FD_LOG_NOTICE(( "using funk only, skipping blockstore ingest" ));
  } else if( args->shredcap ) {
    FD_LOG_NOTICE(( "using shredcap" ));
    fd_shredcap_populate_blockstore( args->shredcap, blockstore, args->start_slot, args->end_slot );
  } else if( args->rocksdb_list[ 0UL ] ) {
    if( args->end_slot >= slot_ctx->slot + args->slot_history_max ) {
      args->end_slot = slot_ctx->slot + args->slot_history_max - 1;
    }
    ingest_rocksdb( args->rocksdb_list[ 0UL ], args->start_slot, args->end_slot,
                    blockstore, args->trash_hash, args->valloc );
  }

#ifdef FD_FUNK_HANDHOLDING
  if( args->verify_funk ) {
    FD_LOG_NOTICE(( "fd_funk_verify() start" ));
    if( fd_funk_verify( funk ) ) {
      FD_LOG_ERR(( "fd_funk_verify() failed" ));
    }
  }
#endif

  checkpt( args );
}

int
replay( fd_ledger_args_t * args ) {
  /* Allows for ingest and direct replay. This can be done with a full checkpoint
     that contains a blockstore and funk, a checkpoint that just has funk, or directly
     using a rocksdb and snapshot.

    On demand block ingest is enabled by default and can be disabled with
    '--on-demand-block-ingest 0'. The number of blocks retained in a blockstore during
    on demand block ingest can be set with '--on-demand-block-history <N slots>'

    In order to replay from a checkpoint, use '--checkpoint <path to checkpoint>'.

    To use a checkpoint, but to consume blocks on demand use '--funkonly true'.
    This option MUST be used if the checkpoint was generated during a replay with
    on demand block ingest.

    For blocks to contain transaction status information use '--txnstatus true'

    Example command loading in from on demand checkpoint and replaying with on demand block ingest.
    It creates a checkpoint every 1000 slots.
    fd_ledger --funk-restore <CHECKPOINT_TO_LOAD_IN> --cmd replay --page-cnt 20
              --abort-on-mismatch 1 --tile-cpus 5-21 --allocator wksp
              --rocksdb dump/rocksdb --checkpt-path dump/checkpoint_new
              --checkpt-freq 1000 --funk-only 1 --on-demand-block-ingest 1 --funk-page-cnt 350

    Example command directly loading in a rocksdb and snapshot and replaying.
    fd_ledger --reset 1 --cmd replay --rocksdb dump/mainnet-257068890/rocksdb --index-max 5000000
              --end-slot 257068895 --txn-max 100 --page-cnt 16 --verify-acc-hash 1
              --snapshot dump/mainnet-257068890/snapshot-257068890-uRVtagPzKhYorycp4CRtKdWrYPij6iBxCYYXmqRvdSp.tar.zst
              --slot-history 5000 --allocator wksp --tile-cpus 5-21 --funk-page-cnt 16
  */

  args->valloc = allocator_setup( args->wksp );

  wksp_restore( args ); /* Restores checkpointed workspace(s) */

  init_funk( args ); /* Joins or creates funk based on if one exists in the workspace */
  init_blockstore( args ); /* Does the same for the blockstore */

  init_tpool( args ); /* Sets up tpool */
  init_exec_spads( args, 1 ); /* Sets up spad */

  uchar *      banks_mem = fd_wksp_alloc_laddr( args->wksp, fd_banks_align(), fd_banks_footprint( 8UL ), 0xABCABC123 );
  fd_banks_t * banks     = fd_banks_join( fd_banks_new( banks_mem, 8UL ) );
  FD_TEST( banks );

  void * runtime_public_mem = fd_wksp_alloc_laddr( args->wksp,
    fd_runtime_public_align(),
    fd_runtime_public_footprint( args->runtime_mem_bound ), 0x3E64F44C9F44366AUL );
  if( FD_UNLIKELY( !runtime_public_mem ) ) {
    FD_LOG_ERR(( "Unable to allocate runtime_public mem" ));
  }

  fd_runtime_public_t * runtime_public = fd_runtime_public_join( fd_runtime_public_new( runtime_public_mem, args->runtime_mem_bound ) );
  args->runtime_spad = fd_spad_join( fd_wksp_laddr( args->wksp, runtime_public->runtime_spad_gaddr ) );
  if( FD_UNLIKELY( !args->runtime_spad ) ) {
    FD_LOG_ERR(( "Unable to join runtime spad" ));
  }

  fd_spad_t * spad = args->runtime_spad;

  FD_SPAD_FRAME_BEGIN( spad ) {

  /* Setup slot_ctx */
  fd_funk_t * funk = args->funk;

  /* TODO: This is very hacky, needs to be cleaned up */

  void * slot_ctx_mem        = fd_spad_alloc_check( spad, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT );
  args->slot_ctx             = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem ) );
  args->slot_ctx->funk       = funk;

  args->slot_ctx->banks    = banks;
  FD_TEST( args->slot_ctx->banks );

  args->slot_ctx->bank = fd_banks_init_bank( args->slot_ctx->banks, 0UL );

  fd_cluster_version_t * cluster_version = fd_bank_cluster_version_modify( args->slot_ctx->bank );
  cluster_version->major = args->cluster_version[0];
  cluster_version->minor = args->cluster_version[1];
  cluster_version->patch = args->cluster_version[2];

  fd_features_t * features = fd_bank_features_modify( args->slot_ctx->bank );

  fd_features_enable_cleaned_up( features, fd_bank_cluster_version_query( args->slot_ctx->bank ) );
  fd_features_enable_one_offs( features, args->one_off_features, args->one_off_features_cnt, 0UL );

  // void * status_cache_mem = fd_spad_alloc_check( spad,
  //     FD_TXNCACHE_ALIGN,
  //     fd_txncache_footprint( FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
  //                            FD_TXNCACHE_DEFAULT_MAX_LIVE_SLOTS,
  //                            MAX_CACHE_TXNS_PER_SLOT,
  //                            FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS) );
  // args->slot_ctx->status_cache = fd_txncache_join( fd_txncache_new( status_cache_mem,
  //                                                                   FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
  //                                                                   FD_TXNCACHE_DEFAULT_MAX_LIVE_SLOTS,
  //                                                                   MAX_CACHE_TXNS_PER_SLOT ) );
  // if( FD_UNLIKELY( !args->slot_ctx->status_cache ) ) {
  //   FD_LOG_ERR(( "Status cache was not allocated" ));
  // }

  /* Check number of records in funk. If rec_cnt == 0, then it can be assumed
     that you need to load in snapshot(s). */

  /* Load in snapshot(s) */
  if( args->snapshot ) {
    fd_snapshot_load_all( args->snapshot,
                          FD_SNAPSHOT_SRC_FILE,
                          NULL,
                          args->slot_ctx,
                          NULL,
                          args->tpool,
                          args->verify_acc_hash,
                          args->check_acc_hash,
                          FD_SNAPSHOT_TYPE_FULL,
                          args->exec_spads,
                          args->exec_spad_cnt,
                          args->runtime_spad );
    FD_LOG_NOTICE(( "imported from snapshot" ));
    if( args->incremental ) {
      fd_snapshot_load_all( args->incremental,
                            FD_SNAPSHOT_SRC_FILE,
                            NULL,
                            args->slot_ctx,
                            NULL,
                            args->tpool,
                            args->verify_acc_hash,
                            args->check_acc_hash,
                            FD_SNAPSHOT_TYPE_INCREMENTAL,
                            args->exec_spads,
                            args->exec_spad_cnt,
                            args->runtime_spad );
      FD_LOG_NOTICE(( "imported from snapshot" ));
    }
  }

  FD_LOG_NOTICE(( "Used memory in spad after loading in snapshot %lu", args->runtime_spad->mem_used ));

  fd_ledger_capture_setup( args );

  if( args->genesis ) {
    fd_runtime_read_genesis( args->slot_ctx, args->genesis, args->snapshot != NULL, args->capture_ctx, args->runtime_spad );
  }

  fd_ledger_main_setup( args );

  fd_blockstore_init( args->blockstore,
                      -1,
                      FD_BLOCKSTORE_ARCHIVE_MIN_SIZE,
                      args->slot_ctx->slot );
  fd_buf_shred_pool_reset( args->blockstore->shred_pool, 0 );

  FD_LOG_WARNING(( "setup done" ));

  int ret = runtime_replay( args );

  fd_ledger_main_teardown( args );

  return ret;

  } FD_SPAD_FRAME_END;
}

/* Parse user arguments and setup shared data structures used across commands */
int
initial_setup( int argc, char ** argv, fd_ledger_args_t * args ) {
  if( FD_UNLIKELY( argc==1 ) ) {
    return 1;
  }

  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  char const * wksp_name             = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--wksp-name",             NULL, NULL                                               );
  ulong        funk_page_cnt         = fd_env_strip_cmdline_ulong ( &argc, &argv, "--funk-page-cnt",         NULL, 5                                                  );
  ulong        page_cnt              = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",              NULL, 5                                                  );
  int          reset                 = fd_env_strip_cmdline_int   ( &argc, &argv, "--reset",                 NULL, 0                                                  );
  char const * cmd                   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cmd",                   NULL, NULL                                               );
  uint        index_max              = fd_env_strip_cmdline_uint  ( &argc, &argv, "--index-max",             NULL, 450000000                                          );
  ulong        txns_max              = fd_env_strip_cmdline_ulong ( &argc, &argv, "--txn-max",               NULL,      100                                          );
  int          verify_funk           = fd_env_strip_cmdline_int   ( &argc, &argv, "--verify-funky",          NULL, 0                                                  );
  char const * snapshot              = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--snapshot",              NULL, NULL                                               );
  char const * incremental           = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--incremental",           NULL, NULL                                               );
  char const * genesis               = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--genesis",               NULL, NULL                                               );
  int          copy_txn_status       = fd_env_strip_cmdline_int   ( &argc, &argv, "--copy-txn-status",       NULL, 0                                                  );
  ulong        slot_history_max      = fd_env_strip_cmdline_ulong ( &argc, &argv, "--slot-history",          NULL, 100UL                                              );
  ulong        shred_max             = fd_env_strip_cmdline_ulong ( &argc, &argv, "--shred-max",             NULL, 1UL << 17                                          );
  ulong        start_slot            = fd_env_strip_cmdline_ulong ( &argc, &argv, "--start-slot",            NULL, 0UL                                                );
  ulong        end_slot              = fd_env_strip_cmdline_ulong ( &argc, &argv, "--end-slot",              NULL, ULONG_MAX                                          );
  uint         verify_acc_hash       = fd_env_strip_cmdline_uint  ( &argc, &argv, "--verify-acc-hash",       NULL, 1                                                  );
  uint         check_acc_hash        = fd_env_strip_cmdline_uint  ( &argc, &argv, "--check-acc-hash",        NULL, 1                                                  );
  char const * restore               = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--restore",               NULL, NULL                                               );
  char const * shredcap              = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--shred-cap",             NULL, NULL                                               );
  ulong        trash_hash            = fd_env_strip_cmdline_ulong ( &argc, &argv, "--trash-hash",            NULL, ULONG_MAX                                          );
  char const * mini_db_dir           = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--minified-rocksdb",      NULL, NULL                                               );
  int          funk_only             = fd_env_strip_cmdline_int   ( &argc, &argv, "--funk-only",             NULL, 0                                                  );
  char const * checkpt               = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--checkpt",               NULL, NULL                                               );
  char const * checkpt_funk          = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--checkpt-funk",          NULL, NULL                                               );
  char const * capture_fpath         = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--capture-solcap",        NULL, NULL                                               );
  ulong        solcap_start_slot     = fd_env_strip_cmdline_ulong ( &argc, &argv, "--solcap-start-slot",     NULL, 0                                                  );
  int          capture_txns          = fd_env_strip_cmdline_int   ( &argc, &argv, "--capture-txns",          NULL, 1                                                  );
  char const * checkpt_path          = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--checkpt-path",          NULL, NULL                                               );
  ulong        checkpt_freq          = fd_env_strip_cmdline_ulong ( &argc, &argv, "--checkpt-freq",          NULL, ULONG_MAX                                          );
  int          checkpt_mismatch      = fd_env_strip_cmdline_int   ( &argc, &argv, "--checkpt-mismatch",      NULL, 0                                                  );
  char const * allocator             = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--allocator",             NULL, "wksp"                                             );
  int          abort_on_mismatch     = fd_env_strip_cmdline_int   ( &argc, &argv, "--abort-on-mismatch",     NULL, 1                                                  );
  int          dump_instr_to_pb      = fd_env_strip_cmdline_int   ( &argc, &argv, "--dump-insn-to-pb",       NULL, 0                                                  );
  int          dump_txn_to_pb        = fd_env_strip_cmdline_int   ( &argc, &argv, "--dump-txn-to-pb",        NULL, 0                                                  );
  int          dump_block_to_pb      = fd_env_strip_cmdline_int   ( &argc, &argv, "--dump-block-to-pb",      NULL, 0                                                  );
  int          dump_syscall_to_pb    = fd_env_strip_cmdline_int   ( &argc, &argv, "--dump-syscall-to-pb",    NULL, 0                                                  );
  int          dump_elf_to_pb        = fd_env_strip_cmdline_int   ( &argc, &argv, "--dump-elf-to-pb",        NULL, 0                                                  );
  ulong        dump_proto_start_slot = fd_env_strip_cmdline_ulong ( &argc, &argv, "--dump-proto-start-slot", NULL, 0                                                  );
  char const * dump_proto_sig_filter = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dump-proto-sig-filter", NULL, NULL                                               );
  char const * dump_proto_output_dir = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dump-proto-output-dir", NULL, NULL                                               );
  ulong        vote_acct_max         = fd_env_strip_cmdline_ulong ( &argc, &argv, "--vote_acct_max",         NULL, 2000000UL                                          );
  char const * rocksdb_list          = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--rocksdb",               NULL, NULL                                               );
  char const * rocksdb_list_starts   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--rocksdb-starts",        NULL, NULL                                               );
  char const * cluster_version       = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cluster-version",       NULL, "2.0.0"                                            );
  char const * checkpt_status_cache  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--checkpt-status-cache",  NULL, NULL                                               );
  char const * one_off_features      = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--one-off-features",      NULL, NULL                                               );
  char const * lthash                = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--lthash",                NULL, "false"                                            );
  double       allowed_mem_delta     = fd_env_strip_cmdline_double( &argc, &argv, "--allowed-mem-delta",     NULL, 0.1                                                );
  ulong        thread_mem_bound      = fd_env_strip_cmdline_ulong ( &argc, &argv, "--thread-mem-bound",      NULL, FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT );
  ulong        runtime_mem_bound     = fd_env_strip_cmdline_ulong ( &argc, &argv, "--runtime-mem-bound",     NULL, (ulong)10e9                                        );

  if( FD_UNLIKELY( !verify_acc_hash ) ) {
    /* We've got full snapshots that contain all 0s for the account
       hash in account meta.  Running hash verify allows us to
       populate the hash in account meta with real values. */
    FD_LOG_WARNING(( "verify-acc-hash should be 1" ));
  }

  // TODO: Add argument validation. Make sure that we aren't including any arguments that aren't parsed for

  char hostname[64];
  gethostname( hostname, sizeof(hostname) );
  ulong hashseed = fd_hash( 0, hostname, strnlen( hostname, sizeof(hostname) ) );
  args->hashseed = (uint)hashseed;

  /* Setup workspace */
  fd_wksp_t * wksp;
  if( wksp_name == NULL ) {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace" ));
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, page_cnt, 0, "wksp", 0UL );
  } else {
    fd_shmem_info_t shmem_info[1];
    if( FD_UNLIKELY( fd_shmem_info( wksp_name, 0UL, shmem_info ) ) )
      FD_LOG_ERR(( "unable to query region \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
    wksp = fd_wksp_attach( wksp_name );
  }

  if( wksp == NULL ) {
    FD_LOG_ERR(( "failed to attach to workspace %s", wksp_name ));
  }
  if( reset ) {
    fd_wksp_reset( wksp, args->hashseed );
  }
  args->wksp = wksp;

  args->funk_wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ,
    funk_page_cnt*(1UL<<18),
    0,
    "funk",
    0
  );
  if( FD_UNLIKELY( !args->funk_wksp ) ) {
    FD_LOG_ERR(( "failed to create funk workspace" ));
  }

  if( checkpt_status_cache && checkpt_status_cache[0] != '\0' ) {
    FD_LOG_NOTICE(( "Creating status cache wksp" ));
    fd_wksp_t * status_cache_wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 23UL, 0, "status_cache_wksp", 0UL );
    fd_wksp_reset( status_cache_wksp, args->hashseed );
    args->status_cache_wksp = status_cache_wksp;
  } else {
    args->status_cache_wksp = NULL;
  }

  /* Setup alloc */
  #define FD_ALLOC_TAG (422UL)
  void * alloc_shmem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), FD_ALLOC_TAG );
  if( FD_UNLIKELY( !alloc_shmem ) ) { FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); }
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, FD_ALLOC_TAG );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { FD_LOG_ERR( ( "fd_alloc_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, FD_ALLOC_TAG );
  args->alloc = alloc;
  #undef FD_ALLOC_TAG

  /* Copy over arguments */
  args->cmd                     = cmd;
  args->start_slot              = start_slot;
  args->end_slot                = end_slot;
  args->checkpt                 = checkpt;
  args->checkpt_funk            = checkpt_funk;
  args->shred_max               = shred_max;
  args->slot_history_max        = slot_history_max;
  args->txns_max                = txns_max;
  args->index_max               = index_max;
  args->funk_page_cnt           = funk_page_cnt;
  args->restore                 = restore;
  args->mini_db_dir             = mini_db_dir;
  args->funk_only               = funk_only;
  args->copy_txn_status         = copy_txn_status;
  args->snapshot                = snapshot;
  args->incremental             = incremental;
  args->genesis                 = genesis;
  args->shredcap                = shredcap;
  args->verify_funk             = verify_funk;
  args->check_acc_hash          = check_acc_hash;
  args->verify_acc_hash         = verify_acc_hash;
  args->trash_hash              = trash_hash;
  args->capture_fpath           = capture_fpath;
  args->solcap_start_slot       = solcap_start_slot;
  args->capture_txns            = capture_txns;
  args->checkpt_path            = checkpt_path;
  args->checkpt_freq            = checkpt_freq;
  args->checkpt_mismatch        = checkpt_mismatch;
  args->allocator               = allocator;
  args->abort_on_mismatch       = abort_on_mismatch;
  args->dump_instr_to_pb        = dump_instr_to_pb;
  args->dump_txn_to_pb          = dump_txn_to_pb;
  args->dump_block_to_pb        = dump_block_to_pb;
  args->dump_syscall_to_pb      = dump_syscall_to_pb;
  args->dump_elf_to_pb          = dump_elf_to_pb;
  args->dump_proto_start_slot   = dump_proto_start_slot;
  args->dump_proto_sig_filter   = dump_proto_sig_filter;
  args->dump_proto_output_dir   = dump_proto_output_dir;
  args->vote_acct_max           = vote_acct_max;
  args->rocksdb_list_cnt        = 0UL;
  args->checkpt_status_cache    = checkpt_status_cache;
  args->one_off_features_cnt    = 0UL;
  args->allowed_mem_delta       = allowed_mem_delta;
  args->lthash                  = lthash;
  args->thread_mem_bound        = thread_mem_bound ? thread_mem_bound : FD_RUNTIME_BORROWED_ACCOUNT_FOOTPRINT;
  args->runtime_mem_bound       = runtime_mem_bound;
  parse_one_off_features( args, one_off_features );
  parse_rocksdb_list( args, rocksdb_list, rocksdb_list_starts );

  if( FD_UNLIKELY( sscanf( cluster_version, "%u.%u.%u", &args->cluster_version[0], &args->cluster_version[1], &args->cluster_version[2] )!=3 ) ) {
    FD_LOG_ERR(( "failed to decode cluster version" ));;
  }

  if( args->rocksdb_list_cnt==1UL ) {
    FD_LOG_NOTICE(( "rocksdb=%s", args->rocksdb_list[0] ));
  } else {
    for( ulong i=0UL; i<args->rocksdb_list_cnt; ++i ) {
      FD_LOG_NOTICE(( "rocksdb_list[ %lu ]=%s slot=%lu", i, args->rocksdb_list[i], args->rocksdb_list_slot[i-1] ));
    }
  }

  return 0;
}

int main( int argc, char ** argv ) {
  /* Declaring this on the stack gets the alignment wrong when using asan */
  fd_ledger_args_t * args = fd_alloca( alignof(fd_ledger_args_t), sizeof(fd_ledger_args_t) );
  memset( args, 0, sizeof(fd_ledger_args_t) );
  initial_setup( argc, argv, args );

  /* TODO: Need to implement snapshot minification. */

  if( args->cmd == NULL ) {
    FD_LOG_ERR(( "no command specified" ));
  } else if( strcmp( args->cmd, "replay" ) == 0 ) {
    return replay( args );
  } else if( strcmp( args->cmd, "ingest" ) == 0 ) {
    ingest( args );
  } else if( strcmp( args->cmd, "minify" ) == 0 ) {
    minify( args );
  } else {
    FD_LOG_ERR(( "unknown command=%s", args->cmd ));
  }

  return 0;
}
