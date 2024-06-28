#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <alloca.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "../../choreo/fd_choreo.h"
#include "../../disco/fd_disco.h"
#include "../../util/fd_util.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/nanopb/pb_decode.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_account.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../flamenco/types/fd_solana_block.pb.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/program/fd_builtin_programs.h"
#include "../../flamenco/shredcap/fd_shredcap.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/snapshot/fd_snapshot.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define TXNCACHE_TXNS_PER_SLOT  (FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT / 16)

extern void fd_write_builtin_bogus_account( fd_exec_slot_ctx_t * slot_ctx, uchar const pubkey[ static 32 ], char const * data, ulong sz );

struct fd_ledger_args {
  fd_wksp_t *           wksp;                    /* wksp for blockstore, it may include funk */
  fd_wksp_t *           funk_wksp;               /* wksp for funk */
  fd_blockstore_t *     blockstore;              /* blockstore for replay */
  fd_funk_t *           funk;                    /* handle to funk */
  fd_alloc_t *          alloc;                   /* handle to alloc*/
  char const *          cmd;                     /* user passed command to fd_ledger */
  ulong                 start_slot;              /* start slot for offline replay */
  ulong                 end_slot;                /* end slot for offline replay */
  uint                  hashseed;                /* hashseed */
  char const *          checkpt;                 /* wksp checkpoint */
  char const *          checkpt_funk;            /* wksp checkpoint for a funk wksp */
  char const *          checkpt_archive;         /* funk archive format */
  char const *          restore;                 /* wksp restore */
  char const *          restore_funk;            /* wksp restore for a funk wksp */
  char const *          restore_archive;         /* restore from a funk archive */
  char const *          allocator;               /* allocator used during replay (libc/wksp) */
  ulong                 shred_max;               /* maximum number of shreds*/
  ulong                 slot_history_max;        /* number of slots stored by blockstore*/
  ulong                 txns_max;                /* txns_max*/
  ulong                 index_max;               /* size of funk index (same as rec max) */
  char const *          snapshot;                /* path to agave snapshot */
  char const *          incremental;             /* path to agave incremental snapshot */
  char const *          genesis;                 /* path to agave genesis */
  char const *          mini_db_dir;             /* path to minifed rocksdb that's to be created */
  int                   copy_txn_status;         /* determine if txns should be copied to the blockstore during minify/replay */
  int                   funk_only;               /* determine if only funk should be ingested */
  char const *          shredcap;                /* path to replay using shredcap instead of rocksdb */
  int                   abort_on_mismatch;       /* determine if execution should abort on mismatch*/
  int                   on_demand_block_ingest;  /* determine if block range should be ingested during execution or beforehand */
  ulong                 on_demand_block_history; /* how many blocks should the blockstore hold at once */
  ulong                 pages_pruned;            /* ledger pruning: how many pages should the pruned wksp have */
  ulong                 index_max_pruned;        /* ledger pruning: how large should the pruned funk index be */
  fd_funk_t *           pruned_funk;             /* ledger pruning: funk used by the pruned wksp */
  char const *          capture_fpath;           /* solcap: path for solcap file to be created */
  int                   capture_txns;            /* solcap: determine if transaction results should be captured for solcap*/
  char const *          checkpt_path;            /* path to dump funk wksp checkpoints during execution*/
  ulong                 checkpt_freq;            /* how often funk wksp checkpoints will be dumped (defaults to never) */
  int                   checkpt_mismatch;        /* determine if a funk wksp checkpoint should be dumped on a mismatch*/
  int                   dump_insn_to_pb;         /* instruction dumping: should insns be dumped */
  ulong                 dump_insn_start_slot;    /* instruction dumping: what slot to start dumping*/
  char const *          dump_insn_sig_filter;    /* instruction dumping: specify txn sig to dump at */
  char const *          dump_insn_output_dir;    /* instruction dumping: output directory for insns */
  int                   verify_funk;             /* verify funk before execution starts */
  uint                  verify_acc_hash;         /* verify account hash from the snapshot */
  uint                  check_acc_hash;          /* check account hash by reconstructing with data */
  char const *          verify_hash;             /* verify the snapshot hash*/
  ulong                 trash_hash;              /* trash hash to be used for negative cases*/
  ulong                 vote_acct_max;           /* max number of vote accounts */
  char const *          rocksdb_list[ 32UL ];    /* max number of rocksdb dirs that can be passed in */
  ulong                 rocksdb_list_cnt;        /* number of rocksdb dirs passe din */
  /* These values are setup before replay  */
  fd_capture_ctx_t *    capture_ctx;             /* capture_ctx is used in runtime_replay for various debugging tasks */
  fd_acc_mgr_t          acc_mgr[ 1UL ];          /* funk wrapper*/
  fd_exec_slot_ctx_t *  slot_ctx;                /* slot_ctx */
  fd_exec_epoch_ctx_t * epoch_ctx;               /* epoch_ctx */
  fd_tpool_t *          tpool;                   /* thread pool for execution */
  ulong                 max_workers;             /* max number of workers for thread pool */
  uchar                 tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  #ifdef _ENABLE_LTHASH
  char const *      lthash;
  #endif

};
typedef struct fd_ledger_args fd_ledger_args_t;

/* Runtime Replay *************************************************************/
int
runtime_replay( fd_ledger_args_t * ledger_args ) {
  ulong tcnt = fd_tile_cnt();
  uchar * tpool_scr_mem = NULL;
  fd_tpool_t * tpool = NULL;
  if( tcnt > 1UL ) {
    tpool = fd_tpool_init( ledger_args->tpool_mem, tcnt );
    if( tpool == NULL ) {
      FD_LOG_ERR(( "failed to create thread pool" ));
    }
    ulong scratch_sz = fd_scratch_smem_footprint( 256UL<<20UL );
    tpool_scr_mem = fd_valloc_malloc( ledger_args->slot_ctx->valloc, FD_SCRATCH_SMEM_ALIGN, scratch_sz*(tcnt-1UL) );
    if( tpool_scr_mem == NULL ) {
      FD_LOG_ERR( ( "failed to allocate thread pool scratch space" ) );
    }
    for( ulong i=1UL; i<tcnt; ++i ) {
      if( fd_tpool_worker_push( tpool, i, tpool_scr_mem + scratch_sz*(i-1UL), scratch_sz ) == NULL ) {
        FD_LOG_ERR(( "failed to launch worker" ));
      }
      else {
        FD_LOG_NOTICE(( "launched worker" ));
      }
    }
  }
  ledger_args->tpool       = tpool;
  ledger_args->max_workers = tcnt;

  fd_funk_start_write( ledger_args->slot_ctx->acc_mgr->funk );
  ulong r = fd_funk_txn_cancel_all( ledger_args->slot_ctx->acc_mgr->funk, 1 );
  fd_funk_end_write( ledger_args->slot_ctx->acc_mgr->funk );
  FD_LOG_INFO(( "Cancelled old transactions %lu", r ));

  fd_features_restore( ledger_args->slot_ctx );

  if( ledger_args->slot_ctx->blockstore->max < ledger_args->end_slot && !ledger_args->on_demand_block_ingest ) {
    ledger_args->end_slot = ledger_args->slot_ctx->blockstore->max;
  }

  fd_runtime_update_leaders( ledger_args->slot_ctx, ledger_args->slot_ctx->slot_bank.slot );

  fd_calculate_epoch_accounts_hash_values( ledger_args->slot_ctx );

  long              replay_time = -fd_log_wallclock();
  ulong             txn_cnt     = 0;
  ulong             slot_cnt    = 0;
  fd_blockstore_t * blockstore  = ledger_args->slot_ctx->blockstore;

  ulong prev_slot  = ledger_args->slot_ctx->slot_bank.slot;
  ulong start_slot = ledger_args->slot_ctx->slot_bank.slot + 1;

  /* On demand rocksdb ingest */
  fd_rocksdb_t rocks_db       = {0};
  fd_rocksdb_root_iter_t iter = {0};
  fd_slot_meta_t slot_meta    = {0};
  ulong curr_rocksdb_idx      = 0UL;
  if( ledger_args->on_demand_block_ingest ) {
    fd_rocksdb_init( &rocks_db, ledger_args->rocksdb_list[ 0UL ] );
    fd_rocksdb_root_iter_new( &iter );
    if( fd_rocksdb_root_iter_seek( &iter, &rocks_db, start_slot, &slot_meta, ledger_args->slot_ctx->valloc ) ) {
      FD_LOG_ERR(( "unable to seek to first slot" ));
    }
  }

  if( ledger_args->capture_ctx && ledger_args->capture_ctx->pruned_funk != NULL ) {
    /* If prune enabled: setup rent partitions */
    fd_funk_start_write( ledger_args->capture_ctx->pruned_funk );
    fd_funk_t * funk = ledger_args->slot_ctx->acc_mgr->funk;
    fd_wksp_t * wksp = fd_funk_wksp( funk );
    fd_funk_partvec_t * partvec = fd_funk_get_partvec( funk, wksp );
    fd_funk_t * pruned_funk = ledger_args->capture_ctx->pruned_funk;
    fd_funk_set_num_partitions( pruned_funk, partvec->num_part );
    fd_funk_end_write( ledger_args->capture_ctx->pruned_funk );
  }

  /* Setup trash_hash */
  uchar trash_hash_buf[32];
  memset( trash_hash_buf, 0xFE, sizeof(trash_hash_buf) );

  for( ulong slot = start_slot; slot <= ledger_args->end_slot; ++slot ) {
    ledger_args->slot_ctx->slot_bank.prev_slot = prev_slot;
    ledger_args->slot_ctx->slot_bank.slot      = slot;

    FD_LOG_DEBUG(( "reading slot %ld", slot ));

    if( ledger_args->capture_ctx && ledger_args->capture_ctx->pruned_funk != NULL ) {
      fd_funk_start_write( ledger_args->capture_ctx->pruned_funk );
      fd_runtime_collect_rent_accounts_prune( slot, ledger_args->slot_ctx, ledger_args->capture_ctx );
      fd_funk_end_write( ledger_args->capture_ctx->pruned_funk );
    }

    if( ledger_args->on_demand_block_ingest ) {
      if( fd_blockstore_block_query( blockstore, slot ) == NULL && slot_meta.slot == slot ) {
        int err = fd_rocksdb_import_block_blockstore( &rocks_db, &slot_meta, blockstore,
                                                      ledger_args->copy_txn_status, slot == (ledger_args->trash_hash) ? trash_hash_buf : NULL );
        if( FD_UNLIKELY( err ) ) {
          FD_LOG_ERR(( "Failed to import block %lu", start_slot ));
        }
      }
      fd_blockstore_slot_remove( blockstore, slot - ledger_args->on_demand_block_history );
    }

    fd_blockstore_start_read( blockstore );
    fd_block_t * blk = fd_blockstore_block_query( blockstore, slot );
    if( blk == NULL ) {
      FD_LOG_WARNING( ( "failed to read slot %ld", slot ) );
      fd_blockstore_end_read( blockstore );
      continue;
    }

    uchar * val = fd_blockstore_block_data_laddr( blockstore, blk );
    ulong   sz  = blk->data_sz;
    fd_blockstore_end_read( blockstore );

    ulong blk_txn_cnt = 0;
    FD_TEST( fd_runtime_block_eval_tpool( ledger_args->slot_ctx,
                                          ledger_args->capture_ctx,
                                          val,
                                          sz,
                                          ledger_args->tpool,
                                          ledger_args->max_workers,
                                          1,
                                          &blk_txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS );
    txn_cnt += blk_txn_cnt;
    slot_cnt++;

    fd_blockstore_start_read( blockstore );
    fd_hash_t const * expected = fd_blockstore_block_hash_query( blockstore, slot );
    if( FD_UNLIKELY( !expected ) ) FD_LOG_ERR( ( "slot %lu is missing its hash", slot ) );
    else if( FD_UNLIKELY( 0 != memcmp( ledger_args->slot_ctx->slot_bank.poh.hash, expected->hash, 32UL ) ) ) {
      FD_LOG_WARNING(( "PoH hash mismatch! slot=%lu expected=%32J, got=%32J",
                        slot,
                        expected->hash,
                        ledger_args->slot_ctx->slot_bank.poh.hash ));

      if( ledger_args->checkpt_mismatch ) {
        fd_runtime_checkpt( ledger_args->capture_ctx, ledger_args->slot_ctx, ULONG_MAX );
      }
      if( ledger_args->abort_on_mismatch ) {
        fd_blockstore_end_read( blockstore );
        return 1;
      }
    }

    expected = fd_blockstore_bank_hash_query( blockstore, slot );
    if( FD_UNLIKELY( !expected ) ) {
      FD_LOG_ERR(( "slot %lu is missing its bank hash", slot ));
    } else if( FD_UNLIKELY( 0 != memcmp( ledger_args->slot_ctx->slot_bank.banks_hash.hash,
                                         expected->hash,
                                         32UL ) ) ) {
      FD_LOG_WARNING(( "Bank hash mismatch! slot=%lu expected=%32J, got=%32J",
                        slot,
                        expected->hash,
                        ledger_args->slot_ctx->slot_bank.banks_hash.hash ));

      if( ledger_args->checkpt_mismatch ) {
        fd_runtime_checkpt( ledger_args->capture_ctx, ledger_args->slot_ctx, ULONG_MAX );
      }
      if( ledger_args->abort_on_mismatch ) {
        fd_blockstore_end_read( blockstore );
        return 1;
      }
    }
    fd_blockstore_end_read( blockstore );

    prev_slot = slot;

    if( ledger_args->on_demand_block_ingest && slot < ledger_args->end_slot ) {
      int ret = fd_rocksdb_root_iter_next( &iter, &slot_meta, ledger_args->slot_ctx->valloc );
      if( ret<0 ) {
        ret = fd_rocksdb_get_meta( &rocks_db, slot+1UL, &slot_meta, ledger_args->slot_ctx->valloc );
        if( ret<0 ) {
          /* If slot doesn't exist try to look in the next indexed rocksdb */
          if( ++curr_rocksdb_idx>=ledger_args->rocksdb_list_cnt ) {
            FD_LOG_ERR(( "Failed to get meta for slot %lu", slot+1UL ));
          }
          fd_rocksdb_root_iter_destroy( &iter );
          fd_rocksdb_destroy( &rocks_db );

          fd_memset( &rocks_db,  0, sizeof(fd_rocksdb_t)           );
          fd_memset( &iter,      0, sizeof(fd_rocksdb_root_iter_t) );
          fd_memset( &slot_meta, 0, sizeof(fd_slot_meta_t)         );

          fd_rocksdb_init( &rocks_db, ledger_args->rocksdb_list[ curr_rocksdb_idx ] );
          fd_rocksdb_root_iter_new( &iter );
          ret = fd_rocksdb_root_iter_seek( &iter, &rocks_db, slot+1UL, &slot_meta, ledger_args->slot_ctx->valloc );
          if( ret<0 ) {
            FD_LOG_ERR(( "Failed to seek to slot %lu", slot+1UL ));
          }
        }
      }
    }
  }

  if( ledger_args->tpool ) {
    fd_tpool_fini( ledger_args->tpool );
  }

  if( ledger_args->on_demand_block_ingest ) {
    fd_rocksdb_root_iter_destroy( &iter );
    fd_rocksdb_destroy( &rocks_db );
  }

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

  if ( slot_cnt == 0 ) {
    FD_LOG_ERR(( "No slots replayed" ));
  }

  return 0;
}

/***************************** Helpers ****************************************/
fd_valloc_t allocator_setup( fd_wksp_t * wksp, char const * allocator ) {
  FD_TEST( wksp );

  void * alloc_shmem =
      fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); }
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) { FD_LOG_ERR( ( "fd_alloc_join failed" ) ); }

  if( strcmp( allocator, "libc" ) == 0 ) {
    return fd_libc_alloc_virtual();
  } else if( strcmp( allocator, "wksp" ) == 0 ) {
    return fd_alloc_virtual( alloc );
  } else {
    FD_LOG_ERR( ( "unknown allocator specified" ) );
  }
}

void
fd_ledger_main_setup( fd_ledger_args_t * args ) {
  fd_flamenco_boot( NULL, NULL );
  fd_funk_t * funk = args->funk;

  /* Setup valloc */
  fd_valloc_t valloc = args->slot_ctx->valloc;

  /* Setup capture context */
  int has_solcap           = args->capture_fpath && args->capture_fpath[0] != '\0';
  int has_checkpt_dump     = args->checkpt_path && args->checkpt_path[0] != '\0';
  int has_checkpt_arch     = args->checkpt_archive && args->checkpt_archive[0] != '\0';
  int has_prune            = args->pruned_funk != NULL;
  int has_dump_to_protobuf = args->dump_insn_to_pb;

  if( has_solcap || has_checkpt_dump || has_checkpt_arch || has_prune || has_dump_to_protobuf ) {
    FILE * capture_file = NULL;

    void * capture_ctx_mem = fd_valloc_malloc( valloc, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
    FD_TEST( capture_ctx_mem );
    fd_memset( capture_ctx_mem, 0, sizeof( fd_capture_ctx_t ) );
    args->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );

    args->capture_ctx->checkpt_freq = ULONG_MAX;

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

    if( has_checkpt_dump || has_checkpt_arch ) {
      args->capture_ctx->checkpt_path = args->checkpt_path;
      args->capture_ctx->checkpt_archive = args->checkpt_archive;
      args->capture_ctx->checkpt_freq = args->checkpt_freq;
    }
    if( has_prune ) {
      args->capture_ctx->pruned_funk = args->pruned_funk;
    }
    if( has_dump_to_protobuf ) {
      args->capture_ctx->dump_insn_to_pb      = args->dump_insn_to_pb;
      args->capture_ctx->dump_insn_sig_filter = args->dump_insn_sig_filter;
      args->capture_ctx->dump_insn_output_dir = args->dump_insn_output_dir;
      args->capture_ctx->dump_insn_start_slot = args->dump_insn_start_slot;
    }
  }

  fd_runtime_recover_banks( args->slot_ctx, 0, args->genesis==NULL );

  /* Finish other runtime setup steps  */
  fd_features_restore( args->slot_ctx );
  fd_runtime_update_leaders( args->slot_ctx, args->slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( args->slot_ctx );
  fd_funk_start_write( funk );
  fd_bpf_scan_and_create_bpf_program_cache_entry( args->slot_ctx, args->slot_ctx->funk_txn );
  fd_funk_end_write( funk );
}

void
fd_ledger_main_teardown( fd_ledger_args_t * args ) {
  /* Flush solcap file and cleanup */
  if( args->capture_ctx && args->capture_ctx->capture ) {
    fd_solcap_writer_flush( args->capture_ctx->capture );
    fd_solcap_writer_delete( args->capture_ctx->capture );
  }
  fd_exec_epoch_ctx_delete( fd_exec_epoch_ctx_leave( args->epoch_ctx ) );
  fd_exec_slot_ctx_delete( fd_exec_slot_ctx_leave( args->slot_ctx ) );
}

void
ingest_rocksdb( fd_alloc_t *      alloc,
                char const *      file,
                ulong             start_slot,
                ulong             end_slot,
                fd_blockstore_t * blockstore,
                int txn_status,
                ulong trash_hash ) {

  fd_valloc_t valloc = fd_alloc_virtual( alloc );
  fd_rocksdb_t rocks_db;
  char *err = fd_rocksdb_init( &rocks_db, file );
  if( err != NULL ) {
    FD_LOG_ERR(( "fd_rocksdb_init returned %s", err ));
  }

  ulong last_slot = fd_rocksdb_last_slot( &rocks_db, &err );
  if( err != NULL ) {
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

  int ret = fd_rocksdb_root_iter_seek( &iter, &rocks_db, start_slot, &slot_meta, valloc );
  if( ret < 0 ) {
    FD_LOG_ERR(( "fd_rocksdb_root_iter_seek returned %d", ret ));
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

    int err = fd_rocksdb_import_block_blockstore( &rocks_db, &slot_meta, blockstore, txn_status,
                                                  (slot == trash_hash) ? trash_hash_buf : NULL );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_rocksdb_get_block failed" ));
    }

    ++blk_cnt;

    fd_bincode_destroy_ctx_t ctx = { .valloc = valloc };
    fd_slot_meta_destroy( &slot_meta, &ctx );

    ret = fd_rocksdb_root_iter_next( &iter, &slot_meta, valloc );
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
parse_rocksdb_list(  fd_ledger_args_t * FD_FN_UNUSED args, char const * rocksdb_list ) {
  if( FD_UNLIKELY( !rocksdb_list ) ) {
    FD_LOG_NOTICE(( "No rocksdb list passed in" ));
    return;
  }

  ulong str_len = strlen( rocksdb_list );
  if ( FD_UNLIKELY( str_len<3UL ) ) {
    FD_LOG_WARNING(( "Invalid rocksdb list" ));
    return;
  }

  /* String is now just the comma seperated paths */
  char * rocksdb_str = strdup( rocksdb_list );
  char * token       = NULL;
  token = strtok( rocksdb_str, ",[]" );
  while( token ) {
    args->rocksdb_list[ args->rocksdb_list_cnt++ ] = token;
    token = strtok( NULL, ",[]" );
  }

  /* TODO: There is technically a leak here since we don't free the duplicated
     string but it's not a big deal. */
}

void
init_scratch( fd_wksp_t * wksp ) {
  #define FD_SCRATCH_TAG (421UL)
  ulong  smax   = 1UL << 31UL; /* 2 GiB */
  ulong  sdepth = 2048UL;       /* 2048 scratch frames */
  void * smem   = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax   ), FD_SCRATCH_TAG );
  void * fmem   = fd_wksp_alloc_laddr( wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ), FD_SCRATCH_TAG );
  #undef FD_SCRATCH_TAG
  FD_TEST( (!!smem) & (!!fmem) );
  fd_scratch_attach( smem, fmem, smax, sdepth );
}

void
cleanup_scratch( void ) {
  void * fmem = NULL;
  void * smem = fd_scratch_detach( &fmem );
  fd_wksp_free_laddr( smem );
  fd_wksp_free_laddr( fmem );
}

void
init_funk( fd_ledger_args_t * args ) {
  fd_wksp_t * wksp = args->funk_wksp == NULL ? args->wksp : args->funk_wksp;
  void * shmem;
  fd_wksp_tag_query_info_t info;
  ulong tag = FD_FUNK_MAGIC;
  fd_funk_t * funk;
  if( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) > 0 ) {
    FD_LOG_NOTICE(("found funk in wksp"));
    shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
    funk = fd_funk_join( shmem );
    if( funk == NULL ) {
      FD_LOG_ERR(( "failed to join a funky" ));
    }
    if( args->verify_funk ) {
      if( fd_funk_verify( funk ) ) {
        FD_LOG_ERR(( "verification failed" ));
      }
    }
  } else {
    shmem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
    if( shmem == NULL ) {
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }
    funk = fd_funk_join( fd_funk_new( shmem, 1, args->hashseed, args->txns_max, args->index_max ) );

    if( funk == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }
  }
  FD_LOG_NOTICE(( "funky at global address 0x%016lx", fd_wksp_gaddr_fast( wksp, shmem ) ));
  args->funk = funk;
}

void
init_blockstore( fd_ledger_args_t * args ) {
  fd_wksp_tag_query_info_t info;
  ulong blockstore_tag = FD_BLOCKSTORE_MAGIC;
  void * shmem;
  if( fd_wksp_tag_query( args->wksp, &blockstore_tag, 1, &info, 1 ) > 0 ) {
    shmem = fd_wksp_laddr_fast( args->wksp, info.gaddr_lo );
    args->blockstore = fd_blockstore_join( shmem );
    if( args->blockstore == NULL ) {
      FD_LOG_ERR(( "failed to join a blockstore" ));
    }
    FD_LOG_NOTICE(( "joined blockstore" ));
  } else {
    shmem = fd_wksp_alloc_laddr( args->wksp, fd_blockstore_align(), fd_blockstore_footprint(), blockstore_tag );
    if( shmem == NULL ) {
      FD_LOG_ERR(( "failed to allocate a blockstore" ));
    }
    int lg_txn_max = 22;
    args->blockstore = fd_blockstore_join( fd_blockstore_new( shmem, 1, args->hashseed, args->shred_max,
                                                              args->slot_history_max, lg_txn_max ) );
    if( args->blockstore == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR(( "failed to allocate a blockstore" ));
    }
    FD_LOG_NOTICE(( "allocating a new blockstore" ));
  }
}

void
checkpt( fd_ledger_args_t * args ) {
  if( !args->checkpt && !args->checkpt_funk && !args->checkpt_archive ) {
    FD_LOG_WARNING(( "No checkpt argument specified" ));
  }

  if( args->checkpt_archive ) {
    FD_LOG_NOTICE(( "writing funk archive %s", args->checkpt_archive ));
    int err = fd_funk_archive( args->funk, args->checkpt_archive );
    if( err ) {
      FD_LOG_ERR(( "funk archive failed: error %d", err ));
    }
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
}

void
archive_restore( fd_ledger_args_t * args ) {
  if( args->restore_archive != NULL ) {
    fd_funk_unarchive( args->funk, args->restore_archive );
  }
}

void
wksp_restore( fd_ledger_args_t * args ) {
  if( args->restore_funk != NULL ) {
    fd_wksp_restore( args->funk_wksp, args->restore_funk, args->hashseed );
  }
  if( args->restore != NULL ) {
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


  fd_rocksdb_t big_rocksdb;
  char *err = fd_rocksdb_init( &big_rocksdb, args->rocksdb_list[ 0UL ] );
  if( err != NULL ) {
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
    ingest_rocksdb( args->alloc, args->rocksdb_list[ 0UL ], args->start_slot,
                    args->end_slot, args->blockstore, 0, ULONG_MAX );

    fd_rocksdb_copy_over_txn_status_range( &big_rocksdb, &mini_rocksdb, args->blockstore,
                                           args->start_slot, args->end_slot );
    FD_LOG_NOTICE(( "copied over all transaction statuses" ));
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
  /* Setup funk, blockstore, epoch_ctx, and slot_ctx */
  init_funk( args );
  if( !args->funk_only ) {
    init_blockstore( args );
  }
  fd_wksp_t * wksp = args->wksp;
  fd_funk_t * funk = args->funk;

  fd_alloc_t * alloc = fd_alloc_join( fd_wksp_laddr_fast( fd_funk_wksp( funk ), funk->alloc_gaddr ), 0UL );
  if( FD_UNLIKELY( !alloc ) ) FD_LOG_ERR(( "fd_alloc_join(gaddr=%#lx) failed", funk->alloc_gaddr ));

  uchar * epoch_ctx_mem = fd_wksp_alloc_laddr( fd_funk_wksp( funk ), fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( args->vote_acct_max ), FD_EXEC_EPOCH_CTX_MAGIC );
  fd_memset( epoch_ctx_mem, 0, fd_exec_epoch_ctx_footprint( args->vote_acct_max ) );
  fd_exec_epoch_ctx_t * epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, args->vote_acct_max ) );

  uchar slot_ctx_mem[FD_EXEC_SLOT_CTX_FOOTPRINT] __attribute__((aligned(FD_EXEC_SLOT_CTX_ALIGN)));
  fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem, fd_alloc_virtual( alloc ) ) );
  slot_ctx->epoch_ctx = epoch_ctx;

  fd_acc_mgr_t mgr[1];
  slot_ctx->acc_mgr = fd_acc_mgr_new( mgr, funk );
  slot_ctx->blockstore = args->blockstore;

  /* Load in snapshot(s) */
  if( args->snapshot ) {
    fd_snapshot_load( args->snapshot, slot_ctx, args->verify_acc_hash, args->check_acc_hash , FD_SNAPSHOT_TYPE_FULL );
    FD_LOG_NOTICE(( "imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) ) ));
  }
  if( args->incremental ) {
    fd_snapshot_load( args->incremental, slot_ctx, args->verify_acc_hash, args->check_acc_hash, FD_SNAPSHOT_TYPE_INCREMENTAL );
    FD_LOG_NOTICE(( "imported %lu records from incremental snapshot", fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) ) ));
  }

  if( args->genesis ) {
    fd_runtime_read_genesis( slot_ctx, args->genesis, args->snapshot != NULL, NULL );
  }

  /* At this point the account state has been ingested into funk. Intake rocksdb */
  if( args->start_slot == 0 ) {
    args->start_slot = slot_ctx->slot_bank.slot;
  }

  fd_blockstore_t * blockstore = args->blockstore;
  if( args->funk_only ) {
    FD_LOG_NOTICE(( "using funk only, skipping blockstore ingest" ));
  } else if( args->shredcap ) {
    FD_LOG_NOTICE(( "using shredcap" ));
    fd_shredcap_populate_blockstore( args->shredcap, blockstore, args->start_slot, args->end_slot );
  } else if( args->rocksdb_list[ 0UL ] ) {
    if( args->end_slot >= slot_ctx->slot_bank.slot + args->slot_history_max ) {
      args->end_slot = slot_ctx->slot_bank.slot + args->slot_history_max - 1;
    }
    ingest_rocksdb( args->alloc, args->rocksdb_list[ 0UL ], args->start_slot, args->end_slot,
                    blockstore, args->copy_txn_status, args->trash_hash );
  }

  /* Verification */
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                    !fd_feature_iter_done( id );
                                id = fd_feature_iter_next( id ) ) {
    ulong activated_at = fd_features_get( &slot_ctx->epoch_ctx->features, id );
    if( activated_at ) {
      FD_LOG_DEBUG(( "feature %32J activated at slot %lu", id->id.key, activated_at ));
    }
  }

  if( args->verify_funk ) {
    FD_LOG_NOTICE(( "verifying funky" ));
    if( fd_funk_verify( funk ) ) {
      FD_LOG_ERR(( "verification failed" ));
    }
  }

  #ifdef _ENABLE_LTHASH
    if( (NULL != args->lthash) && ( strcmp( args->lthash, "true" ) == 0) ) {
      fd_accounts_init_lthash( slot_ctx );
      fd_accounts_check_lthash( slot_ctx );
    }
  #endif

  if( args->verify_hash ) {
    fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );
    ulong num_iter_accounts = fd_funk_rec_map_key_cnt( rec_map );

    FD_LOG_NOTICE(( "verifying hash for %lu accounts", num_iter_accounts ));

    ulong zero_accounts = 0;
    ulong num_pairs = 0;
    fd_pubkey_hash_pair_t * pairs = (fd_pubkey_hash_pair_t *) malloc( num_iter_accounts*sizeof(fd_pubkey_hash_pair_t) );
    for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
         !fd_funk_rec_map_iter_done( rec_map, iter );
         iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
      fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );
      if( !fd_funk_key_is_acc( rec->pair.key ) ) {
        continue;
      }

      if( num_pairs % 10000000 == 0 ) {
        FD_LOG_NOTICE(( "read %lu so far", num_pairs ));
      }

      fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( rec, wksp );
      if( (metadata->magic != FD_ACCOUNT_META_MAGIC) || (metadata->hlen != sizeof(fd_account_meta_t)) ) {
        FD_LOG_ERR(( "invalid magic on metadata" ));
      }

      if( (metadata->info.lamports == 0) | ((metadata->info.executable & ~1) != 0) ) {
        zero_accounts++;
        continue;
      }

      fd_hash_t acc_hash;
      if( fd_hash_account_v0( acc_hash.uc, metadata, rec->pair.key->uc, fd_account_get_data( metadata ), metadata->slot )==NULL ) {
        FD_LOG_ERR(("error processing account hash"));
      }

      if( memcmp( acc_hash.uc, metadata->hash, 32 ) != 0 ) {
        FD_LOG_ERR(("account hash mismatch - num_pairs: %lu, slot: %lu, acc: %32J, acc_hash: %32J, snap_hash: %32J", num_pairs, slot_ctx->slot_bank.slot, rec->pair.key->uc, acc_hash.uc, metadata->hash));
      }

      pairs[num_pairs].pubkey = (const fd_pubkey_t *)rec->pair.key->uc;
      pairs[num_pairs].hash = (const fd_hash_t *)metadata->hash;
      num_pairs++;
    }
    FD_LOG_NOTICE(( "num_iter_accounts: %ld zero_accounts: %lu", num_iter_accounts, zero_accounts ));

    fd_hash_t accounts_hash;
    fd_hash_account_deltas( pairs, num_pairs, &accounts_hash, slot_ctx );

    free( pairs );

    char accounts_hash_58[FD_BASE58_ENCODED_32_SZ];
    fd_base58_encode_32( (uchar const *)accounts_hash.hash, NULL, accounts_hash_58 );

    FD_LOG_NOTICE(( "hash result %s", accounts_hash_58 ));
    if( strcmp( args->verify_hash, accounts_hash_58 ) == 0 ) {
      FD_LOG_NOTICE(( "hash verified!" ));
    } else {
      FD_LOG_ERR(( "hash does not match!" ));
    }
  }

  cleanup_scratch();
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

  wksp_restore( args ); /* Restores checkpointed workspace(s) */

  init_funk( args ); /* Joins or creates funk based on if one exists in the workspace */
  init_blockstore( args ); /* Does the same for the blockstore */

  archive_restore( args ); /* Restores checkpointed workspace(s) */

  fd_funk_t * funk = args->funk;
  fd_wksp_t * wksp = args->wksp;

  /* Setup slot_ctx */
  fd_valloc_t valloc = allocator_setup( args->wksp, args->allocator );

  void * epoch_ctx_mem = fd_wksp_alloc_laddr( args->wksp, fd_exec_epoch_ctx_align(),
                                              fd_exec_epoch_ctx_footprint( args->vote_acct_max ), FD_EXEC_EPOCH_CTX_MAGIC );
  fd_memset( epoch_ctx_mem, 0, fd_exec_epoch_ctx_footprint( args->vote_acct_max ) );
  void * slot_ctx_mem = fd_wksp_alloc_laddr( args->wksp, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT, FD_EXEC_SLOT_CTX_MAGIC );
  args->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, args->vote_acct_max ) );
  args->slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem, valloc ) );
  args->slot_ctx->epoch_ctx = args->epoch_ctx;
  args->slot_ctx->valloc = valloc;
  args->slot_ctx->acc_mgr = fd_acc_mgr_new( args->acc_mgr, funk );
  args->slot_ctx->blockstore = args->blockstore;

  uchar * status_cache_mem = fd_wksp_alloc_laddr( wksp, fd_txncache_align(), fd_txncache_footprint(FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS, FD_TXNCACHE_DEFAULT_MAX_LIVE_SLOTS, TXNCACHE_TXNS_PER_SLOT), FD_TXNCACHE_MAGIC );
  args->slot_ctx->status_cache = fd_txncache_join( fd_txncache_new( status_cache_mem, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS, FD_TXNCACHE_DEFAULT_MAX_LIVE_SLOTS, TXNCACHE_TXNS_PER_SLOT ) );
  FD_TEST(args->slot_ctx->status_cache);

  /* Check number of records in funk. If rec_cnt == 0, then it can be assumed
     that you need to load in snapshot(s). */
  ulong rec_cnt = fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) );
  if( !rec_cnt ) {
    /* Load in snapshot(s) */
    if( args->snapshot ) {
      fd_snapshot_load( args->snapshot, args->slot_ctx, args->verify_acc_hash, args->check_acc_hash, FD_SNAPSHOT_TYPE_FULL );
      FD_LOG_NOTICE(( "imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) ) ));
    }
    if( args->incremental ) {
      fd_snapshot_load( args->incremental, args->slot_ctx, args->verify_acc_hash, args->check_acc_hash, FD_SNAPSHOT_TYPE_INCREMENTAL );
      FD_LOG_NOTICE(( "imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) ) ));
    }
    if( args->genesis ) {
      fd_runtime_read_genesis( args->slot_ctx, args->genesis, args->snapshot != NULL, NULL );
    }
  } else {
    FD_LOG_NOTICE(( "found funk with %lu records", rec_cnt ));
  }

  fd_ledger_main_setup( args );

  if( !args->on_demand_block_ingest ) {
    ingest_rocksdb( args->alloc, args->rocksdb_list[ 0UL ], args->start_slot, args->end_slot, args->blockstore, 0, args->trash_hash );
  }

  FD_LOG_WARNING(( "setup done" ));

  int ret = runtime_replay( args );

  fd_ledger_main_teardown( args );

  return ret;
}

void
prune( fd_ledger_args_t * args ) {
 if( args->start_slot != 0 ) {
    /* Set prune start and end slot */
    ulong prune_start_slot = args->start_slot;
    ulong prune_end_slot = args->end_slot;
    bool abort_on_mismatch = args->abort_on_mismatch;

    /* Replay all slots before prune slot and checkpoint at prune_start_slot */
    args->start_slot = 0;
    args->end_slot = prune_start_slot + FD_RUNTIME_NUM_ROOT_BLOCKS;
    args->checkpt_freq = prune_start_slot;
    args->checkpt_path = ( args->checkpt_funk != NULL ? args->checkpt_funk : args->checkpt );
    args->abort_on_mismatch = 0;

    int err = replay( args );
    if( err ) {
      FD_LOG_ERR(( "Error on replay in prune" ));
    }

    /* Restore from checkpoint created in replay */
    args->snapshot = NULL;
    args->start_slot = prune_start_slot;
    args->end_slot = prune_end_slot;
    args->restore = args->checkpt;
    args->restore_funk = args->checkpt_funk;
    args->restore_archive = args->checkpt_archive;
    args->abort_on_mismatch = abort_on_mismatch;
  }

  wksp_restore( args );

  /* Setup data structures required for the unpruned workspace & replay ********/
  init_funk( args );
  init_blockstore( args );

  archive_restore( args );

  fd_funk_t * funk = args->funk;

  fd_valloc_t valloc = allocator_setup( args->wksp, args->allocator );

  void * epoch_ctx_mem = fd_wksp_alloc_laddr( args->wksp, fd_exec_epoch_ctx_align(),
                                              fd_exec_epoch_ctx_footprint( args->vote_acct_max ), FD_EXEC_EPOCH_CTX_MAGIC );
  fd_memset( epoch_ctx_mem, 0, fd_exec_epoch_ctx_footprint( args->vote_acct_max ) );
  void * slot_ctx_mem = fd_wksp_alloc_laddr( args->wksp, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT, FD_EXEC_SLOT_CTX_MAGIC );
  args->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, args->vote_acct_max ) );
  args->slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem, valloc ) );
  args->slot_ctx->epoch_ctx = args->epoch_ctx;
  args->slot_ctx->valloc = valloc;
  args->slot_ctx->acc_mgr = fd_acc_mgr_new( args->acc_mgr, funk );
  args->slot_ctx->blockstore = args->blockstore;

  ulong rec_cnt = fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) );
  if( !rec_cnt ) {
    /* Load in snapshot(s) */
    if( args->snapshot ) {
      fd_snapshot_load( args->snapshot, args->slot_ctx, args->verify_acc_hash, args->check_acc_hash, FD_SNAPSHOT_TYPE_FULL );
      FD_LOG_NOTICE(( "imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) ) ));
    }
    if( args->incremental ) {
      fd_snapshot_load( args->incremental, args->slot_ctx, args->verify_acc_hash, args->check_acc_hash, FD_SNAPSHOT_TYPE_INCREMENTAL );
      FD_LOG_NOTICE(( "imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) ) ));
    }
  }

  /* Repeat for the pruned worksapce ******************************************/
  /* Create wksp */
  fd_wksp_t * pruned_wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, args->pages_pruned, 0, "prunedwksp", 0UL );
  if( pruned_wksp == NULL ) {
    FD_LOG_ERR(( "failed to create and attach to a pruned_wksp" ));
  }
  /* Create blockstore */
  fd_blockstore_t * pruned_blockstore;
  void * shmem = fd_wksp_alloc_laddr( pruned_wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
  if( shmem == NULL ) {
    FD_LOG_ERR(( "failed to allocate a blockstore" ));
  }
  pruned_blockstore = fd_blockstore_join( fd_blockstore_new( shmem, 1, args->hashseed, args->shred_max,
                                                             args->slot_history_max, 22 ) );
  if( pruned_blockstore == NULL ) {
    fd_wksp_free_laddr( shmem );
    FD_LOG_ERR(( "failed to allocate a blockstore" ));
  }
  FD_LOG_NOTICE(( "pruned blockstore at global address 0x%016lx", fd_wksp_gaddr_fast( pruned_wksp, shmem ) ));

  /* Create funk */
  fd_funk_t * pruned_funk = NULL;
  shmem = fd_wksp_alloc_laddr( pruned_wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
  if( shmem == NULL ) {
    FD_LOG_ERR(( "failed to allocate a funky" ));
  }
  pruned_funk = fd_funk_join( fd_funk_new( shmem, FD_FUNK_MAGIC, args->hashseed,
                                           args->txns_max, args->index_max_pruned ) );
  if( pruned_funk == NULL ) {
    fd_wksp_free_laddr( shmem );
    FD_LOG_ERR(( "failed to allocate a funky" ));
  }
  FD_LOG_NOTICE(( "pruned funky at global address 0x%016lx", fd_wksp_gaddr_fast( pruned_wksp, shmem ) ));

  /* Junk xid for pruning transaction */
  fd_funk_txn_xid_t prune_xid = {0};
  fd_memset( &prune_xid, 0x42, sizeof(fd_funk_txn_xid_t) );
  fd_funk_start_write( pruned_funk );
  fd_funk_txn_t * prune_txn = fd_funk_txn_prepare( pruned_funk, NULL, &prune_xid, 1 );
  fd_funk_end_write( pruned_funk );
  FD_TEST(( !!prune_txn ));

  /* Setup slot/epoch contexts */
  fd_valloc_t pruned_valloc = allocator_setup( pruned_wksp, args->allocator );

  void * epoch_ctx_mem_pruned = fd_wksp_alloc_laddr( pruned_wksp, fd_exec_epoch_ctx_align(),
                                              fd_exec_epoch_ctx_footprint( args->vote_acct_max ), FD_EXEC_EPOCH_CTX_MAGIC );
  fd_memset( epoch_ctx_mem_pruned, 0, fd_exec_epoch_ctx_footprint( args->vote_acct_max ) );
  void * slot_ctx_mem_pruned = fd_wksp_alloc_laddr( pruned_wksp, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT, FD_EXEC_SLOT_CTX_MAGIC );
  fd_exec_epoch_ctx_t * epoch_ctx_pruned = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem_pruned, args->vote_acct_max ) );
  fd_exec_slot_ctx_t *  slot_ctx_pruned  = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem_pruned, pruned_valloc ) );
  slot_ctx_pruned->epoch_ctx = epoch_ctx_pruned;
  slot_ctx_pruned->valloc = pruned_valloc;
  fd_acc_mgr_t acc_mgr_pruned[1];
  slot_ctx_pruned->acc_mgr = fd_acc_mgr_new( acc_mgr_pruned, pruned_funk );
  slot_ctx_pruned->blockstore = pruned_blockstore;

  args->pruned_funk = pruned_funk;

  /* Replay through the desired slot range ************************************/

  fd_ledger_main_setup( args );
  int err = runtime_replay( args );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Error while replaying" ));
  }

  FD_LOG_NOTICE(("There are currently %lu records in the pruned funk", fd_funk_rec_cnt( fd_funk_rec_map( pruned_funk, pruned_wksp ) ) ));

  /* Reset the unpruned wksp, reload snapshot *********************************/
  /* Reset the wksp */
  fd_funk_delete( fd_funk_leave( args->funk ) );
  ulong funk_tag = FD_FUNK_MAGIC;
  fd_wksp_tag_free( args->wksp, &funk_tag, 1 );
  fd_wksp_reset( args->wksp,      args->hashseed );
  fd_wksp_reset( args->funk_wksp, args->hashseed );

  /* Setup funk again */
  init_funk( args );
  init_blockstore( args );
  init_scratch( args->wksp );

  /* Setup contexts */
  valloc = allocator_setup( args->wksp, args->allocator );

  epoch_ctx_mem = fd_wksp_alloc_laddr( args->wksp, fd_exec_epoch_ctx_align(),
                                       fd_exec_epoch_ctx_footprint( args->vote_acct_max ), FD_EXEC_EPOCH_CTX_MAGIC );
  fd_memset( epoch_ctx_mem, 0, fd_exec_epoch_ctx_footprint( args->vote_acct_max ) );
  slot_ctx_mem = fd_wksp_alloc_laddr( args->wksp, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT, FD_EXEC_SLOT_CTX_MAGIC );
  args->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, args->vote_acct_max ) );
  args->slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem, valloc ) );
  args->slot_ctx->epoch_ctx = args->epoch_ctx;
  args->slot_ctx->valloc = valloc;
  fd_acc_mgr_t mgr[1];
  args->slot_ctx->acc_mgr = fd_acc_mgr_new( mgr, args->funk );

  /* Load in snapshot(s) */
  if( args->snapshot ) {
    fd_snapshot_load( args->snapshot, args->slot_ctx, 0, 0, FD_SNAPSHOT_TYPE_FULL );
    FD_LOG_NOTICE(( "reload: imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) ) ));
  }
  if( args->incremental ) {
    fd_snapshot_load( args->incremental, args->slot_ctx, 0, 0, FD_SNAPSHOT_TYPE_INCREMENTAL );
    FD_LOG_NOTICE(( "reload: imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) ) ));
  }

  /* Copy over funk record state **********************************************/
  /* After replaying, update all touched accounts to contain the data that is
     present before execution begins. Look up the corresponding account in the
     unpruned funk and copy over the contents */
  fd_funk_t * unpruned_funk = args->funk;
  fd_funk_start_write( pruned_funk   );
  fd_funk_start_write( unpruned_funk );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( pruned_funk, fd_funk_wksp( pruned_funk ) );
  ulong txn_rec_cnt = 0UL;
  for( const fd_funk_rec_t * rec = fd_funk_txn_rec_head( prune_txn, rec_map );
       rec; rec = fd_funk_txn_next_rec( pruned_funk, rec ) ) {

    const fd_funk_rec_t * original_rec = fd_funk_rec_query_global( unpruned_funk, NULL, rec->pair.key );
    if( original_rec != NULL ) {
      txn_rec_cnt++;
      fd_funk_rec_t * mod_rec = fd_funk_rec_modify( pruned_funk, rec );
      mod_rec = fd_funk_val_copy( mod_rec, fd_funk_val_const( original_rec, fd_funk_wksp( unpruned_funk ) ),
                                  fd_funk_val_sz( original_rec ), fd_funk_val_sz( original_rec ),
                                  fd_funk_alloc( pruned_funk, pruned_wksp ), pruned_wksp, NULL );
      FD_TEST(( memcmp( fd_funk_val( original_rec, fd_funk_wksp( unpruned_funk ) ), fd_funk_val_const( rec, pruned_wksp ),
                        fd_funk_val_sz( original_rec ) ) == 0 ));
    } else {
      fd_funk_rec_t * mod_rec = fd_funk_rec_modify( pruned_funk, rec );
      int res = fd_funk_rec_remove( pruned_funk, mod_rec, 1 );
      FD_TEST(( res == 0 ));
    }
  }
  FD_LOG_NOTICE(( "Copied over %lu records from transactions", txn_rec_cnt ));

  /* Repeat above steps with all features */
  ulong features_cnt = 0UL;
  for( fd_feature_id_t const * id = fd_feature_iter_init();
        !fd_feature_iter_done( id ); id = fd_feature_iter_next( id ) ) {
    features_cnt++;

    fd_pubkey_t const *   pubkey      = (fd_pubkey_t *) id->id.key;
    fd_funk_rec_key_t     feature_id  = fd_acc_funk_key( pubkey );
    fd_funk_rec_t const * feature_rec = fd_funk_rec_query_global( unpruned_funk, NULL, &feature_id );
    if( !feature_rec ) {
      continue;
    }
    fd_funk_rec_t * new_feature_rec = fd_funk_rec_write_prepare( pruned_funk, prune_txn, &feature_id,
                                                                 0, 1, NULL, NULL );
    FD_TEST(( !!new_feature_rec ));
    new_feature_rec = fd_funk_val_copy( new_feature_rec, fd_funk_val_const( feature_rec, fd_funk_wksp( unpruned_funk ) ),
                                        fd_funk_val_sz( feature_rec ), fd_funk_val_sz( feature_rec ),
                                        fd_funk_alloc( pruned_funk, fd_funk_wksp( pruned_funk ) ), pruned_wksp, NULL );
    FD_TEST(( !!new_feature_rec ));
  }
  FD_LOG_NOTICE(( "Copied over %lu features", features_cnt ));

  /* Do the same with the epoch/slot bank keys and sysvars */
  fd_runtime_recover_banks( args->slot_ctx, 0, 1 );

  fd_funk_rec_key_t id_epoch_bank       = fd_runtime_epoch_bank_key();
  fd_funk_rec_key_t id_slot_bank        = fd_runtime_slot_bank_key();
  fd_funk_rec_key_t recent_block_hashes = fd_acc_funk_key( &fd_sysvar_recent_block_hashes_id );
  fd_funk_rec_key_t clock               = fd_acc_funk_key( &fd_sysvar_clock_id );
  fd_funk_rec_key_t slot_history        = fd_acc_funk_key( &fd_sysvar_slot_history_id );
  fd_funk_rec_key_t slot_hashes         = fd_acc_funk_key( &fd_sysvar_slot_hashes_id );
  fd_funk_rec_key_t epoch_schedule      = fd_acc_funk_key( &fd_sysvar_epoch_schedule_id );
  fd_funk_rec_key_t epoch_rewards       = fd_acc_funk_key( &fd_sysvar_epoch_rewards_id );
  fd_funk_rec_key_t sysvar_fees         = fd_acc_funk_key( &fd_sysvar_fees_id );
  fd_funk_rec_key_t rent                = fd_acc_funk_key( &fd_sysvar_rent_id );
  fd_funk_rec_key_t stake_history       = fd_acc_funk_key( &fd_sysvar_stake_history_id );
  fd_funk_rec_key_t owner               = fd_acc_funk_key( &fd_sysvar_owner_id );
  fd_funk_rec_key_t last_restart_slot   = fd_acc_funk_key( &fd_sysvar_last_restart_slot_id );
  fd_funk_rec_key_t instructions        = fd_acc_funk_key( &fd_sysvar_instructions_id );
  fd_funk_rec_key_t incinerator         = fd_acc_funk_key( &fd_sysvar_incinerator_id );

  fd_funk_rec_key_t records[15] = { id_epoch_bank, id_slot_bank, recent_block_hashes, clock, slot_history,
                                    slot_hashes, epoch_schedule, epoch_rewards, sysvar_fees, rent,
                                    stake_history, owner, last_restart_slot, instructions, incinerator };
  for( uint i = 0; i < sizeof( records ) / sizeof( fd_funk_rec_key_t ); ++i ) {
    fd_funk_rec_t const * original_rec = fd_funk_rec_query_global( unpruned_funk, NULL, &records[i] );
    if( !original_rec ) {
      /* Some sysvars aren't touched during execution. Not a problem. */
      FD_LOG_DEBUG(("Record is not in account pubkey=%32J at index=%lu", &records[i], i));
      continue;
    }
    fd_funk_rec_t * new_rec = fd_funk_rec_write_prepare( pruned_funk, prune_txn, &records[i], 0, 1, NULL, NULL );
    FD_TEST(( !!new_rec ));
    new_rec = fd_funk_val_copy( new_rec, fd_funk_val_const( original_rec, fd_funk_wksp( unpruned_funk) ),
                                fd_funk_val_sz( original_rec ), fd_funk_val_sz( original_rec ),
                                fd_funk_alloc( pruned_funk, pruned_wksp ), pruned_wksp, NULL );
    FD_TEST( memcmp( fd_funk_val( original_rec, fd_funk_wksp( unpruned_funk ) ), fd_funk_val_const( new_rec, pruned_wksp ),
             fd_funk_val_sz( original_rec ) ) == 0 );
    FD_TEST(( !!new_rec ));
  }
  FD_LOG_NOTICE(("Copied over all sysvars and bank keys"));

  /* Publish transaction with pruned records to the root of funk */
  if( fd_funk_txn_publish( pruned_funk, prune_txn, 1 )==0 ) {
    FD_LOG_ERR(("failed to publish transaction into pruned funk"));
  }

  /* Verify that the pruned records are in the funk */
  FD_LOG_NOTICE(("Pruned funk record count is %lu", fd_funk_rec_global_cnt( pruned_funk, pruned_wksp )));

  cleanup_scratch();
  fd_funk_leave( unpruned_funk );

  if( fd_funk_verify( pruned_funk ) ) {
    FD_LOG_ERR(( "pruned funk verification failed" ));
  }

  slot_ctx_pruned->funk_txn = NULL;
  fd_funk_end_write( pruned_funk );
  fd_funk_end_write( unpruned_funk );
  args->funk = pruned_funk;
  args->wksp = pruned_wksp;
  checkpt( args );
}

/* Parse user arguments and setup shared data structures used across commands */
int
initial_setup( int argc, char ** argv, fd_ledger_args_t * args ) {
  if( FD_UNLIKELY( argc==1 ) ) {
    return 1;
  }

  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  char const * wksp_name               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp-name",               NULL, NULL      );
  char const * wksp_name_funk          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--funk-wksp-name",          NULL, NULL      );
  ulong        funk_page_cnt           = fd_env_strip_cmdline_ulong( &argc, &argv, "--funk-page-cnt",           NULL, 5         );
  ulong        page_cnt                = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",                NULL, 5         );
  int          reset                   = fd_env_strip_cmdline_int  ( &argc, &argv, "--reset",                   NULL, 0         );
  char const * cmd                     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cmd",                     NULL, NULL      );
  ulong        index_max               = fd_env_strip_cmdline_ulong( &argc, &argv, "--index-max",               NULL, 450000000 );
  ulong        txns_max                = fd_env_strip_cmdline_ulong( &argc, &argv, "--txn-max",                 NULL,      1000 );
  int          verify_funk             = fd_env_strip_cmdline_int  ( &argc, &argv, "--verify-funky",            NULL, 0         );
  char const * snapshot                = fd_env_strip_cmdline_cstr ( &argc, &argv, "--snapshot",                NULL, NULL      );
  char const * incremental             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--incremental",             NULL, NULL      );
  char const * genesis                 = fd_env_strip_cmdline_cstr ( &argc, &argv, "--genesis",                 NULL, NULL      );
  int          copy_txn_status         = fd_env_strip_cmdline_int  ( &argc, &argv, "--copy-txn-status",         NULL, 0         );
  ulong        slot_history_max        = fd_env_strip_cmdline_ulong( &argc, &argv, "--slot-history",            NULL, FD_BLOCK_MAX );
  ulong        shred_max               = fd_env_strip_cmdline_ulong( &argc, &argv, "--shred-max",               NULL, 1UL << 17 );
  ulong        start_slot              = fd_env_strip_cmdline_ulong( &argc, &argv, "--start-slot",              NULL, 0UL       );
  ulong        end_slot                = fd_env_strip_cmdline_ulong( &argc, &argv, "--end-slot",                NULL, ULONG_MAX );
  char const * verify_hash             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--verify-hash",             NULL, NULL      );
  uint         verify_acc_hash         = fd_env_strip_cmdline_uint ( &argc, &argv, "--verify-acc-hash",         NULL, 0         );
  uint         check_acc_hash          = fd_env_strip_cmdline_uint ( &argc, &argv, "--check-acc-hash",          NULL, 0         );
  char const * restore                 = fd_env_strip_cmdline_cstr ( &argc, &argv, "--restore",                 NULL, NULL      );
  char const * restore_funk            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--funk-restore",            NULL, NULL      );
  char const * restore_archive         = fd_env_strip_cmdline_cstr ( &argc, &argv, "--restore-archive",         NULL, NULL      );
  char const * shredcap                = fd_env_strip_cmdline_cstr ( &argc, &argv, "--shred-cap",               NULL, NULL      );
  ulong        trash_hash              = fd_env_strip_cmdline_ulong( &argc, &argv, "--trash-hash",              NULL, ULONG_MAX );
  char const * mini_db_dir             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--minified-rocksdb",        NULL, NULL      );
  ulong        index_max_pruned        = fd_env_strip_cmdline_ulong( &argc, &argv, "--pruned-index-max",        NULL, 450000000 );
  ulong        pages_pruned            = fd_env_strip_cmdline_ulong( &argc, &argv, "--pruned-page-cnt",         NULL, ULONG_MAX );
  int          funk_only               = fd_env_strip_cmdline_int  ( &argc, &argv, "--funk-only",               NULL, 0         );
  char const * checkpt                 = fd_env_strip_cmdline_cstr ( &argc, &argv, "--checkpt",                 NULL, NULL      );
  char const * checkpt_funk            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--checkpt-funk",            NULL, NULL      );
  char const * checkpt_archive         = fd_env_strip_cmdline_cstr ( &argc, &argv, "--checkpt-archive",         NULL, NULL      );
  char const * capture_fpath           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--capture-solcap",          NULL, NULL      );
  int          capture_txns            = fd_env_strip_cmdline_int  ( &argc, &argv, "--capture-txns",            NULL, 1         );
  char const * checkpt_path            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--checkpt-path",            NULL, NULL      );
  ulong        checkpt_freq            = fd_env_strip_cmdline_ulong( &argc, &argv, "--checkpt-freq",            NULL, ULONG_MAX );
  int          checkpt_mismatch        = fd_env_strip_cmdline_int  ( &argc, &argv, "--checkpt-mismatch",        NULL, 0         );
  char const * allocator               = fd_env_strip_cmdline_cstr ( &argc, &argv, "--allocator",               NULL, "wksp"    );
  int          abort_on_mismatch       = fd_env_strip_cmdline_int  ( &argc, &argv, "--abort-on-mismatch",       NULL, 1         );
  int          on_demand_block_ingest  = fd_env_strip_cmdline_int  ( &argc, &argv, "--on-demand-block-ingest",  NULL, 0         );
  ulong        on_demand_block_history = fd_env_strip_cmdline_ulong( &argc, &argv, "--on-demand-block-history", NULL, 100       );
  int          dump_insn_to_pb         = fd_env_strip_cmdline_int  ( &argc, &argv, "--dump-insn-to-pb",         NULL, 0         );
  ulong        dump_insn_start_slot    = fd_env_strip_cmdline_ulong( &argc, &argv, "--dump-insn-start-slot",    NULL, 0         );
  char const * dump_insn_sig_filter    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dump-insn-sig-filter",    NULL, NULL      );
  char const * dump_insn_output_dir    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dump-insn-output-dir",    NULL, NULL      );
  ulong        vote_acct_max           = fd_env_strip_cmdline_ulong( &argc, &argv, "--vote_acct_max",           NULL, 2000000UL );
  int          use_funk_wksp           = fd_env_strip_cmdline_int  ( &argc, &argv, "--use-funk-wksp",           NULL, 1         );
  char const * rocksdb_list            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--rocksdb",                 NULL, NULL      );

  #ifdef _ENABLE_LTHASH
  char const * lthash             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--lthash",           NULL, "false"   );
  #endif

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

  init_scratch( wksp );

  /* Setup funk workspace if specified. */
  if( use_funk_wksp ) {
    fd_wksp_t * funk_wksp = NULL;
    if( wksp_name_funk == NULL ) {
      FD_LOG_NOTICE(( "--funk-wksp-name not specified, using an anonymous local funk workspace" ));
      funk_wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, funk_page_cnt, 0, "funk_wksp", 0UL );
    } else {
      fd_shmem_info_t shmem_info[1];
      if( FD_UNLIKELY( fd_shmem_info( wksp_name_funk, 0UL, shmem_info ) ) )
        FD_LOG_ERR(( "unable to query region \"%s\"\n\tprobably does not exist or bad permissions", wksp_name_funk ));
      funk_wksp = fd_wksp_attach( wksp_name_funk );
    }
    if( reset || snapshot ) {
      fd_wksp_reset( funk_wksp, args->hashseed );
    }
    args->funk_wksp = funk_wksp;
  }

  /* Setup alloc and valloc */
  #define FD_ALLOC_TAG (422UL)
  void * alloc_shmem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), FD_ALLOC_TAG );
  if( FD_UNLIKELY( !alloc_shmem ) ) { FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); }
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, FD_ALLOC_TAG );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, FD_ALLOC_TAG );
  args->alloc = alloc;
  #undef FD_ALLOC_TAG

  /* Copy over arguments */
  args->cmd                     = cmd;
  args->start_slot              = start_slot;
  args->end_slot                = end_slot;
  args->checkpt                 = checkpt;
  args->checkpt_funk            = checkpt_funk;
  args->checkpt_archive         = checkpt_archive;
  args->shred_max               = shred_max;
  args->slot_history_max        = slot_history_max;
  args->txns_max                = txns_max;
  args->index_max               = index_max;
  args->restore                 = restore;
  args->restore_funk            = restore_funk;
  args->restore_archive         = restore_archive;
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
  args->verify_hash             = verify_hash;
  args->index_max_pruned        = index_max_pruned;
  args->pages_pruned            = pages_pruned;
  args->capture_fpath           = capture_fpath;
  args->capture_txns            = capture_txns;
  args->checkpt_path            = checkpt_path;
  args->checkpt_freq            = checkpt_freq;
  args->checkpt_mismatch        = checkpt_mismatch;
  args->allocator               = allocator;
  args->abort_on_mismatch       = abort_on_mismatch;
  args->on_demand_block_ingest  = on_demand_block_ingest;
  args->on_demand_block_history = on_demand_block_history;
  args->dump_insn_to_pb         = dump_insn_to_pb;
  args->dump_insn_start_slot    = dump_insn_start_slot;
  args->dump_insn_sig_filter    = dump_insn_sig_filter;
  args->dump_insn_output_dir    = dump_insn_output_dir;
  args->vote_acct_max           = vote_acct_max;
  args->rocksdb_list_cnt        = 0UL;
  parse_rocksdb_list( args, rocksdb_list );

  for( ulong i = 0; i < args->rocksdb_list_cnt; ++i ) {
    FD_LOG_NOTICE(( "rocksdb_list[%lu] = %s", i, args->rocksdb_list[i] ));
  }

  #ifdef _ENABLE_LTHASH
  args->lthash           = lthash;
  #endif

  return 0;
}

int main( int argc, char ** argv ) {
  fd_ledger_args_t args = {0};
  initial_setup( argc, argv, &args );

  if( args.cmd == NULL ) {
    FD_LOG_ERR(( "no command specified" ));
  } else if( strcmp( args.cmd, "replay" ) == 0 ) {
    return replay( &args );
  } else if( strcmp( args.cmd, "ingest" ) == 0 ) {
    ingest( &args );
  } else if( strcmp( args.cmd, "minify" ) == 0 ) {
    minify( &args );
  } else if( strcmp( args.cmd, "prune" ) == 0 ) {
    prune( &args );
  } else {
    FD_LOG_ERR(( "unknown command=%s", args.cmd ));
  }
  return 0;
}
