#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <alloca.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "../../disco/fd_disco.h"
#include "../../disco/tvu/fd_tvu.h"
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
#include "../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/program/fd_builtin_programs.h"
#include "../../flamenco/shredcap/fd_shredcap.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

extern void fd_write_builtin_bogus_account( fd_exec_slot_ctx_t * slot_ctx, uchar const       pubkey[ static 32 ], char const *      data, ulong             sz );

static void usage(char const * progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --cmd ingest --snapshotfile <file>               ingest solana snapshot file\n");
  fprintf(stderr, "              --incremental <file>                also ingest incremental snapshot file\n");
  fprintf(stderr, "              --rocksdb <file>                    also ingest a rocks database file\n");
  fprintf(stderr, "              --txnstatus true                    also ingest transaction status from rocksdb\n");
  fprintf(stderr, "              --genesis <file>                    also ingest a genesis file\n");
  fprintf(stderr, "              --shredcap <directory>              also ingest a shredcap\n");
  fprintf(stderr, "              --trashhash <slot>                  use trashhash for invalid test cases\n");
  fprintf(stderr, " --cmd minify --rocksdb <file>                    ingest full sized rocksdb\n");
  fprintf(stderr, "              --minidb <file>                     output minified rocksdb\n");
  fprintf(stderr, "              --startslot <slot>                  start slot (only used for minify)");
  fprintf(stderr, "              --endslot <slot>                    end slot");
  fprintf(stderr, "              --copytxnstatus true                copy over transaction statuses\n");
  fprintf(stderr, " --cmd prune                                      prune funk to end slot\n");
  fprintf(stderr, "              --snapshotfile <file>               ingest solana snapshot file\n");
  fprintf(stderr, "              --rocksdb <file>                    also ingest a rocks database file\n");
  fprintf(stderr, "              --endslot <slot>                    last slot to replay up to\n");
  fprintf(stderr, "              --indexmaxunpruned <count>          indexmax for the unpruned funk\n");
  fprintf(stderr, "              --indexmax <count>                  indexmax for the pruned funk\n");
  fprintf(stderr, "              --backup <file>                     make a backup file\n");
  fprintf(stderr, "              --startslot <slot>                  verify database integrity\n");
  fprintf(stderr, " --verifyfunky true                               verify database integrity\n");
  fprintf(stderr, " --wksp <name>                                    workspace name\n");
  fprintf(stderr, " --pages <count>                                  number of gigantic pages in anonymous workspace\n");
  fprintf(stderr, " --reset true                                     reset workspace before ingesting\n");
  fprintf(stderr, " --backup <file>                                  make a funky backup file\n");
  fprintf(stderr, " --indexmax <count>                               size of funky account map\n");
  fprintf(stderr, " --txnmax <count>                                 size of funky transaction map\n");
  fprintf(stderr, " --slothistory <count>                            maximum slot history in blockstore\n");
  fprintf(stderr, " --endslot <slot>                                 last slot to recover\n");
  fprintf(stderr, " --verifyhash <base58hash>                        verify that the accounts hash matches the given one\n");
  fprintf(stderr, " --verifyfunky true                               verify database integrity\n");
  fprintf(stderr, " --verifypoh true                                 verify proof-of-history while importing blocks\n");
  fprintf(stderr, " --loglevel <level>                               Set logging level\n");
  fprintf(stderr, " --network <net>                                  main/dev/testnet\n");
  fprintf(stderr, " --verifyacchash true                             check account hash against ledger\n");
  fprintf(stderr, " --checkacchash true                              check account hash against hash generated by data\n");
}

void
ingest_rocksdb( fd_exec_slot_ctx_t * slot_ctx,
                char const *      file,
                ulong             end_slot,
                fd_blockstore_t * blockstore,
                int txnstatus,
                ulong trashhash) {
  fd_rocksdb_t rocks_db;
  char *err = fd_rocksdb_init(&rocks_db, file);
  if (err != NULL) {
    FD_LOG_ERR(("fd_rocksdb_init returned %s", err));
  }

  ulong last_slot = fd_rocksdb_last_slot(&rocks_db, &err);
  if (err != NULL) {
    FD_LOG_ERR(("fd_rocksdb_last_slot returned %s", err));
  }
  // if (end_slot > last_slot)
  //   end_slot = last_slot;

  ulong start_slot = slot_ctx->slot_bank.slot;
  if ( last_slot < start_slot ) {
    FD_LOG_ERR(("rocksdb blocks are older than snapshot. first=%lu last=%lu wanted=%lu",
                fd_rocksdb_first_slot(&rocks_db, &err), last_slot, start_slot));
  }

  FD_LOG_NOTICE(("ingesting rocksdb from start=%lu to end=%lu", start_slot, end_slot));

  fd_rocksdb_root_iter_t iter;
  fd_rocksdb_root_iter_new ( &iter );

  fd_slot_meta_t m;
  fd_memset(&m, 0, sizeof(m));

  int ret = fd_rocksdb_root_iter_seek( &iter, &rocks_db, start_slot, &m, slot_ctx->valloc );
  if (ret < 0)
    FD_LOG_ERR(("fd_rocksdb_root_iter_seek returned %d", ret));

  uchar trash_hash[32];
  memset(trash_hash, 0xFE, sizeof(trash_hash));

  ulong blk_cnt = 0;
  do {
    ulong slot = m.slot;
    if (slot > end_slot)
      break;

    /* Read and deshred block from RocksDB */
    if( blk_cnt % 100 == 0 ) {
      FD_LOG_WARNING(("imported %lu blocks", blk_cnt));
    }

    int err = fd_rocksdb_import_block_blockstore(&rocks_db, &m, blockstore, txnstatus, (slot == trashhash) ? trash_hash : NULL);
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_rocksdb_get_block failed" ));

    ++blk_cnt;

    fd_bincode_destroy_ctx_t ctx = { .valloc = slot_ctx->valloc };
    fd_slot_meta_destroy(&m, &ctx);

    ret = fd_rocksdb_root_iter_next( &iter, &m, slot_ctx->valloc );
    if (ret < 0) {
      // FD_LOG_WARNING(("Failed for slot %lu", slot + 1));
      ret = fd_rocksdb_get_meta(&rocks_db, slot + 1, &m, slot_ctx->valloc);
      if (ret < 0) {
        break;
      }
    }
      // FD_LOG_ERR(("fd_rocksdb_root_iter_seek returned %d", ret));
  } while (1);

  fd_rocksdb_root_iter_destroy( &iter );
  fd_rocksdb_destroy(&rocks_db);

  FD_LOG_NOTICE(("ingested %lu blocks", blk_cnt));
}

int
main( int     argc,
      char ** argv ) {

  if( FD_UNLIKELY( argc==1 ) ) {
    usage( argv[0] );
    return 1;
  }

  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  char const * wkspname           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",             NULL, NULL      );
  ulong        pages              = fd_env_strip_cmdline_ulong( &argc, &argv, "--pages",            NULL, ULONG_MAX );
  if( pages == ULONG_MAX )
    pages                         = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",         NULL, 5         );
  char const * reset              = fd_env_strip_cmdline_cstr ( &argc, &argv, "--reset",            NULL, "false"   );
  char const * cmd                = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cmd",              NULL, NULL      );
  ulong        index_max          = fd_env_strip_cmdline_ulong( &argc, &argv, "--indexmax",         NULL, 450000000 );
  ulong        xactions_max       = fd_env_strip_cmdline_ulong( &argc, &argv, "--txnmax",           NULL,      1000 );
  char const * verifyfunky        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--verifyfunky",      NULL, "false"   );
  char const * snapshotfile       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--snapshotfile",     NULL, NULL      );
  char const * incremental        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--incremental",      NULL, NULL      );
  char const * genesis            = fd_env_strip_cmdline_cstr ( &argc, &argv, "--genesis",          NULL, NULL      );
  char const * rocksdb_dir        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--rocksdb",          NULL, NULL      );
  char const * txnstatus          = fd_env_strip_cmdline_cstr ( &argc, &argv, "--txnstatus",        NULL, "false"   );
  ulong    slot_history_max       = fd_env_strip_cmdline_ulong( &argc, &argv, "--slothistory",      NULL, FD_BLOCKSTORE_SLOT_HISTORY_MAX );
  ulong        shred_max          = fd_env_strip_cmdline_ulong( &argc, &argv, "--shredmax",         NULL, 1UL << 17 );
  ulong        start_slot         = fd_env_strip_cmdline_ulong( &argc, &argv, "--startslot",        NULL, 0UL       );
  ulong        end_slot           = fd_env_strip_cmdline_ulong( &argc, &argv, "--endslot",          NULL, ULONG_MAX );
  char const * verifyhash         = fd_env_strip_cmdline_cstr ( &argc, &argv, "--verifyhash",       NULL, NULL      );
  char const * verifyacchash      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--verifyacchash",    NULL, NULL      );
  char const * backup             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--backup",           NULL, NULL      );
  char const * capture_fpath      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--capture",          NULL, NULL      );
  char const * checkacchash       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--checkacchash",     NULL, NULL      );
  char const * shredcap           = fd_env_strip_cmdline_cstr ( &argc, &argv, "--shredcap",         NULL, NULL      );
  ulong        trashhash          = fd_env_strip_cmdline_ulong( &argc, &argv, "--trashhash",        NULL, ULONG_MAX );
  char const * mini_db_dir        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--minidb",           NULL, "false"   );
  char const * copy_txnstatus     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--copytxnstatus",    NULL, "true"    );
  ulong        index_max_unpruned = fd_env_strip_cmdline_ulong( &argc, &argv, "--indexmaxunpruned", NULL, 450000000 );
  ulong        pages_pruned       = fd_env_strip_cmdline_ulong( &argc, &argv, "--pagespruned",      NULL, ULONG_MAX );
  ulong        vote_acct_max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--voteaccs",         NULL,   2000000 );

#ifdef _ENABLE_LTHASH
  char const * lthash             = fd_env_strip_cmdline_cstr ( &argc, &argv, "--lthash",           NULL, "false"   );
#endif

  int is_pruned = cmd != NULL && strcmp(cmd, "prune") == 0;
  if ( is_pruned && (pages_pruned == ULONG_MAX || index_max_unpruned == ULONG_MAX) ) {
    FD_LOG_ERR(( "pruning requires --pagespruned and --indexmaxunpruned" ));
  }

  /* Setup wksp(s) */
  fd_wksp_t* wksp;
  if (wkspname == NULL) {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace" ));
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, pages, 0, "wksp", 0UL );
  } else {
    fd_shmem_info_t shmem_info[1];
    if ( FD_UNLIKELY( fd_shmem_info( wkspname, 0UL, shmem_info ) ) )
      FD_LOG_ERR(( "unable to query region \"%s\"\n\tprobably does not exist or bad permissions", wkspname ));
    wksp = fd_wksp_attach(wkspname);
  }
  if (wksp == NULL)
    FD_LOG_ERR(( "failed to attach to workspace %s", wkspname ));

  /* Setup pruned wksp */
  fd_wksp_t * pruned_wksp = NULL;
  if ( is_pruned ) {
    pruned_wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, pages_pruned, 0, "prunedwksp", 0UL );
    if ( pruned_wksp == NULL ) {
      FD_LOG_ERR(( "failed to create and attach to a pruned_wksp" ));
    }
  }

  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  if( strcmp(reset, "true") == 0 ) {
    fd_wksp_reset( wksp, (uint)hashseed);
  }

  /* Create scratch region */
  ulong  smax   = 1024UL /*MiB*/ << 21;
  ulong  sdepth = 128;      /* 128 scratch frames */
  void * smem   = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax   ), 421UL );
  void * fmem   = fd_wksp_alloc_laddr( wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ), 421UL );
  FD_TEST( (!!smem) & (!!fmem) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  fd_funk_t* funk;

  if( FD_UNLIKELY( !cmd ) ) FD_LOG_ERR(( "no command specified" ));

  /* Setup Funk(s). If we are pruning, setup funk on the pruned_wksp*/
  fd_wksp_t * funk_wksp = is_pruned ? pruned_wksp : wksp;

  void* shmem;
  fd_wksp_tag_query_info_t info;
  ulong tag = FD_FUNK_MAGIC;
  if (fd_wksp_tag_query(funk_wksp, &tag, 1, &info, 1) > 0) {
    shmem = fd_wksp_laddr_fast( funk_wksp, info.gaddr_lo );
    funk = fd_funk_join(shmem);
    if (funk == NULL)
      FD_LOG_ERR(( "failed to join a funky" ));
    if (strcmp(verifyfunky, "true") == 0)
      if (fd_funk_verify(funk))
        FD_LOG_ERR(( "verification failed" ));
  } else {
    shmem = fd_wksp_alloc_laddr( funk_wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
    if (shmem == NULL)
      FD_LOG_ERR(( "failed to allocate a funky" ));
    funk = fd_funk_join(fd_funk_new(shmem, 1, hashseed, xactions_max, index_max));

    if (funk == NULL) {
      fd_wksp_free_laddr(shmem);
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }
  }
  FD_LOG_NOTICE(( "funky at global address 0x%016lx", fd_wksp_gaddr_fast( funk_wksp, shmem ) ));

  /* Setup blockstore */
  fd_blockstore_t * blockstore;

  tag = FD_BLOCKSTORE_MAGIC;
  if (fd_wksp_tag_query(wksp, &tag, 1, &info, 1) > 0) {
    shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
    blockstore = fd_blockstore_join(shmem);
    if (blockstore == NULL)
      FD_LOG_ERR(( "failed to join a blockstore" ));
  } else {
    shmem = fd_wksp_alloc_laddr( wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
    if (shmem == NULL)
      FD_LOG_ERR(( "failed to allocate a blockstore" ));

    int   lg_txn_max    = 22;

    blockstore = fd_blockstore_join(fd_blockstore_new(shmem, 1, hashseed, shred_max, slot_history_max, lg_txn_max));
    if (blockstore == NULL) {
      fd_wksp_free_laddr(shmem);
      FD_LOG_ERR(( "failed to allocate a blockstore" ));
    }
  }

  FD_LOG_NOTICE(( "blockstore at global address 0x%016lx", fd_wksp_gaddr_fast( wksp, shmem ) ));

  /* Create a duplicate blockstore for pruning in the pruned wksp. Otherwise ignore. */
  fd_blockstore_t * pruned_blockstore = NULL;
  if ( is_pruned ) {
    shmem = fd_wksp_alloc_laddr( pruned_wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
    if ( shmem == NULL ) {
      FD_LOG_ERR(( "failed to allocate a blockstore" ));
    }
    int lg_txn_max = 22;
    pruned_blockstore = fd_blockstore_join( fd_blockstore_new( shmem, 1, hashseed, shred_max,
                                                               slot_history_max, lg_txn_max ) );
    if ( pruned_blockstore == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR(( "failed to allocate a blockstore" ));
    }
    FD_LOG_NOTICE(( "pruned blockstore at global address 0x%016lx", fd_wksp_gaddr_fast( pruned_wksp, shmem ) ));
  }

  fd_alloc_t * alloc = fd_alloc_join( fd_wksp_laddr_fast( funk_wksp, funk->alloc_gaddr ), 0UL );
  if( FD_UNLIKELY( !alloc ) ) FD_LOG_ERR(( "fd_alloc_join(gaddr=%#lx) failed", funk->alloc_gaddr ));

  uchar * epoch_ctx_mem = fd_wksp_alloc_laddr( wksp, fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( vote_acct_max ), FD_EXEC_EPOCH_CTX_MAGIC );
  fd_exec_epoch_ctx_t * epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, vote_acct_max ) );

  uchar slot_ctx_mem[FD_EXEC_SLOT_CTX_FOOTPRINT] __attribute__((aligned(FD_EXEC_SLOT_CTX_ALIGN)));
  fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem, fd_alloc_virtual( alloc ) ) );
  slot_ctx->epoch_ctx = epoch_ctx;

  fd_acc_mgr_t mgr[1];
  slot_ctx->acc_mgr = fd_acc_mgr_new( mgr, funk );

  slot_ctx->blockstore = is_pruned ? pruned_blockstore : blockstore;

  fd_tpool_t * tpool = NULL;

  if (cmd == NULL) {
    // Do nothing

  } else if ( strcmp(cmd, "prune") == 0 ) {
    /* build/native/clang/bin/fd_frank_ledger --cmd prune --indexmax <index max for pruned funk>
       --indexmaxunpruned <index max for unpruned funk> --pages <PAGES> --rocksdb <ROCKSDB>
       --snapshotfile <SNAPSHOT> --backup <BACKUP> --endslot <END_SLOT>
       --pagespruned <num pages in checkpt> */

    if ( pruned_blockstore == NULL ) { /* Should never happen */
      FD_LOG_ERR(( "pruned blockstore not initialized" ));
    } else if ( snapshotfile == NULL ) {
      FD_LOG_ERR(("missing snapshot file"));
    } else if ( rocksdb_dir == NULL ) {
      FD_LOG_ERR(("missing rocksdb directory"));
    }

    /* Setup a temporary funk with all accounts. This will be deleted and not checkpointed. */
    fd_funk_t * unpruned_funk;
    shmem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC ); // TODO: maybe delete this
    if ( shmem == NULL ) {
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }
    unpruned_funk = fd_funk_join( fd_funk_new( shmem, FD_FUNK_MAGIC, hashseed,
                                               xactions_max, index_max_unpruned ) );
    if ( unpruned_funk == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }
    FD_LOG_NOTICE(( "unpruned funky at global address 0x%016lx", fd_wksp_gaddr_fast( wksp, shmem ) ));

    /* Set up slot and epoch contexts used for execution (unpruned). */
    fd_alloc_t * alloc_unpruned = fd_alloc_join( fd_wksp_laddr_fast( wksp, unpruned_funk->alloc_gaddr ), 0UL );
    if( FD_UNLIKELY( !alloc_unpruned ) ) {
      FD_LOG_ERR(( "fd_alloc_join(gaddr=%#lx) failed", unpruned_funk->alloc_gaddr ));
    }

    uchar * epoch_ctx_mem_unpruned = fd_wksp_alloc_laddr( wksp, fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( vote_acct_max ), FD_EXEC_EPOCH_CTX_MAGIC );
    fd_exec_epoch_ctx_t * epoch_ctx_unpruned = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem_unpruned, vote_acct_max ) );

    uchar slot_ctx_mem_unpruned[FD_EXEC_SLOT_CTX_FOOTPRINT] __attribute__((aligned(FD_EXEC_SLOT_CTX_ALIGN)));
    fd_exec_slot_ctx_t * slot_ctx_unpruned = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem_unpruned, fd_alloc_virtual( alloc_unpruned ) ) );
    slot_ctx_unpruned->epoch_ctx = epoch_ctx_unpruned;

    slot_ctx_unpruned->valloc = fd_alloc_virtual( alloc_unpruned );

    fd_acc_mgr_t mgr_unpruned[1];
    slot_ctx_unpruned->acc_mgr = fd_acc_mgr_new( mgr_unpruned, unpruned_funk );
    slot_ctx_unpruned->blockstore = blockstore;

    fd_funk_leave( funk );

    /* Load in snapshot and rocksdb */
    fd_snapshot_load( snapshotfile, slot_ctx_unpruned, verifyacchash != NULL,
                      checkacchash != NULL, FD_SNAPSHOT_TYPE_FULL );
    FD_LOG_NOTICE(("imported %lu records from snapshot",
                   fd_funk_rec_cnt( fd_funk_rec_map ( unpruned_funk, wksp ))));

    if( incremental ) {
      fd_snapshot_load( incremental, slot_ctx_unpruned, (verifyacchash != NULL), (checkacchash != NULL), FD_SNAPSHOT_TYPE_INCREMENTAL );
      FD_LOG_NOTICE(("imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map ( unpruned_funk, wksp ))));
    }

    if ( end_slot >= slot_ctx_unpruned->slot_bank.slot + slot_history_max ) {
      end_slot = slot_ctx->slot_bank.slot + slot_history_max - 1;
    }

    ingest_rocksdb( slot_ctx_unpruned, rocksdb_dir, end_slot, blockstore, 0, trashhash );
    FD_LOG_NOTICE(("imported unpruned rocksdb"));

    slot_ctx->slot_bank.slot = slot_ctx_unpruned->slot_bank.slot;
    ingest_rocksdb( slot_ctx, rocksdb_dir, end_slot, pruned_blockstore,
                    strcmp( txnstatus, "true" ) == 0, trashhash );
    FD_LOG_NOTICE(("imported pruned rocksdb"));

    fd_scratch_detach( NULL );

    /* Replay to get all accounts that are touched (r/w) during execution */
    fd_runtime_args_t args;
    fd_memset( &args, 0, sizeof(args) );
    args.end_slot = end_slot;
    args.pruned_funk = funk;
    args.cmd = "replay";
    args.allocator = "wksp";

    fd_runtime_ctx_t state;
    fd_memset( &state, 0, sizeof(state) );

    fd_tvu_gossip_deliver_arg_t gossip_deliver_arg[1];
    fd_replay_t * replay = NULL;
    fd_tvu_main_setup( &state, &replay, NULL, NULL, 0, wksp, &args, gossip_deliver_arg );

    args.tcnt = fd_tile_cnt();
    uchar * tpool_scr_mem = NULL;
    if( args.tcnt > 1 ) {
      tpool = fd_tpool_init( state.tpool_mem, args.tcnt );
      if( tpool == NULL ) {
        FD_LOG_ERR(( "failed to create thread pool" ));
      }
      ulong scratch_sz = fd_scratch_smem_footprint( 256UL<<20UL );
      tpool_scr_mem = fd_valloc_malloc( replay->valloc, FD_SCRATCH_SMEM_ALIGN, scratch_sz*(args.tcnt - 1U) );
      if( tpool_scr_mem == NULL ) {
        FD_LOG_ERR( ( "failed to allocate thread pool scratch space" ) );
      }
      for( ulong i = 1; i < args.tcnt; ++i ) {
        if( fd_tpool_worker_push( tpool, i, tpool_scr_mem + scratch_sz*(i - 1U), scratch_sz ) == NULL ) {
          FD_LOG_ERR(( "failed to launch worker" ));
        }
        else {
          FD_LOG_NOTICE(( "launched worker" ));
        }
      }
    }
    state.tpool       = tpool;
    state.max_workers = args.tcnt;

    /* Junk xid for pruning transaction */ // TODO: factor out the xid nicelY
    fd_funk_txn_xid_t prune_xid;
    fd_memset( &prune_xid, 0x42, sizeof(fd_funk_txn_xid_t));
    fd_funk_txn_t * prune_txn = fd_funk_txn_prepare( funk, NULL, &prune_xid, 1 );
    FD_TEST(( !!prune_txn ));

    int err = fd_runtime_replay( &state, &args );
    if( err != 0 ) {
      fd_tvu_main_teardown( &state, NULL );
      return err;
    }

    /* Reset the wksp and load in funk again. */
    /* TODO: A better implementation of this would be to just rollback the
       funk transactions. This can be done by publishing all funk transactions
       into a parent and then cancelling the parent after execution is complete. */

    fd_wksp_reset( wksp, (uint)hashseed );

    shmem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
    if ( shmem == NULL ) {
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }
    unpruned_funk = fd_funk_join( fd_funk_new( shmem, FD_FUNK_MAGIC, hashseed,
                                               xactions_max, index_max_unpruned ) );
    fd_scratch_detach( NULL );
    smem = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax   ), 421UL );
    fmem = fd_wksp_alloc_laddr( wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ), 421UL );
    FD_TEST( (!!smem) & (!!fmem) );
    fd_scratch_attach( smem, fmem, smax, sdepth );

    alloc_unpruned = fd_alloc_join( fd_wksp_laddr_fast( wksp, unpruned_funk->alloc_gaddr ), 0UL );
    if( FD_UNLIKELY( !alloc_unpruned ) ) {
      FD_LOG_ERR(( "fd_alloc_join(gaddr=%#lx) failed", unpruned_funk->alloc_gaddr ));
    }
    epoch_ctx_unpruned = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem_unpruned, vote_acct_max ) );
    slot_ctx_unpruned = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem_unpruned, fd_alloc_virtual( alloc_unpruned ) ) );
    slot_ctx_unpruned->epoch_ctx = epoch_ctx_unpruned;

    slot_ctx_unpruned->valloc = fd_alloc_virtual( alloc_unpruned );

    fd_acc_mgr_t mgr_unpruned_new[1];
    slot_ctx_unpruned->acc_mgr = fd_acc_mgr_new( mgr_unpruned_new, unpruned_funk );
    fd_snapshot_load( snapshotfile, slot_ctx_unpruned, verifyacchash != NULL,
                      checkacchash != NULL, FD_SNAPSHOT_TYPE_FULL );

    if( incremental ) {
      fd_snapshot_load( incremental, slot_ctx_unpruned, (verifyacchash != NULL), (checkacchash != NULL), FD_SNAPSHOT_TYPE_INCREMENTAL );
    }

    FD_LOG_NOTICE(("imported %lu records from snapshot",
                   fd_funk_rec_cnt( fd_funk_rec_map ( unpruned_funk, wksp ))));

    /* After replaying, update all touched accounts to contain the data that is
       present before execution begins. Look up the corresponding account in the
       unpruned funk and copy over the contents */
    fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, pruned_wksp );
    for ( const fd_funk_rec_t * rec = fd_funk_txn_rec_head( prune_txn, rec_map );
          rec; rec = fd_funk_txn_next_rec( funk, rec ) ) {

      const fd_funk_rec_t * original_rec = fd_funk_rec_query_global( unpruned_funk, NULL, rec->pair.key );
      if ( original_rec != NULL ) {
        fd_funk_rec_t * mod_rec = fd_funk_rec_modify( funk, rec );
        mod_rec = fd_funk_val_copy( mod_rec, fd_funk_val_const( original_rec, wksp ),
                                    fd_funk_val_sz( original_rec ),fd_funk_val_sz( original_rec ),
                                    fd_funk_alloc( funk, pruned_wksp ), pruned_wksp, NULL );
        FD_TEST(( memcmp( fd_funk_val( original_rec, wksp ), fd_funk_val_const( rec, pruned_wksp ),
                          fd_funk_val_sz( original_rec ) ) == 0 ));
      } else {
        fd_funk_rec_t * mod_rec = fd_funk_rec_modify( funk, rec );
        int res = fd_funk_rec_remove( funk, mod_rec, 1 );
        FD_TEST(( res == 0 ));
      }
    }
    FD_LOG_NOTICE(("Copied over all records from transactions"));

    /* Repeat above steps with all features */
    for ( fd_feature_id_t const * id = fd_feature_iter_init();
          !fd_feature_iter_done( id ); id = fd_feature_iter_next( id ) ) {

      fd_pubkey_t const *   pubkey      = (fd_pubkey_t *) id->id.key;
      fd_funk_rec_key_t     feature_id  = fd_acc_funk_key( pubkey );
      fd_funk_rec_t const * feature_rec = fd_funk_rec_query_global( unpruned_funk, NULL, &feature_id );
      if ( !feature_rec ) {
        FD_LOG_DEBUG(("Feature is not present; pubkey=%32J", &feature_id));
        continue;
      }
      fd_funk_rec_t * new_feature_rec = fd_funk_rec_write_prepare( funk, prune_txn, &feature_id,
                                                                   0, 1, NULL, NULL );
      FD_TEST(( !!new_feature_rec ));
      new_feature_rec = fd_funk_val_copy( new_feature_rec, fd_funk_val_const( feature_rec, wksp ),
                                          fd_funk_val_sz( feature_rec ), fd_funk_val_sz( feature_rec ),
                                          fd_funk_alloc( funk, pruned_wksp ), pruned_wksp, NULL );
      FD_TEST(( !!new_feature_rec ));
    }
    FD_LOG_NOTICE(("Copied over all features"));

    /* Do the same with the epoch/slot bank keys and sysvars */
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
    for ( uint i = 0; i < sizeof( records ) / sizeof( fd_funk_rec_key_t ); ++i ) {
      fd_funk_rec_t const * original_rec = fd_funk_rec_query_global( unpruned_funk, NULL, &records[i] );
      if ( !original_rec ) {
        /* Some sysvars aren't touched during execution. Not a problem. */
        FD_LOG_DEBUG(("Record is not in account pubkey=%32J", &records[i]));
        continue;
      }
      fd_funk_rec_t * new_rec = fd_funk_rec_write_prepare( funk, prune_txn, &records[i], 0, 1, NULL, NULL );
      FD_TEST(( !!new_rec ));
      new_rec = fd_funk_val_copy( new_rec, fd_funk_val_const( original_rec, wksp ),
                                  fd_funk_val_sz( original_rec ), fd_funk_val_sz( original_rec ),
                                  fd_funk_alloc( funk, pruned_wksp ), pruned_wksp, NULL );
      FD_TEST(( !!new_rec ));
    }
    FD_LOG_NOTICE(("Copied over all sysvars and bank keys"));

    /* Publish transaction with pruned records to the root of funk */
    if ( fd_funk_txn_publish( funk, prune_txn, 1 ) == 0 ) {
      FD_LOG_ERR(("failed to publish transaction into pruned funk"));
    }

    /* Verify that the pruned records are in the funk */
    FD_LOG_NOTICE(("Pruned funk record count is %lu", fd_funk_rec_global_cnt( funk, pruned_wksp )));

    fd_scratch_detach( NULL );
    fd_funk_leave( unpruned_funk );

    if ( fd_funk_verify( funk ) ) {
      FD_LOG_ERR(( "pruned funk verification failed" ));
    }

    if ( tpool ) {
      fd_tpool_fini( tpool );
    }

    fd_wksp_free_laddr( smem );
    fd_wksp_free_laddr( fmem );
    fd_wksp_free_laddr( epoch_ctx_mem_unpruned );

    if ( backup ) {
      FD_LOG_NOTICE(( "writing %s", backup ));
      unlink( backup );
      int err = fd_wksp_checkpt( pruned_wksp, backup, 0666, 0, NULL );
      if ( err ) {
        FD_LOG_ERR(( "backup failed: error %d", err ));
      }
    }
    return 0;

  } else if (strcmp(cmd, "minify") == 0) {
    /* Example commmand:
     fd_frank_ledger --cmd minify --rocksdb <LARGE_ROCKSDB> --minidb <MINI_ROCKSDB>
                     --startslot <START_SLOT> --end_slot <END_SLOT> --copytxnstatus true
    */

    fd_rocksdb_t big_rocksdb;
    char *err = fd_rocksdb_init( &big_rocksdb, rocksdb_dir );
    if ( err != NULL ) {
      FD_LOG_ERR(("fd_rocksdb_init at path=%s returned error=%s", rocksdb_dir, err));
    }

    /* If the directory for the minified rocksdb already exists, error out */
    struct stat statbuf;
    if ( stat( mini_db_dir, &statbuf ) == 0 ) {
      FD_LOG_ERR(("path for mini_db_dir=%s already exists", mini_db_dir));
    }

    /* Create a new smaller rocksdb */
    fd_rocksdb_t mini_rocksdb;
    fd_rocksdb_new( &mini_rocksdb, mini_db_dir );

    /* Correctly bound off start and end slot */
    ulong first_slot = fd_rocksdb_first_slot(&big_rocksdb, &err);
    ulong last_slot  = fd_rocksdb_last_slot(&big_rocksdb, &err);
    if ( start_slot < first_slot ) start_slot = first_slot;
    if ( end_slot > last_slot )    end_slot = last_slot;

    FD_LOG_NOTICE(("copying over rocks db for range [%lu, %lu]", start_slot, end_slot));

    /* Copy over all slot indexed columns */
    for ( ulong cf_idx = 1; cf_idx < FD_ROCKSDB_CF_CNT; ++cf_idx ) {
      fd_rocksdb_copy_over_slot_indexed_range( &big_rocksdb, &mini_rocksdb, cf_idx,
                                               start_slot, end_slot );
    }
    FD_LOG_NOTICE(("copied over all slot indexed columns"));

    /* Copy over transactions. This is more complicated because first, a temporary
       blockstore will be populated. This will be used to look up transactions
       which can be quickly queried */

    if ( strcmp( copy_txnstatus, "true" ) == 0 ) {
      /* Ingest block range into blockstore */
      slot_ctx->slot_bank.slot = start_slot;
      ingest_rocksdb( slot_ctx, rocksdb_dir, end_slot, blockstore, 0, ULONG_MAX );

      fd_rocksdb_copy_over_txn_status_range( &big_rocksdb, &mini_rocksdb, blockstore,
                                             start_slot, end_slot );
      FD_LOG_NOTICE(("copied over all transaction statuses"));
    }
    else {
      FD_LOG_NOTICE(("skipping copying of transaction statuses"));
    }

    /* TODO: Currently, the address signatures column family isn't copied as it
             is indexed on the pubkey */

    return 0;

  } else if (strcmp(cmd, "ingest") == 0) {

    if( snapshotfile ) {
      fd_snapshot_load( snapshotfile, slot_ctx, (verifyacchash != NULL), (checkacchash != NULL), FD_SNAPSHOT_TYPE_FULL );
      FD_LOG_NOTICE(("imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map ( funk, wksp ))));
    }
    if( incremental ) {
      fd_snapshot_load( incremental,  slot_ctx, (verifyacchash != NULL), (checkacchash != NULL), FD_SNAPSHOT_TYPE_INCREMENTAL );
      FD_LOG_NOTICE(("imported %lu records from snapshot", fd_funk_rec_cnt( fd_funk_rec_map ( funk, wksp ))));
    }

    if( genesis ) {

      FILE *               capture_file = NULL;
      fd_capture_ctx_t *   capture_ctx  = NULL;
      if( capture_fpath ) {
        capture_file = fopen( capture_fpath, "w+" );
        if( FD_UNLIKELY( !capture_file ) )
          FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", capture_fpath, errno, strerror( errno ) ));

        void * capture_ctx_mem = fd_alloc_malloc( alloc, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
        FD_TEST( capture_ctx_mem );
        capture_ctx = fd_capture_ctx_new( capture_ctx_mem );

        // FD_TEST( fd_solcap_writer_init( capture_ctx->capture, capture_file ) );
      }

      // fd_solcap_writer_set_slot( capture_ctx->capture, 0UL );

      struct stat sbuf;
      if( FD_UNLIKELY( stat( genesis, &sbuf) < 0 ) )
        FD_LOG_ERR(("cannot open %s : %s", genesis, strerror(errno)));
      int fd = open( genesis, O_RDONLY );
      if( FD_UNLIKELY( fd < 0 ) )
        FD_LOG_ERR(("cannot open %s : %s", genesis, strerror(errno)));
      uchar * buf = malloc((ulong) sbuf.st_size);  /* TODO Make this a scratch alloc */
      ssize_t n = read(fd, buf, (ulong) sbuf.st_size);
      close(fd);

      fd_genesis_solana_t genesis_block;
      fd_genesis_solana_new(&genesis_block);
      fd_bincode_decode_ctx_t ctx = {
        .data = buf,
        .dataend = buf + n,
        .valloc  = slot_ctx->valloc
      };
      if( fd_genesis_solana_decode(&genesis_block, &ctx) )
        FD_LOG_ERR(("fd_genesis_solana_decode failed"));

      // The hash is generated from the raw data... don't mess with this..
      fd_hash_t genesis_hash;
      fd_sha256_hash( buf, (ulong)n, genesis_hash.uc );
      FD_LOG_NOTICE(( "Genesis Hash: %32J", &genesis_hash ));
      fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
      fd_memcpy( epoch_bank->genesis_hash.uc, genesis_hash.uc, 32U );
      epoch_bank->cluster_type = genesis_block.cluster_type;

      free(buf);

      fd_funk_start_write( funk );

      /* If we are loading from a snapshot, do not overwrite from genesis */
      if ( !snapshotfile ) {
        fd_runtime_init_bank_from_genesis( slot_ctx, &genesis_block, &genesis_hash );

        fd_runtime_init_program( slot_ctx );

        FD_LOG_DEBUG(( "start genesis accounts - count: %lu", genesis_block.accounts_len));

        for( ulong i=0; i < genesis_block.accounts_len; i++ ) {
          fd_pubkey_account_pair_t * a = &genesis_block.accounts[i];

          FD_BORROWED_ACCOUNT_DECL(rec);

          int err = fd_acc_mgr_modify(
            slot_ctx->acc_mgr,
            slot_ctx->funk_txn,
            &a->key,
            /* do_create */ 1,
            a->account.data_len,
            rec);
          if( FD_UNLIKELY( err ) )
            FD_LOG_ERR(( "fd_acc_mgr_modify failed (%d)", err ));

          rec->meta->dlen            = a->account.data_len;
          rec->meta->info.lamports   = a->account.lamports;
          rec->meta->info.rent_epoch = a->account.rent_epoch;
          rec->meta->info.executable = !!a->account.executable;
          memcpy( rec->meta->info.owner, a->account.owner.key, 32UL );
          if( a->account.data_len )
            memcpy( rec->data, a->account.data, a->account.data_len );
        }

        FD_LOG_DEBUG(( "end genesis accounts"));

        FD_LOG_DEBUG(( "native instruction processors - count: %lu", genesis_block.native_instruction_processors_len));

        for( ulong i=0; i < genesis_block.native_instruction_processors_len; i++ ) {
          fd_string_pubkey_pair_t * a = &genesis_block.native_instruction_processors[i];
          fd_write_builtin_bogus_account( slot_ctx, a->pubkey.uc, a->string, strlen(a->string) );
        }

        /* sort and update bank hash */
        int result = fd_update_hash_bank( slot_ctx, capture_ctx, &slot_ctx->slot_bank.banks_hash, slot_ctx->signature_cnt );
        if (result != FD_EXECUTOR_INSTR_SUCCESS) {
          return result;
        }

        slot_ctx->slot_bank.slot = 0UL;
      }

      FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS == fd_runtime_save_epoch_bank( slot_ctx ) );

      FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS == fd_runtime_save_slot_bank( slot_ctx ) );

      fd_funk_end_write( funk );

      fd_bincode_destroy_ctx_t ctx2 = { .valloc = slot_ctx->valloc };
      fd_genesis_solana_destroy(&genesis_block, &ctx2);

      if( capture_ctx )  {
        fd_solcap_writer_flush( capture_ctx->capture );
        fclose( capture_file );
      }
    }

    /* Give preference to shredcap over rocksdb if both are passed in */
    if ( shredcap ) {
      FD_LOG_NOTICE(("using shredcap"));
      fd_shredcap_populate_blockstore( shredcap, blockstore, slot_ctx->slot_bank.slot, end_slot );
    }
    else if( rocksdb_dir ) {
      if ( end_slot >= slot_ctx->slot_bank.slot + slot_history_max )
        end_slot = slot_ctx->slot_bank.slot + slot_history_max - 1;
      ingest_rocksdb( slot_ctx, rocksdb_dir, end_slot, blockstore, (strcmp( txnstatus, "true" ) == 0), trashhash );
    }

    /* Dump feature activation state */

    for( fd_feature_id_t const * id = fd_feature_iter_init();
                                     !fd_feature_iter_done( id );
                                 id = fd_feature_iter_next( id ) ) {
      ulong activated_at = fd_features_get( &slot_ctx->epoch_ctx->features, id );
      if( activated_at )
        FD_LOG_DEBUG(( "feature %32J activated at slot %lu", id->id.key, activated_at ));
    }
  }

  if (strcmp(verifyfunky, "true") == 0) {
    FD_LOG_NOTICE(("verifying funky"));
    if (fd_funk_verify(funk))
      FD_LOG_ERR(( "verification failed" ));
  }

#ifdef _ENABLE_LTHASH
    if ((NULL != lthash) && (strcmp(lthash, "true") == 0)) {
      fd_accounts_init_lthash(slot_ctx);
      fd_accounts_check_lthash(slot_ctx);
    }
#endif

  if (verifyhash) {
    fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );
    ulong num_iter_accounts = fd_funk_rec_map_key_cnt( rec_map );

    FD_LOG_NOTICE(( "verifying hash for %lu accounts", num_iter_accounts ));

    ulong zero_accounts = 0;
    ulong num_pairs = 0;
    fd_pubkey_hash_pair_t * pairs = (fd_pubkey_hash_pair_t *) malloc(num_iter_accounts*sizeof(fd_pubkey_hash_pair_t));
    for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
         !fd_funk_rec_map_iter_done( rec_map, iter );
         iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
      fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );
      if ( !fd_funk_key_is_acc( rec->pair.key ) )
        continue;

      if (num_pairs % 10000000 == 0) {
        FD_LOG_NOTICE(( "read %lu so far", num_pairs ));
      }

      fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( rec, wksp );
      if ((metadata->magic != FD_ACCOUNT_META_MAGIC) || (metadata->hlen != sizeof(fd_account_meta_t))) {
        FD_LOG_ERR(("invalid magic on metadata"));
      }

      if ((metadata->info.lamports == 0) | ((metadata->info.executable & ~1) != 0)) {
        zero_accounts++;
        continue;
      }

      fd_hash_t acc_hash;
      if( fd_hash_account_v0(acc_hash.uc, metadata, rec->pair.key->uc, fd_account_get_data(metadata), metadata->slot)==NULL )
        FD_LOG_ERR(("error processing account hash"));

      if( memcmp(acc_hash.uc, metadata->hash, 32) != 0 ) {
        FD_LOG_ERR(("account hash mismatch - num_pairs: %lu, slot: %lu, acc: %32J, acc_hash: %32J, snap_hash: %32J", num_pairs, slot_ctx->slot_bank.slot, rec->pair.key->uc, acc_hash.uc, metadata->hash));
      }

      pairs[num_pairs].pubkey = (const fd_pubkey_t *)rec->pair.key->uc;
      pairs[num_pairs].hash = (const fd_hash_t *)metadata->hash;
      num_pairs++;
    }
    FD_LOG_NOTICE(("num_iter_accounts: %ld  zero_accounts: %lu", num_iter_accounts, zero_accounts));

    fd_hash_t accounts_hash;
    fd_hash_account_deltas(pairs, num_pairs, &accounts_hash, slot_ctx);

    free(pairs);

    char accounts_hash_58[FD_BASE58_ENCODED_32_SZ];
    fd_base58_encode_32((uchar const *)accounts_hash.hash, NULL, accounts_hash_58);

    FD_LOG_NOTICE(("hash result %s", accounts_hash_58));
    if (strcmp(verifyhash, accounts_hash_58) == 0)
      FD_LOG_NOTICE(("hash verified!"));
    else
      FD_LOG_ERR(("hash does not match!"));
  }

  if ( tpool )
    fd_tpool_fini( tpool );

  fd_funk_log_mem_usage( funk );
  fd_blockstore_log_mem_usage( blockstore );

  fd_alloc_leave( alloc );

  fd_scratch_detach( NULL );
  fd_wksp_free_laddr( smem );
  fd_wksp_free_laddr( fmem );
  fd_wksp_free_laddr( epoch_ctx_mem );

  if (backup) {
    /* Copy the entire workspace into a file in the most naive way */
    fd_funk_start_write( funk );
    FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS == fd_runtime_save_epoch_bank( slot_ctx ) );
    FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS == fd_runtime_save_slot_bank( slot_ctx ) );
    fd_funk_end_write( funk );
    FD_LOG_NOTICE(("writing %s", backup));
    unlink(backup);
    int err = fd_wksp_checkpt(wksp, backup, 0666, 0, NULL);
    if (err)
      FD_LOG_ERR(("backup failed: error %d", err));
  }

  fd_alloc_delete( fd_alloc_leave( alloc ) );
  fd_funk_leave( funk );
  fd_blockstore_leave( blockstore );

  fd_log_flush();
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
