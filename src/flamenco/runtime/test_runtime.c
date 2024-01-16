/****

build/native/gcc/bin/fd_frank_ledger --rocksdb $LEDGER/rocksdb --genesis $LEDGER/genesis.bin --cmd ingest --indexmax 10000 --txnmax 100 --backup test_ledger_backup

build/native/gcc/unit-test/test_runtime --load test_ledger_backup --cmd replay --end-slot 25 --confirm_hash AsHedZaZkabNtB8XBiKWQkKwaeLy2y4Hrqm6MkQALT5h --confirm_parent CvgPeR54qpVRZGBuiQztGXecxSXREPfTF8wALujK4WdE --confirm_account_delta 7PL6JZgcNy5vkPSc6JsMHET9dvpvsFMWR734VtCG29xN  --confirm_signature 2  --confirm_last_block G4YL2SieHDGNZGjiwBsJESK7jMDfazg33ievuCwbkjrv --validate true

build/native/gcc/bin/fd_shmem_cfg reset

build/native/gcc/bin/fd_wksp_ctl new giant_wksp 200 gigantic 32-63 0666

build/native/gcc/bin/fd_frank_ledger --wksp giant_wksp --reset true --cmd ingest --snapshotfile /home/jsiegel/mainnet-ledger/snapshot-179244883-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --incremental /home/jsiegel/mainnet-ledger/incremental-snapshot-179244883-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst --rocksdb /home/jsiegel/mainnet-ledger/rocksdb --endslot 179249378 --backup /home/asiegel/mainnet_backup

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --reset true --load /home/asiegel/mainnet_backup --cmd replay --index-max 350000000

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --gaddr 0xc7ce180 --cmd replay
  NOTE: gaddr argument may be different

build/native/gcc/bin/fd_frank_ledger --wksp giant_wksp --reset true --cmd ingest --snapshotfile /data/jsiegel/mainnet-ledger/snapshot-179244883-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --incremental /data/jsiegel/mainnet-ledger/incremental-snapshot-179244883-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst --rocksdb /data/jsiegel/mainnet-ledger/rocksdb --endslot 179248378 --backup /data/jsiegel/mainnet_backup

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --gaddr 0x000000000c7ce180 --cmd replay

/data/jsiegel/mainnet-ledger/snapshot-179244883-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst
/data/jsiegel/mainnet-ledger/incremental-snapshot-179244883-179248368-6TprbHABozQQLjjc1HBeQ2p4AigMC7rhHJS2Q5WLcbyw.tar.zst

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --gaddr 0xc7ce180 --cmd verifyonly

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --gaddr 0xc7ce180 --cmd verifyonly --tile-cpus 32-100

build/native/gcc/bin/fd_frank_ledger --wksp giant_wksp --reset true --cmd ingest --snapshotfile /data/jsiegel/mainnet-ledger/snapshot-179244882-2DyMb1qN8JuTijCjsW8w4G2tg1hWuAw2AopH7Bj9Qstu.tar.zst --rocksdb /data/jsiegel/mainnet-ledger/rocksdb --endslot 179244982 --backup /data/asiegel/mainnet_backup

build/native/gcc/unit-test/test_runtime --wksp giant_wksp --cmd replay --load /data/asiegel/mainnet_backup

****/

#include "../fd_flamenco.h"
#include <errno.h>
#include "fd_runtime.h"
#include "fd_replay.h"
#include "context/fd_capture_ctx.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  fd_runtime_args_t args;
  FD_TEST(fd_tvu_parse_args( &args, argc, argv ) == 0);

  fd_runtime_ctx_t state;
  fd_memset(&state, 0, sizeof(state));

  fd_tvu_main_setup( &state, 0, NULL, &args);

  // TODO: tracing, captures, and capitalization is broken
#if 0
  state.map = capitalization_map_join(capitalization_map_new(state.capitalization_map_mem));

  if (NULL != state.capitalization_file) {
    FILE *fp = fopen(state.capitalization_file, "r");
    if (NULL == fp) {
      perror(state.capitalization_file);
      return -1;
    }
    ulong slot = 0;
    ulong cap = 0;
    while (fscanf(fp, "%ld,%ld", &slot, &cap) == 2) {
      slot_capitalization_t *c = capitalization_map_insert(state.map, slot);
      c->capitalization = cap;
    }
    fclose(fp);
  }

  if( capture_fpath ) {
    state.capture_file = fopen( capture_fpath, "w+" );
    if( FD_UNLIKELY( !state.capture_file ) )
      FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", capture_fpath, errno, fd_io_strerror( errno ) ));


    // FD_TEST( fd_solcap_writer_init( state.capture_ctx->capture, state.capture_file ) );
  }

  if( trace_fpath ) {
    FD_LOG_NOTICE(( "Exporting traces to %s", trace_fpath ));

    if( FD_UNLIKELY( 0!=mkdir( trace_fpath, 0777 ) && errno!=EEXIST ) )
      FD_LOG_ERR(( "mkdir(%s) failed (%d-%s)", trace_fpath, errno, fd_io_strerror( errno ) ));

    int fd = open( trace_fpath, O_DIRECTORY );
    if( FD_UNLIKELY( fd<=0 ) )  /* technically 0 is valid, but it serves as a sentinel here */
      FD_LOG_ERR(( "open(%s) failed (%d-%s)", trace_fpath, errno, fd_io_strerror( errno ) ));

    // state.capture_ctx->trace_mode |= FD_RUNTIME_TRACE_SAVE;
    // state.capture_ctx->trace_dirfd = fd;
  }

  if( retrace ) {
    FD_LOG_NOTICE(( "Retrace mode enabled" ));

    state.capture_ctx->trace_mode |= FD_RUNTIME_TRACE_REPLAY;
  }
#endif

  fd_runtime_recover_banks( state.slot_ctx, 0 );

  if (strcmp(args.cmd, "replay") == 0) {
    int err = fd_replay(&state, &args);
    if( err!=0 ) return err;
  }

  // fd_alloc_free( alloc, fd_solcap_writer_delete( fd_solcap_writer_fini( state.capture_ctx->capture ) ) );
  //if( state.capture_file  ) fclose( state.capture_file );
  // if( state.capture_ctx->trace_dirfd>0 ) close( state.capture_ctx->trace_dirfd );

  fd_valloc_free(state.slot_ctx->valloc, state.epoch_ctx->leaders);
  fd_exec_slot_ctx_delete(fd_exec_slot_ctx_leave(state.slot_ctx));
  fd_exec_epoch_ctx_delete(fd_exec_epoch_ctx_leave(state.epoch_ctx));

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();

  return 0;
}
