// /home/asiegel/solana/test-ledger

/* This is an attempt to wire together all the components of runtime...

   Start with a non-consensus participating, non-fork tracking tile that can
     1. receive shreds from Repair
     2. put them in the Blockstore
     3. validate and execute them

   ./build/native/gcc/unit-test/test_tvu \
      --rpc-port 8124 \
      --gossip-peer-addr 86.109.3.165:8000 \
      --repair-peer-addr 86.109.3.165:8008 \
      --repair-peer-id F7SW17yGN7UUPQ519nxaDt26UMtvwJPSFVu9kBMBQpW \
      --snapshot snapshot-24* \
      --incremental-snapshot incremental-snapshot-24* \
      --log-level-logfile 0 \
      --log-level-stderr 0

    More sample commands:

    rm -f *.zst ; wget --trust-server-names http://localhost:8899/snapshot.tar.bz2 ; wget --trust-server-names http://localhost:8899/incremental-snapshot.tar.bz2

    build/native/gcc/bin/fd_frank_ledger --cmd ingest --snapshotfile snapshot-24* --incremental incremental-snapshot-24* --rocksdb /data/testnet/ledger/rocksdb --genesis /data/testnet/ledger/genesis.bin --txnstatus true --pages 100 --backup /data/asiegel/test_backup --slothistory 100

    build/native/gcc/unit-test/test_tvu --load /data/asiegel/test_backup --rpc-port 8123 --page-cnt 100 \
      --gossip-peer-addr :8000 \
      --repair-peer-addr :8008 \
      --repair-peer-id F7SW17yGN7UUPQ519nxaDt26UMtvwJPSFVu9kBMBQpW \
      --log-level-stderr 0

*/

#define _GNU_SOURCE /* See feature_test_macros(7) */

#define FD_TVU_TILE_SLOT_DELAY 32

#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/fd_util.h"
#include "fd_tvu.h"
#include "../../util/net/fd_eth.h"
#include "../fd_flamenco.h"
#include "../gossip/fd_gossip.h"
#include "../repair/fd_repair.h"
#include "../rpc/fd_rpc_service.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#ifdef FD_HAS_LIBMICROHTTP
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef FD_HAS_LIBMICROHTTP
static fd_rpc_ctx_t * rpc_ctx = NULL;
#endif

typedef struct {
  char const * blockstore_wksp_name;
  char const * funk_wksp_name;
  char const * gossip_peer_addr;
  char const * incremental_snapshot;
  char const * load;
  char const * my_gossip_addr;
  char const * my_repair_addr;
  char const * repair_peer_addr;
  char const * repair_peer_id;
  char const * snapshot;
  ulong  index_max;
  ulong  page_cnt;
  ulong  tcnt;
  ulong  txn_max;
  ushort rpc_port;
} args_t;

static args_t
parse_args( int argc, char ** argv ) {
  char const * blockstore_wksp_name =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--blockstore-wksp", NULL, NULL );
  char const * funk_wksp_name =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--funk-wksp", NULL, NULL );
  char const * peer_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--gossip-peer-addr", NULL, ":1024" );
  char const * incremental =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--incremental-snapshot", NULL, NULL );
  char const * load =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--load", NULL, NULL );
  char const * my_gossip_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--my_gossip_addr", NULL, ":0" );
  char const * my_repair_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--my-repair-addr", NULL, ":0" );
  char const * repair_peer_addr_ =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-addr", NULL, "127.0.0.1:1032" );
  char const * repair_peer_id_ =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-id", NULL, NULL );
  char const * snapshot =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--snapshot", NULL, NULL );
  ulong  index_max =
      fd_env_strip_cmdline_ulong( &argc, &argv, "--indexmax", NULL, ULONG_MAX );
  ulong  page_cnt =
      fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 128UL);
  ulong  tcnt =
      fd_env_strip_cmdline_ulong( &argc, &argv, "--tcnt", NULL, ULONG_MAX );
  ulong  xactions_max =
      fd_env_strip_cmdline_ulong( &argc, &argv, "--txnmax", NULL, 1000 );
  ushort rpc_port =
      fd_env_strip_cmdline_ushort( &argc, &argv, "--rpc-port", NULL, 8899U );

  args_t args = {
    .blockstore_wksp_name = blockstore_wksp_name,
    .funk_wksp_name = funk_wksp_name,
    .gossip_peer_addr = peer_addr,
    .incremental_snapshot = incremental,
    .load = load,
    .my_gossip_addr = my_gossip_addr,
    .my_repair_addr = my_repair_addr,
    .repair_peer_addr = repair_peer_addr_,
    .repair_peer_id = repair_peer_id_,
    .snapshot = snapshot,
    .index_max = index_max,
    .page_cnt = page_cnt,
    .tcnt = tcnt,
    .txn_max = xactions_max,
    .rpc_port = rpc_port
  };
  return args;
}

// SIGINT signal handler
volatile int * stopflag;
static void
stop( int sig ) {
  (void)sig;
  *stopflag = 1;
}

int
main( int argc, char ** argv ) {
  signal( SIGINT, stop );
  signal( SIGPIPE, SIG_IGN );

  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );
  fd_valloc_t valloc = fd_libc_alloc_virtual();

  args_t args = parse_args( argc, argv );
  tvu_main_args_t tvu_main_args;
  tvu_main_setup( &tvu_main_args,
                  valloc,
                  NULL,
                  args.blockstore_wksp_name,
                  args.funk_wksp_name,
                  args.gossip_peer_addr,
                  args.incremental_snapshot,
                  args.load,
                  args.my_gossip_addr,
                  args.my_repair_addr,
                  args.snapshot,
                  args.index_max,
                  args.page_cnt,
                  args.tcnt,
                  args.txn_max,
                  args.rpc_port );
  if( tvu_main_args.blowup ) return 1;
  stopflag = &tvu_main_args.stopflag;

  /**********************************************************************/
  /* Tile                                                               */
  /**********************************************************************/

  if( tvu_main( tvu_main_args.gossip,
                &tvu_main_args.gossip_config,
                &tvu_main_args.repair_ctx,
                &tvu_main_args.repair_config,
                &tvu_main_args.stopflag,
                args.repair_peer_id,
                args.repair_peer_addr ) ) {
    return 1;
  }

  /***********************************************************************/
  /* Cleanup                                                             */
  /***********************************************************************/

#ifdef FD_HAS_LIBMICROHTTP
  fd_rpc_stop_service( rpc_ctx );
#endif
  fd_halt();
  return 0;
}
