#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run/run.h"
#include "rpc_client/fd_rpc_client.h"

#include "../../disco/topo/fd_topob.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../util/net/fd_ip4.h"

#include <unistd.h>
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/capability.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "../../util/tile/fd_tile_private.h"

void
bench_cmd_perm( args_t *         args,
                fd_caps_ctx_t *  caps,
                config_t * const config ) {
  (void)args;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
    configure_args.configure.stages[ i ] = STAGES[ i ];
  configure_cmd_perm( &configure_args, caps, config );

  run_cmd_perm( NULL, caps, config );
}

void
bench_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {
  (void)pargc;
  (void)pargv;
  (void)args;
  args->spammer.no_quic = fd_env_strip_cmdline_contains( pargc, pargv, "--no-quic" );
}

static void *
solana_labs_thread_main( void * _args ) {
  config_t * config = _args;
  solana_labs_boot( config );

  /* Solana Labs will never exit, we never set exit flag to true */
  FD_LOG_ERR(( "solana_labs_boot() exited" ));
  return NULL;
}

void
add_bench_topo( fd_topo_t  * topo,
                char const * affinity,
                ulong        benchg_tile_cnt,
                ulong        benchs_tile_cnt,
                ulong        accounts_cnt,
                ulong        conn_cnt,
                ushort       send_to_port,
                uint         send_to_ip_addr,
                ushort       rpc_port,
                uint         rpc_ip_addr,
                int          no_quic ) {

  fd_topob_wksp( topo, "bench" );
  fd_topob_link( topo, "bencho_out", "bench", 0, 128UL, 64UL, 1UL );
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) fd_topob_link( topo, "benchg_s", "bench", 0, 65536UL, FD_TXN_MTU, 1UL );

  ushort tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) tile_to_cpu[ i ] = USHORT_MAX; /* Unassigned tiles will be floating. */
  ulong affinity_tile_cnt = fd_tile_private_cpus_parse( affinity, tile_to_cpu );

  if( FD_UNLIKELY( affinity_tile_cnt<benchg_tile_cnt+1UL+benchs_tile_cnt ) )
    FD_LOG_ERR(( "The benchmark topology you are using has %lu tiles, but the CPU affinity specified "
                 "in the [development.bench.affinity] only provides for %lu cores. ",
                 benchg_tile_cnt+1UL+benchs_tile_cnt, affinity_tile_cnt ));

  fd_topo_tile_t * bencho = fd_topob_tile( topo, "bencho", "bench", "bench", "bench", tile_to_cpu[ 0 ], 0, "bencho_out", 0 );
  bencho->bencho.rpc_port    = rpc_port;
  bencho->bencho.rpc_ip_addr = rpc_ip_addr;
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) {
    fd_topo_tile_t * benchg = fd_topob_tile( topo, "benchg", "bench", "bench", "bench", tile_to_cpu[ i+1UL ], 0, "benchg_s", i );
    benchg->benchg.accounts_cnt = accounts_cnt;
  }
  for( ulong i=0UL; i<benchs_tile_cnt; i++ ) {
    fd_topo_tile_t * benchs = fd_topob_tile( topo, "benchs", "bench", "bench", "bench", tile_to_cpu[ benchg_tile_cnt+1UL+i ], 0, NULL, 0 );
    benchs->benchs.send_to_ip_addr = send_to_ip_addr;
    benchs->benchs.send_to_port    = send_to_port;
    benchs->benchs.conn_cnt        = conn_cnt;
    benchs->benchs.no_quic         = no_quic;
  }

  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) fd_topob_tile_in( topo, "benchg", i, "bench", "bencho_out", 0, 1, 1 );
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) {
    for( ulong j=0UL; j<benchs_tile_cnt; j++ ) {
      fd_topob_tile_in( topo, "benchs", j, "bench", "benchg_s", i, 1, 1 );
    }
  }

  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );
}

extern int * fd_log_private_shared_lock;

void
bench_cmd_fn( args_t *         args,
              config_t * const config ) {
  (void)args;

  ushort dest_port = fd_ushort_if( args->spammer.no_quic,
                                   config->tiles.quic.regular_transaction_listen_port,
                                   config->tiles.quic.quic_transaction_listen_port );

  add_bench_topo( &config->topo,
                  config->development.bench.affinity,
                  config->development.bench.benchg_tile_count,
                  config->development.bench.benchs_tile_count,
                  config->development.genesis.fund_initial_accounts,
                  config->layout.quic_tile_count,
                  dest_port,
                  config->tiles.net.ip_addr,
                  config->rpc.port,
                  config->tiles.net.ip_addr,
                  args->spammer.no_quic );

  if( FD_LIKELY( !args->dev.no_configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
      configure_args.configure.stages[ i ] = STAGES[ i ];
    configure_cmd_fn( &configure_args, config );
  }

  update_config_for_dev( config );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run, NULL );
  pthread_t solana;
  pthread_create( &solana, NULL, solana_labs_thread_main, config );

  /* Sleep parent thread forever, Ctrl+C will terminate. */
  for(;;) pause();
}
