#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run/run.h"
#include "../fdctl/run/topos/topos.h"
#include "../../disco/topo/fd_topob.h"

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

void
bench_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {
  (void)pargc;
  (void)pargv;
  (void)args;
  args->load.no_quic = fd_env_strip_cmdline_contains( pargc, pargv, "--no-quic" );
}

void
bench_cmd_topo( args_t *   args,
                config_t * config ) {

  config->rpc.port     = fd_ushort_if( config->rpc.port, config->rpc.port, 8899 );
  config->rpc.full_api = 1;

  int is_auto_affinity       = !strcmp( config->layout.affinity,            "auto" );
  int is_agave_auto_affinity = !strcmp( config->layout.agave_affinity,      "auto" );
  int is_bench_auto_affinity = !strcmp( config->development.bench.affinity, "auto" );

  if( FD_UNLIKELY( is_auto_affinity != is_agave_auto_affinity ||
                   is_auto_affinity != is_bench_auto_affinity ) ) {
    FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity], [layout.agave_affinity], and [development.bench.affinity] must all be set to 'auto' or all be set to a specific CPU affinity string." ));
  }

  ushort dest_port = fd_ushort_if( args->load.no_quic,
                                   config->tiles.quic.regular_transaction_listen_port,
                                   config->tiles.quic.quic_transaction_listen_port );

  fd_topos_create_validator( &config->topo, config );
  add_bench_topo( &config->topo,
                  config->development.bench.affinity,
                  config->development.bench.benchg_tile_count,
                  config->development.bench.benchs_tile_count,
                  config->development.genesis.fund_initial_accounts,
                  0, 0.0f, 0.0f,
                  config->layout.quic_tile_count,
                  dest_port,
                  config->tiles.net.ip_addr,
                  config->rpc.port,
                  config->tiles.net.ip_addr,
                  args->load.no_quic );
  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( &config->topo );
  fd_topos_seal( &config->topo );

}

static void *
agave_thread_main( void * _args ) {
  config_t * config = _args;
  agave_boot( config );

  /* Agave will never exit, we never set exit flag to true */
  FD_LOG_ERR(( "agave_boot() exited" ));
  return NULL;
}

void
add_bench_topo( fd_topo_t  * topo,
                char const * affinity_str,
                ulong        benchg_tile_cnt,
                ulong        benchs_tile_cnt,
                ulong        accounts_cnt,
                int          transaction_mode,
                float        contending_fraction,
                float        cu_price_spread,
                ulong        conn_cnt,
                ushort       send_to_port,
                uint         send_to_ip_addr,
                ushort       rpc_port,
                uint         rpc_ip_addr,
                int          no_quic ) {

  int is_bench_auto_affinity = !strcmp( affinity_str, "auto" );
  fd_topos_affinity_t affinity[1];
  fd_topos_affinity( affinity, affinity_str, "development.bench.affinity" );

  fd_topob_wksp( topo, "bench" );
  fd_topob_link( topo, "bencho_out", "bench", 128UL, 64UL, 1UL );
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) fd_topob_link( topo, "benchg_s", "bench", 65536UL, FD_TXN_MTU, 1UL );

  if( FD_LIKELY( !is_bench_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity->tile_cnt < benchg_tile_cnt+1UL+benchs_tile_cnt ) )
      FD_LOG_ERR(( "The benchmark topology you are using has %lu bench tiles, but the CPU affinity specified "
                   "in the [development.bench.affinity] only provides for %lu cores. ",
                   benchg_tile_cnt+1UL+benchs_tile_cnt, affinity->tile_cnt ));
    else if( FD_UNLIKELY( affinity->tile_cnt > benchg_tile_cnt+1UL+benchs_tile_cnt ) )
      FD_LOG_WARNING(( "The benchmark topology you are using has %lu bench tiles, but the CPU affinity specified "
                       "in the [development.bench.affinity] provides for %lu cores. The extra cores will be unused.",
                       benchg_tile_cnt+1UL+benchs_tile_cnt, affinity->tile_cnt ));
  }
  ulong const * tile_to_cpu = affinity->tile_to_cpu;
  fd_topo_tile_t * bencho = fd_topob_tile( topo, "bencho", "bench", "bench", tile_to_cpu[ 0 ], 0, 0 );
  bencho->bencho.rpc_port    = rpc_port;
  bencho->bencho.rpc_ip_addr = rpc_ip_addr;
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) {
    fd_topo_tile_t * benchg = fd_topob_tile( topo, "benchg", "bench", "bench", tile_to_cpu[ i+1UL ], 0, 0 );
    benchg->benchg.accounts_cnt        = accounts_cnt;
    benchg->benchg.mode                = transaction_mode;
    benchg->benchg.contending_fraction = contending_fraction;
    benchg->benchg.cu_price_spread     = cu_price_spread;
  }
  for( ulong i=0UL; i<benchs_tile_cnt; i++ ) {
    fd_topo_tile_t * benchs = fd_topob_tile( topo, "benchs", "bench", "bench", tile_to_cpu[ benchg_tile_cnt+1UL+i ], 0, 0 );
    benchs->benchs.send_to_ip_addr = send_to_ip_addr;
    benchs->benchs.send_to_port    = send_to_port;
    benchs->benchs.conn_cnt        = conn_cnt;
    benchs->benchs.no_quic         = no_quic;
  }

  fd_topob_tile_out( topo, "bencho", 0UL, "bencho_out", 0UL );
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) {
    fd_topob_tile_in( topo, "benchg", i, "bench", "bencho_out", 0, 1, 1 );
    fd_topob_tile_out( topo, "benchg", i, "benchg_s", i );
  }
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) {
    for( ulong j=0UL; j<benchs_tile_cnt; j++ ) {
      fd_topob_tile_in( topo, "benchs", j, "bench", "benchg_s", i, 1, 1 );
    }
  }
}

extern int * fd_log_private_shared_lock;

void
bench_cmd_fn( args_t *         args,
              config_t * const config ) {

  if( FD_LIKELY( !args->dev.no_configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
      configure_args.configure.stages[ i ] = STAGES[ i ];
    configure_cmd_fn( &configure_args, config );
  }

  update_config_for_dev( config );

  run_firedancer_init( config, 1 );
  fdctl_setup_netns( config );

  fd_xdp_fds_t fds = fd_topo_install_xdp( &config->topo );
  (void)fds;

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run, NULL );
  pthread_t agave;
  pthread_create( &agave, NULL, agave_thread_main, config );

  /* Sleep parent thread forever, Ctrl+C will terminate. */
  for(;;) pause();
}
