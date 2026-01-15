#define _GNU_SOURCE
#include "../../../shared/commands/configure/configure.h"
#include "../../../shared/commands/run/run.h"

#include "../../../shared/commands/watch/watch.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../util/tile/fd_tile_private.h"

#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/capability.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

void
update_config_for_dev( config_t * config );

void
bench_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {
  args->load.no_quic = fd_env_strip_cmdline_contains( pargc, pargv, "--no-quic" );
}

void
add_bench_topo( fd_topo_t  * topo,
                char const * affinity,
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
                int          no_quic,
                int          reserve_agave_cores ) {

  fd_topob_wksp( topo, "bench" );
  fd_topob_link( topo, "bencho_out", "bench", 128UL, 64UL, 1UL );
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) fd_topob_link( topo, "benchg_s", "bench", 65536UL, FD_TXN_MTU, 1UL );

  int is_bench_auto_affinity = !strcmp( affinity, "auto" );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_bench_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [development.bench.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }
  if( FD_LIKELY( !is_bench_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity_tile_cnt<benchg_tile_cnt+1UL+benchs_tile_cnt ) )
      FD_LOG_ERR(( "The benchmark topology you are using has %lu bench tiles, but the CPU affinity specified "
                   "in the [development.bench.affinity] only provides for %lu cores. ",
                   benchg_tile_cnt+1UL+benchs_tile_cnt, affinity_tile_cnt ));
    else if( FD_UNLIKELY( affinity_tile_cnt>benchg_tile_cnt+1UL+benchs_tile_cnt ) )
      FD_LOG_WARNING(( "The benchmark topology you are using has %lu bench tiles, but the CPU affinity specified "
                       "in the [development.bench.affinity] provides for %lu cores. The extra cores will be unused.",
                       benchg_tile_cnt+1UL+benchs_tile_cnt, affinity_tile_cnt ));
  }
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

  /* This will blow away previous auto topology layouts and recompute an auto topology. */
  if( FD_UNLIKELY( is_bench_auto_affinity ) ) fd_topob_auto_layout( topo, reserve_agave_cores );
  fd_topob_finish( topo, CALLBACKS );
}

extern int * fd_log_private_shared_lock;

void
bench_cmd_fn( args_t *   args,
              config_t * config,
              int        watch ) {

  ushort dest_port = fd_ushort_if( args->load.no_quic,
                                   config->tiles.quic.regular_transaction_listen_port,
                                   config->tiles.quic.quic_transaction_listen_port );

  ushort rpc_port;
  uint rpc_ip_addr;
  if( FD_UNLIKELY( !config->is_firedancer ) ) {
    config->frankendancer.rpc.port     = fd_ushort_if( config->frankendancer.rpc.port, config->frankendancer.rpc.port, 8899 );
    config->frankendancer.rpc.full_api = 1;
    rpc_port = config->frankendancer.rpc.port;
    rpc_ip_addr = config->net.ip_addr;
  } else {
    if( FD_UNLIKELY( !config->tiles.rpc.enabled ) ) FD_LOG_ERR(( "RPC tile must be enabled to run bench" ));
    rpc_port = config->tiles.rpc.rpc_listen_port;
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.rpc.rpc_listen_address, &rpc_ip_addr ) ) )
      FD_LOG_ERR(( "failed to parse rpc listen address `%s`", config->tiles.rpc.rpc_listen_address ));
  }

  int is_auto_affinity = !strcmp( config->layout.affinity, "auto" );
  int is_agave_auto_affinity;
  if( FD_UNLIKELY( config->is_firedancer ) ) {
    is_agave_auto_affinity = is_auto_affinity;
  } else {
    is_agave_auto_affinity = !strcmp( config->frankendancer.layout.agave_affinity, "auto" );
  }
  int is_bench_auto_affinity = !strcmp( config->development.bench.affinity, "auto" );

  if( FD_UNLIKELY( is_auto_affinity != is_agave_auto_affinity ||
                   is_auto_affinity != is_bench_auto_affinity ) ) {
    FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity], [layout.agave_affinity], and [development.bench.affinity] must all be set to 'auto' or all be set to a specific CPU affinity string." ));
  }

  add_bench_topo( &config->topo,
                  config->development.bench.affinity,
                  config->development.bench.benchg_tile_count,
                  config->development.bench.benchs_tile_count,
                  config->development.genesis.fund_initial_accounts,
                  0, 0.0f, 0.0f,
                  config->layout.quic_tile_count,
                  dest_port,
                  config->net.ip_addr,
                  rpc_port,
                  rpc_ip_addr,
                  args->load.no_quic,
                  !config->is_firedancer );

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  for( ulong i=0UL; STAGES[ i ]; i++ )
    configure_args.configure.stages[ i ] = STAGES[ i ];
  configure_cmd_fn( &configure_args, config );

  update_config_for_dev( config );

  run_firedancer_init( config, 1, 1 );
  fdctl_setup_netns( config, 1 );

  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_topo_install_xdp_simple( &config->topo, config->net.bind_address_parsed );
  }

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  if( watch ) {
    int pipefd[2];
    if( FD_UNLIKELY( pipe2( pipefd, O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    args_t watch_args;
    watch_args.watch.drain_output_fd = pipefd[0];
    if( FD_UNLIKELY( -1==dup2( pipefd[ 1 ], STDERR_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    /* FIXME allow running sandboxed/multiprocess */
    fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );
    watch_cmd_fn( &watch_args, config );
  } else {
    /* FIXME allow running sandboxed/multiprocess */
    fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );
  }
}
