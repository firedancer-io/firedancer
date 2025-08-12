#define _GNU_SOURCE
#include "../fd_shared_dev.h"
#include "bench/bench.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/net/fd_ip4.h"

#include <unistd.h>

void
load_cmd_perm( args_t *         args FD_PARAM_UNUSED,
               fd_cap_chk_t *   chk,
               config_t const * config ) {
  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  for( ulong i=0UL; STAGES[ i ]; i++ ) {
    if( FD_UNLIKELY( !strcmp( STAGES[ i ]->name, "hugetlbfs" ) ) )
      configure_args.configure.stages[ 0 ] = STAGES[ i ];
  }
  configure_args.configure.stages[ 2 ] = NULL;
  configure_cmd_perm( &configure_args, chk, config );
}

void
load_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args ) {
  const char * tpu_ip      = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--tpu-ip",   NULL, NULL );
  const char * rpc_ip      = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--rpc-ip",   NULL, NULL );
  const char * affinity    = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--affinity", NULL, NULL );

  args->load.tpu_port    = fd_env_strip_cmdline_ushort( pargc, pargv, "--tpu-port",     NULL, 0 );
  args->load.rpc_port    = fd_env_strip_cmdline_ushort( pargc, pargv, "--rpc-port",     NULL, 0 );
  args->load.benchg      = fd_env_strip_cmdline_ulong ( pargc, pargv, "--num-benchg",   NULL, 0 );
  args->load.benchs      = fd_env_strip_cmdline_ulong ( pargc, pargv, "--num-benchs",   NULL, 0 );
  args->load.accounts    = fd_env_strip_cmdline_ulong ( pargc, pargv, "--num-accounts", NULL, 0 );
  args->load.connections = fd_env_strip_cmdline_ulong ( pargc, pargv, "--connections",  NULL, 0 );
  args->load.transaction_mode    = fd_env_strip_cmdline_int  ( pargc, pargv, "--transaction-mode",    NULL, 0    );
  args->load.contending_fraction = fd_env_strip_cmdline_float( pargc, pargv, "--contending-fraction", NULL, 0.0f );
  args->load.cu_price_spread     = fd_env_strip_cmdline_float( pargc, pargv, "--cu-price-spread",     NULL, 0.0f );

  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->load.affinity ), affinity, sizeof( args->load.affinity )-1UL ) );

  args->load.tpu_ip = 0;
  args->load.rpc_ip = 0;
  if( FD_LIKELY( tpu_ip ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( tpu_ip, &args->load.tpu_ip ) ) )
      FD_LOG_ERR(( "invalid --tpu-ip" ));
  }
  if( FD_LIKELY( rpc_ip ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( rpc_ip, &args->load.rpc_ip ) ) )
      FD_LOG_ERR(( "invalid --rpc-ip" ));
  }

  args->load.no_quic = fd_env_strip_cmdline_contains( pargc, pargv, "--no-quic" );

}

void
load_cmd_fn( args_t *   args,
             config_t * config ) {

  /* set defaults */
  if( FD_UNLIKELY( !args->load.tpu_ip ) )
    args->load.tpu_ip      = config->net.ip_addr;

  if( FD_UNLIKELY( !args->load.rpc_ip ) )
    args->load.rpc_ip      = config->net.ip_addr;

  if( FD_UNLIKELY( !args->load.tpu_port ) ) {
    args->load.tpu_port    = fd_ushort_if( args->load.no_quic,
                 config->tiles.quic.regular_transaction_listen_port,
                 config->tiles.quic.quic_transaction_listen_port );
  }

  if( FD_UNLIKELY( !args->load.rpc_port ) )
    args->load.rpc_port    = config->rpc.port;
  if( FD_UNLIKELY( !args->load.rpc_port ) )
    FD_LOG_ERR(( "Missing --rpc-port" ));

  if( FD_UNLIKELY( !strcmp( args->load.affinity, "" ) ) )
    fd_cstr_append_cstr_safe( args->load.affinity, config->development.bench.affinity, sizeof( args->load.affinity )-1UL );

  if( FD_UNLIKELY( !args->load.benchg ) )
    args->load.benchg      = config->development.bench.benchg_tile_count;

  if( FD_UNLIKELY( !args->load.benchs ) )
    args->load.benchs      = config->development.bench.benchs_tile_count;

  if( FD_UNLIKELY( !args->load.accounts ) )
    args->load.accounts    = config->development.genesis.fund_initial_accounts;

  if( FD_UNLIKELY( !args->load.connections ) )
    args->load.connections = config->layout.quic_tile_count;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  add_bench_topo( topo,
                  args->load.affinity,
                  args->load.benchg,
                  args->load.benchs,
                  args->load.accounts,
                  args->load.transaction_mode,
                  args->load.contending_fraction,
                  args->load.cu_price_spread,
                  args->load.connections,
                  args->load.tpu_port,
                  args->load.tpu_ip,
                  args->load.rpc_port,
                  args->load.rpc_ip,
                  args->load.no_quic,
                  0 );
  config->topo = *topo;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  for( ulong i=0UL; STAGES[ i ]; i++ ) {
    if( FD_LIKELY( STAGES[ i ] ) ) {
      if( FD_UNLIKELY( !strcmp( STAGES[ i ]->name, "hugetlbfs" ) ) )
        configure_args.configure.stages[ 0 ] = STAGES[ i ];
    }
  }
  configure_args.configure.stages[ 1 ] = NULL;
  configure_cmd_fn( &configure_args, config );

  initialize_workspaces( config );
  initialize_stacks( config );

  FD_LOG_NOTICE(( "Running" ));
  FD_LOG_NOTICE(( "  --tpu-ip " FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( args->load.tpu_ip ) ));
  FD_LOG_NOTICE(( "  --tpu-port %d",             args->load.tpu_port                       ));
  FD_LOG_NOTICE(( "  --rpc-ip " FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( args->load.rpc_ip ) ));
  FD_LOG_NOTICE(( "  --rpc-port %d",             args->load.rpc_port                       ));
  FD_LOG_NOTICE(( "  --affinity %s",             args->load.affinity                       ));
  FD_LOG_NOTICE(( "  --num-benchg %lu",          args->load.benchg                         ));
  FD_LOG_NOTICE(( "  --num-benchs %lu",          args->load.benchs                         ));
  FD_LOG_NOTICE(( "  --num-accounts %lu",        args->load.accounts                       ));
  FD_LOG_NOTICE(( "  --connections %lu",         args->load.connections                    ));
  FD_LOG_NOTICE(( "  --transaction-mode %d",     args->load.transaction_mode               ));
  FD_LOG_NOTICE(( "  --contending-fraction %g",  (double)args->load.contending_fraction    ));
  FD_LOG_NOTICE(( "  --cu-price-spread %g",      (double)args->load.cu_price_spread        ));

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( &config->topo, 0, config->uid, config->gid, fdctl_tile_run );

  /* Sleep parent thread forever, Ctrl+C will terminate. */
  for(;;) pause();
}

action_t fd_action_load = {
  .name        = "load",
  .args        = load_cmd_args,
  .perm        = load_cmd_perm,
  .fn          = load_cmd_fn,
  .description = "Load test an external validator"
};
