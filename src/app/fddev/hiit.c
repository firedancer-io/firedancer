#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run/run.h"

#include "../../disco/topo/fd_topob.h"
#include "../../util/net/fd_ip4.h"

#include "../../util/tile/fd_tile_private.h"

void
hiit_cmd_perm( args_t *         args,
                  fd_caps_ctx_t *  caps,
                  config_t * const config ) {
  (void)args;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  FD_TEST( CONFIGURE_STAGE_COUNT>2 );
  for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ ) {
    if( FD_LIKELY( STAGES[ i ] ) ) {
      if( FD_UNLIKELY( !strcmp( STAGES[ i ]->name, "hugetlbfs" ) ) )
        configure_args.configure.stages[ 0 ] = STAGES[ i ];
      if( FD_UNLIKELY( !strcmp( STAGES[ i ]->name, "workspace" ) ) )
        configure_args.configure.stages[ 1 ] = STAGES[ i ];
    }
  }
  configure_args.configure.stages[ 2 ] = NULL;
  configure_cmd_perm( &configure_args, caps, config );

}

void
hiit_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args ) {
  const char * tpu_ip      = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--tpu-ip",      NULL,  NULL );
  const char * rpc_ip      = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--rpc-ip",      NULL,  NULL );
  const char * affinity    = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--affinity",     "-a", NULL );

  args->hiit.tpu_port    = fd_env_strip_cmdline_ushort( pargc, pargv, "--tpu-port",    NULL,     0 );
  args->hiit.rpc_port    = fd_env_strip_cmdline_ushort( pargc, pargv, "--rpc-port",    NULL,     0 );
  args->hiit.benchg      = fd_env_strip_cmdline_ulong ( pargc, pargv, "--num-benchg",   "-g",    0 );
  args->hiit.benchs      = fd_env_strip_cmdline_ulong ( pargc, pargv, "--num-benchs",   "-s",    0 );
  args->hiit.accounts    = fd_env_strip_cmdline_ulong ( pargc, pargv, "--num-accounts", NULL,    0 );
  args->hiit.connections = fd_env_strip_cmdline_ulong ( pargc, pargv, "--connections",  "-c",    0 );

  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->hiit.affinity ), affinity, sizeof( args->hiit.affinity )-1UL ) );

  args->hiit.tpu_ip = 0;
  args->hiit.rpc_ip = 0;
  if( FD_LIKELY( tpu_ip ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( tpu_ip, &args->hiit.tpu_ip ) ) )
      FD_LOG_ERR(( "invalid --tpu-ip" ));
  }
  if( FD_LIKELY( rpc_ip ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( rpc_ip, &args->hiit.rpc_ip ) ) )
      FD_LOG_ERR(( "invalid --rpc-ip" ));
  }

  args->hiit.no_quic = fd_env_strip_cmdline_contains( pargc, pargv, "--no-quic" );

}

void
hiit_cmd_fn( args_t *         args,
                config_t * const config ) {

  /* set defaults */
  if( FD_UNLIKELY( !args->hiit.tpu_ip ) )
    args->hiit.tpu_ip      = config->tiles.net.ip_addr;

  if( FD_UNLIKELY( !args->hiit.rpc_ip ) )
    args->hiit.rpc_ip      = config->tiles.net.ip_addr;

  if( FD_UNLIKELY( !args->hiit.tpu_port ) )
    args->hiit.tpu_port    = config->tiles.quic.regular_transaction_listen_port;

  if( FD_UNLIKELY( !args->hiit.rpc_port ) )
    args->hiit.rpc_port    = config->rpc.port;

  if( FD_UNLIKELY( !strcmp( args->hiit.affinity, "" ) ) )
    fd_cstr_append_cstr_safe( args->hiit.affinity, config->development.bench.affinity, sizeof( args->hiit.affinity )-1UL );

  if( FD_UNLIKELY( !args->hiit.benchg ) )
    args->hiit.benchg      = config->development.bench.benchg_tile_count;

  if( FD_UNLIKELY( !args->hiit.benchs ) )
    args->hiit.benchs      = config->development.bench.benchs_tile_count;

  if( FD_UNLIKELY( !args->hiit.accounts ) )
    args->hiit.accounts    = config->development.genesis.fund_initial_accounts;

  if( FD_UNLIKELY( !args->hiit.connections ) )
    args->hiit.connections = config->layout.quic_tile_count;

  fd_topo_t topo[ 1 ] = { fd_topob_new( config->name ) };
  add_bench_topo( topo,
                  args->hiit.affinity,
                  args->hiit.benchg,
                  args->hiit.benchs,
                  args->hiit.accounts,
                  args->hiit.connections,
                  args->hiit.tpu_port,
                  args->hiit.tpu_ip,
                  args->hiit.rpc_port,
                  args->hiit.rpc_ip,
                  args->hiit.no_quic );
  config->topo = *topo;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ ) {
    if( FD_LIKELY( STAGES[ i ] ) ) {
      if( FD_UNLIKELY( !strcmp( STAGES[ i ]->name, "hugetlbfs" ) ) )
        configure_args.configure.stages[ 0 ] = STAGES[ i ];
      if( FD_UNLIKELY( !strcmp( STAGES[ i ]->name, "workspace" ) ) )
        configure_args.configure.stages[ 1 ] = STAGES[ i ];
    }
  }
  configure_args.configure.stages[ 2 ] = NULL;
  configure_cmd_fn( &configure_args, config );

  // Do we need a sandbox?

  fd_topo_run_single_process( &config->topo, 0, config->uid, config->gid, fdctl_tile_run, NULL );

  /* Sleep parent thread forever, Ctrl+C will terminate. */
  for(;;) pause();
}
