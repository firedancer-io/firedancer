#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run/run.h"

#include "../../disco/topo/fd_topob.h"
#include "../../util/net/fd_ip4.h"

#include "../../util/tile/fd_tile_private.h"

void
spammer_cmd_perm( args_t *         args,
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
spammer_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args ) {
  const char * tpu_ip      = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--tpu-ip",      NULL,  NULL );
  const char * rpc_ip      = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--rpc-ip",      NULL,  NULL );
  const char * affinity    = fd_env_strip_cmdline_cstr  ( pargc, pargv, "--affinity",     "-a", NULL );

  args->spammer.tpu_port    = fd_env_strip_cmdline_ushort( pargc, pargv, "--tpu-port",    NULL,     0 );
  args->spammer.rpc_port    = fd_env_strip_cmdline_ushort( pargc, pargv, "--rpc-port",    NULL,     0 );
  args->spammer.benchg      = fd_env_strip_cmdline_ulong ( pargc, pargv, "--num-benchg",   "-g",    0 );
  args->spammer.benchs      = fd_env_strip_cmdline_ulong ( pargc, pargv, "--num-benchs",   "-s",    0 );
  args->spammer.accounts    = fd_env_strip_cmdline_ulong ( pargc, pargv, "--num-accounts", NULL,    0 );
  args->spammer.connections = fd_env_strip_cmdline_ulong ( pargc, pargv, "--connections",  "-c",    0 );

  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->spammer.affinity ), affinity, sizeof( args->spammer.affinity )-1UL ) );

  args->spammer.tpu_ip = 0;
  args->spammer.rpc_ip = 0;
  if( FD_LIKELY( tpu_ip ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( tpu_ip, &args->spammer.tpu_ip ) ) )
      FD_LOG_ERR(( "invalid --tpu-ip" ));
  }
  if( FD_LIKELY( rpc_ip ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( rpc_ip, &args->spammer.rpc_ip ) ) )
      FD_LOG_ERR(( "invalid --rpc-ip" ));
  }

  args->spammer.no_quic = fd_env_strip_cmdline_contains( pargc, pargv, "--no-quic" );

}

void
spammer_cmd_fn( args_t *         args,
                config_t * const config ) {

  /* set defaults */
  if( FD_UNLIKELY( !args->spammer.tpu_ip ) )
    args->spammer.tpu_ip      = config->tiles.net.ip_addr;

  if( FD_UNLIKELY( !args->spammer.rpc_ip ) )
    args->spammer.rpc_ip      = config->tiles.net.ip_addr;

  if( FD_UNLIKELY( !args->spammer.tpu_port ) )
    args->spammer.tpu_port    = config->tiles.quic.regular_transaction_listen_port;

  if( FD_UNLIKELY( !args->spammer.rpc_port ) )
    args->spammer.rpc_port    = config->rpc.port;

  if( FD_UNLIKELY( !strcmp( args->spammer.affinity, "" ) ) )
    fd_cstr_append_cstr_safe( args->spammer.affinity, config->development.bench.affinity, sizeof( args->spammer.affinity )-1UL );

  if( FD_UNLIKELY( !args->spammer.benchg ) )
    args->spammer.benchg      = config->development.bench.benchg_tile_count;

  if( FD_UNLIKELY( !args->spammer.benchs ) )
    args->spammer.benchs      = config->development.bench.benchs_tile_count;

  if( FD_UNLIKELY( !args->spammer.accounts ) )
    args->spammer.accounts    = config->development.genesis.fund_initial_accounts;

  if( FD_UNLIKELY( !args->spammer.connections ) )
    args->spammer.connections = config->layout.quic_tile_count;

  fd_topo_t topo[ 1 ] = { fd_topob_new( config->name ) };
  add_bench_topo( topo,
                  args->spammer.affinity,
                  args->spammer.benchg,
                  args->spammer.benchs,
                  args->spammer.accounts,
                  args->spammer.connections,
                  args->spammer.tpu_port,
                  args->spammer.tpu_ip,
                  args->spammer.rpc_port,
                  args->spammer.rpc_ip,
                  args->spammer.no_quic );
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
