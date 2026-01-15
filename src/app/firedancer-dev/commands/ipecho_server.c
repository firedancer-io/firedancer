
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/topo/fd_topob.h"

#include <time.h>
#include <stdio.h>
#include <unistd.h>

#define NAME "ipecho-server"

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
ipecho_topo( fd_topo_t *  topo,
             char const * name ) {
  fd_topob_new( topo, name );
  topo->max_page_size = 1UL<<21UL;

  fd_topob_wksp( topo, "all" );
  fd_topo_link_t * link = fd_topob_link( topo, "ipecho_out", "all", 4UL, 0UL, 1UL );
  link->permit_no_consumers = 1;
  fd_topo_tile_t * tile = fd_topob_tile( topo, "ipecho", "all", "all", 0UL, 0, 0 );
  tile->ipecho.expected_shred_version = 32;
  tile->ipecho.entrypoints_cnt = 0UL;
  tile->ipecho.bind_address = FD_IP4_ADDR(127,0,0,1);
  tile->ipecho.bind_port    = 12008;
  fd_topob_tile_out( topo, "ipecho", 0UL, "ipecho_out", 0UL );

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

extern int * fd_log_private_shared_lock;

static void
ipecho_server_cmd_topo( config_t * config ) {
  ipecho_topo( &config->topo, config->name );
}

static args_t
configure_args( void ) {
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  ulong stage_idx = 0UL;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args.configure.stages[ stage_idx++ ] = NULL;

  return args;
}

void
ipecho_server_cmd_perm( args_t *    args FD_PARAM_UNUSED,
                   fd_cap_chk_t *   chk,
                   config_t const * config ) {
  args_t c_args = configure_args();
  configure_cmd_perm( &c_args, chk, config );
  run_cmd_perm( NULL, chk, config );
}

static void
ipecho_server_cmd_fn( args_t *   args,
                      config_t * config ) {
  (void)args;

  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  run_firedancer_init( config, 1, 0 );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( &config->topo );

  ulong tile_idx1 = fd_topo_find_tile( &config->topo, "ipecho", 0UL );
  fd_topo_tile_t * ipecho_tile1 = &config->topo.tiles[ tile_idx1 ];
  ulong volatile * const ipecho_metrics1 = fd_metrics_tile( ipecho_tile1->metrics );
  (void)ipecho_metrics1;

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );

  ulong tile_idx = fd_topo_find_tile( &config->topo, "ipecho", 0UL );
  FD_TEST( tile_idx!=ULONG_MAX );
  fd_topo_tile_t * ipecho_tile = &config->topo.tiles[ tile_idx ];

  sleep(1);
  ulong volatile * const ipecho_metrics = fd_metrics_tile( ipecho_tile->metrics );

  ulong last_conns = ULONG_MAX;
  ulong last_closed_ok = ULONG_MAX;
  ulong last_closed_error = ULONG_MAX;

  for(;;) {
    ulong ipecho_conns = FD_VOLATILE_CONST( ipecho_metrics[ MIDX( GAUGE, IPECHO, CONNECTION_COUNT ) ] );
    ulong ipecho_closed_ok = FD_VOLATILE_CONST( ipecho_metrics[ MIDX( COUNTER, IPECHO, CONNECTIONS_CLOSED_OK ) ] );
    ulong ipecho_closed_error = FD_VOLATILE_CONST( ipecho_metrics[ MIDX( COUNTER, IPECHO, CONNECTIONS_CLOSED_ERROR ) ] );

    if( FD_UNLIKELY( ipecho_conns!=last_conns || ipecho_closed_ok!=last_closed_ok || ipecho_closed_error!=last_closed_error ) ) {
      FD_LOG_NOTICE(( "connections=%lu closed_ok=%lu closed_err=%lu", ipecho_conns, ipecho_closed_ok, ipecho_closed_error ));
      last_conns = ipecho_conns;
      last_closed_ok = ipecho_closed_ok;
      last_closed_error = ipecho_closed_error;
    }

    nanosleep( &(struct timespec){ .tv_sec=0, .tv_nsec=1000L*1000L }, NULL );
  }
}

action_t fd_action_ipecho_server = {
  .name = NAME,
  .args = NULL,
  .perm = ipecho_server_cmd_perm,
  .fn   = ipecho_server_cmd_fn,
  .topo = ipecho_server_cmd_topo,
};
