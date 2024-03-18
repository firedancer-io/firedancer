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
}

static void *
solana_labs_thread_main( void * _args ) {
  config_t * config = _args;
  solana_labs_boot( config );

  /* Solana Labs will never exit, we never set exit flag to true */
  FD_LOG_ERR(( "solana_labs_boot() exited" ));
  return NULL;
}

static void
add_bench_topo( fd_topo_t * topo,
                ushort      send_to_port,
                uint        send_to_ip_addr,
                ushort      rpc_port,
                uint        rpc_ip_addr ) {
  (void)topo;

  ulong benchg_tile_cnt = 4UL;

  fd_topob_wksp( topo, "bench" );
  fd_topob_link( topo, "bencho_out", "bench", 0, 128UL, 64UL, 1UL );
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) fd_topob_link( topo, "benchg_s", "bench", 0, 65536UL, FD_TXN_MTU, 1UL );

  fd_topo_tile_t *bencho = fd_topob_tile( topo, "bencho", "bench", "bench", "bench", USHORT_MAX, 0, "bencho_out", 0 );
  bencho->bencho.rpc_port    = rpc_port;
  bencho->bencho.rpc_ip_addr = rpc_ip_addr;
  for( ulong i=0UL; i<benchg_tile_cnt; i++ )  fd_topob_tile( topo, "benchg", "bench", "bench", "bench", USHORT_MAX, 0, "benchg_s", i );
  fd_topo_tile_t * benchs = fd_topob_tile( topo, "benchs", "bench", "bench", "bench", USHORT_MAX, 0, NULL, 0 );
  benchs->benchs.send_to_ip_addr = send_to_ip_addr;
  benchs->benchs.send_to_port    = send_to_port;

  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) fd_topob_tile_in( topo, "benchg", i, "bench", "bencho_out", 0, 1, 1 );
  for( ulong i=0UL; i<benchg_tile_cnt; i++ ) fd_topob_tile_in( topo, "benchs", 0, "bench", "benchg_s", i, 1, 1 );

  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );
}

extern int * fd_log_private_shared_lock;

void
bench_cmd_fn( args_t *         args,
              config_t * const config ) {
  (void)args;

  add_bench_topo( &config->topo, config->tiles.quic.regular_transaction_listen_port, config->tiles.net.ip_addr,
                  config->rpc.port, config->tiles.net.ip_addr );

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
