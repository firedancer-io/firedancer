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

  int exited_tile = INT_MAX;
  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run, &exited_tile );
  pthread_t solana;
  pthread_create( &solana, NULL, solana_labs_thread_main, config );

  for(;;) {
    if( FD_UNLIKELY( -1==syscall( SYS_futex, &exited_tile, FUTEX_WAIT_PRIVATE, ULONG_MAX, NULL, NULL, 0 ) ) ) {
      if( FD_UNLIKELY( errno!=EAGAIN ) ) FD_LOG_ERR(( "futex() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( exited_tile!=INT_MAX ) ) break;
  }

  ulong bench_tile = fd_topo_find_tile( &config->topo, "bencho", 0UL );
  FD_TEST( bench_tile!=ULONG_MAX );

  if( FD_UNLIKELY( (ulong)exited_tile!=bench_tile ) )
    FD_LOG_ERR(( "unexpected tile %s exited", config->topo.tiles[ exited_tile ].name ));

  printf( "\n             link |  ovrnp cnt |  ovrnr cnt |   slow cnt |     tx seq |     rx seq\n" );
  printf(   "------------------+------------+------------+------------+------------+-----------\n" );

  fd_topo_t * topo = &config->topo;
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    for( ulong in_idx=0UL; in_idx<topo->tiles[ tile_idx ].in_cnt; in_idx++ ) {
      fd_topo_link_t * link = &topo->links[ topo->tiles[ tile_idx ].in_link_id[ in_idx ] ];
      ulong producer_tile_id = fd_topo_find_link_producer( topo, link );
      FD_TEST( producer_tile_id != ULONG_MAX );
      char * producer = topo->tiles[ producer_tile_id ].name;

      ulong const * in_metrics = (ulong const *)fd_metrics_link_in( topo->tiles[ tile_idx ].metrics, in_idx );

      ulong producer_id = fd_topo_find_link_producer( topo, link );
      ulong const * out_metrics = NULL;
      if( FD_LIKELY( producer_id!=ULONG_MAX && topo->tiles[ tile_idx ].in_link_reliable[ in_idx ] ) ) {
        fd_topo_tile_t * producer = &topo->tiles[ producer_id ];
        ulong out_idx;
        for( out_idx=0UL; out_idx<producer->out_cnt; out_idx++ ) {
          if( producer->out_link_id[ out_idx ]==link->id ) break;
        }
        out_metrics = fd_metrics_link_out( producer->metrics, out_idx );
      }

      printf( " %7s->%-7s", producer, topo->tiles[ tile_idx ].name );
      printf( " | %10lu", in_metrics[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF ] );
      printf( " | %10lu", in_metrics[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_OFF ] );
      printf( " | %10lu", out_metrics ? out_metrics[ FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF ] : 0UL );

      fd_frag_meta_t const * mcache = topo->links[ topo->tiles[ tile_idx ].in_link_id[ in_idx  ] ].mcache;
      ulong const * seq = (ulong const *)fd_mcache_seq_laddr_const( mcache );
      printf( " | %10lu", fd_mcache_seq_query( seq ) );

      ulong const * fseq = topo->tiles[ tile_idx ].in_link_fseq[ in_idx ];
      printf( " | %10lu\n", fd_fseq_query( fseq ) );
    }
  }

  /* Clean exit with exited_tile still on stack */
  exit_group(0);
}
