#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include "../../util/wksp/fd_wksp_private.h"
#include "../../disco/topo/fd_topo.h"
#include "fd_rpc_service.h"

/*
static void usage( char const * progname ) {
  fprintf( stderr, "fd_rpcserver usage: %s\n", progname );
  fprintf( stderr, " --wksp-name-funk <workspace name>          funk workspace name\n" );
  fprintf( stderr, " --wksp-name-blockstore <workspace name>    blockstore workspace name\n" );
  fprintf( stderr, " --wksp-name-replay-notify <workspace name> replay notification workspace name\n" );
  fprintf( stderr, " --num-threads <count>                      number of http service threads\n" );
  fprintf( stderr, " --port <port number>                       http service port\n" );
}
*/

static void
init_args( int * argc, char *** argv, fd_rpcserver_args_t * args ) {
  char const * wksp_name = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-funk", NULL, "fd1_funk.wksp" );
  FD_LOG_NOTICE(( "attaching to workspace \"%s\"", wksp_name ));
  fd_wksp_t * wksp = fd_wksp_attach( wksp_name );
  if( FD_UNLIKELY( !wksp ) )
    FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
  fd_wksp_tag_query_info_t info;
  ulong tag = FD_FUNK_MAGIC;
  if( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace \"%s\" does not contain a funk", wksp_name ));
  }
  void * shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
  args->funk = fd_funk_join( shmem );
  if( args->funk == NULL ) {
    FD_LOG_ERR(( "failed to join a funky" ));
  }
  fd_wksp_mprotect( wksp, 1 );

  wksp_name = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-blockstore", NULL, "fd1_bstore.wksp" );
  FD_LOG_NOTICE(( "attaching to workspace \"%s\"", wksp_name ));
  wksp = fd_wksp_attach( wksp_name );
  if( FD_UNLIKELY( !wksp ) )
    FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
  tag = FD_BLOCKSTORE_MAGIC;
  if( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace \"%s\" does not contain a blockstore", wksp_name ));
  }
  shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
  args->blockstore = fd_blockstore_join( shmem );
  if( args->blockstore == NULL ) {
    FD_LOG_ERR(( "failed to join a blockstore" ));
  }
  FD_LOG_NOTICE(( "blockstore has slot min=%lu smr=%lu max=%lu",
                  args->blockstore->min, args->blockstore->smr, args->blockstore->max ));
  fd_wksp_mprotect( wksp, 1 );

  wksp_name = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-replay-notify", NULL, "fd1_replay_notif.wksp" );
  FD_LOG_NOTICE(( "attaching to workspace \"%s\"", wksp_name ));
  args->rep_notify_wksp = wksp = fd_wksp_attach( wksp_name );
  if( FD_UNLIKELY( !wksp ) )
    FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
  ulong offset = fd_ulong_align_up( fd_wksp_private_data_off( wksp->part_max ), fd_topo_workspace_align() );
  args->rep_notify = fd_mcache_join( (void *)((ulong)wksp + offset) );
  if( args->rep_notify == NULL ) {
    FD_LOG_ERR(( "failed to join a replay notifier" ));
  }

  args->num_threads = fd_env_strip_cmdline_ulong( argc, argv, "--num-threads", NULL, 10 );

  args->port = (ushort)fd_env_strip_cmdline_ulong( argc, argv, "--port", NULL, 8899 );
  args->ws_port = (ushort)fd_env_strip_cmdline_ulong( argc, argv, "--ws-port", NULL, 8900 );
}

static int stopflag = 0;
static void
signal1( int sig ) {
  (void)sig;
  stopflag = 1;
}

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rpcserver_args_t args;
  init_args( &argc, &argv, &args );

  struct sigaction sa = {
    .sa_handler = signal1,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_rpc_ctx_t * ctx = NULL;
  fd_rpc_start_service( &args, &ctx );

  fd_frag_meta_t * mcache = args.rep_notify;
  fd_wksp_t * mcache_wksp = args.rep_notify_wksp;
  ulong depth  = fd_mcache_depth( mcache );
  ulong seq_expect = fd_mcache_seq0( mcache );
  while( !stopflag ) {
    while( 1 ) {
      fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq_expect, depth );

      ulong seq_found = fd_frag_meta_seq_query( mline );
      long  diff      = fd_seq_diff( seq_found, seq_expect );
      if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
        if( FD_UNLIKELY( diff>0L ) ) {
          FD_LOG_NOTICE(( "overrun: seq=%lu seq_found=%lu diff=%ld", seq_expect, seq_found, diff ));
          seq_expect = seq_found;
        } else {
          /* caught up */
          break;
        }
        continue;
      }

      fd_replay_notif_msg_t msg;
      FD_TEST( mline->sz == sizeof(msg) );
      fd_memcpy(&msg, fd_chunk_to_laddr( mcache_wksp, mline->chunk ), sizeof(msg));

      seq_found = fd_frag_meta_seq_query( mline );
      diff      = fd_seq_diff( seq_found, seq_expect );
      if( FD_UNLIKELY( diff ) ) { /* overrun, optimize for expected sequence number ready */
        FD_LOG_NOTICE(( "overrun: seq=%lu seq_found=%lu diff=%ld", seq_expect, seq_found, diff ));
        seq_expect = seq_found;
        continue;
      }

      fd_rpc_replay_notify( ctx, &msg );

      ++seq_expect;
    }

    fd_rpc_ws_poll( ctx );
  }

  fd_rpc_stop_service( ctx );

  fd_halt();
  return 0;
}
