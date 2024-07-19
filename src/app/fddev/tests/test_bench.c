#define _GNU_SOURCE
#include "test_fddev.h"
#include "../rpc_client/fd_rpc_client.h"
#include "../rpc_client/fd_rpc_client_private.h"

#define FD_TEST_RPC_RESPONSE_TIMEOUT 5L*1000L*1000L*1000L /* 5 seconds */

static ulong
rpc_txn_count( fd_rpc_client_t * rpc ) {

  long txncount_request  = fd_rpc_client_request_transaction_count( rpc );
  if( FD_UNLIKELY( txncount_request<0L ) ) FD_LOG_ERR(( "failed to send RPC request" ));

  long txncount_deadline = fd_log_wallclock() + FD_TEST_RPC_RESPONSE_TIMEOUT;

  fd_rpc_client_response_t * response;
  do {
    fd_rpc_client_service( rpc, 0 );
    response = fd_rpc_client_status( rpc, txncount_request, 0 );
    if( FD_UNLIKELY( response->status==FD_RPC_CLIENT_PENDING ) ) {
      if( FD_UNLIKELY( fd_log_wallclock()>=txncount_deadline ) )
        FD_LOG_ERR(( "timed out waiting for RPC server to respond" ));
      continue;
    }
    break;
  } while(1);

  if( FD_UNLIKELY( response->status!=FD_RPC_CLIENT_SUCCESS ) )
    FD_LOG_ERR(( "RPC server returned error %ld", response->status ));
  
  ulong txns = response->result.transaction_count.transaction_count;

  fd_rpc_client_close( rpc, txncount_request );
  return txns;
}

static int
fddev_spammer_quic( config_t * config,
                    int        pipe_fd ) {
  (void)pipe_fd;

  fd_log_thread_set( "spammer" );
  args_t args = {0};
  /* Run the spammer for 5 seconds */
  args.spammer.duration = 5L;

  fd_caps_ctx_t caps[1] = {0};
  spammer_cmd_perm( &args, caps, config );
  if( FD_UNLIKELY( caps->err_cnt ) ) {
    for( ulong i=0; i<caps->err_cnt; i++ ) FD_LOG_WARNING(( "%s", caps->err[ i ] ));
    FD_LOG_ERR(( "insufficient permissions to run spammer" ));
  }
  spammer_cmd_fn( &args, config );
  return 0;
}

static int
fddev_spammer_udp( config_t * config,
                   int        pipe_fd ) {
  (void)pipe_fd;

  fd_log_thread_set( "spammer" );
  args_t args = {0};
  /* Run the spammer for 5 seconds */
  args.spammer.duration = 5L;
  args.spammer.no_quic  = 1;

  fd_caps_ctx_t caps[1] = {0};
  spammer_cmd_perm( &args, caps, config );
  if( FD_UNLIKELY( caps->err_cnt ) ) {
    for( ulong i=0; i<caps->err_cnt; i++ ) FD_LOG_WARNING(( "%s", caps->err[ i ] ));
    FD_LOG_ERR(( "insufficient permissions to run spammer" ));
  }
  spammer_cmd_fn( &args, config );
  return 0;
}

int
fddev_test_run( int     argc,
                char ** argv,
                int (* run)( config_t * config ) ) {
  int is_base_run = argc==1 ||
    (argc==5 && !strcmp( argv[ 1 ], "--log-path" ) && !strcmp( argv[ 3 ], "--log-level-stderr" ));

  if( FD_LIKELY( is_base_run ) ) {
    if( FD_UNLIKELY( -1==unshare( CLONE_NEWPID ) ) ) FD_LOG_ERR(( "unshare(CLONE_NEWPID) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    int pid = fork();
    if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( !pid ) {
      fd_boot( &argc, &argv );
      fd_log_thread_set( "supervisor" );

      static config_t config[1];
      fdctl_cfg_from_env( &argc, &argv, config );
      config->log.log_fd = fd_log_private_logfile_fd();
      config->log.lock_fd = init_log_memfd();
      config->tick_per_ns_mu = fd_tempo_tick_per_ns( &config->tick_per_ns_sigma );
      config->rpc.port = 8899;
      config->rpc.full_api = 1;

      return run( config );
    } else {
      int wstatus;
      for(;;) {
        int exited_pid = waitpid( pid, &wstatus, __WALL );
        if( FD_UNLIKELY( -1==exited_pid && errno==EINTR ) ) continue;
        else if( FD_UNLIKELY( -1==exited_pid ) ) FD_LOG_ERR(( "waitpid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        else if( FD_UNLIKELY( !exited_pid ) ) FD_LOG_ERR(( "supervisor did not exit" ));
        break;
      }

      if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) return 128 + WTERMSIG( wstatus );
      else if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) return WEXITSTATUS( wstatus );
    }
  } else {
    return fddev_main( argc, argv );
  }

  return 0;
}

static int
test_fddev_bench( config_t * config ) {
  struct child_info configure = fork_child( "fddev configure", config, fddev_configure );
  wait_children( &configure, 1UL, 15UL );
  struct child_info wksp = fork_child( "fddev wksp", config, fddev_wksp );
  wait_children( &wksp, 1UL, 15UL );

  struct child_info dev = fork_child( "fddev dev", config, fddev_dev );
  
  fd_rpc_client_t rpc[ 1 ] = {0};
  FD_TEST( fd_rpc_client_join( fd_rpc_client_new( rpc, config->tiles.net.ip_addr, config->rpc.port ) ) );

  struct child_info spammer_quic = fork_child( "fddev spammer quic", config, fddev_spammer_quic );
  wait_children( &spammer_quic, 1UL, 10UL );
  ulong quic_txn = rpc_txn_count( rpc );

  struct child_info spammer_udp = fork_child( "fddev spammer udp", config, fddev_spammer_udp );

  struct child_info children[ 2 ] = { spammer_udp, dev };
  ulong exited = wait_children( children, 2UL, 10UL );
  if( FD_UNLIKELY( exited!=0UL ) ) FD_LOG_ERR(( "`%s` exited unexpectedly", children[ exited-1 ].name ));

  ulong udp_txn = rpc_txn_count( rpc );

  FD_TEST( quic_txn>10000UL );
  FD_TEST( ( udp_txn-quic_txn )>10000UL );

  return 0;
}

int
main( int     argc,
      char ** argv ) {
  return fddev_test_run( argc, argv, test_fddev_bench );
}
