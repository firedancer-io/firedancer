#define _DEFAULT_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../discof/rpcserver/fd_rpc_service.h"
#include "../../funk/fd_funk.h"

#define SHAM_LINK_CONTEXT fd_rpc_ctx_t
#define SHAM_LINK_NAME    replay_sham_link
#include "sham_link.h"

#define SHAM_LINK_CONTEXT fd_rpc_ctx_t
#define SHAM_LINK_NAME    stake_sham_link
#include "sham_link.h"

static void
init_args( int * argc, char *** argv, fd_rpcserver_args_t * args ) {
  memset( args, 0, sizeof(fd_rpcserver_args_t) );

  const char * funk_wksp_name = fd_env_strip_cmdline_cstr( argc, argv, "--funk-wksp-name", NULL, "fd1_funk.wksp" );
  if( FD_UNLIKELY( !funk_wksp_name ))
    FD_LOG_ERR(( "--funk-wksp-name argument is required" ));
  fd_wksp_t * funk_wksp = fd_wksp_attach( funk_wksp_name );
  if( FD_UNLIKELY( !funk_wksp ))
    FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", funk_wksp_name ));
  fd_wksp_tag_query_info_t info;
  ulong tag = 1;
  if( fd_wksp_tag_query( funk_wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace does not contain a funk" ));
  }
  void * funk_shmem = fd_wksp_laddr_fast( funk_wksp, info.gaddr_lo );
  fd_funk_t * funk = fd_funk_join( args->funk, funk_shmem );
  if( FD_UNLIKELY( !funk ))
    FD_LOG_ERR(( "failed to join funk" ));


  const char * wksp_name = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-blockstore", NULL, "fd1_blockstore.wksp" );
  FD_LOG_NOTICE(( "attaching to workspace \"%s\"", wksp_name ));
  fd_wksp_t * wksp = fd_wksp_attach( wksp_name );
  if( FD_UNLIKELY( !wksp ) )
    FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
  tag = 1;
  if( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace \"%s\" does not contain a blockstore", wksp_name ));
  }
  fd_wksp_mprotect( wksp, 1 );

  args->port    = (ushort)fd_env_strip_cmdline_ulong( argc, argv, "--port", NULL, 8899 );

  args->params.max_connection_cnt =    fd_env_strip_cmdline_ulong( argc, argv, "--max-connection-cnt",    NULL, 30 );
  args->params.max_ws_connection_cnt = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-connection-cnt", NULL, 10 );
  args->params.max_request_len =       fd_env_strip_cmdline_ulong( argc, argv, "--max-request-len",       NULL, 1<<16 );
  args->params.max_ws_recv_frame_len = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-recv-frame-len", NULL, 1<<16 );
  args->params.max_ws_send_frame_cnt = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-send-frame-cnt", NULL, 100 );
  args->params.outgoing_buffer_sz    = fd_env_strip_cmdline_ulong( argc, argv, "--max-send-buf",          NULL, 100U<<20U );
  args->block_index_max              = fd_env_strip_cmdline_uint ( argc, argv, "--max-block_idx",         NULL, 65536 );
  args->txn_index_max                = fd_env_strip_cmdline_uint ( argc, argv, "--max-txn-idx",           NULL, 1048576 );
  args->acct_index_max               = fd_env_strip_cmdline_uint ( argc, argv, "--max-acct-idx",          NULL, 1048576 );
  strncpy(args->history_file,          fd_env_strip_cmdline_cstr ( argc, argv, "--rpc-history-file",      NULL, "rpc_history" ), sizeof(args->history_file)-1 );

  const char * tpu_host = fd_env_strip_cmdline_cstr ( argc, argv, "--local-tpu-host", NULL, "127.0.0.1" );
  ulong tpu_port = fd_env_strip_cmdline_ulong( argc, argv, "--local-tpu-port", NULL, 9001U );
  memset( &args->tpu_addr, 0, sizeof(args->tpu_addr) );
  args->tpu_addr.sin_family = AF_INET;
  if( !inet_aton( tpu_host, &args->tpu_addr.sin_addr ) ) {
    struct hostent * hent = gethostbyname( tpu_host );
    if( hent == NULL ) {
      FD_LOG_WARNING(( "unable to resolve tpu host %s", tpu_host ));
      exit(-1);
    }
    args->tpu_addr.sin_addr.s_addr = ( (struct in_addr *)hent->h_addr_list[0] )->s_addr;
  }
  if( tpu_port < 1024 || tpu_port > (int)USHORT_MAX ) {
    FD_LOG_ERR(( "invalid tpu port number" ));
    exit(-1);
  }
  args->tpu_addr.sin_port = htons( (ushort)tpu_port );
  FD_LOG_NOTICE(( "using tpu %s:%u", inet_ntoa( args->tpu_addr.sin_addr ), (uint)ntohs( args->tpu_addr.sin_port ) ));
}

static void
init_args_offline( int * argc, char *** argv, fd_rpcserver_args_t * args ) {
  memset( args, 0, sizeof(fd_rpcserver_args_t) );
  args->offline = 1;

  const char * funk_wksp_name = fd_env_strip_cmdline_cstr( argc, argv, "--funk-wksp-name", NULL, "fd1_funk.wksp" );
  if( FD_UNLIKELY( !funk_wksp_name ))
    FD_LOG_ERR(( "--funk-wksp-name argument is required" ));
  fd_wksp_t * funk_wksp = fd_wksp_attach( funk_wksp_name );
  if( FD_UNLIKELY( !funk_wksp ))
    FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", funk_wksp_name ));
  fd_wksp_tag_query_info_t info;
  ulong tag = 1;
  if( fd_wksp_tag_query( funk_wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace does not contain a funk" ));
  }
  void * funk_shmem = fd_wksp_laddr_fast( funk_wksp, info.gaddr_lo );
  fd_funk_t * funk = fd_funk_join( args->funk, funk_shmem );
  if( FD_UNLIKELY( !funk ))
    FD_LOG_ERR(( "failed to join funk" ));

  fd_wksp_t * wksp;
  const char * wksp_name = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-blockstore", NULL, NULL );
  if( wksp_name != NULL ) {
    FD_LOG_NOTICE(( "attaching to workspace \"%s\"", wksp_name ));
    wksp = fd_wksp_attach( wksp_name );
    if( !wksp ) FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
  } else {
    char const * restore = fd_env_strip_cmdline_cstr ( argc, argv, "--restore-blockstore", NULL, NULL );
    if( restore == NULL ) FD_LOG_ERR(( "must use --wksp-name-blockstore or --restore-blockstore in offline mode" ));
    fd_wksp_preview_t preview[1];
    int err = fd_wksp_preview( restore, preview );
    if( err ) FD_LOG_ERR(( "unable to restore %s: error %d", restore, err ));
    ulong page_cnt = (preview->data_max + FD_SHMEM_GIGANTIC_PAGE_SZ-1U)/FD_SHMEM_GIGANTIC_PAGE_SZ;
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, page_cnt, 0, "wksp-blockstore", 0UL );
    if( !wksp ) FD_LOG_ERR(( "unable to restore %s: failed to create wksp", restore ));
    FD_LOG_NOTICE(( "restoring blockstore wksp %s", restore ));
    fd_wksp_restore( wksp, restore, preview->seed );
  }
  tag = 1;
  if( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace does not contain a blockstore" ));
  }
  fd_wksp_mprotect( wksp, 1 );

  args->port = (ushort)fd_env_strip_cmdline_ulong( argc, argv, "--port", NULL, 8899 );

  args->params.max_connection_cnt =    fd_env_strip_cmdline_ulong( argc, argv, "--max-connection-cnt",    NULL, 50 );
  args->params.max_ws_connection_cnt = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-connection-cnt", NULL, 10 );
  args->params.max_request_len =       fd_env_strip_cmdline_ulong( argc, argv, "--max-request-len",       NULL, 1<<16 );
  args->params.max_ws_recv_frame_len = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-recv-frame-len", NULL, 2048 );
  args->params.max_ws_send_frame_cnt = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-send-frame-cnt", NULL, 100 );
  args->params.outgoing_buffer_sz    = fd_env_strip_cmdline_ulong( argc, argv, "--max-send-buf",          NULL, 100U<<20U );
  args->block_index_max              = fd_env_strip_cmdline_uint ( argc, argv, "--max-block_idx",         NULL, 65536 );
  args->txn_index_max                = fd_env_strip_cmdline_uint ( argc, argv, "--max-txn-idx",           NULL, 1048576 );
  args->acct_index_max               = fd_env_strip_cmdline_uint ( argc, argv, "--max-acct-idx",          NULL, 1048576 );
  strncpy(args->history_file,          fd_env_strip_cmdline_cstr ( argc, argv, "--rpc-history-file",      NULL, "rpc_history" ), sizeof(args->history_file)-1 );
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

  replay_sham_link_t * rep_notify = NULL;
  stake_sham_link_t * stake_notify = NULL;

  ulong offline = fd_env_strip_cmdline_ulong( &argc, &argv, "--offline", NULL, 0 );
  if( !offline ) {
    init_args( &argc, &argv, &args );

    const char * wksp_name = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp-name-replay-notify", NULL, "fd1_replay_notif.wksp" );
    rep_notify = replay_sham_link_new( aligned_alloc( replay_sham_link_align(), replay_sham_link_footprint() ), wksp_name );

    wksp_name = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp-name-stake-out", NULL, "fd1_stake_out.wksp" );
    stake_notify = stake_sham_link_new( aligned_alloc( stake_sham_link_align(), stake_sham_link_footprint() ), wksp_name );

  } else {
    init_args_offline( &argc, &argv, &args );
  }

#define SMAX 1LU<<30
  uchar * smem = aligned_alloc( FD_SPAD_ALIGN, SMAX );
  args.spad = fd_spad_join( fd_spad_new( smem, SMAX ) );
  fd_spad_push( args.spad );

  struct sigaction sa = {
    .sa_handler = signal1,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  signal( SIGPIPE, SIG_IGN );

  fd_rpc_ctx_t * ctx = NULL;
  fd_rpc_create_ctx( &args, &ctx );
  fd_rpc_start_service( &args, ctx );

  if( args.offline ) {
    while( !stopflag ) {
      fd_rpc_ws_poll( ctx );
    }
    fd_halt();
    return 0;
  }

  replay_sham_link_start( rep_notify );
  stake_sham_link_start( stake_notify );
  while( !stopflag ) {
    replay_sham_link_poll( rep_notify, ctx );

    stake_sham_link_poll( stake_notify, ctx );

    fd_rpc_ws_poll( ctx );
  }

  fd_halt();
  return 0;
}

static void
replay_sham_link_during_frag(fd_rpc_ctx_t * ctx, void const * msg, int sz) {
  fd_rpc_replay_during_frag( ctx, msg, sz );
}

static void
replay_sham_link_after_frag(fd_rpc_ctx_t * ctx) {
  fd_rpc_replay_after_frag( ctx );
}

static void
stake_sham_link_during_frag(fd_rpc_ctx_t * ctx, void const * msg, int sz) {
  fd_rpc_stake_during_frag( ctx, msg, sz );
}

static void
stake_sham_link_after_frag(fd_rpc_ctx_t * ctx) {
  fd_rpc_stake_after_frag( ctx );
}
