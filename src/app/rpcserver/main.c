#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fd_rpc_service.h"

/*
  Offline sample:
    build/native/gcc/bin/fd_ledger --cmd ingest --rocksdb /data/asiegel/firedancer/dump/testnet-281688085/rocksdb --index-max 5000000 --end-slot 281688085 --page-cnt 30 --funk-page-cnt 16 --snapshot /data/asiegel/firedancer/dump/testnet-281688085/snapshot-281688080-6NHAVEju9WSsz7LQ3sLS9Yn2Tk9J7QByHRFEQLvXKqHG.tar.zst --checkpt /data/asiegel/test-bstore.wksp --checkpt-funk /data/asiegel/test-funk.wksp --copy-txn-status 1
    build/native/gcc/bin/fd_rpcserver --offline 1 --port 8123 --restore-funk /data/asiegel/test-funk.wksp --restore-blockstore /data/asiegel/test-bstore.wksp
*/

static void
init_args( int * argc, char *** argv, fd_rpcserver_args_t * args ) {
  memset( args, 0, sizeof(fd_rpcserver_args_t) );

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
  FD_LOG_NOTICE(( "blockstore has slot root=%lu", args->blockstore->smr ));
  fd_wksp_mprotect( wksp, 1 );

  wksp_name = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-replay-notify", NULL, "fd1_replay_notif.wksp" );
  args->rep_notify = replay_sham_link_new( aligned_alloc( replay_sham_link_align(), replay_sham_link_footprint() ), wksp_name );

  wksp_name = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-stake-out", NULL, "fd1_stake_out.wksp" );
  args->stake_notify = stake_sham_link_new( aligned_alloc( stake_sham_link_align(), stake_sham_link_footprint() ), wksp_name );
  fd_pubkey_t identity_key[1]; /* Just the public key */
  memset( identity_key, 0xa5, sizeof(fd_pubkey_t) );
  args->stake_ci = fd_stake_ci_join( fd_stake_ci_new( aligned_alloc( fd_stake_ci_align(), fd_stake_ci_footprint() ), identity_key ) );

  args->port = (ushort)fd_env_strip_cmdline_ulong( argc, argv, "--port", NULL, 8899 );

  args->params.max_connection_cnt =    fd_env_strip_cmdline_ulong( argc, argv, "--max-connection-cnt",    NULL, 10 );
  args->params.max_ws_connection_cnt = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-connection-cnt", NULL, 10 );
  args->params.max_request_len =       fd_env_strip_cmdline_ulong( argc, argv, "--max-request-len",       NULL, 1<<16 );
  args->params.max_ws_recv_frame_len = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-recv-frame-len", NULL, 2048 );
  args->params.max_ws_send_frame_cnt = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-send-frame-cnt", NULL, 100 );
  args->params.outgoing_buffer_sz    = fd_env_strip_cmdline_ulong( argc, argv, "--max-send-buf",          NULL, 100U<<20U );

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

  fd_wksp_t * wksp;
  char const * wksp_name = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-funk", NULL, NULL );
  if( wksp_name != NULL ) {
    FD_LOG_NOTICE(( "attaching to workspace \"%s\"", wksp_name ));
    wksp = fd_wksp_attach( wksp_name );
    if( !wksp ) FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
  } else {
    char const * restore = fd_env_strip_cmdline_cstr ( argc, argv, "--restore-funk", NULL, NULL );
    if( restore == NULL ) FD_LOG_ERR(( "must use --wksp-name-funk or --restore-funk in offline mode" ));
    uint seed;
    ulong part_max;
    ulong data_max;
    int err = fd_wksp_restore_preview( restore, &seed, &part_max, &data_max );
    if( err ) FD_LOG_ERR(( "unable to restore %s: error %d", restore, err ));
    ulong page_cnt = (data_max + FD_SHMEM_GIGANTIC_PAGE_SZ-1U)/FD_SHMEM_GIGANTIC_PAGE_SZ;
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, page_cnt, 0, "wksp-funk", 0UL );
    if( !wksp ) FD_LOG_ERR(( "unable to restore %s: failed to create wksp", restore ));
    FD_LOG_NOTICE(( "restoring funk wksp %s", restore ));
    fd_wksp_restore( wksp, restore, seed );
  }
  fd_wksp_tag_query_info_t info;
  ulong tag = FD_FUNK_MAGIC;
  if( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace does not contain a funk" ));
  }
  void * shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
  args->funk = fd_funk_join( shmem );
  if( args->funk == NULL ) {
    FD_LOG_ERR(( "failed to join a funky" ));
  }
  fd_wksp_mprotect( wksp, 1 );

  wksp_name = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-blockstore", NULL, NULL );
  if( wksp_name != NULL ) {
    FD_LOG_NOTICE(( "attaching to workspace \"%s\"", wksp_name ));
    wksp = fd_wksp_attach( wksp_name );
    if( !wksp ) FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
  } else {
    char const * restore = fd_env_strip_cmdline_cstr ( argc, argv, "--restore-blockstore", NULL, NULL );
    if( restore == NULL ) FD_LOG_ERR(( "must use --wksp-name-blockstore or --restore-blockstore in offline mode" ));
    uint seed;
    ulong part_max;
    ulong data_max;
    int err = fd_wksp_restore_preview( restore, &seed, &part_max, &data_max );
    if( err ) FD_LOG_ERR(( "unable to restore %s: error %d", restore, err ));
    ulong page_cnt = (data_max + FD_SHMEM_GIGANTIC_PAGE_SZ-1U)/FD_SHMEM_GIGANTIC_PAGE_SZ;
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, page_cnt, 0, "wksp-blockstore", 0UL );
    if( !wksp ) FD_LOG_ERR(( "unable to restore %s: failed to create wksp", restore ));
    FD_LOG_NOTICE(( "restoring blockstore wksp %s", restore ));
    fd_wksp_restore( wksp, restore, seed );
  }
  tag = FD_BLOCKSTORE_MAGIC;
  if( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace does not contain a blockstore" ));
  }
  shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
  args->blockstore = fd_blockstore_join( shmem );
  if( args->blockstore == NULL ) {
    FD_LOG_ERR(( "failed to join a blockstore" ));
  }
  FD_LOG_NOTICE(( "blockstore has slot root=%lu", args->blockstore->smr ));
  fd_wksp_mprotect( wksp, 1 );

  args->port = (ushort)fd_env_strip_cmdline_ulong( argc, argv, "--port", NULL, 8899 );

  args->params.max_connection_cnt =    fd_env_strip_cmdline_ulong( argc, argv, "--max-connection-cnt",    NULL, 50 );
  args->params.max_ws_connection_cnt = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-connection-cnt", NULL, 10 );
  args->params.max_request_len =       fd_env_strip_cmdline_ulong( argc, argv, "--max-request-len",       NULL, 1<<16 );
  args->params.max_ws_recv_frame_len = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-recv-frame-len", NULL, 2048 );
  args->params.max_ws_send_frame_cnt = fd_env_strip_cmdline_ulong( argc, argv, "--max-ws-send-frame-cnt", NULL, 100 );
  args->params.outgoing_buffer_sz    = fd_env_strip_cmdline_ulong( argc, argv, "--max-send-buf",          NULL, 100U<<20U );
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

#define SMAX 1LU<<28
  uchar * smem = aligned_alloc( FD_SCRATCH_SMEM_ALIGN,
                                fd_ulong_align_up( fd_scratch_smem_footprint( SMAX  ), FD_SCRATCH_SMEM_ALIGN ) );
  ulong fmem[16U];
  fd_scratch_attach( smem, fmem, SMAX, 16U );

  ulong offline = fd_env_strip_cmdline_ulong( &argc, &argv, "--offline", NULL, 0 );
  if( !offline ) {
    init_args( &argc, &argv, &args );
  } else {
    init_args_offline( &argc, &argv, &args );
  }

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
  fd_rpc_start_service( &args, &ctx );

  if( args.offline ) {
    while( !stopflag ) {
      fd_rpc_ws_poll( ctx );
    }
    fd_rpc_stop_service( ctx );
    fd_halt();
    return 0;
  }

  replay_sham_link_start( args.rep_notify );
  stake_sham_link_start( args.stake_notify );
  while( !stopflag ) {
    fd_replay_notif_msg_t msg;
    replay_sham_link_poll( args.rep_notify, ctx, &msg );

    stake_sham_link_poll( args.stake_notify, ctx, args.stake_ci );

    fd_rpc_ws_poll( ctx );
  }

  fd_rpc_stop_service( ctx );

  fd_halt();
  return 0;
}
