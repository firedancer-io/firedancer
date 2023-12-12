#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run/run.h"
#include "rpc_client/fd_rpc_client.h"

#include "../../util/net/fd_ip4.h"

#include <unistd.h>
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

static ushort
bench_cpu_idx( config_t * const config ) {
  ushort tile_to_cpu[ FD_TILE_MAX ];
  ulong  affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, tile_to_cpu );

  ushort i;
  for( i=0; i<128; i++ ) {
    int found = 0;
    if( FD_UNLIKELY( i==config->layout.poh_core ) ) {
      found = 1;
      break;
    }
    for( ulong j=0; j<affinity_tile_cnt; j++ ) {
      if( tile_to_cpu[ j ]==i ) {
        found = 1;
        break;
      }
    }
    if( FD_UNLIKELY( !found ) ) break;
  }

  if( FD_UNLIKELY( i>=128 ) ) FD_LOG_ERR(( "no cpus left for bench" ));
  return i;
}

typedef struct __attribute__((packed)) {
    uchar sig_cnt; /* = 1 */
    uchar signature[64];
    uchar _sig_cnt; /* also 1 */
    uchar ro_signed_cnt; /* = 0 */
    uchar ro_unsigned_cnt; /* = 1 . System program */
    uchar acct_addr_cnt; /* = 3 */
    uchar fee_payer[32];
    uchar dest_acct[32];
    uchar system_program[32]; /* = {0} */
    uchar recent_blockhash[32];
    uchar instr_cnt; /* = 1 */
    /* Start of instruction */
    uchar prog_id; /* = 2 */
    uchar acct_cnt; /* = 2 */
    uchar acct_idx[2]; /* 0, 1 */
    uchar data_sz; /* = 12 */
    uint  transfer_descriminant; /* = 2 */
    ulong lamports;
} transfer_t;

static void
generate_transfers( transfer_t *  transfers,
                    ulong         transfers_cnt,
                    const uchar * sender_public_key,
                    const uchar * sender_private_key,
                    uchar *       recent_blockhash ) {
  fd_sha512_t _sha[1];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  FD_TEST( sha );

  for( ulong i=0UL; i<transfers_cnt; i++ ) {
    transfer_t * transfer = &transfers[ i ];
    *transfer = (transfer_t){
      /* Fixed values */
      .sig_cnt = 1,
      ._sig_cnt = 1,
      .ro_signed_cnt = 0,
      .ro_unsigned_cnt = 1,
      .acct_addr_cnt = 3,
      .system_program = {0},
      .instr_cnt = 1,
      .prog_id = 2,
      .acct_cnt = 2,
      .acct_idx = { 0, 1 },
      .data_sz = 12,
      .transfer_descriminant = 2,

      /* Variable */
      .lamports = i, /* Unique per transaction so they aren't duplicates */
    };

    fd_memcpy( transfer->fee_payer, sender_public_key, 32UL );
    fd_memset( transfer->dest_acct, 0, 32UL ); /* Just send to nowhere */
    fd_memcpy( transfer->recent_blockhash, recent_blockhash, 32UL );

    fd_ed25519_sign( transfer->signature,
                     &(transfer->_sig_cnt),
                     sizeof(*transfer)-65UL,
                     sender_public_key,
                     sender_private_key,
                     sha );
  }
}

extern int * fd_log_private_shared_lock;

static int
main_bencher( void * _args ) {
  config_t * const config = _args;

  if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, -19 ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  cpu_set_t cpu_set[1];
  CPU_ZERO( cpu_set );
  CPU_SET( bench_cpu_idx( config ), cpu_set );
  if( FD_UNLIKELY( -1==sched_setaffinity( 0, sizeof(cpu_set_t), cpu_set ) ) ) FD_LOG_ERR(( "sched_setaffinity() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int conn = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( -1==conn ) ) FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = fd_ushort_bswap( config->tiles.quic.regular_transaction_listen_port ),
    .sin_addr.s_addr = config->tiles.net.ip_addr,
  };
  if( FD_UNLIKELY( -1==connect( conn, fd_type_pun( &addr ), sizeof(addr) ) ) ) FD_LOG_ERR(( "connect() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  char faucet_key_path[ PATH_MAX ];
  snprintf1( faucet_key_path, PATH_MAX, "%s/faucet.json", config->scratch_directory );

  const uchar * private_key = load_key_into_protected_memory( faucet_key_path, 0 );
  const uchar * public_key = private_key+32UL;

  fd_rpc_client_t * rpc_client = fd_rpc_client_join( fd_rpc_client_new( aligned_alloc( FD_RPC_CLIENT_ALIGN, FD_RPC_CLIENT_FOOTPRINT ),
                                                                        FD_IP4_ADDR(127, 0, 0, 1),
                                                                        config->rpc.port ) );

  FD_TEST( FD_RPC_CLIENT_SUCCESS==fd_rpc_client_wait_ready( rpc_client, 5000000000L ) );

  long request = fd_rpc_client_request_latest_block_hash( rpc_client );
  FD_TEST( request>=0L );

  fd_rpc_client_response_t * response = fd_rpc_client_status( rpc_client, request, 1 );
  if( FD_UNLIKELY( response->status!=FD_RPC_CLIENT_SUCCESS ) ) FD_LOG_ERR(( "fd_rpc_client_status() failed" ));

#define TRANSFER_CNT (1000000UL)
  FD_LOG_NOTICE(( "generating %lu transfers", TRANSFER_CNT ));

  transfer_t * transfers = malloc( TRANSFER_CNT * sizeof(transfer_t ) );
  FD_TEST( transfers );
  generate_transfers( transfers, TRANSFER_CNT, public_key, private_key, response->result.latest_block_hash.block_hash );

  /* wait until validator is ready to receive txns before sending */
  ready_cmd_fn( NULL, config );

  /* Wait until sampler is ready. */
  fd_log_private_shared_lock[ 1 ]++;
  while( fd_log_private_shared_lock[ 1 ]!=2 ) FD_SPIN_PAUSE();

  FD_LOG_NOTICE(( "sending %lu transfers", TRANSFER_CNT ));

  for( ulong i=0; i<TRANSFER_CNT; i++ ) {
    transfer_t * transfer = &transfers[ i ];
    if( FD_UNLIKELY( -1==send( conn, transfer, sizeof(*transfer), 0 ) ) ) FD_LOG_ERR(( "send() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
#undef TRANSFER_CNT

  FD_LOG_NOTICE(( "done sending" ));

  return 0;
}

static int
main_sampler( void * _args ) {
  config_t * const config = _args;

  while( fd_log_private_shared_lock[ 1 ]!=1 ) FD_SPIN_PAUSE();

  fd_rpc_client_t * rpc_client = fd_rpc_client_join( fd_rpc_client_new( aligned_alloc( FD_RPC_CLIENT_ALIGN, FD_RPC_CLIENT_FOOTPRINT ),
                                                                        FD_IP4_ADDR(127, 0, 0, 1),
                                                                        config->rpc.port ) );

  FD_TEST( FD_RPC_CLIENT_SUCCESS==fd_rpc_client_wait_ready( rpc_client, 5000000000L ) );

  long request = fd_rpc_client_request_transaction_count( rpc_client );
  FD_TEST( request>=0L );

  fd_rpc_client_response_t * response = fd_rpc_client_status( rpc_client, request, 1 );
  if( FD_UNLIKELY( response->status!=FD_RPC_CLIENT_SUCCESS ) ) FD_LOG_ERR(( "fd_rpc_client_status() failed" ));

  ulong last_transaction_count = response->result.transaction_count.transaction_count;

  fd_rpc_client_close( rpc_client, request );

  fd_log_private_shared_lock[ 1 ]++;

  long then = fd_log_wallclock() + 1000000000L;
  for( ulong i=0; i<3UL; i++ ) {
    long now = fd_log_wallclock();

    long dt = fd_long_if( now<then, then-now, 0 );
    while( dt ) dt = fd_log_sleep( dt );

    request = fd_rpc_client_request_transaction_count( rpc_client );
    FD_TEST( request>=0L );
    fd_rpc_client_response_t * response = fd_rpc_client_status( rpc_client, request, 1 );
    if( FD_UNLIKELY( response->status!=FD_RPC_CLIENT_SUCCESS ) ) FD_LOG_ERR(( "fd_rpc_client_status() failed" ));

    FD_LOG_NOTICE(( "TPS: %lu", response->result.transaction_count.transaction_count - last_transaction_count ));
    last_transaction_count = response->result.transaction_count.transaction_count;

    fd_rpc_client_close( rpc_client, request );

    then += 1000000000L;
  }

  return 0;
}

static int
clone_child( config_t * const config,
             int            (*fn)(void *),
             int *            out_pipefd ) {
  int pipefd[2];
  if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC | O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  void * stack = fd_tile_private_stack_new( 0, 65535UL );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for boot process" ));

  int bencher_pid = clone( fn, (uchar *)stack + FD_TILE_PRIVATE_STACK_SZ, 0, config );
  if( FD_UNLIKELY( bencher_pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  *out_pipefd = pipefd[ 0 ];
  return bencher_pid;
}

static void
printf_left( fd_topo_t * topo ,
             ulong       row_idx,
             char *      buf,
             ulong       buf_sz ) {
  if( 0UL==row_idx ) {
    snprintf( buf, buf_sz, "\n             link |  ovrnp cnt |  ovrnr cnt |   slow cnt |     tx seq |     rx seq" );
    return;
  } else if( 1UL==row_idx ) {
    snprintf( buf, buf_sz,   "------------------+------------+------------+------------+------------+-----------" );
    return;
  }

  ulong link_idx = row_idx-2UL;
  ulong tile_idx=0UL;
  ulong in_idx=0UL;
  for( ; link_idx && tile_idx<topo->tile_cnt; tile_idx++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ tile_idx ];
    for( in_idx=0UL; in_idx<tile->in_cnt; in_idx++ ) {
      if( !--link_idx ) break;
    }
    if( !link_idx ) break;
  }

  if( tile_idx>=topo->tile_cnt ) {
    snprintf( buf, buf_sz,   "                                                                                  " );
    return;
  }

  fd_topo_link_t * link = &topo->links[ topo->tiles[ tile_idx ].in_link_id[ in_idx ] ];
  fd_topo_tile_t * link_consumer = &topo->tiles[ tile_idx ];
  ulong link_consumer_in_idx = in_idx;

  char * producer;
  switch( link->kind ) {
    /* Special case Solana produced link names for now since we can't find them
        in the topology. */
    case FD_TOPO_LINK_KIND_POH_TO_SHRED: {
      producer = "poh";
      break;
    }
    case FD_TOPO_LINK_KIND_STAKE_TO_OUT: {
      producer = "stakes";
      break;
    }
    case FD_TOPO_LINK_KIND_GOSSIP_TO_PACK: {
      producer = "gossip";
      break;
    }
    case FD_TOPO_LINK_KIND_CRDS_TO_SHRED: {
      producer = "crds";
      break;
    }
    default: {
      ulong producer_tile_id = fd_topo_find_link_producer( topo, link );
      FD_TEST( producer_tile_id != ULONG_MAX );
      producer = fd_topo_tile_kind_str( topo->tiles[ producer_tile_id ].kind );
    }
  }

  ulong const * in_metrics = (ulong const *)fd_metrics_link_in( link_consumer->metrics, link_consumer_in_idx );

  ulong producer_id = fd_topo_find_link_producer( topo, link );
  ulong const * out_metrics = NULL;
  if( FD_LIKELY( producer_id!=ULONG_MAX && link_consumer->in_link_reliable[ link_consumer_in_idx ] ) ) {
    fd_topo_tile_t * producer = &topo->tiles[ producer_id ];
    ulong out_idx;
    for( out_idx=0UL; out_idx<producer->out_cnt; out_idx++ ) {
      if( producer->out_link_id[ out_idx ]==link->id ) break;
    }
    out_metrics = fd_metrics_link_out( producer->metrics, out_idx );
  }

  ulong printed = 0;
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " %7s->%-7s", producer, fd_topo_tile_kind_str( link_consumer->kind ) );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %10lu", in_metrics[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF ] );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %10lu", in_metrics[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_OFF ] );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %10lu", out_metrics ? out_metrics[ FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF ] : 0UL );

  ulong const * seq = (ulong const *)fd_mcache_seq_laddr_const( link->mcache );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %10lu", fd_mcache_seq_query( seq ) );

  ulong const * fseq = link_consumer->in_link_fseq[ link_consumer_in_idx ];
  if( fseq ) {
    printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %10lu", fd_fseq_query( fseq ) );
  } else {
    printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %10lu", 0UL );
  }
}

static void
printf_right( fd_topo_t * topo ,
              ulong       row_idx,
              char *      buf,
              ulong       buf_sz ) {
  ulong tile_kind=0UL;
  for( tile_kind=0UL; tile_kind<FD_TOPO_TILE_KIND_MAX; tile_kind++ ) {
    ulong cnt = fd_topo_tile_kind_cnt( topo, tile_kind );
    if( cnt==0UL ) continue;

    if( tile_kind==FD_TOPO_TILE_KIND_MAX-1 && 2+cnt<=row_idx ) {
      row_idx -= 2+cnt;
      continue;
    } else if( 3+cnt<=row_idx ) {
      row_idx -= 3+cnt;
      continue;
    } else {
      break;
    }
  }

  if( tile_kind>=FD_TOPO_TILE_KIND_MAX ) {
    return;
  }

  if( 0UL==row_idx ) {
    snprintf( buf, buf_sz, "        tile |  backp cnt | %% hkeep | %% backp |  %% wait | %% ovrnp | %% ovrnr | %% filt1 | %% filt2 | %% finish" );
    return;
  } else if( 1UL==row_idx ) {
    snprintf( buf, buf_sz, "-------------+------------+---------+---------+---------+---------+---------+---------+---------+----------" );
    return;
  } else if( 2UL+fd_topo_tile_kind_cnt( topo, tile_kind )==row_idx ) {
    snprintf( buf, buf_sz, "" );
    return;
  }

  ulong tile_idx=row_idx-2UL;
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    if( topo->tiles[ i ].kind==tile_kind ) {
      if( !tile_idx-- ) {
        tile_idx = i;
        break;
      }
    }
  }
  
  fd_topo_tile_t * tile = &topo->tiles[ tile_idx ];

  fd_metrics_register( tile->metrics );

  ulong hkeep_ticks = FD_MHIST_SUM( STEM, LOOP_HOUSEKEEPING_DURATION_SECONDS );
  ulong backp_ticks = FD_MHIST_SUM( STEM, LOOP_BACKPRESSURE_DURATION_SECONDS );
  ulong caught_ticks = FD_MHIST_SUM( STEM, LOOP_CAUGHT_UP_DURATION_SECONDS );
  ulong ovrnp_ticks = FD_MHIST_SUM( STEM, LOOP_OVERRUN_POLLING_DURATION_SECONDS );
  ulong ovrnr_ticks = FD_MHIST_SUM( STEM, LOOP_OVERRUN_READING_DURATION_SECONDS );
  ulong filt1_ticks = FD_MHIST_SUM( STEM, LOOP_FILTER_BEFORE_FRAGMENT_DURATION_SECONDS );
  ulong filt2_ticks = FD_MHIST_SUM( STEM, LOOP_FILTER_AFTER_FRAGMENT_DURATION_SECONDS );
  ulong finish_ticks = FD_MHIST_SUM( STEM, LOOP_FINISH_DURATION_SECONDS );
  ulong total_ticks = hkeep_ticks + backp_ticks + caught_ticks + ovrnp_ticks + ovrnr_ticks + filt1_ticks + filt2_ticks + finish_ticks;

  ulong printed = 0;
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " %7s(%lu) ", fd_topo_tile_kind_str( tile->kind ), tile->kind_id );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %10lu", FD_MCNT_GET( STEM, BACKPRESSURE_COUNT ) );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %7.3lf", 100.0*(double)hkeep_ticks/(double)total_ticks );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %7.3lf", 100.0*(double)backp_ticks/(double)total_ticks );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %7.3lf", 100.0*(double)caught_ticks/(double)total_ticks );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %7.3lf", 100.0*(double)ovrnp_ticks/(double)total_ticks );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %7.3lf", 100.0*(double)ovrnr_ticks/(double)total_ticks );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %7.3lf", 100.0*(double)filt1_ticks/(double)total_ticks );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %7.3lf", 100.0*(double)filt2_ticks/(double)total_ticks );
  printed += (ulong)snprintf( buf+printed, buf_sz-printed, " | %7.3lf", 100.0*(double)finish_ticks/(double)total_ticks );
}

void
bench_cmd_fn( args_t *         args,
              config_t * const config ) {
  (void)args;

  if( FD_LIKELY( !args->dev.no_configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
      configure_args.configure.stages[ i ] = STAGES[ i ];
    configure_cmd_fn( &configure_args, config );
  }

  update_config_for_dev( config );

  int stderr = dup( STDERR_FILENO );
  if( FD_UNLIKELY( -1==stderr ) ) FD_LOG_ERR(( "dup() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int nullfd = open( "/dev/null", O_RDWR );
  if( FD_UNLIKELY( nullfd==-1 ) ) FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==dup2( nullfd, STDERR_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( nullfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( STDIN_FILENO ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( STDOUT_FILENO ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int firedancer_pipefd;
  int firedancer_pid = clone_firedancer( config, stderr, &firedancer_pipefd );

  fd_log_private_shared_lock[ 1 ] = 0;

  if( FD_UNLIKELY( -1==dup2( stderr, STDERR_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( stderr) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int bencher_pipefd, sampler_pipefd;
  int bencher_pid = clone_child( config, main_bencher, &bencher_pipefd );
  int sampler_pid = clone_child( config, main_sampler, &sampler_pipefd );

  for( ulong i=0; i<2UL; i++ ) {
    int wstatus;
    int exited_pid = wait4( -1, &wstatus, (int)__WALL, NULL );
    if( FD_UNLIKELY( -1==exited_pid ) ) FD_LOG_ERR(( "wait4() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    char * child = NULL;
    if( FD_UNLIKELY( exited_pid==bencher_pid ) ) child = "bencher";
    else if( FD_UNLIKELY( exited_pid==sampler_pid ) ) child = "sampler";
    else if( FD_UNLIKELY( exited_pid==firedancer_pid ) ) child = "firedancer";
    else FD_LOG_ERR(( "unknown child process exited" ));

    if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
      FD_LOG_ERR(( "child `%s` process exited with signal %s", child, fd_io_strsignal( WTERMSIG( wstatus ) ) ));
      exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
    } else {
      int status = WEXITSTATUS( wstatus );
      if( FD_LIKELY( !status && (exited_pid==bencher_pid || exited_pid==sampler_pid) ) ) continue;
      FD_LOG_ERR(( "child `%s` process exited with status %d", child, status ));
      exit_group( status ? status : 1 );
    }
  }

  if( FD_UNLIKELY( close( firedancer_pipefd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( bencher_pipefd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( sampler_pipefd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( -1==dup2( STDERR_FILENO, STDOUT_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_topo_join_workspaces( config->name, &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topo_fill( &config->topo, FD_TOPO_FILL_MODE_JOIN );
  
  fd_topo_t * topo = &config->topo;

  ulong link_cnt = 0UL;
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    for( ulong in_idx=0UL; in_idx<topo->tiles[ tile_idx ].in_cnt; in_idx++ ) {
      link_cnt++;
    }
  }

  ulong tile_kind_cnt = 0UL;
  int tile_kind_seen[ FD_TOPO_TILE_KIND_MAX ] = {0};
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    if( !tile_kind_seen[ topo->tiles[ tile_idx ].kind ] ) {
      tile_kind_seen[ topo->tiles[ tile_idx ].kind ] = 1;
      tile_kind_cnt++;
    }
  }

  ulong row_cnt = fd_ulong_max( topo->tile_cnt + 3UL*tile_kind_cnt - 1, 2UL+link_cnt );
  for( ulong row_idx=0UL; row_idx<row_cnt; row_idx++ ) {
      char left[ 1024UL ];
      char right[ 1024UL ];

      printf_left( topo, row_idx, left, 1024UL );
      printf_right( topo, row_idx, right, 1024UL );

      printf( "%s      %s\n", left, right );
  }
}
