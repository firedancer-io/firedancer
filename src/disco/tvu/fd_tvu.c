#define _GNU_SOURCE /* See feature_test_macros(7) */

/* This represents a non-consensus node that validates block and serves them via RPC.
     1. receive shreds from Turbine / Repair
     2. put them in the Blockstore
     3. validate and execute them
     4. track and prune forks once they are finalized

   ./build/native/gcc/unit-test/test_tvu \
      --rpc-port 8124 \
      --gossip-peer-addr 86.109.3.165:8000 \
      --repair-peer-addr 86.109.3.165:8008 \
      --repair-peer-id F7SW17yGN7UUPQ519nxaDt26UMtvwJPSFVu9kBMBQpW \
      --incremental-snapshot http://entrypoint3.testnet.solana.com:8899/incremental-snapshot.tar.bz2 \
      --log-level-logfile 0 \
      --log-level-stderr 2 \
      --load /data/chali/funk

    ./build/native/gcc/unit-test/test_tvu \
      --rpc-port 8124 \
      --gossip-peer-addr entrypoint3.testnet.solana.com:8001 \
      --incremental-snapshot http://entrypoint3.testnet.solana.com:8899/incremental-snapshot.tar.bz2 \
      --load /data/chali/funk \
      --log-level-logfile 0 \
      --log-level-stderr 2

    ./build/native/gcc/unit-test/test_tvu \
      --rpc-port 8124 \
      --gossip-peer-addr 86.109.3.165:8000 \
      --load /data/funk \
    --log-level-logfile 0 \
    --log-level-stderr 2

    ./build/native/gcc/unit-test/test_tvu \
      --rpc-port 8124 \
      --gossip-peer-addr 127.0.0.1:1024 \
      --repair-peer-addr 127.0.0.1:1032 \
      --repair-peer-id DR4i5ZzAoEPxai8QiQ15wFvQSG7UbKDidBn5SLoyZ1p \
      --snapshot snapshot-* \
      --indexmax 16384 \
      --page-cnt 16
      --log-level-logfile 0 \
      --log-level-stderr 2

    More sample commands:

    rm -f *.zst ; wget --trust-server-names http://localhost:8899/snapshot.tar.bz2 ; wget
   --trust-server-names http://localhost:8899/incremental-snapshot.tar.bz2

    wget --trust-server-names http://86.109.3.165:8899/snapshot.tar.bz2 && wget --trust-server-names
   http://86.109.3.165:8899/incremental-snapshot.tar.bz2

    wget --trust-server-names http://entrypoint3.testnet.solana.com:8899/snapshot.tar.bz2 && wget \
   --trust-server-names http://entrypoint3.testnet.solana.com:8899/incremental-snapshot.tar.bz2

    build/native/gcc/bin/fd_frank_ledger --cmd ingest --snapshotfile snapshot-24* --incremental
   incremental-snapshot-24* --rocksdb /data/testnet/ledger/rocksdb --genesis
   /data/testnet/ledger/genesis.bin --txnstatus true --pages 100 --backup /data/asiegel/test_backup
   --slothistory 100

    build/native/gcc/unit-test/test_tvu --load /data/asiegel/test_backup --rpc-port 8123 --page-cnt
   100 \
      --gossip-peer-addr :8000 \
      --repair-peer-addr :8008 \
      --repair-peer-id F7SW17yGN7UUPQ519nxaDt26UMtvwJPSFVu9kBMBQpW \
      --log-level-stderr 0

*/

#include "fd_tvu.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "fd_replay.h"
#ifdef FD_HAS_LIBMICROHTTP
#include "../rpc/fd_rpc_service.h"
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define FD_TVU_TILE_SLOT_DELAY 32

static int gossip_sockfd = -1;
static int repair_sockfd = -1;

static void
repair_deliver_fun( fd_shred_t const *                            shred,
                    FD_PARAM_UNUSED ulong                         shred_sz,
                    FD_PARAM_UNUSED fd_repair_peer_addr_t const * from,
                    FD_PARAM_UNUSED fd_pubkey_t const *           id,
                    void *                                        arg ) {
  fd_replay_t * replay = (fd_replay_t *)arg;
  fd_replay_repair_rx( replay, shred );
}

static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  fd_tvu_gossip_deliver_arg_t * arg_ = (fd_tvu_gossip_deliver_arg_t *)arg;
  if( data->discriminant == fd_crds_data_enum_contact_info_v1 ) {
    fd_repair_peer_addr_t repair_peer_addr = { 0 };
    fd_gossip_from_soladdr( &repair_peer_addr, &data->inner.contact_info_v1.serve_repair );
    if( repair_peer_addr.port == 0 ) return;
    if( FD_UNLIKELY( fd_repair_add_active_peer(
            arg_->repair, &repair_peer_addr, &data->inner.contact_info_v1.id ) ) ) {
      FD_LOG_DEBUG( ( "error adding peer" ) ); /* Probably filled up the table */
    };
  }
}

static void
repair_deliver_fail_fun( fd_pubkey_t const * id,
                         ulong               slot,
                         uint                shred_index,
                         void *              arg,
                         int                 reason ) {
  (void)arg;
  FD_LOG_WARNING( ( "repair_deliver_fail_fun - shred: %32J, slot: %lu, idx: %u, reason: %d",
                    id,
                    slot,
                    shred_index,
                    reason ) );
}

/* Convert my style of address to UNIX style */
static int
gossip_to_sockaddr( uchar * dst, fd_gossip_peer_addr_t const * src ) {
  fd_memset( dst, 0, sizeof( struct sockaddr_in ) );
  struct sockaddr_in * t = (struct sockaddr_in *)dst;
  t->sin_family          = AF_INET;
  t->sin_addr.s_addr     = src->addr;
  t->sin_port            = src->port;
  return sizeof( struct sockaddr_in );
}

/* Convert my style of address from UNIX style */
static int
gossip_from_sockaddr( fd_gossip_peer_addr_t * dst, uchar const * src ) {
  FD_STATIC_ASSERT( sizeof( fd_gossip_peer_addr_t ) == sizeof( ulong ), "messed up size" );
  dst->l                        = 0;
  const struct sockaddr_in * sa = (const struct sockaddr_in *)src;
  dst->addr                     = sa->sin_addr.s_addr;
  dst->port                     = sa->sin_port;
  return 0;
}

static void
gossip_send_packet( uchar const *                 data,
                    size_t                        sz,
                    fd_gossip_peer_addr_t const * addr,
                    void *                        arg ) {
  (void)arg;
  uchar saddr[sizeof( struct sockaddr_in )];
  int   saddrlen = gossip_to_sockaddr( saddr, addr );
  char  s[1000]  = { 0 };
  fd_gossip_addr_str( s, sizeof( s ), addr );
  if( sendto( gossip_sockfd,
              data,
              sz,
              MSG_DONTWAIT,
              (const struct sockaddr *)saddr,
              (socklen_t)saddrlen ) < 0 ) {
    FD_LOG_WARNING( ( "sendto failed: %s", strerror( errno ) ) );
  }
}

void
signer_fun( void *    arg,
            uchar         signature[ static 64 ],
            uchar const * buffer,
            ulong         len ) {
  fd_keyguard_client_t * keyguard_client = (fd_keyguard_client_t *)arg;
  fd_keyguard_client_sign( keyguard_client, signature, buffer, len );
}

/* Convert my style of address to UNIX style */
static int
repair_to_sockaddr( uchar * dst, fd_repair_peer_addr_t const * src ) {
  fd_memset( dst, 0, sizeof( struct sockaddr_in ) );
  struct sockaddr_in * t = (struct sockaddr_in *)dst;
  t->sin_family          = AF_INET;
  t->sin_addr.s_addr     = src->addr;
  t->sin_port            = src->port;
  return sizeof( struct sockaddr_in );
}

/* Convert my style of address from UNIX style */
static int
repair_from_sockaddr( fd_repair_peer_addr_t * dst, uchar const * src ) {
  FD_STATIC_ASSERT( sizeof( fd_repair_peer_addr_t ) == sizeof( ulong ), "messed up size" );
  dst->l                        = 0;
  const struct sockaddr_in * sa = (const struct sockaddr_in *)src;
  dst->addr                     = sa->sin_addr.s_addr;
  dst->port                     = sa->sin_port;
  return 0;
}

static void
send_packet( uchar const * data, size_t sz, fd_repair_peer_addr_t const * addr, void * arg ) {
  // FD_LOG_HEXDUMP_NOTICE( ( "send: ", data, sz ) );
  (void)arg;
  uchar saddr[sizeof( struct sockaddr_in )];
  int   saddrlen = repair_to_sockaddr( saddr, addr );
  if( sendto( repair_sockfd,
              data,
              sz,
              MSG_DONTWAIT,
              (const struct sockaddr *)saddr,
              (socklen_t)saddrlen ) < 0 ) {
    FD_LOG_WARNING( ( "sendto failed: %s", strerror( errno ) ) );
  }
}

/* Convert a host:port string to a repair network address. If host is
 * missing, it assumes the local hostname. */
static fd_repair_peer_addr_t *
resolve_hostport( const char * str /* host:port */, fd_repair_peer_addr_t * res ) {
  fd_memset( res, 0, sizeof( fd_repair_peer_addr_t ) );

  /* Find the : and copy out the host */
  char buf[128];
  uint i;
  for( i = 0;; ++i ) {
    if( str[i] == '\0' || i > sizeof( buf ) - 1U ) {
      FD_LOG_ERR( ( "missing colon" ) );
      return NULL;
    }
    if( str[i] == ':' ) {
      buf[i] = '\0';
      break;
    }
    buf[i] = str[i];
  }
  if( i == 0 || strcmp( buf, "localhost" ) == 0 ||
      strcmp( buf, "127.0.0.1" ) == 0 ) /* :port means $HOST:port */
    gethostname( buf, sizeof( buf ) );

  struct hostent * host = gethostbyname( buf );
  if( host == NULL ) {
    FD_LOG_WARNING( ( "unable to resolve host %s", buf ) );
    return NULL;
  }
  /* Convert result to repair address */
  res->l    = 0;
  res->addr = ( (struct in_addr *)host->h_addr )->s_addr;
  int port  = atoi( str + i + 1 );
  if( ( port > 0 && port < 1024 ) || port > (int)USHORT_MAX ) {
    FD_LOG_ERR( ( "invalid port number" ) );
    return NULL;
  }
  res->port = htons( (ushort)port );

  return res;
}

static void
print_stats( fd_exec_slot_ctx_t * slot_ctx,
             FD_PARAM_UNUSED fd_funk_t * funk,
             FD_PARAM_UNUSED fd_blockstore_t * blockstore ) {
  FD_LOG_NOTICE( ( "current slot: %lu, transactions: %lu",
                   slot_ctx->slot_bank.slot,
                   slot_ctx->slot_bank.transaction_count ) );
  // These calls are expensive. Uncomment for development only
  // fd_funk_log_mem_usage( funk );
  // fd_blockstore_log_mem_usage( blockstore );
}

static int
fd_tvu_create_socket( fd_gossip_peer_addr_t * addr ) {
  int fd;
  if( ( fd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {
    FD_LOG_ERR( ( "socket failed: %s", strerror( errno ) ) );
    return -1;
  }
  int optval = 1 << 20;
  if( setsockopt( fd, SOL_SOCKET, SO_RCVBUF, (char *)&optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR( ( "setsocketopt failed: %s", strerror( errno ) ) );
    return -1;
  }

  if( setsockopt( fd, SOL_SOCKET, SO_SNDBUF, (char *)&optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR( ( "setsocketopt failed: %s", strerror( errno ) ) );
    return -1;
  }

  uchar saddr[sizeof( struct sockaddr_in6 )];
  int   addrlen = gossip_to_sockaddr( saddr, addr );
  if( addrlen < 0 || bind( fd, (struct sockaddr *)saddr, (uint)addrlen ) < 0 ) {
    char tmp[100];
    FD_LOG_ERR( ( "bind failed: %s for %s",
                  strerror( errno ),
                  fd_gossip_addr_str( tmp, sizeof( tmp ), addr ) ) );
    return -1;
  }
  if( getsockname( fd, (struct sockaddr *)saddr, (uint *)&addrlen ) < 0 ) {
    FD_LOG_ERR( ( "getsockname failed: %s", strerror( errno ) ) );
    return -1;
  }
  gossip_from_sockaddr( addr, saddr );

  return fd;
}

struct fd_turbine_thread_args {
  int            tvu_fd;
  fd_replay_t *  replay;
  fd_store_t *   store;
};

static int fd_turbine_thread( int argc, char ** argv );

struct fd_repair_thread_args {
  int            repair_fd;
  fd_replay_t *  replay;
};

static int fd_repair_thread( int argc, char ** argv );

struct fd_gossip_thread_args {
  int            gossip_fd;
  fd_replay_t *  replay;
};

static int fd_gossip_thread( int argc, char ** argv );

static fd_exec_slot_ctx_t *
fd_tvu_late_incr_snap( fd_runtime_ctx_t *    runtime_ctx,
                       fd_runtime_args_t *   runtime_args,
                       fd_replay_t *         replay,
                       ulong                 snapshot_slot,
                       fd_tower_t * towers );

int
fd_tvu_main( fd_runtime_ctx_t *    runtime_ctx,
             fd_runtime_args_t *   runtime_args,
             fd_replay_t *         replay,
             fd_exec_slot_ctx_t *  slot_ctx ) {

  replay->now = fd_log_wallclock();

  /* initialize gossip */
  int gossip_fd = fd_tvu_create_socket( &runtime_ctx->gossip_config.my_addr );
  gossip_sockfd = gossip_fd;
  fd_gossip_update_addr( runtime_ctx->gossip, &runtime_ctx->gossip_config.my_addr );

  fd_gossip_settime( runtime_ctx->gossip, fd_log_wallclock() );
  fd_gossip_start( runtime_ctx->gossip );

  /* initialize repair */
  int repair_fd = fd_tvu_create_socket( &runtime_ctx->repair_config.intake_addr );
  repair_sockfd = repair_fd;
  fd_repair_update_addr(
      replay->repair, &runtime_ctx->repair_config.intake_addr, &runtime_ctx->repair_config.service_addr );
  if( fd_gossip_update_repair_addr( runtime_ctx->gossip, &runtime_ctx->repair_config.service_addr ) )
    FD_LOG_ERR( ( "error setting gossip config" ) );

  fd_repair_settime( replay->repair, fd_log_wallclock() );
  fd_repair_start( replay->repair );

  /* optionally specify a repair peer identity to skip waiting for a contact info to come through */
  if( runtime_args->repair_peer_id ) {
    fd_pubkey_t repair_peer_id;
    fd_base58_decode_32( runtime_args->repair_peer_id, repair_peer_id.uc );
    fd_repair_peer_addr_t repair_peer_addr = { 0 };
    if( FD_UNLIKELY(
            fd_repair_add_active_peer( replay->repair,
                                       resolve_hostport( runtime_args->repair_peer_addr, &repair_peer_addr ),
                                       &repair_peer_id ) ) ) {
      FD_LOG_ERR( ( "error adding repair active peer" ) );
    }
    fd_repair_add_sticky(replay->repair, &repair_peer_id);
    fd_repair_set_permanent(replay->repair, &repair_peer_id);
  }

  fd_repair_peer_addr_t tvu_addr[1] = { 0 };
  resolve_hostport( runtime_args->tvu_addr, tvu_addr );
  fd_repair_peer_addr_t tvu_fwd_addr[1] = { 0 };
  resolve_hostport( runtime_args->tvu_fwd_addr, tvu_fwd_addr );

  /* initialize tvu */
  int tvu_fd = fd_tvu_create_socket( tvu_addr );
  if( fd_gossip_update_tvu_addr( runtime_ctx->gossip, tvu_addr, tvu_fwd_addr ) )
    FD_LOG_ERR( ( "error setting gossip tvu" ) );

  if( runtime_args->tcnt < 3 )
    FD_LOG_ERR(( "tcnt parameter must be >= 3 in live case" ));

  /* FIXME: replace with real tile */
  struct fd_turbine_thread_args ttarg =
    { .tvu_fd = tvu_fd, .replay = replay };
  fd_tile_exec_t * tile = fd_tile_exec_new( 1, fd_turbine_thread, 0, fd_type_pun( &ttarg ) );
  if( tile == NULL )
    FD_LOG_ERR( ( "error creating turbine thread" ) );

  /* FIXME: replace with real tile */
  struct fd_repair_thread_args reparg =
    { .repair_fd = repair_fd, .replay = replay };
  tile = fd_tile_exec_new( 2, fd_repair_thread, 0, fd_type_pun( &reparg ) );
  if( tile == NULL )
    FD_LOG_ERR( ( "error creating repair thread:" ) );

  /* FIXME: replace with real tile */
  struct fd_gossip_thread_args gosarg =
    { .gossip_fd = gossip_fd, .replay = replay };
  tile = fd_tile_exec_new( 3, fd_gossip_thread, 0, fd_type_pun( &gosarg ) );
  if( tile == NULL )
    FD_LOG_ERR( ( "error creating repair thread" ) );

  fd_tpool_t * tpool = NULL;
  if( runtime_args->tcnt > 3 ) {
    tpool = fd_tpool_init( runtime_ctx->tpool_mem, runtime_args->tcnt - 3 );
    if( tpool == NULL ) FD_LOG_ERR( ( "failed to create thread pool" ) );
    for( ulong i = 4; i < runtime_args->tcnt; ++i ) {
      if( fd_tpool_worker_push( tpool, i, NULL, fd_scratch_smem_footprint( 256UL<<20UL ) ) == NULL )
        FD_LOG_ERR( ( "failed to launch worker" ) );
    }
  }
  replay->tpool       = runtime_ctx->tpool       = tpool;
  replay->max_workers = runtime_ctx->max_workers = runtime_args->tcnt-3;

  if( runtime_ctx->need_incr_snap ) {
    /* Wait for first turbine packet before grabbing the incremental snapshot */
    while( replay->first_turbine_slot == FD_SLOT_NULL ){
      struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)1e6 };
      nanosleep(&ts, NULL);
      //if( fd_tile_shutdown_flag ) goto shutdown;
    }
    slot_ctx = fd_tvu_late_incr_snap( runtime_ctx, runtime_args, replay, slot_ctx->slot_bank.slot, slot_ctx->towers );
    runtime_ctx->need_incr_snap = 0;
  }

  long last_call  = fd_log_wallclock();
  long last_stats = last_call;
  while( FD_LIKELY( 1 /* !fd_tile_shutdown_flag */ ) ) {

    /* Housekeeping */
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( ( now - last_stats ) > (long)30e9 ) ) {
      print_stats( slot_ctx, replay->funk, replay->blockstore );
      last_stats = now;
    }
    replay->now = now;

    /* Try to progress replay */
    fd_replay_t * replay_tmp = replay;
    for( ulong i = fd_replay_pending_iter_init( replay_tmp );
         ( i = fd_replay_pending_iter_next( replay_tmp, now, i ) ) != ULONG_MAX; ) {
      fd_fork_t * fork = fd_replay_slot_prepare( replay_tmp, i );
      if( FD_LIKELY( fork ) ) {
        fd_replay_slot_execute( replay_tmp, i, fork, runtime_ctx->capture_ctx );
        if( i > 64U ) replay->smr = fd_ulong_max( replay->smr, i - 64U );
        replay->now = now = fd_log_wallclock();
      }
    }

    /* Allow other threads to add pendings */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)1e6 };
    nanosleep(&ts, NULL);
    if (NULL != runtime_ctx->capture_file)
      fd_solcap_writer_flush( runtime_ctx->capture_ctx->capture );
  }

// shutdown:
  close( gossip_fd );
  close( repair_fd );
  close( tvu_fd );
  return 0;
}

static ulong
fd_tvu_setup_scratch( fd_valloc_t valloc ) {
  ulong  smax   = 1UL << 31UL; /* 2 GiB scratch memory */
  ulong  sdepth = 1UL << 11UL; /* 2048 scratch frames, 1 MiB each */
  void * smem =
      fd_valloc_malloc( valloc, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ) );
  void * fmem =
      fd_valloc_malloc( valloc, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ) );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, smax, sdepth );
  return smax;
}

static int
fd_turbine_thread( int argc, char ** argv ) {
  (void)argc;
  struct fd_turbine_thread_args * args = (struct fd_turbine_thread_args *)argv;
  int tvu_fd = args->tvu_fd;

  fd_tvu_setup_scratch( args->replay->valloc );

#define VLEN 32U
  struct mmsghdr msgs[VLEN];
  struct iovec   iovecs[VLEN];
  uchar          bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */
#define CLEAR_MSGS                                                                                 \
  fd_memset( msgs, 0, sizeof( msgs ) );                                                            \
  for( uint i = 0; i < VLEN; i++ ) {                                                               \
    iovecs[i].iov_base          = bufs[i];                                                         \
    iovecs[i].iov_len           = FD_ETH_PAYLOAD_MAX;                                              \
    msgs[i].msg_hdr.msg_iov     = &iovecs[i];                                                      \
    msgs[i].msg_hdr.msg_iovlen  = 1;                                                               \
    msgs[i].msg_hdr.msg_name    = sockaddrs[i];                                                    \
    msgs[i].msg_hdr.msg_namelen = sizeof( struct sockaddr_in6 );                                   \
  }
  while( FD_LIKELY( 1 /* !fd_tile_shutdown_flag */ ) ) {
    CLEAR_MSGS;
    int tvu_rc = recvmmsg( tvu_fd, msgs, VLEN, MSG_DONTWAIT, NULL );
    if( tvu_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) continue;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      break;
    }

    for( uint i = 0; i < (uint)tvu_rc; ++i ) {
      fd_gossip_peer_addr_t from;
      gossip_from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      fd_shred_t const * shred = fd_shred_parse( bufs[i], msgs[i].msg_len );
      fd_replay_turbine_rx( args->replay, shred, msgs[i].msg_len );
    }
  }
  return 0;
}

static int
fd_repair_thread( int argc, char ** argv ) {
  (void)argc;
  struct fd_repair_thread_args * args = (struct fd_repair_thread_args *)argv;
  int repair_fd = args->repair_fd;
  fd_repair_t * repair = args->replay->repair;

  fd_tvu_setup_scratch( args->replay->valloc );

  struct mmsghdr msgs[VLEN];
  struct iovec   iovecs[VLEN];
  uchar          bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */
  while( FD_LIKELY( 1 /* !fd_tile_shutdown_flag */ ) ) {
    long now = fd_log_wallclock();
    fd_repair_settime( repair, now );

    /* Loop repair */
    fd_repair_continue( repair );

    /* Read more packets */
    CLEAR_MSGS;
    int repair_rc = recvmmsg( repair_fd, msgs, VLEN, MSG_DONTWAIT, NULL );
    if( repair_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) continue;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      break;
    }

    for( uint i = 0; i < (uint)repair_rc; ++i ) {
      fd_repair_peer_addr_t from;
      repair_from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      fd_repair_recv_packet( repair, bufs[i], msgs[i].msg_len, &from );
    }
  }
  return 0;
}

static int
fd_gossip_thread( int argc, char ** argv ) {
  (void)argc;
  struct fd_gossip_thread_args * args = (struct fd_gossip_thread_args *)argv;
  int gossip_fd = args->gossip_fd;
  fd_gossip_t * gossip = args->replay->gossip;

  fd_tvu_setup_scratch( args->replay->valloc );

  struct mmsghdr msgs[VLEN];
  struct iovec   iovecs[VLEN];
  uchar          bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */
  while( FD_LIKELY( 1 /* !fd_tile_shutdown_flag */ ) ) {
    long now = fd_log_wallclock();
    fd_gossip_settime( gossip, now );

    /* Loop gossip */
    fd_gossip_continue( gossip );

    /* Read more packets */
    CLEAR_MSGS;
    int gossip_rc = recvmmsg( gossip_fd, msgs, VLEN, MSG_DONTWAIT, NULL );
    if( gossip_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) continue;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      break;
    }

    for( uint i = 0; i < (uint)gossip_rc; ++i ) {
      fd_gossip_peer_addr_t from;
      gossip_from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      fd_gossip_recv_packet( gossip, bufs[i], msgs[i].msg_len, &from );
    }
  }
  return 0;
}

typedef struct {
  ulong       hashseed;
  char        hostname[64];
  fd_funk_t * funk;
} funk_setup_t;

void funk_setup( fd_wksp_t *  wksp,
                 char const * funk_wksp_name,
                 char const * snapshot,
                 char const * load,
                 ulong        txn_max,
                 ulong        rec_max,
                 funk_setup_t * out ) {
  fd_memset( out, 0, sizeof( funk_setup_t ) );
  gethostname( out->hostname, sizeof( out->hostname ) );
  out->hashseed = fd_hash( 0, out->hostname, strnlen( out->hostname, sizeof( out->hostname ) ) );

  fd_wksp_t * funk_wksp = NULL;
  if( funk_wksp_name == NULL ) {
    funk_wksp = wksp;
    if( rec_max == ULONG_MAX ) { rec_max = 100000000; }
  } else {
    funk_wksp = fd_wksp_attach( funk_wksp_name );
    if( funk_wksp == NULL )
      FD_LOG_ERR( ( "failed to attach to workspace %s", funk_wksp_name ) );
    if( rec_max == ULONG_MAX ) { rec_max = 450000000; }
  }
  FD_TEST( funk_wksp );

  if( snapshot && snapshot[0] != '\0' ) {
    if( wksp != funk_wksp ) /* Start from scratch */
      fd_wksp_reset( funk_wksp, (uint)out->hashseed );
  } else if( load ) {
    FD_LOG_NOTICE( ( "loading %s", load ) );
    int err = fd_wksp_restore( funk_wksp, load, (uint)out->hashseed );
    if( err ) FD_LOG_ERR( ( "load failed: error %d", err ) );

  } else {
    FD_LOG_WARNING( ( "using --snapshot or --load is recommended" ) );
  }

  fd_wksp_tag_query_info_t funk_info;
  ulong                    funk_tag = FD_FUNK_MAGIC;
  if( fd_wksp_tag_query( funk_wksp, &funk_tag, 1, &funk_info, 1 ) > 0 ) {
    void * shmem = fd_wksp_laddr_fast( funk_wksp, funk_info.gaddr_lo );
    out->funk         = fd_funk_join( shmem );
    if( out->funk == NULL ) FD_LOG_ERR( ( "failed to join a funky" ) );
  } else {
    void * shmem =
        fd_wksp_alloc_laddr( funk_wksp, fd_funk_align(), fd_funk_footprint(), funk_tag );
    if( shmem == NULL ) FD_LOG_ERR( ( "failed to allocate a funky" ) );
    out->funk = fd_funk_join( fd_funk_new( shmem, 1, out->hashseed, txn_max, rec_max ) );
    if( out->funk == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR( ( "failed to allocate a funky" ) );
    }
  }
}

fd_valloc_t allocator_setup( fd_wksp_t *  wksp, char const * allocator ) {
  FD_TEST( wksp );

  void * alloc_shmem =
      fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); }
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) { FD_LOG_ERR( ( "fd_alloc_join failed" ) ); }

  if( strcmp( allocator, "libc" ) == 0 ) {
    return fd_libc_alloc_virtual();
  } else if( strcmp( allocator, "wksp" ) == 0 ) {
    return fd_alloc_virtual( alloc );
  } else {
    FD_LOG_ERR( ( "unknown allocator specified" ) );
  }
}

typedef struct {
  FILE * capture_file;
  fd_capture_ctx_t * capture_ctx;
} solcap_setup_t;

void solcap_setup( char const * capture_fpath, fd_valloc_t valloc, solcap_setup_t * out ) {
  fd_memset( out, 0, sizeof( solcap_setup_t ) );
  out->capture_file = fopen( capture_fpath, "w+" );
  if( FD_UNLIKELY( !out->capture_file ) )
    FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", capture_fpath, errno, strerror( errno ) ));

  void * capture_ctx_mem = fd_valloc_malloc( valloc, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  FD_TEST( capture_ctx_mem );
  out->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );

  FD_TEST( fd_solcap_writer_init( out->capture_ctx->capture, out->capture_file ) );
}

void capture_ctx_setup( fd_runtime_ctx_t * runtime_ctx, fd_runtime_args_t * args,
                        solcap_setup_t * solcap_setup_out, fd_valloc_t valloc ) {
  runtime_ctx->capture_ctx  = NULL;
  runtime_ctx->capture_file = NULL;

  /* If a capture path is passed in, setup solcap, but nothing else in capture_ctx*/
  if( args->capture_fpath && args->capture_fpath[0] != '\0' ) {
    solcap_setup( args->capture_fpath, valloc, solcap_setup_out );
    runtime_ctx->capture_file = solcap_setup_out->capture_file;
    runtime_ctx->capture_ctx  = solcap_setup_out->capture_ctx;
    runtime_ctx->capture_ctx->capture_txns = args->capture_txns && strcmp( "true", args->capture_txns ) ? 0 : 1;

    runtime_ctx->capture_ctx->checkpt_path = NULL;
    runtime_ctx->capture_ctx->checkpt_slot = 0;
    runtime_ctx->capture_ctx->pruned_funk  = NULL;
  }

  int has_checkpt_dump = args->checkpt_path && args->checkpt_path[0] != '\0' && args->checkpt_slot;
  int has_prune        = args->pruned_funk != NULL;
  int dump_to_protobuf = args->dump_instructions_to_protobuf;

  /* If not using solcap, but setting up checkpoint dump or prune OR dumping to Protobuf, allocate memory for capture_ctx */
  if( ( has_checkpt_dump || has_prune || dump_to_protobuf ) && runtime_ctx->capture_ctx == NULL ) {
    /* Initialize capture_ctx if it doesn't exist */
    void * capture_ctx_mem = fd_valloc_malloc( valloc, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
    FD_TEST( !!capture_ctx_mem );
    runtime_ctx->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );
    runtime_ctx->capture_ctx->capture = NULL;
  }

  if ( has_checkpt_dump ) {
    runtime_ctx->capture_ctx->checkpt_slot = args->checkpt_slot;
    runtime_ctx->capture_ctx->checkpt_path = args->checkpt_path;
  }
  if ( has_prune ) {
    runtime_ctx->capture_ctx->pruned_funk = args->pruned_funk;
  }
  if ( dump_to_protobuf ) {
    runtime_ctx->capture_ctx->dump_instructions_to_protobuf = args->dump_instructions_to_protobuf;
    runtime_ctx->capture_ctx->instruction_dump_signature_filter = args->instruction_dump_signature_filter;
  }
}

typedef struct {
  fd_blockstore_t * blockstore;
} blockstore_setup_t;

void blockstore_setup( fd_wksp_t * wksp, ulong hashseed, blockstore_setup_t * out ) {
  FD_TEST( wksp );
  fd_memset( out, 0, sizeof( blockstore_setup_t ) );

  fd_wksp_tag_query_info_t blockstore_info;
  ulong                    blockstore_tag = FD_BLOCKSTORE_MAGIC;
  if( fd_wksp_tag_query( wksp, &blockstore_tag, 1, &blockstore_info, 1 ) > 0 ) {
    void * shmem = fd_wksp_laddr_fast( wksp, blockstore_info.gaddr_lo );
    out->blockstore   = fd_blockstore_join( shmem );
    if( out->blockstore == NULL ) FD_LOG_ERR( ( "failed to join a blockstore" ) );
  } else {
    void * shmem = fd_wksp_alloc_laddr( wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
    if( shmem == NULL ) FD_LOG_ERR( ( "failed to allocate a blockstore" ) );

    // Sensible defaults for an anon blockstore:
    // - 1mb of shreds
    // - 64 slots of history (~= finalized = 31 slots on top of a confirmed block)
    // - 1mb of txns
    ulong tmp_shred_max    = 1UL << 20;
    ulong slot_history_max = FD_BLOCKSTORE_SLOT_HISTORY_MAX;
    int   lg_txn_max       = 22;
    out->blockstore             = fd_blockstore_join(
        fd_blockstore_new( shmem, 1, hashseed, tmp_shred_max, slot_history_max, lg_txn_max ) );
    if( out->blockstore == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR( ( "failed to allocate a blockstore" ) );
    }
  }
}

typedef struct {
  uchar * data_shreds;
  uchar * parity_shreds;
  fd_fec_set_t * fec_sets;
  fd_fec_resolver_t * fec_resolver;
} turbine_setup_t;

void turbine_setup( fd_wksp_t * wksp, turbine_setup_t * out ) {
  FD_TEST( wksp );
  fd_memset( out, 0, sizeof( turbine_setup_t ) );

  ulong   depth          = 512;
  ulong   partial_depth  = 1;
  ulong   complete_depth = 1;
  ulong   total_depth    = depth + partial_depth + complete_depth;
  out->data_shreds       = fd_wksp_alloc_laddr(
      wksp, 128UL, FD_REEDSOL_DATA_SHREDS_MAX * total_depth * FD_SHRED_MAX_SZ, 42UL );
  out->parity_shreds     = fd_wksp_alloc_laddr(
      wksp, 128UL, FD_REEDSOL_PARITY_SHREDS_MAX * total_depth * FD_SHRED_MIN_SZ, 42UL );
  out->fec_sets          = fd_wksp_alloc_laddr(
      wksp, alignof( fd_fec_set_t ), total_depth * sizeof( fd_fec_set_t ), 42UL );

  ulong k = 0;
  ulong l = 0;
  /* TODO move this into wksp mem */
  for( ulong i = 0; i < total_depth; i++ ) {
    for( ulong j = 0; j < FD_REEDSOL_DATA_SHREDS_MAX; j++ ) {
      out->fec_sets[i].data_shreds[j] = &out->data_shreds[FD_SHRED_MAX_SZ * k++];
    }
    for( ulong j = 0; j < FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) {
      out->fec_sets[i].parity_shreds[j] = &out->parity_shreds[FD_SHRED_MIN_SZ * l++];
    }
  }
  FD_TEST( k == FD_REEDSOL_DATA_SHREDS_MAX * total_depth );
  FD_TEST( l == FD_REEDSOL_PARITY_SHREDS_MAX * total_depth );

  ulong  done_depth       = 1024;
  void * fec_resolver_mem = fd_wksp_alloc_laddr(
      wksp,
      fd_fec_resolver_align(),
      fd_fec_resolver_footprint( depth, partial_depth, complete_depth, done_depth ),
      42UL );
  out->fec_resolver = fd_fec_resolver_join( fd_fec_resolver_new(
      fec_resolver_mem, depth, partial_depth, complete_depth, done_depth, out->fec_sets ) );
}
typedef struct {
  fd_replay_t * replay;
} replay_setup_t;

void replay_setup( fd_wksp_t         * wksp,
                   fd_valloc_t         valloc,
                   uchar             * data_shreds,
                   uchar             * parity_shreds,
                   fd_fec_set_t      * fec_sets,
                   fd_fec_resolver_t * fec_resolver,
                   replay_setup_t    * out ) {
  FD_TEST( wksp );
  fd_memset( out, 0, sizeof( replay_setup_t ) );

  void * replay_mem =
      fd_wksp_alloc_laddr( wksp, fd_replay_align(), fd_replay_footprint(), 42UL );
  out->replay = fd_replay_join( fd_replay_new( replay_mem ) );
  if( out->replay == NULL ) FD_LOG_ERR( ( "failed to allocate a replay" ) );
  out->replay->valloc       = valloc;

  FD_TEST( out->replay );

  out->replay->data_shreds   = data_shreds;
  out->replay->parity_shreds = parity_shreds;
  out->replay->fec_sets      = fec_sets;
  out->replay->fec_resolver  = fec_resolver;

  FD_TEST( out->replay->data_shreds );
  FD_TEST( out->replay->parity_shreds );
  FD_TEST( out->replay->fec_sets );
  FD_TEST( out->replay->fec_resolver );
}
typedef struct {
  fd_exec_epoch_ctx_t  * exec_epoch_ctx;
  fd_exec_slot_ctx_t   * exec_slot_ctx;
  fd_fork_t *            fork;
} slot_ctx_setup_t;

void slot_ctx_setup( fd_valloc_t valloc,
                     uchar * epoch_ctx_mem,
                     fd_fork_t * fork_pool,
                     fd_blockstore_t * blockstore,
                     fd_funk_t * funk,
                     fd_acc_mgr_t * acc_mgr,
                     slot_ctx_setup_t * out ) {
  fd_memset( out, 0, sizeof( slot_ctx_setup_t ) );

  out->exec_epoch_ctx   = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem ) );
  out->fork             = fd_fork_pool_ele_acquire( fork_pool );
  out->exec_slot_ctx    = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &fork_pool->slot_ctx, valloc ) );

  FD_TEST( out->exec_slot_ctx );

  out->exec_slot_ctx->epoch_ctx = out->exec_epoch_ctx;
  out->exec_epoch_ctx->valloc = valloc;
  out->exec_slot_ctx->valloc  = valloc;

  out->exec_slot_ctx->acc_mgr      = fd_acc_mgr_new( acc_mgr, funk );
  out->exec_slot_ctx->blockstore   = blockstore;
}

typedef struct {
  ulong snapshot_slot;
} snapshot_setup_t;

void snapshot_setup( char const * snapshot,
                     char const * validate_snapshot,
                     char const * check_hash,
                     fd_exec_slot_ctx_t * exec_slot_ctx,
                     snapshot_setup_t * out ) {
  fd_memset( out, 0, sizeof( snapshot_setup_t ) );

  char snapshot_out[128];
  if( strncmp( snapshot, "http", 4 ) == 0 ) {
    FILE * fp;

    /* Open the command for reading. */
    char   cmd[128];
    snprintf( cmd, sizeof( cmd ), "./shenanigans.sh %s", snapshot );
    FD_LOG_NOTICE(("cmd: %s", cmd));
    fp = popen( cmd, "r" );
    if( fp == NULL ) {
      printf( "Failed to run command\n" );
      exit( 1 );
    }

    /* Read the output a line at a time - output it. */
    if( !fgets( snapshot_out, sizeof( snapshot_out ) - 1, fp ) ) {
        FD_LOG_ERR( ( "failed to pass snapshot name" ) );
    }
    snapshot_out[strcspn( snapshot_out, "\n" )]  = '\0';
    snapshot = snapshot_out;

    /* close */
    pclose( fp );
  }

  const char * p = strstr( snapshot, "incremental-snapshot-" );
  fd_snapshot_type_t snapshot_type = FD_SNAPSHOT_TYPE_UNSPECIFIED;
  if( p != NULL ) {
    snapshot_type = FD_SNAPSHOT_TYPE_INCREMENTAL;
    ulong i, j;
    if( sscanf( p, "incremental-snapshot-%lu-%lu", &i, &j ) < 2 )
      FD_LOG_ERR( ( "--incremental value is badly formatted: %s", snapshot ) );
    if( i != exec_slot_ctx->slot_bank.slot )
      FD_LOG_ERR( ( "ledger slot number does not match --incremental-snapshot, %lu %lu %s", i, exec_slot_ctx->slot_bank.slot, p ) );
    if( fd_slot_to_epoch( &exec_slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, i, NULL ) !=
        fd_slot_to_epoch( &exec_slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, j, NULL ) )
      FD_LOG_ERR( ( "we do not support an incremental snapshot spanning an epoch boundary" ) );
    out->snapshot_slot = j;
  } else {
    snapshot_type = FD_SNAPSHOT_TYPE_FULL;
    p = strstr( snapshot, "snapshot-" );
    if( p != NULL ) {
      if( sscanf( p, "snapshot-%lu", &out->snapshot_slot ) < 1 )
        FD_LOG_ERR( ( "--snapshot-file value is badly formatted: %s", snapshot ) );
    } else {
      FD_LOG_ERR( ( "--snapshot-file value is badly formatted: %s", snapshot ) );
    }
  }

  fd_snapshot_load( snapshot, exec_slot_ctx,
                    ((NULL != validate_snapshot) && (strcasecmp( validate_snapshot, "true" ) == 0)),
                    ((NULL != check_hash) && (strcasecmp( check_hash, "true ") == 0)),
                    snapshot_type
                  );

  fd_runtime_cleanup_incinerator( exec_slot_ctx );
}

void
snapshot_insert( fd_fork_t *       fork,
                 ulong             snapshot_slot,
                 fd_blockstore_t * blockstore,
                 fd_replay_t *     replay,
                 fd_tower_t *      towers ) {

  /* Add snapshot slot to blockstore.*/

  fd_blockstore_snapshot_insert( blockstore, &fork->slot_ctx.slot_bank );

  /* Add snapshot slot to frontier. */

  fork->slot = snapshot_slot;
  fd_fork_frontier_ele_insert( replay->forks->frontier, fork, replay->forks->pool );

  /* Set the towers pointer to passed-in towers mem. */

  fork->slot_ctx.towers = towers;

  /* Add snapshot slot to ghost. */

  fd_slot_hash_t slot_hash = { .slot = snapshot_slot, .hash = fork->slot_ctx.slot_bank.banks_hash };
  fd_ghost_leaf_insert( replay->bft->ghost, &slot_hash, NULL );

  /* Add snapshot slot to bft. */

  replay->bft->snapshot_slot = snapshot_slot;

  /* Add snapshot slot to bash hash cmp. */

  replay->epoch_ctx->bank_hash_cmp->slot = snapshot_slot;

  /* Set the SMR on replay.*/

  replay->smr = snapshot_slot;
  replay->snapshot_slot = snapshot_slot;
}

static fd_exec_slot_ctx_t *
fd_tvu_late_incr_snap( fd_runtime_ctx_t *  runtime_ctx,
                       fd_runtime_args_t * runtime_args,
                       fd_replay_t *       replay,
                       ulong               snapshot_slot,
                       fd_tower_t *        towers ) {
  (void)runtime_ctx;

  fd_fork_t *          fork     = fd_fork_pool_ele_acquire( replay->forks->pool );
  fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &fork->slot_ctx, replay->valloc ) );
  slot_ctx->acc_mgr               = replay->acc_mgr;
  slot_ctx->blockstore            = replay->blockstore;
  slot_ctx->valloc                = replay->valloc;
  slot_ctx->epoch_ctx             = replay->epoch_ctx;
  slot_ctx->slot_bank.slot        = snapshot_slot; /* needed for matching old snapshot with new */

  snapshot_setup_t snapshot_setup_out = {0};
  snapshot_setup(runtime_args->incremental_snapshot,
                 runtime_args->validate_snapshot,
                 runtime_args->check_hash,
                 slot_ctx,
                 &snapshot_setup_out );

  snapshot_slot = replay->smr = slot_ctx->slot_bank.slot;

  slot_ctx->leader = fd_epoch_leaders_get( replay->epoch_ctx->leaders, snapshot_slot );
  slot_ctx->slot_bank.collected_fees = 0;
  slot_ctx->slot_bank.collected_rent = 0;

  snapshot_insert( fork, snapshot_slot, replay->blockstore, replay, towers);

  return slot_ctx;
}

void
fd_tvu_main_setup( fd_runtime_ctx_t *    runtime_ctx,
                   fd_replay_t **         replay,
                   fd_exec_slot_ctx_t **  slot_ctx,
                   fd_keyguard_client_t * keyguard_client,
                   int                   live,
                   fd_wksp_t *           _wksp,
                   fd_runtime_args_t *   args,
                   fd_tvu_gossip_deliver_arg_t * gossip_deliver_arg ) {
  fd_flamenco_boot( NULL, NULL );

  runtime_ctx->live = live;

  /**********************************************************************/
  /* Anonymous wksp                                                     */
  /**********************************************************************/

  fd_wksp_t * wksp;
  if( !_wksp ) {
    char * _page_sz = "gigantic";
    ulong  numa_idx = fd_shmem_numa_idx( 0 );
    FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                     args->page_cnt,
                     _page_sz,
                     numa_idx ) );
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                  args->page_cnt,
                                  fd_shmem_cpu_idx( numa_idx ),
                                  "wksp",
                                  0UL );
  } else {
    wksp = _wksp;
  }
  FD_TEST( wksp );

  runtime_ctx->local_wksp = wksp;

  funk_setup_t funk_setup_out = {0};
  funk_setup( wksp, args->funk_wksp_name, args->snapshot, args->load, args->txn_max, args->index_max, &funk_setup_out );

  fd_valloc_t valloc = allocator_setup( wksp, args->allocator );

  /* Sets up solcap, checkpoint dumps, and/or pruning */
  solcap_setup_t solcap_setup = {0};
  capture_ctx_setup( runtime_ctx, args, &solcap_setup, valloc );

  blockstore_setup_t blockstore_setup_out = {0};
  blockstore_setup( wksp, funk_setup_out.hashseed, &blockstore_setup_out );

  fd_tvu_setup_scratch( valloc );

  turbine_setup_t turbine_setup_out = {0};
  turbine_setup( wksp, &turbine_setup_out );

  replay_setup_t replay_setup_out = {0};
  replay_setup( wksp,
                valloc,
                turbine_setup_out.data_shreds,
                turbine_setup_out.parity_shreds,
                turbine_setup_out.fec_sets,
                turbine_setup_out.fec_resolver,
                &replay_setup_out );
  if( replay != NULL ) *replay = replay_setup_out.replay;

  /* forks */

  ulong        forks_max = fd_ulong_pow2_up( FD_DEFAULT_SLOTS_PER_EPOCH );
  void *       forks_mem = fd_wksp_alloc_laddr( wksp, fd_forks_align(), fd_forks_footprint( forks_max ), 1UL );
  fd_forks_t * forks     = fd_forks_join( fd_forks_new( forks_mem, forks_max, 42UL ) );
  FD_TEST( forks );

  forks->acc_mgr = runtime_ctx->_acc_mgr;
  forks->blockstore = blockstore_setup_out.blockstore;
  forks->funk = funk_setup_out.funk;
  forks->valloc = valloc;
  replay_setup_out.replay->forks = forks;

  slot_ctx_setup_t slot_ctx_setup_out = {0};
  slot_ctx_setup( valloc,
                  runtime_ctx->epoch_ctx_mem,
                  replay_setup_out.replay->forks->pool,
                  blockstore_setup_out.blockstore,
                  funk_setup_out.funk,
                  runtime_ctx->_acc_mgr,
                  &slot_ctx_setup_out );

  forks->epoch_ctx = slot_ctx_setup_out.exec_epoch_ctx;

  if( slot_ctx != NULL ) *slot_ctx = slot_ctx_setup_out.exec_slot_ctx;
  runtime_ctx->epoch_ctx = slot_ctx_setup_out.exec_epoch_ctx;
  runtime_ctx->slot_ctx  = slot_ctx_setup_out.exec_slot_ctx;

  /**********************************************************************/
  /* snapshots                                                          */
  /**********************************************************************/
  snapshot_setup_t snapshot_setup_out = {0};
  if( args->snapshot && args->snapshot[0] != '\0' ) {
    snapshot_setup( args->snapshot,
                    args->validate_snapshot,
                    args->check_hash,
                    slot_ctx_setup_out.exec_slot_ctx,
                    &snapshot_setup_out );
  } else {
    fd_runtime_recover_banks( slot_ctx_setup_out.exec_slot_ctx, 0 );
  }

  runtime_ctx->need_incr_snap = ( args->incremental_snapshot && args->incremental_snapshot[0] != '\0' );

  /**********************************************************************/
  /* Thread pool                                                        */
  /**********************************************************************/

  runtime_ctx->tpool       = NULL;
  runtime_ctx->max_workers = 0;

  if( runtime_ctx->live ) {
#ifdef FD_HAS_LIBMICROHTTP
    /**********************************************************************/
    /* rpc service                                                        */
    /**********************************************************************/
    (*replay)->rpc_ctx =
        fd_rpc_alloc_ctx( *replay, &runtime_ctx->public_key );
    fd_rpc_start_service( args->rpc_port, (*replay)->rpc_ctx );
#endif

    /**********************************************************************/
    /* Repair                                                             */
    /**********************************************************************/

    runtime_ctx->repair_config.private_key = runtime_ctx->private_key;
    runtime_ctx->repair_config.public_key  = &runtime_ctx->public_key;

    FD_TEST( resolve_hostport( args->my_repair_addr, &runtime_ctx->repair_config.intake_addr ) );
    runtime_ctx->repair_config.service_addr      = runtime_ctx->repair_config.intake_addr;
    runtime_ctx->repair_config.service_addr.port = 0; /* pick a port */

    runtime_ctx->repair_config.deliver_fun      = repair_deliver_fun;
    runtime_ctx->repair_config.send_fun         = send_packet;
    runtime_ctx->repair_config.deliver_fail_fun = repair_deliver_fail_fun;
    runtime_ctx->repair_config.fun_arg = replay_setup_out.replay;
    runtime_ctx->repair_config.sign_fun         = NULL;
    runtime_ctx->repair_config.sign_arg         = NULL;

    void *        repair_mem = fd_valloc_malloc( valloc, fd_repair_align(), fd_repair_footprint() );
    fd_repair_t * repair     = fd_repair_join( fd_repair_new( repair_mem, funk_setup_out.hashseed, valloc ) );
    runtime_ctx->repair      = repair;

    if( fd_repair_set_config( repair, &runtime_ctx->repair_config ) ) runtime_ctx->blowup = 1;

    /***********************************************************************/
    /* ghost                                                               */
    /***********************************************************************/

    void * ghost_mem =
        fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( 1024UL, 1 << 16 ), 42UL );
    fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 1024UL, 1 << 16, 42UL ) );

    /***********************************************************************/
    /* towers                                                           */
    /***********************************************************************/

    void * towers_mem =
        fd_wksp_alloc_laddr( wksp, fd_tower_deque_align(), fd_tower_deque_footprint(), 42UL );
    fd_tower_t * towers =
        fd_tower_deque_join( fd_tower_deque_new( towers_mem ) );
    FD_TEST( towers );

    /***********************************************************************/
    /* bft                                                                 */
    /***********************************************************************/

    void *     bft_mem = fd_wksp_alloc_laddr( wksp, fd_bft_align(), fd_bft_footprint(), 42UL );
    fd_bft_t * bft     = fd_bft_join( fd_bft_new( bft_mem ) );

    bft->acc_mgr    = forks->acc_mgr;
    bft->blockstore = forks->blockstore;
    bft->commitment = NULL;
    bft->forks      = forks;
    bft->ghost      = ghost;
    bft->valloc     = valloc;

    replay_setup_out.replay->bft = bft;

    /**********************************************************************/
    /* Store                                                              */
    /**********************************************************************/
    ulong snapshot_slot = slot_ctx_setup_out.exec_slot_ctx->slot_bank.slot;
    void *        store_mem = fd_valloc_malloc( valloc, fd_store_align(), fd_store_footprint() );
    fd_store_t * store     = fd_store_join( fd_store_new( store_mem, snapshot_slot ) );
    store->blockstore = blockstore_setup_out.blockstore;
    store->smr = snapshot_slot;
    store->snapshot_slot = snapshot_slot;
    store->valloc = valloc;

    // repair_ctx->store = store;

    /**********************************************************************/
    /* Gossip                                                             */
    /**********************************************************************/

    runtime_ctx->gossip_config.private_key = runtime_ctx->private_key;
    runtime_ctx->gossip_config.public_key  = &runtime_ctx->public_key;

    FD_TEST( resolve_hostport( args->my_gossip_addr, &runtime_ctx->gossip_config.my_addr ) );

    gossip_deliver_arg->bft = bft;
    gossip_deliver_arg->repair = repair;
    gossip_deliver_arg->valloc = valloc;

    runtime_ctx->gossip_config.shred_version = 0;
    runtime_ctx->gossip_config.deliver_fun   = gossip_deliver_fun;
    runtime_ctx->gossip_config.deliver_arg   = gossip_deliver_arg;
    runtime_ctx->gossip_config.send_fun      = gossip_send_packet;
    runtime_ctx->gossip_config.send_arg      = NULL;
    runtime_ctx->gossip_config.sign_fun      = signer_fun;
    runtime_ctx->gossip_config.sign_arg      = keyguard_client;

    ulong seed = fd_hash( 0, funk_setup_out.hostname, strnlen( funk_setup_out.hostname, sizeof( funk_setup_out.hostname ) ) );

    void *        gossip_mem = fd_valloc_malloc( valloc, fd_gossip_align(), fd_gossip_footprint() );
    fd_gossip_t * gossip     = fd_gossip_join( fd_gossip_new( gossip_mem, seed, valloc ) );
    runtime_ctx->gossip      = gossip;

    if( fd_gossip_set_config( gossip, &runtime_ctx->gossip_config ) )
      FD_LOG_ERR( ( "error setting gossip config" ) );

    if( fd_gossip_add_active_peer(
            gossip, resolve_hostport( args->gossip_peer_addr, &runtime_ctx->gossip_peer_addr ) ) )
      FD_LOG_ERR( ( "error adding gossip active peer" ) );

    /***********************************************************************/
    /* Prepare                                                             */
    /***********************************************************************/
    fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool = slot_ctx_setup_out.exec_epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t * vote_accounts_root = slot_ctx_setup_out.exec_epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_root;

    ulong stake_weights_cnt = fd_vote_accounts_pair_t_map_size( vote_accounts_pool, vote_accounts_root );
    ulong stake_weight_idx = 0;

    FD_SCRATCH_SCOPE_BEGIN {
      fd_stake_weight_t * stake_weights = fd_scratch_alloc( fd_stake_weight_align(), stake_weights_cnt * fd_stake_weight_footprint() );
      for( fd_vote_accounts_pair_t_mapnode_t const * n = fd_vote_accounts_pair_t_map_minimum_const( vote_accounts_pool, vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor_const( vote_accounts_pool, n ) ) {
        fd_vote_state_versioned_t versioned;
        fd_bincode_decode_ctx_t   decode_ctx;
        decode_ctx.data    = n->elem.value.data;
        decode_ctx.dataend = n->elem.value.data + n->elem.value.data_len;
        decode_ctx.valloc  = fd_scratch_virtual();
        int rc             = fd_vote_state_versioned_decode( &versioned, &decode_ctx );
        if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) continue;
        fd_stake_weight_t * stake_weight = &stake_weights[stake_weight_idx];
        stake_weight->stake = n->elem.stake;

        switch( versioned.discriminant ) {
        case fd_vote_state_versioned_enum_current:
          stake_weight->key = versioned.inner.current.node_pubkey;
          break;
        case fd_vote_state_versioned_enum_v0_23_5:
          stake_weight->key = versioned.inner.v0_23_5.node_pubkey;
          break;
        case fd_vote_state_versioned_enum_v1_14_11:
          stake_weight->key = versioned.inner.v1_14_11.node_pubkey;
          break;
        default:
          FD_LOG_DEBUG( ( "unrecognized vote_state_versioned type" ) );
          continue;
        }

        stake_weight_idx++;
      }

      fd_repair_set_stake_weights( repair, stake_weights, stake_weights_cnt );
      fd_gossip_set_stake_weights( gossip, stake_weights, stake_weights_cnt );
    } FD_SCRATCH_SCOPE_END;

    replay_setup_out.replay->blockstore  = blockstore_setup_out.blockstore;
    replay_setup_out.replay->funk        = funk_setup_out.funk;
    replay_setup_out.replay->acc_mgr     = runtime_ctx->_acc_mgr;
    replay_setup_out.replay->epoch_ctx   = slot_ctx_setup_out.exec_epoch_ctx;
    replay_setup_out.replay->repair      = repair;
    replay_setup_out.replay->gossip      = gossip;

    /* BFT update epoch stakes */

    fd_bft_epoch_stake_update(bft, slot_ctx_setup_out.exec_epoch_ctx);

    /* bank hash cmp */

    int    bank_hash_cmp_lg_slot_cnt = 10; /* max vote lag 512 => fill ratio 0.5 => 1024 */
    void * bank_hash_cmp_mem =
        fd_wksp_alloc_laddr( wksp,
                             fd_bank_hash_cmp_align(),
                             fd_bank_hash_cmp_footprint( bank_hash_cmp_lg_slot_cnt ),
                             42UL );
    replay_setup_out.replay->epoch_ctx->bank_hash_cmp = fd_bank_hash_cmp_join(
        fd_bank_hash_cmp_new( bank_hash_cmp_mem, bank_hash_cmp_lg_slot_cnt ) );

    /* bootstrap replay with the snapshot slot */

    slot_ctx_setup_out.exec_slot_ctx->towers = towers;
    if( !runtime_ctx->need_incr_snap ) {
      snapshot_insert( slot_ctx_setup_out.fork,
                       slot_ctx_setup_out.exec_slot_ctx->slot_bank.slot,
                       blockstore_setup_out.blockstore,
                       replay_setup_out.replay,
                       towers );
    }

    /* TODO @yunzhang open files, set the replay pointers, etc. you need here*/
    if (args->shred_cap == NULL) {
        replay_setup_out.replay->shred_cap = NULL;
    } else {
        replay_setup_out.replay->shred_cap = fopen(args->shred_cap, "w");
    }
    replay_setup_out.replay->stable_slot_start = 0;
    replay_setup_out.replay->stable_slot_end = 0;
  }

  slot_ctx_setup_out.fork->slot    = slot_ctx_setup_out.exec_slot_ctx->slot_bank.slot;

  /* FIXME epoch boundary stuff when replaying */
  fd_features_restore( slot_ctx_setup_out.exec_slot_ctx );
  fd_runtime_update_leaders( slot_ctx_setup_out.exec_slot_ctx, slot_ctx_setup_out.exec_slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( slot_ctx_setup_out.exec_slot_ctx );
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx_setup_out.exec_slot_ctx, slot_ctx_setup_out.exec_slot_ctx->funk_txn );

  if( FD_LIKELY( snapshot_setup_out.snapshot_slot != 0 ) ) {
    blockstore_setup_out.blockstore->root = snapshot_setup_out.snapshot_slot;
    blockstore_setup_out.blockstore->min  = snapshot_setup_out.snapshot_slot;
  }

  runtime_ctx->abort_on_mismatch = (uchar)args->abort_on_mismatch;
}

int
fd_tvu_parse_args( fd_runtime_args_t * args, int argc, char ** argv ) {

  const char * wksp = fd_env_strip_cmdline_cstr( &argc, &argv, "--wksp", NULL, NULL );
  if( NULL != wksp )
    FD_LOG_ERR( ( "--wksp is no longer a valid argument.  Please use --funk-wksp" ) );

  const char * pages = fd_env_strip_cmdline_cstr( &argc, &argv, "--pages", NULL, NULL );
  if( NULL != pages )
    FD_LOG_ERR( ( "--pages is no longer a valid argument.  Please use --page-cnt" ) );

  char const * index_max_opt = fd_env_strip_cmdline_cstr( &argc, &argv, "--index-max", NULL, NULL );
  if( NULL != index_max_opt )
    FD_LOG_ERR( ( "--index-max is no longer a valid argument.  Please use --indexmax" ) );

  args->blockstore_wksp_name =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--blockstore-wksp", NULL, NULL );
  args->funk_wksp_name = fd_env_strip_cmdline_cstr( &argc, &argv, "--funk-wksp", NULL, NULL );
  args->gossip_peer_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--gossip-peer-addr", NULL, ":1024" );
  args->incremental_snapshot =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--incremental-snapshot", NULL, NULL );
  args->load = fd_env_strip_cmdline_cstr( &argc, &argv, "--load", NULL, NULL );
  args->my_gossip_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--my_gossip_addr", NULL, ":9001" );
  args->my_repair_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--my-repair-addr", NULL, ":9002" );
  args->repair_peer_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-addr", NULL, ":1032" );
  args->repair_peer_id = fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-id", NULL, NULL );
  args->tvu_addr       = fd_env_strip_cmdline_cstr( &argc, &argv, "--tvu", NULL, ":9003" );
  args->tvu_fwd_addr   = fd_env_strip_cmdline_cstr( &argc, &argv, "--tvu_fwd", NULL, ":9004" );
  args->snapshot       = fd_env_strip_cmdline_cstr( &argc, &argv, "--snapshot", NULL, NULL );
  args->index_max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--indexmax", NULL, ULONG_MAX );
  args->page_cnt       = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 128UL );
  args->tcnt           = fd_env_strip_cmdline_ulong( &argc, &argv, "--tcnt", NULL, ULONG_MAX );
  args->txn_max        = fd_env_strip_cmdline_ulong( &argc, &argv, "--txnmax", NULL, 1000 );
  args->rpc_port       = fd_env_strip_cmdline_ushort( &argc, &argv, "--rpc-port", NULL, 8899U );
  args->end_slot       = fd_env_strip_cmdline_ulong( &argc, &argv, "--end-slot", NULL, ULONG_MAX );
  args->cmd            = fd_env_strip_cmdline_cstr( &argc, &argv, "--cmd", NULL, NULL );
  args->reset          = fd_env_strip_cmdline_cstr( &argc, &argv, "--reset", NULL, NULL );
  args->capitalization_file = fd_env_strip_cmdline_cstr( &argc, &argv, "--cap", NULL, NULL );
  args->allocator   = fd_env_strip_cmdline_cstr( &argc, &argv, "--allocator", NULL, "wksp" );
  args->validate_db = fd_env_strip_cmdline_cstr( &argc, &argv, "--validate", NULL, NULL );
  args->validate_snapshot =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--validate-snapshot", NULL, "false" );
  args->check_hash =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--check_hash", NULL, "false" );
  args->capture_fpath = fd_env_strip_cmdline_cstr( &argc, &argv, "--capture", NULL, NULL );
  /* Disabling capture_txns speeds up runtime and makes solcap captures significantly smaller */
  args->capture_txns  = fd_env_strip_cmdline_cstr( &argc, &argv, "--capture-txns", NULL, "true" );
  args->trace_fpath   = fd_env_strip_cmdline_cstr( &argc, &argv, "--trace", NULL, NULL );
  /* TODO @yunzhang: I added this to get the shred_cap file path,
   *  but shred_cap is now NULL despite there is such an entry in the toml config */
  args->shred_cap = fd_env_strip_cmdline_cstr( &argc, &argv, "--shred-cap", NULL, NULL );
  args->retrace       = fd_env_strip_cmdline_int( &argc, &argv, "--retrace", NULL, 0 );
  args->abort_on_mismatch =
      (uchar)fd_env_strip_cmdline_int( &argc, &argv, "--abort-on-mismatch", NULL, 0 );
  args->checkpt_slot = fd_env_strip_cmdline_ulong( &argc, &argv, "--checkpt-slot", NULL, 0 );
  args->checkpt_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--checkpt-path", NULL, NULL );
  args->dump_instructions_to_protobuf = fd_env_strip_cmdline_int( &argc, &argv, "--dump-instructions-to-protobuf", NULL, 0 );
  args->instruction_dump_signature_filter = fd_env_strip_cmdline_cstr( &argc, &argv, "--instruction-dump-signature-filter", NULL, NULL );

  /* These argument(s) should never be modified via the command line */
  args->pruned_funk = NULL;

  return 0;
}

void
fd_tvu_main_teardown( fd_runtime_ctx_t * tvu_args, fd_replay_t * replay ) {
  if( tvu_args->capture_file != NULL) {
    fd_solcap_writer_flush( tvu_args->capture_ctx->capture );
    fd_valloc_free( tvu_args->slot_ctx->valloc, fd_capture_ctx_delete( tvu_args->capture_ctx ) );
    fclose( tvu_args->capture_file );
  }

  if( tvu_args->tpool ) fd_tpool_fini( tvu_args->tpool );

  if ( NULL != replay ) {
#ifdef FD_HAS_LIBMICROHTTP
    if( replay->rpc_ctx ) fd_rpc_stop_service( replay->rpc_ctx );
#endif

    for( fd_fork_frontier_iter_t iter =
             fd_fork_frontier_iter_init( replay->forks->frontier, replay->forks->pool );
         !fd_fork_frontier_iter_done( iter, replay->forks->frontier, replay->forks->pool );
         iter = fd_fork_frontier_iter_next( iter, replay->forks->frontier, replay->forks->pool ) ) {
      fd_fork_t * fork =
          fd_fork_frontier_iter_ele( iter, replay->forks->frontier, replay->forks->pool );
      fd_exec_slot_ctx_free( &fork->slot_ctx );
      if( &fork->slot_ctx == tvu_args->slot_ctx ) tvu_args->slot_ctx = NULL;
    }

    /* ensure it's no longer valid to join */
    fd_fork_frontier_delete( fd_fork_frontier_leave( replay->forks->frontier ) );
    fd_fork_pool_delete( fd_fork_pool_leave( replay->forks->pool ) );

    /* TODO @yunzhang: I added this and hopefully this is
     * the right place toclose the shred log file */
    if( replay->shred_cap != NULL) {
        fclose(replay->shred_cap);
    }
  }

  /* Some replay paths don't use frontiers */
  if( tvu_args->slot_ctx ) fd_exec_slot_ctx_free( tvu_args->slot_ctx );

  fd_exec_epoch_ctx_free( tvu_args->epoch_ctx );
}
