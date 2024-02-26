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
#ifdef FD_HAS_LIBMICROHTTP
#include "../../flamenco/rpc/fd_rpc_service.h"
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

#define FD_TVU_TILE_SLOT_DELAY 32

static int gossip_sockfd = -1;
static int repair_sockfd = -1;

static void
repair_deliver_fun( fd_shred_t const *                            shred,
                    FD_PARAM_UNUSED ulong                         shred_sz,
                    FD_PARAM_UNUSED fd_repair_peer_addr_t const * from,
                    FD_PARAM_UNUSED fd_pubkey_t const *           id,
                    void *                                        arg ) {
  fd_tvu_repair_ctx_t * repair_ctx = (fd_tvu_repair_ctx_t *)arg;
  fd_store_shred_insert( repair_ctx->store, shred );
}

static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  fd_tvu_gossip_ctx_t * gossip_ctx = (fd_tvu_gossip_ctx_t *)arg;
  if( data->discriminant == fd_crds_data_enum_contact_info_v1 ) {
    fd_repair_peer_addr_t repair_peer_addr = { 0 };
    fd_gossip_from_soladdr( &repair_peer_addr, &data->inner.contact_info_v1.serve_repair );
    if( repair_peer_addr.port == 0 ) return;
    if( FD_UNLIKELY( fd_repair_add_active_peer(
            gossip_ctx->repair, &repair_peer_addr, &data->inner.contact_info_v1.id ) ) ) {
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
print_stats( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_LOG_NOTICE( ( "current slot: %lu, transactions: %lu",
                   slot_ctx->slot_bank.slot,
                   slot_ctx->slot_bank.transaction_count ) );
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
  volatile int * stopflag;
  int            tvu_fd;
  fd_replay_t *  replay;
  fd_store_t *   store;
};

static void * fd_turbine_thread( void * ptr );

struct fd_repair_thread_args {
  volatile int * stopflag;
  int            repair_fd;
  fd_replay_t *  replay;
};

static void * fd_repair_thread( void * ptr );

struct fd_gossip_thread_args {
  volatile int * stopflag;
  int            gossip_fd;
  fd_replay_t *  replay;
};

static void * fd_gossip_thread( void * ptr );

fd_replay_slot_ctx_t *
fd_tvu_slot_prepare( int store_slot_prepare_mode,
                     fd_replay_t * replay,
                     fd_repair_t * repair,
                     ulong slot ) {

  switch( store_slot_prepare_mode ) {
    case FD_STORE_SLOT_PREPARE_CONTINUE: {
      break;
    }
    case FD_STORE_SLOT_PREPARE_NEED_REPAIR: {
      fd_replay_slot_repair( replay, slot );
      return NULL;
    }
    case FD_STORE_SLOT_PREPARE_NEED_ORPHAN: {
      fd_repair_need_orphan( repair, slot );
      return NULL;
    }
    default: {
      FD_LOG_ERR(( "unrecognized store slot prepare mode" ));
    }
  }
  
  if( store_slot_prepare_mode == FD_STORE_SLOT_PREPARE_CONTINUE ) {
    fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( replay->blockstore, slot );
    if( !slot_meta ) {
      FD_LOG_ERR(( "slot meta not found for newly prepared slot" ));
    }

    ulong parent_slot = slot_meta->parent_slot;
    /* Query for the parent in the frontier */
    fd_replay_slot_ctx_t * parent =
        fd_replay_frontier_ele_query( replay->frontier, &parent_slot, NULL, replay->pool );

    /* If the parent block is both present and executed (see earlier conditionals), but isn't in the
      frontier, that means this block is starting a new fork and the parent needs to be added to the
      frontier. This requires rolling back to that txn in funk, and then inserting it into the
      frontier. */

    if( FD_UNLIKELY( !parent ) ) {
      /* Alloc a new slot_ctx */
      parent       = fd_replay_pool_ele_acquire( replay->pool );
      parent->slot = parent_slot;

      /* Format and join the slot_ctx */
      fd_exec_slot_ctx_t * slot_ctx =
          fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &parent->slot_ctx ) );
      if( FD_UNLIKELY( !slot_ctx ) ) { FD_LOG_ERR( ( "failed to new and join slot_ctx" ) ); }

      /* Restore and decode w/ funk */
      fd_replay_slot_ctx_restore( replay, parent->slot, slot_ctx );

      /* Add to frontier */
      fd_replay_frontier_ele_insert( replay->frontier, parent, replay->pool );
    }

    return parent;
  }

  return NULL;
}

int
fd_tvu_main( fd_gossip_t *         gossip,
             fd_gossip_config_t *  gossip_config,
             fd_tvu_repair_ctx_t * repair_ctx,
             fd_repair_config_t *  repair_config,
             volatile int *        stopflag,
             char const *          repair_peer_id_,
             char const *          repair_peer_addr_,
             char const *          tvu_addr_,
             char const *          tvu_fwd_addr_ ) {

  repair_ctx->store->now = repair_ctx->replay->now = fd_log_wallclock();
  
  /* initialize gossip */
  int gossip_fd = fd_tvu_create_socket( &gossip_config->my_addr );
  gossip_sockfd = gossip_fd;
  fd_gossip_update_addr( gossip, &gossip_config->my_addr );

  fd_gossip_settime( gossip, fd_log_wallclock() );
  fd_gossip_start( gossip );

  /* initialize repair */
  int repair_fd = fd_tvu_create_socket( &repair_config->intake_addr );
  repair_sockfd = repair_fd;
  fd_repair_update_addr(
      repair_ctx->repair, &repair_config->intake_addr, &repair_config->service_addr );
  if( fd_gossip_update_repair_addr( gossip, &repair_config->service_addr ) )
    FD_LOG_ERR( ( "error setting gossip config" ) );

  fd_repair_settime( repair_ctx->repair, fd_log_wallclock() );
  fd_repair_start( repair_ctx->repair );

  /* optionally specify a repair peer identity to skip waiting for a contact info to come through */
  if( repair_peer_id_ ) {
    fd_pubkey_t repair_peer_id;
    fd_base58_decode_32( repair_peer_id_, repair_peer_id.uc );
    fd_repair_peer_addr_t repair_peer_addr = { 0 };
    if( FD_UNLIKELY(
            fd_repair_add_active_peer( repair_ctx->repair,
                                       resolve_hostport( repair_peer_addr_, &repair_peer_addr ),
                                       &repair_peer_id ) ) ) {
      FD_LOG_ERR( ( "error adding repair active peer" ) );
    }
    fd_repair_add_sticky(repair_ctx->repair, &repair_peer_id);
    fd_repair_set_permanent(repair_ctx->repair, &repair_peer_id);
  }

  fd_repair_peer_addr_t tvu_addr[1] = { 0 };
  resolve_hostport( tvu_addr_, tvu_addr );
  fd_repair_peer_addr_t tvu_fwd_addr[1] = { 0 };
  resolve_hostport( tvu_fwd_addr_, tvu_fwd_addr );

  /* initialize tvu */
  int tvu_fd = fd_tvu_create_socket( tvu_addr );
  if( fd_gossip_update_tvu_addr( gossip, tvu_addr, tvu_fwd_addr ) )
    FD_LOG_ERR( ( "error setting gossip tvu" ) );

  /* FIXME: replace with real tile */
  struct fd_turbine_thread_args ttarg =
    { .stopflag = stopflag, .tvu_fd = tvu_fd, .replay = repair_ctx->replay, .store = repair_ctx->store };
  pthread_t turb_thread;
  int rc = pthread_create( &turb_thread, NULL, fd_turbine_thread, &ttarg );
  if (rc)
    FD_LOG_ERR( ( "error creating turbine thread: %s", strerror(errno) ) );

  /* FIXME: replace with real tile */
  struct fd_repair_thread_args reparg =
    { .stopflag = stopflag, .repair_fd = repair_fd, .replay = repair_ctx->replay };
  pthread_t repair_thread;
  rc = pthread_create( &repair_thread, NULL, fd_repair_thread, &reparg );
  if (rc)
    FD_LOG_ERR( ( "error creating repair thread: %s", strerror(errno) ) );

  /* FIXME: replace with real tile */
  struct fd_gossip_thread_args gosarg =
    { .stopflag = stopflag, .gossip_fd = gossip_fd, .replay = repair_ctx->replay };
  pthread_t gossip_thread;
  rc = pthread_create( &gossip_thread, NULL, fd_gossip_thread, &gosarg );
  if (rc)
    FD_LOG_ERR( ( "error creating repair thread: %s", strerror(errno) ) );

  long last_call  = fd_log_wallclock();
  long last_stats = last_call;
  while( !*stopflag ) {

    /* Housekeeping */
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( ( now - last_stats ) > (long)30e9 ) ) {
      print_stats( repair_ctx->slot_ctx );
      last_stats = now;
    }
    repair_ctx->replay->now = now;
    repair_ctx->store->now = now;

    /* Try to progress replay */
    fd_replay_t * replay = repair_ctx->replay;
    fd_store_t * store = repair_ctx->store;
    for (ulong i = fd_pending_slots_iter_init( store->pending_slots );
         (i = fd_pending_slots_iter_next( store->pending_slots, now, i )) != ULONG_MAX; ) {
      uchar const * block;
      ulong         block_sz = 0;
      ulong repair_slot = FD_SLOT_NULL;
      int store_slot_prepare_mode = fd_store_slot_prepare( store, i, &repair_slot, &block, &block_sz );
      fd_replay_slot_ctx_t * parent_slot_ctx = fd_tvu_slot_prepare( store_slot_prepare_mode, replay, repair_ctx->repair, repair_slot );
      if( FD_LIKELY( parent_slot_ctx ) ) {
        fd_replay_slot_execute( replay, i, parent_slot_ctx, block, block_sz );
      }
    }

    /* Allow other threads to add pendings */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)1e6 };
    nanosleep(&ts, NULL);
  }

  pthread_join( turb_thread, NULL );
  pthread_join( repair_thread, NULL );
  pthread_join( gossip_thread, NULL );

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

static void
fd_tvu_turbine_rx( fd_replay_t * replay, 
                   fd_store_t * store,
                   fd_shred_t const * shred, 
                   ulong shred_sz ) {
  FD_LOG_DEBUG( ( "[turbine] received shred - type: %x slot: %lu idx: %u",
                  fd_shred_type( shred->variant ) & FD_SHRED_TYPEMASK_DATA,
                  shred->slot,
                  shred->idx ) );
  fd_pubkey_t const *  leader = fd_epoch_leaders_get( replay->epoch_ctx->leaders, shred->slot );
  fd_fec_set_t const * out_fec_set = NULL;
  fd_shred_t const *   out_shred   = NULL;
  int                  rc          = fd_fec_resolver_add_shred(
      replay->fec_resolver, shred, shred_sz, leader->uc, &out_fec_set, &out_shred );
  if( rc == FD_FEC_RESOLVER_SHRED_COMPLETES ) {
    if( FD_UNLIKELY( replay->turbine_slot == FD_SLOT_NULL ) ) {
      replay->turbine_slot = shred->slot;
    }
    fd_shred_t * parity_shred = (fd_shred_t *)fd_type_pun( out_fec_set->parity_shreds[0] );
    FD_LOG_DEBUG( ( "slot: %lu. parity: %lu. data: %lu",
                    parity_shred->slot,
                    parity_shred->code.code_cnt,
                    parity_shred->code.data_cnt ) );
    
    /* Start repairs in 300ms */
    ulong slot = parity_shred->slot;
    fd_store_add_pending( store, slot, (ulong)300e6 );

    fd_blockstore_t * blockstore = store->blockstore;
    fd_blockstore_start_write( blockstore );

    if( fd_blockstore_block_query( blockstore, slot ) != NULL ) {
      fd_blockstore_end_write( blockstore );
      return;
    }

    for( ulong i = 0; i < parity_shred->code.data_cnt; i++ ) {
      fd_shred_t * data_shred = (fd_shred_t *)fd_type_pun( out_fec_set->data_shreds[i] );
      FD_LOG_DEBUG(
          ( "[turbine] rx shred - slot: %lu idx: %u", slot, data_shred->idx ) );
      int rc = fd_store_shred_insert( store, shred );
      if( rc < FD_BLOCKSTORE_OK ) {
        FD_LOG_ERR(( "error storing shred from turbine" ));
      }
      // int rc = fd_blockstore_shred_insert( blockstore, data_shred );
      // if( FD_UNLIKELY( rc == FD_BLOCKSTORE_OK_SLOT_COMPLETE ) ) {
      //   FD_LOG_NOTICE(( "[turbine] slot %lu complete", slot ));
        
      //   fd_blockstore_end_write( blockstore );
        
      //   /* Execute immediately */
      //   fd_replay_add_pending( replay, slot, 0 );
      //   return;
      // }
    }
    
    fd_blockstore_end_write( blockstore );
  }
}

static void *
fd_turbine_thread( void * ptr ) {
  struct fd_turbine_thread_args * args = (struct fd_turbine_thread_args *)ptr;
  volatile int * stopflag = args->stopflag;
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
  while( !*stopflag ) {
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
      fd_tvu_turbine_rx( args->replay, args->store, shred, msgs[i].msg_len );
    }
  }
  return NULL;
}

static void *
fd_repair_thread( void * ptr ) {
  struct fd_repair_thread_args * args = (struct fd_repair_thread_args *)ptr;
  volatile int * stopflag = args->stopflag;
  int repair_fd = args->repair_fd;
  fd_repair_t * repair = args->replay->repair;

  fd_tvu_setup_scratch( args->replay->valloc );

  struct mmsghdr msgs[VLEN];
  struct iovec   iovecs[VLEN];
  uchar          bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */
  while( !*stopflag ) {
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
  return NULL;
}

static void *
fd_gossip_thread( void * ptr ) {
  struct fd_gossip_thread_args * args = (struct fd_gossip_thread_args *)ptr;
  volatile int * stopflag = args->stopflag;
  int gossip_fd = args->gossip_fd;
  fd_gossip_t * gossip = args->replay->gossip;

  fd_tvu_setup_scratch( args->replay->valloc );

  struct mmsghdr msgs[VLEN];
  struct iovec   iovecs[VLEN];
  uchar          bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */
  while( !*stopflag ) {
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
  return NULL;
}

void
fd_tvu_main_setup( fd_runtime_ctx_t *    runtime_ctx,
                   fd_tvu_repair_ctx_t * repair_ctx,
                   fd_tvu_gossip_ctx_t * gossip_ctx,
                   int                   live,
                   fd_wksp_t *           _wksp,
                   fd_runtime_args_t *   args ) {
  fd_flamenco_boot( NULL, NULL );
  fd_memset( runtime_ctx, 0, sizeof( fd_runtime_ctx_t ) );

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

  /**********************************************************************/
  /* funk */
  /**********************************************************************/

  char hostname[64];
  gethostname( hostname, sizeof( hostname ) );
  ulong hashseed = fd_hash( 0, hostname, strnlen( hostname, sizeof( hostname ) ) );

  fd_wksp_t * funk_wksp = NULL;
  if( args->funk_wksp_name == NULL ) {
    funk_wksp = wksp;
    if( args->index_max == ULONG_MAX ) { args->index_max = 100000000; }
  } else {
    funk_wksp = fd_wksp_attach( args->funk_wksp_name );
    if( funk_wksp == NULL )
      FD_LOG_ERR( ( "failed to attach to workspace %s", args->funk_wksp_name ) );
    if( args->index_max == ULONG_MAX ) { args->index_max = 350000000; }
  }
  FD_TEST( funk_wksp );

  if( args->snapshot && args->snapshot[0] != '\0' ) {
    if( wksp != funk_wksp ) /* Start from scratch */
      fd_wksp_reset( funk_wksp, (uint)hashseed );
  } else if( args->load ) {
    FD_LOG_NOTICE( ( "loading %s", args->load ) );
    int err = fd_wksp_restore( funk_wksp, args->load, (uint)hashseed );
    if( err ) FD_LOG_ERR( ( "load failed: error %d", err ) );

  } else {
    FD_LOG_WARNING( ( "using --snapshot or --load is recommended" ) );
  }

  fd_funk_t *              funk = NULL;
  fd_wksp_tag_query_info_t funk_info;
  ulong                    funk_tag = FD_FUNK_MAGIC;
  if( fd_wksp_tag_query( funk_wksp, &funk_tag, 1, &funk_info, 1 ) > 0 ) {
    void * shmem = fd_wksp_laddr_fast( funk_wksp, funk_info.gaddr_lo );
    funk         = fd_funk_join( shmem );
    if( funk == NULL ) FD_LOG_ERR( ( "failed to join a funky" ) );
  } else {
    void * shmem =
        fd_wksp_alloc_laddr( funk_wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
    if( shmem == NULL ) FD_LOG_ERR( ( "failed to allocate a funky" ) );
    funk = fd_funk_join( fd_funk_new( shmem, 1, hashseed, args->txn_max, args->index_max ) );
    if( funk == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR( ( "failed to allocate a funky" ) );
    }
  }

  /**********************************************************************/
  /* we need a local allocator */
  /**********************************************************************/

  void * alloc_shmem =
      fd_wksp_alloc_laddr( runtime_ctx->local_wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); }
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
  runtime_ctx->alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !runtime_ctx->alloc ) ) { FD_LOG_ERR( ( "fd_alloc_join failed" ) ); }

  fd_valloc_t valloc;

  if( strcmp( args->allocator, "libc" ) == 0 ) {
    valloc = fd_libc_alloc_virtual();
  } else if( strcmp( args->allocator, "wksp" ) == 0 ) {
    valloc = fd_alloc_virtual( runtime_ctx->alloc );
  } else {
    FD_LOG_ERR( ( "unknown allocator specified" ) );
  }

  /**********************************************************************/
  /* Solcap                                                             */
  /**********************************************************************/

  runtime_ctx->capture_file = NULL;
  if( args->capture_fpath ) {
    runtime_ctx->capture_file = fopen( args->capture_fpath, "w+" );
    if( FD_UNLIKELY( !runtime_ctx->capture_file ) )
      FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", args->capture_fpath, errno, strerror( errno ) ));

    void * capture_ctx_mem = fd_valloc_malloc( valloc, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
    FD_TEST( capture_ctx_mem );
    runtime_ctx->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );

    FD_TEST( fd_solcap_writer_init( runtime_ctx->capture_ctx->capture, runtime_ctx->capture_file ) );
  }

  /**********************************************************************/
  /* Blockstore                                                         */
  /**********************************************************************/

  fd_wksp_t * blockstore_wksp = NULL;
  if( blockstore_wksp == NULL ) {
    blockstore_wksp = wksp;
  } else {
    blockstore_wksp = fd_wksp_attach( args->blockstore_wksp_name );
  }
  FD_TEST( blockstore_wksp );

  fd_blockstore_t *        blockstore = NULL;
  fd_wksp_tag_query_info_t blockstore_info;
  ulong                    blockstore_tag = FD_BLOCKSTORE_MAGIC;
  if( fd_wksp_tag_query( blockstore_wksp, &blockstore_tag, 1, &blockstore_info, 1 ) > 0 ) {
    void * shmem = fd_wksp_laddr_fast( blockstore_wksp, blockstore_info.gaddr_lo );
    blockstore   = fd_blockstore_join( shmem );
    if( blockstore == NULL ) FD_LOG_ERR( ( "failed to join a blockstore" ) );
  } else {
    void * shmem = fd_wksp_alloc_laddr(
        blockstore_wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
    if( shmem == NULL ) FD_LOG_ERR( ( "failed to allocate a blockstore" ) );

    // Sensible defaults for an anon blockstore:
    // - 1mb of shreds
    // - 64 slots of history (~= finalized = 31 slots on top of a confirmed block)
    // - 1mb of txns
    ulong tmp_shred_max    = 1UL << 20;
    ulong slot_history_max = FD_BLOCKSTORE_SLOT_HISTORY_MAX;
    int   lg_txn_max       = 20;
    blockstore             = fd_blockstore_join(
        fd_blockstore_new( shmem, 1, hashseed, tmp_shred_max, slot_history_max, lg_txn_max ) );
    if( blockstore == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR( ( "failed to allocate a blockstore" ) );
    }
  }

  /**********************************************************************/
  /* Scratch                                                            */
  /**********************************************************************/

  ulong smax = fd_tvu_setup_scratch( valloc );

  /**********************************************************************/
  /* Turbine                                                            */
  /**********************************************************************/

  ulong   depth          = 512;
  ulong   partial_depth  = 1;
  ulong   complete_depth = 1;
  ulong   total_depth    = depth + partial_depth + complete_depth;
  uchar * data_shreds    = fd_wksp_alloc_laddr(
      wksp, 128UL, FD_REEDSOL_DATA_SHREDS_MAX * total_depth * FD_SHRED_MAX_SZ, 42UL );
  uchar * parity_shreds = fd_wksp_alloc_laddr(
      wksp, 128UL, FD_REEDSOL_PARITY_SHREDS_MAX * total_depth * FD_SHRED_MIN_SZ, 42UL );
  fd_fec_set_t * fec_sets = fd_wksp_alloc_laddr(
      wksp, alignof( fd_fec_set_t ), total_depth * sizeof( fd_fec_set_t ), 42UL );

  ulong k = 0;
  ulong l = 0;
  /* TODO move this into wksp mem */
  for( ulong i = 0; i < total_depth; i++ ) {
    for( ulong j = 0; j < FD_REEDSOL_DATA_SHREDS_MAX; j++ ) {
      fec_sets[i].data_shreds[j] = &data_shreds[FD_SHRED_MAX_SZ * k++];
    }
    for( ulong j = 0; j < FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) {
      fec_sets[i].parity_shreds[j] = &parity_shreds[FD_SHRED_MIN_SZ * l++];
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
  fd_fec_resolver_t * fec_resolver = fd_fec_resolver_join( fd_fec_resolver_new(
      fec_resolver_mem, depth, partial_depth, complete_depth, done_depth, fec_sets ) );

  /**********************************************************************/
  /* Replay                                                             */
  /**********************************************************************/

  void * replay_mem =
      fd_wksp_alloc_laddr( wksp, fd_replay_align(), fd_replay_footprint( 1024UL ), 42UL );
  fd_replay_t * replay = fd_replay_join( fd_replay_new( replay_mem, 1024UL, 42UL ) );
  replay->valloc       = valloc;

  replay->data_shreds   = data_shreds;
  replay->parity_shreds = parity_shreds;
  replay->fec_sets      = fec_sets;
  replay->fec_resolver  = fec_resolver;

  FD_TEST( replay );
  FD_TEST( replay->frontier );
  FD_TEST( replay->pool );
  FD_TEST( replay->data_shreds );
  FD_TEST( replay->parity_shreds );
  FD_TEST( replay->fec_sets );
  FD_TEST( replay->fec_resolver );

  /**********************************************************************/
  /* slot_ctx                                                           */
  /**********************************************************************/

  fd_exec_epoch_ctx_t * epoch_ctx =
      fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( runtime_ctx->epoch_ctx_mem ) );
  fd_replay_slot_ctx_t * replay_slot = fd_replay_pool_ele_acquire( replay->pool );
  fd_exec_slot_ctx_t *   slot_ctx =
      fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &replay_slot->slot_ctx ) );
  FD_TEST( slot_ctx );
  slot_ctx->epoch_ctx = runtime_ctx->epoch_ctx = epoch_ctx;
  runtime_ctx->slot_ctx                        = slot_ctx;

  epoch_ctx->valloc = valloc;
  slot_ctx->valloc  = valloc;

  fd_acc_mgr_t * acc_mgr = fd_acc_mgr_new( runtime_ctx->_acc_mgr, funk );
  slot_ctx->acc_mgr      = acc_mgr;
  slot_ctx->blockstore   = blockstore;

  /**********************************************************************/
  /* snapshots                                                          */
  /**********************************************************************/

  ulong snapshot_slot = 0;
  if( args->snapshot && args->snapshot[0] != '\0' ) {
    if( !args->incremental_snapshot || args->incremental_snapshot[0] == '\0' ) {
      FD_LOG_WARNING( ( "Running without incremental snapshot. This only makes sense if you're "
                        "using a local validator." ) );
      // TODO: LML We really need to fix the way these arguments are handled
      args->incremental_snapshot = NULL;
    }
    const char * p = strstr( args->snapshot, "snapshot-" );
    if( p == NULL ) FD_LOG_ERR( ( "--snapshot-file value is badly formatted" ) );
    do {
      const char * p2 = strstr( p + 1, "snapshot-" );
      if( p2 == NULL ) break;
      p = p2;
    } while( 1 );
    if( sscanf( p, "snapshot-%lu", &snapshot_slot ) < 1 )
      FD_LOG_ERR( ( "--snapshot-file value is badly formatted" ) );

    if( args->incremental_snapshot && args->incremental_snapshot[0] != '\0' ) {

      p = strstr( args->incremental_snapshot, "incremental-snapshot-" );
      if( p == NULL ) FD_LOG_ERR( ( "--incremental value is badly formatted" ) );
      do {
        const char * p2 = strstr( p + 1, "incremental-snapshot-" );
        if( p2 == NULL ) break;
        p = p2;
      } while( 1 );
      ulong i, j;
      if( sscanf( p, "incremental-snapshot-%lu-%lu", &i, &j ) < 2 )
        FD_LOG_ERR( ( "--incremental value is badly formatted" ) );
      if( i != snapshot_slot )
        FD_LOG_ERR( ( "--snapshot-file slot number does not match --incremental" ) );
      snapshot_slot = j;
    }

    const char * snapshotfiles[3];
    snapshotfiles[0] = args->snapshot;
    snapshotfiles[1] = args->incremental_snapshot;
    snapshotfiles[2] = NULL;
    fd_snapshot_load( snapshotfiles, slot_ctx,
      ((NULL != args->validate_snapshot) && (strcasecmp( args->validate_snapshot, "true" ) == 0)),
      ((NULL != args->check_hash) && (strcasecmp( args->check_hash, "true ") == 0))
      );

  } else if( args->incremental_snapshot && args->incremental_snapshot[0] != '\0' ) {
    fd_runtime_recover_banks( slot_ctx, 0 );

    char   out[128];
    if( strncmp( args->incremental_snapshot, "http", 4 ) == 0 ) {
      FILE * fp;

      /* Open the command for reading. */
      char   cmd[128];
      snprintf( cmd, sizeof( cmd ), "./shenanigans.sh %s", args->incremental_snapshot );
      FD_LOG_NOTICE(("cmd: %s", cmd));
      fp = popen( cmd, "r" );
      if( fp == NULL ) {
        printf( "Failed to run command\n" );
        exit( 1 );
      }

      /* Read the output a line at a time - output it. */
      if( !fgets( out, sizeof( out ) - 1, fp ) ) {
        FD_LOG_ERR( ( "failed to pass incremental snapshot" ) );
      }
      out[strcspn( out, "\n" )]  = '\0';
      args->incremental_snapshot = out;

      /* close */
      pclose( fp );
    }
    const char * p = strstr( args->incremental_snapshot, "snapshot-" );
    if( p == NULL ) FD_LOG_ERR( ( "--incremental value is badly formatted" ) );
    do {
      const char * p2 = strstr( p + 1, "snapshot-" );
      if( p2 == NULL ) break;
      p = p2;
    } while( 1 );
    ulong i, j;
    if( sscanf( p, "snapshot-%lu-%lu", &i, &j ) < 2 )
      FD_LOG_ERR( ( "--incremental value is badly formatted" ) );
    if( i != slot_ctx->slot_bank.slot )
      FD_LOG_ERR( ( "ledger slot number does not match --incremental, %lu %lu %s", i, slot_ctx->slot_bank.slot, args->incremental_snapshot ) );
    snapshot_slot = j;

    const char * snapshotfiles[2];
    snapshotfiles[0] = args->incremental_snapshot;
    snapshotfiles[1] = NULL;
    fd_snapshot_load( snapshotfiles, slot_ctx,
      ((NULL != args->validate_snapshot) && (strcasecmp( args->validate_snapshot, "true" ) == 0)),
      ((NULL != args->check_hash) && (strcasecmp( args->check_hash, "true ") == 0))
      );

  } else {
    fd_runtime_recover_banks( slot_ctx, 0 );
  }

  fd_runtime_cleanup_incinerator( slot_ctx );

  /**********************************************************************/
  /* Identity                                                           */
  /**********************************************************************/

  FD_TEST( 32UL == getrandom( runtime_ctx->private_key, 32UL, 0 ) );
  fd_sha512_t sha[1];
  FD_TEST(
      fd_ed25519_public_from_private( runtime_ctx->public_key.uc, runtime_ctx->private_key, sha ) );

  /**********************************************************************/
  /* Thread pool                                                        */
  /**********************************************************************/

  if( args->tcnt == ULONG_MAX ) { args->tcnt = fd_tile_cnt(); }
  fd_tpool_t * tpool = NULL;
  if( args->tcnt > 1 ) {
    tpool = fd_tpool_init( runtime_ctx->tpool_mem, args->tcnt );
    if( tpool == NULL ) FD_LOG_ERR( ( "failed to create thread pool" ) );
    for( ulong i = 1; i < args->tcnt; ++i ) {
      void * smem =
          fd_valloc_malloc( valloc, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ) );
      if( fd_tpool_worker_push( tpool, i, smem, smax ) == NULL )
        FD_LOG_ERR( ( "failed to launch worker" ) );
    }
  }
  runtime_ctx->tpool       = tpool;
  runtime_ctx->max_workers = args->tcnt;

  if( runtime_ctx->live ) {
#ifdef FD_HAS_LIBMICROHTTP
    /**********************************************************************/
    /* rpc service                                                        */
    /**********************************************************************/
    runtime_ctx->rpc_ctx =
        fd_rpc_alloc_ctx( funk, blockstore, &runtime_ctx->public_key, slot_ctx, valloc );
    fd_rpc_start_service( args->rpc_port, runtime_ctx->rpc_ctx );
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

    void *        repair_mem = fd_valloc_malloc( valloc, fd_repair_align(), fd_repair_footprint() );
    fd_repair_t * repair     = fd_repair_join( fd_repair_new( repair_mem, hashseed, valloc ) );
    runtime_ctx->repair      = repair;

    repair_ctx->repair     = repair;
    repair_ctx->blockstore = blockstore;
    repair_ctx->slot_ctx   = slot_ctx;
    repair_ctx->peer_iter  = 0;

    runtime_ctx->repair_config.fun_arg = repair_ctx;

    if( fd_repair_set_config( repair, &runtime_ctx->repair_config ) ) runtime_ctx->blowup = 1;

    /**********************************************************************/
    /* Store                                                              */
    /**********************************************************************/
    void *        store_mem = fd_valloc_malloc( valloc, fd_store_align(), fd_store_footprint() );
    fd_store_t * store     = fd_store_join( fd_store_new( store_mem ) );
    store->blockstore = blockstore;
    store->smr = snapshot_slot;
    store->snapshot_slot = snapshot_slot;
    store->turbine_slot = FD_SLOT_NULL;
    store->valloc = valloc;

    repair_ctx->store = store;

    /**********************************************************************/
    /* Gossip                                                             */
    /**********************************************************************/

    runtime_ctx->gossip_config.private_key = runtime_ctx->private_key;
    runtime_ctx->gossip_config.public_key  = &runtime_ctx->public_key;

    FD_TEST( resolve_hostport( args->my_gossip_addr, &runtime_ctx->gossip_config.my_addr ) );

    runtime_ctx->gossip_config.shred_version = 0;
    runtime_ctx->gossip_config.deliver_fun   = gossip_deliver_fun;
    runtime_ctx->gossip_config.send_fun      = gossip_send_packet;

    ulong seed = fd_hash( 0, hostname, strnlen( hostname, sizeof( hostname ) ) );

    void *        gossip_mem = fd_valloc_malloc( valloc, fd_gossip_align(), fd_gossip_footprint() );
    fd_gossip_t * gossip     = fd_gossip_join( fd_gossip_new( gossip_mem, seed, valloc ) );
    runtime_ctx->gossip      = gossip;

    gossip_ctx->gossip                 = gossip;
    gossip_ctx->repair                 = repair;
    runtime_ctx->gossip_config.fun_arg = gossip_ctx;
    if( fd_gossip_set_config( gossip, &runtime_ctx->gossip_config ) )
      FD_LOG_ERR( ( "error setting gossip config" ) );

    if( fd_gossip_add_active_peer(
            gossip, resolve_hostport( args->gossip_peer_addr, &runtime_ctx->gossip_peer_addr ) ) )
      FD_LOG_ERR( ( "error adding gossip active peer" ) );

    repair_ctx->tpool       = tpool;
    repair_ctx->max_workers = args->tcnt;

    /***********************************************************************/
    /* Prepare                                                             */
    /***********************************************************************/

    fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool = epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t * vote_accounts_root = epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_root;

    ulong stake_weights_cnt = fd_vote_accounts_pair_t_map_size( vote_accounts_pool, vote_accounts_root );
    ulong stake_weight_idx = 0;
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

    replay->blockstore  = blockstore;
    replay->funk        = funk;
    replay->acc_mgr     = acc_mgr;
    replay->epoch_ctx   = epoch_ctx;
    replay->tpool       = tpool;
    replay->max_workers = args->tcnt;
    replay->repair      = repair;
    replay->gossip      = gossip;

    /* bootstrap replay with the snapshot slot */
    ulong snapshot_slot = slot_ctx->slot_bank.slot;
    replay->smr         = snapshot_slot;
    replay_slot->slot   = snapshot_slot;

    /* add it to the frontier */
    fd_replay_frontier_ele_insert( replay->frontier, replay_slot, replay->pool );

    /* fake the snapshot slot's block and mark it as executed */
    fd_blockstore_slot_map_t * slot_entry =
        fd_blockstore_slot_map_insert( fd_blockstore_slot_map( blockstore ), snapshot_slot );
    slot_entry->block.data_gaddr = ULONG_MAX;
    slot_entry->block.flags = fd_uint_set_bit( slot_entry->block.flags, FD_BLOCK_FLAG_SNAPSHOT );
    slot_entry->block.flags = fd_uint_set_bit( slot_entry->block.flags, FD_BLOCK_FLAG_EXECUTED );

    repair_ctx->replay = replay;
    gossip_ctx->replay = replay;
  } // if (runtime_ctx->live)

  replay_slot->slot    = slot_ctx->slot_bank.slot;
  replay->turbine_slot = FD_SLOT_NULL;

  /* FIXME epoch boundary stuff when replaying */
  fd_features_restore( slot_ctx );
  fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( slot_ctx );

  if( FD_LIKELY( snapshot_slot != 0 ) ) {
    blockstore->root = snapshot_slot;
    blockstore->min  = snapshot_slot;
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
  args->trace_fpath   = fd_env_strip_cmdline_cstr( &argc, &argv, "--trace", NULL, NULL );
  args->retrace       = fd_env_strip_cmdline_int( &argc, &argv, "--retrace", NULL, 0 );
  args->abort_on_mismatch =
      (uchar)fd_env_strip_cmdline_int( &argc, &argv, "--abort-on-mismatch", NULL, 0 );

  return 0;
}

void
fd_tvu_main_teardown( fd_runtime_ctx_t * tvu_args, fd_tvu_repair_ctx_t * repair_ctx ) {
#ifdef FD_HAS_LIBMICROHTTP
  if( tvu_args->rpc_ctx ) fd_rpc_stop_service( tvu_args->rpc_ctx );
#endif

  if( tvu_args->capture_file != NULL) {
    fd_solcap_writer_fini( tvu_args->capture_ctx->capture );
    fd_valloc_free( tvu_args->slot_ctx->valloc, fd_capture_ctx_delete( tvu_args->capture_ctx ) );
    fclose( tvu_args->capture_file );
  }

  fd_exec_epoch_ctx_free( tvu_args->epoch_ctx );

  if (( NULL != repair_ctx) && (NULL != repair_ctx->replay )) {
    fd_replay_t * replay = repair_ctx->replay;
    for( fd_replay_frontier_iter_t iter =
             fd_replay_frontier_iter_init( replay->frontier, replay->pool );
         !fd_replay_frontier_iter_done( iter, replay->frontier, replay->pool );
         iter = fd_replay_frontier_iter_next( iter, replay->frontier, replay->pool ) ) {
      fd_replay_slot_ctx_t * slot =
          fd_replay_frontier_iter_ele( iter, replay->frontier, replay->pool );
      fd_exec_slot_ctx_free( &slot->slot_ctx );
      if( &slot->slot_ctx == tvu_args->slot_ctx ) tvu_args->slot_ctx = NULL;
    }

    /* ensure it's no longer valid to join */
    fd_replay_frontier_delete( fd_replay_frontier_leave( replay->frontier ) );
    fd_replay_pool_delete( fd_replay_pool_leave( replay->pool ) );
  }

  /* Some replay paths don't use frontiers */
  if( tvu_args->slot_ctx ) fd_exec_slot_ctx_free( tvu_args->slot_ctx );
}
