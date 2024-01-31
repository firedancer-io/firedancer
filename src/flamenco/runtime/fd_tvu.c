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
      --snapshot snapshot-24* \
      --incremental-snapshot incremental-snapshot-24* \
      --log-level-logfile 0 \
      --log-level-stderr 0

    ./build/native/gcc/unit-test/test_tvu \
      --rpc-port 8124 \
      --gossip-peer-addr entrypoint.testnet.solana.com:8001 \
      --load /data/funk \
      --log-level-logfile 0 \
      --log-level-stderr 0

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
#include "../fd_flamenco.h"
#include "fd_hashes.h"
// #include "../gossip/fd_gossip.h"
#include "../repair/fd_repair.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_blockstore.h"
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

#define FD_TVU_TILE_SLOT_DELAY 32

static int gossip_sockfd = -1;
static int repair_sockfd = -1;

static bool has_peer = 0;

static void
repair_deliver_fun( fd_shred_t const *                            shred,
                    FD_PARAM_UNUSED ulong                         shred_sz,
                    FD_PARAM_UNUSED fd_repair_peer_addr_t const * from,
                    fd_pubkey_t const *                           id,
                    void *                                        arg ) {
  FD_LOG_DEBUG( ( "received shred - slot: %lu idx: %u", shred->slot, shred->idx ) );

  fd_tvu_repair_ctx_t * repair_ctx = (fd_tvu_repair_ctx_t *)arg;
  fd_repair_peer_t *    peer = fd_repair_peer_query( repair_ctx->replay->repair_peers, *id, NULL );
  if( FD_LIKELY( peer ) ) peer->reply_cnt++;

  fd_blockstore_start_read( repair_ctx->blockstore );
  /* TODO remove this check it's wrong for duplicate shreds */
  if( shred->slot < repair_ctx->slot_ctx->slot_bank.slot ||
      fd_blockstore_block_query( repair_ctx->blockstore, shred->slot ) != NULL ) {
    fd_blockstore_end_read( repair_ctx->blockstore );
    return;
  }
  fd_blockstore_end_read( repair_ctx->blockstore );

  fd_blockstore_start_write( repair_ctx->blockstore );
  int rc;
  if( FD_UNLIKELY( rc = fd_blockstore_shred_insert( repair_ctx->blockstore, NULL, shred ) !=
                        FD_BLOCKSTORE_OK ) ) {
    FD_LOG_WARNING(
        ( "fd_blockstore_upsert_shred error: slot %lu, reason: %02x", shred->slot, rc ) );
  };
  fd_blockstore_end_write( repair_ctx->blockstore );

  fd_blockstore_start_read( repair_ctx->blockstore );
  fd_slot_meta_t const * slot_meta =
      fd_blockstore_slot_meta_query( repair_ctx->blockstore, shred->slot );

  if( FD_UNLIKELY( slot_meta->consumed == slot_meta->last_index ) ) {
    // FD_LOG_NOTICE( ( "completed block: %lu", shred->slot ) );
    fd_replay_pending_push_tail( repair_ctx->replay->pending, shred->slot );
  }

  fd_blockstore_end_read( repair_ctx->blockstore );
}

static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  fd_tvu_gossip_ctx_t * gossip_ctx = (fd_tvu_gossip_ctx_t *)arg;
  // fd_blockstore_t *     blockstore     = gossip_app_ctx->blockstore;
  // fd_repair_t *         repair         = gossip_app_ctx->repair;
  // TODO blockstore needs to support partial shreds
  if( data->discriminant == fd_crds_data_enum_epoch_slots ) {
    //  an EpochSlots message indicates which slots the validator has all shreds
    fd_gossip_epoch_slots_t * epoch_slots = &data->inner.epoch_slots;
    if( epoch_slots->slots->discriminant == fd_gossip_slots_enum_enum_uncompressed ) {
      fd_gossip_slots_t  slots = epoch_slots->slots->inner.uncompressed;
      fd_repair_peer_t * peer =
          fd_repair_peer_query( gossip_ctx->replay->repair_peers, epoch_slots->from, NULL );
      if( FD_UNLIKELY( peer ) ) {
        peer->first_slot = slots.first_slot;
        peer->last_slot  = slots.first_slot + slots.num;
      }
    } else if( epoch_slots->slots->discriminant == fd_gossip_slots_enum_enum_flate2 ) {
      fd_gossip_flate2_slots_t slots = epoch_slots->slots->inner.flate2;
      fd_repair_peer_t *       peer =
          fd_repair_peer_query( gossip_ctx->replay->repair_peers, epoch_slots->from, NULL );
      if( FD_UNLIKELY( peer ) ) {
        peer->first_slot = slots.first_slot;
        peer->last_slot  = slots.first_slot + slots.num;
      }
    }
  } else if( data->discriminant == fd_crds_data_enum_contact_info_v1 ) {
    if( FD_LIKELY( fd_repair_peer_query(
            gossip_ctx->replay->repair_peers, data->inner.contact_info_v1.id, NULL ) ) ) {
      return;
    }

    fd_repair_peer_addr_t repair_peer_addr = { 0 };
    fd_gossip_from_soladdr( &repair_peer_addr, &data->inner.contact_info_v1.serve_repair );
    if( FD_UNLIKELY( fd_repair_add_active_peer(
            gossip_ctx->repair, &repair_peer_addr, &data->inner.contact_info_v1.id ) ) ) {
      FD_LOG_DEBUG( ( "error adding peer" ) ); /* Probably filled up the table */
      return;
    };

    fd_repair_peer_t * peer =
        fd_repair_peer_insert( gossip_ctx->replay->repair_peers, data->inner.contact_info_v1.id );
    peer->first_slot  = 0;
    peer->last_slot   = 0;
    peer->request_cnt = 0;
    peer->reply_cnt   = 0;
    has_peer          = 1;

    FD_LOG_DEBUG( ( "adding repair peer %32J", peer->id.uc ) );
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
print_stats( fd_tvu_repair_ctx_t * repair_ctx ) {
  ulong slot          = repair_ctx->slot_ctx->slot_bank.slot;
  ulong peer_cnt      = 0;
  ulong good_peer_cnt = 0;
  for( ulong i = 0; i < fd_repair_peer_slot_cnt(); i++ ) {
    fd_repair_peer_t * peer = &repair_ctx->replay->repair_peers[i];
    if( memcmp( &peer->id, &pubkey_null, sizeof( fd_pubkey_t ) ) == 0 ) continue;
    ++peer_cnt;
    if( slot >= peer->first_slot && slot <= peer->last_slot &&
        !( peer->request_cnt > 100U && peer->reply_cnt * 3U < peer->request_cnt ) ) /* 2/3 fails */
      ++good_peer_cnt;
    if( peer->request_cnt )
      FD_LOG_NOTICE( ( "peer %32J - avg requests: %lu, avg responses: %lu, ratio: %f, first_slot: "
                       "%lu, last_slot: %lu",
                       &peer->id,
                       peer->request_cnt,
                       peer->reply_cnt,
                       ( (double)peer->reply_cnt ) / ( (double)peer->request_cnt ),
                       peer->first_slot,
                       peer->last_slot ) );
    /* Do a moving average over several minutes */
    peer->request_cnt >>= 1;
    peer->reply_cnt >>= 1;
  }
  FD_LOG_NOTICE( ( "current slot: %lu, transactions: %lu, peer count: %lu, 'good' peer count: %lu",
                   slot,
                   repair_ctx->slot_ctx->slot_bank.transaction_count,
                   peer_cnt,
                   good_peer_cnt ) );
}

static int
fd_tvu_create_socket(fd_gossip_peer_addr_t * addr) {
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
  if( addrlen < 0 ||
      bind( fd, (struct sockaddr *)saddr, (uint)addrlen ) < 0 ) {
    char tmp[100];
    FD_LOG_ERR( ( "bind failed: %s for %s", strerror( errno ), fd_gossip_addr_str(tmp, sizeof(tmp), addr) ) );
    return -1;
  }
  if( getsockname( fd, (struct sockaddr *)saddr, (uint *)&addrlen ) < 0 ) {
    FD_LOG_ERR( ( "getsockname failed: %s", strerror( errno ) ) );
    return -1;
  }
  gossip_from_sockaddr( addr, saddr );

  return fd;
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

  /* initialize gossip */
  int gossip_fd = fd_tvu_create_socket(&gossip_config->my_addr);
  gossip_sockfd = gossip_fd;
  fd_gossip_update_addr( gossip, &gossip_config->my_addr );

  fd_gossip_settime( gossip, fd_log_wallclock() );
  fd_gossip_start( gossip );

  /* initialize repair */
  int repair_fd = fd_tvu_create_socket(&repair_config->intake_addr);
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
    fd_repair_peer_t * peer =
        fd_repair_peer_insert( repair_ctx->replay->repair_peers, repair_peer_id );
    // FIXME hack to be able to immediately send a msg for the CLI-specified peer
    peer->first_slot  = repair_ctx->blockstore->root;
    peer->last_slot   = ULONG_MAX;
    peer->request_cnt = 0;
    peer->reply_cnt   = 0;
    has_peer          = 1;
  }

  fd_repair_peer_addr_t tvu_addr[1]     = { 0 };
  resolve_hostport( tvu_addr_, tvu_addr );
  fd_repair_peer_addr_t tvu_fwd_addr[1] = { 0 };
  resolve_hostport( tvu_fwd_addr_, tvu_fwd_addr );

  /* initialize tvu */
  int tvu_fd = fd_tvu_create_socket(tvu_addr);
  if( fd_gossip_update_tvu_addr( gossip, tvu_addr, tvu_fwd_addr ) )
    FD_LOG_ERR( ( "error setting gossip tvu" ) );

#define VLEN 32U
  struct mmsghdr msgs[VLEN];
  struct iovec   iovecs[VLEN];
  uchar          bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar          sockaddrs[VLEN][sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */
#define CLEAR_MSGS                                               \
  fd_memset( msgs, 0, sizeof( msgs ) );                          \
  for( uint i = 0; i < VLEN; i++ ) {                             \
    iovecs[i].iov_base          = bufs[i];                       \
    iovecs[i].iov_len           = FD_ETH_PAYLOAD_MAX;            \
    msgs[i].msg_hdr.msg_iov     = &iovecs[i];                    \
    msgs[i].msg_hdr.msg_iovlen  = 1;                             \
    msgs[i].msg_hdr.msg_name    = sockaddrs[i];                  \
    msgs[i].msg_hdr.msg_namelen = sizeof( struct sockaddr_in6 ); \
  }
  
  long last_call  = fd_log_wallclock();
  long last_stats = last_call;
  while( !*stopflag ) {

    /* Housekeeping */
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( ( now - last_stats ) > (long)30e9 ) ) {
      print_stats( repair_ctx );
      last_stats = now;
    }

    /* Try to progress replay */
    fd_replay_t * replay = repair_ctx->replay;
    if( FD_LIKELY( fd_replay_pending_cnt( replay->pending ) ) ) {
      ulong slot = fd_replay_pending_pop_head( replay->pending );
      if( FD_LIKELY( slot > replay->smr ) ) {
        uchar const * block;
        ulong         block_sz = 0;
        fd_replay_slot_ctx_t * parent_slot_ctx =
            fd_replay_slot_prepare( replay, slot, &block, &block_sz );
        if( FD_LIKELY( parent_slot_ctx ) ) {
          fd_replay_slot_execute( replay, slot, parent_slot_ctx, block, block_sz );
        } else {
          fd_replay_pending_push_tail( replay->pending, slot );
        }
      }
    }

    /* Loop TVU (ie. Turbine) */
    CLEAR_MSGS;
    int tvu_rc = recvmmsg( tvu_fd, msgs, VLEN, MSG_DONTWAIT, NULL );
    if( tvu_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) goto gossip_loop;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      return -1;
    }

    for( uint i = 0; i < (uint)tvu_rc; ++i ) {
      fd_gossip_peer_addr_t from;
      gossip_from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      // fd_shred_t const * shred = fd_shred_parse( bufs[i], msgs[i].msg_len );
      FD_LOG_HEXDUMP_NOTICE(( "recv: ", bufs[i], msgs[i].msg_len ) );
      // fd_replay_turbine_rx( repair_ctx->replay, shred );
    }

  gossip_loop:
    /* Loop gossip */
    fd_gossip_settime( gossip, fd_log_wallclock() );
    fd_gossip_continue( gossip );

    /* Read more packets */
    CLEAR_MSGS;
    int gossip_rc = recvmmsg( gossip_fd, msgs, VLEN, MSG_DONTWAIT, NULL );
    if( gossip_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) goto repair_loop;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      return -1;
    }

    for( uint i = 0; i < (uint)gossip_rc; ++i ) {
      fd_gossip_peer_addr_t from;
      gossip_from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      fd_gossip_recv_packet( gossip, bufs[i], msgs[i].msg_len, &from );
    }

  repair_loop:
    /* Loop repair */
    fd_repair_settime( repair_ctx->repair, fd_log_wallclock() );
    fd_repair_continue( repair_ctx->repair );

    /* Read more packets */
    CLEAR_MSGS;
    int repair_rc = recvmmsg( repair_fd, msgs, VLEN, MSG_DONTWAIT, NULL );
    // FD_LOG_NOTICE( ( "repair rc %d", repair_rc ) );
    if( repair_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) continue;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      return -1;
    }

    for( uint i = 0; i < (uint)repair_rc; ++i ) {
      // FD_LOG_NOTICE( ( "processing %u", i ) );
      fd_repair_peer_addr_t from;
      repair_from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      // FD_LOG_HEXDUMP_NOTICE( ( "recv: ", bufs[i], msgs[i].msg_len ) );
      fd_repair_recv_packet( repair_ctx->repair, bufs[i], msgs[i].msg_len, &from );
    }
  }

  close( gossip_fd );
  close( repair_fd );
  return 0;
}

void
fd_tvu_main_setup( fd_runtime_ctx_t *    runtime_ctx,
                   fd_tvu_repair_ctx_t * repair_ctx,
                   fd_tvu_gossip_ctx_t * gossip_ctx,
                   int                   live,
                   fd_wksp_t *           _wksp,
                   fd_runtime_args_t *   args ) {

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

  if( args->snapshot ) {
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
    if( blockstore == NULL ) FD_LOG_ERR( ( "failed to join a blockstorey" ) );
  } else {
    void * shmem = fd_wksp_alloc_laddr(
        blockstore_wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
    if( shmem == NULL ) FD_LOG_ERR( ( "failed to allocate a blockstorey" ) );

    // Sensible defaults for an anon blockstore:
    // - 1mb of shreds
    // - 64 slots of history (~= finalized = 31 slots on top of a confirmed block)
    // - 1mb of txns
    ulong tmp_shred_max    = 1UL << 20;
    int   lg_txn_max       = 20;
    ulong slot_history_max = FD_DEFAULT_SLOT_HISTORY_MAX;
    blockstore             = fd_blockstore_join(
        fd_blockstore_new( shmem, 1, hashseed, tmp_shred_max, lg_txn_max, slot_history_max ) );
    if( blockstore == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR( ( "failed to allocate a blockstorey" ) );
    }
  }

  /**********************************************************************/
  /* Scratch                                                            */
  /**********************************************************************/

  ulong  smax   = 1UL << 31UL; /* 2 GiB scratch memory */
  ulong  sdepth = 1UL << 11UL; /* 2048 scratch frames, 1 MiB each */
  void * smem =
      fd_valloc_malloc( valloc, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ) );
  void * fmem =
      fd_valloc_malloc( valloc, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ) );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  /**********************************************************************/
  /* Replay                                                             */
  /**********************************************************************/

  void * replay_mem =
      fd_wksp_alloc_laddr( wksp, fd_replay_align(), fd_replay_footprint( 1024UL ), 0xABCDEF );
  fd_replay_t * replay = fd_replay_join( fd_replay_new( replay_mem, 1024UL, 42UL ) );
  FD_TEST( replay );
  FD_TEST( replay->frontier );
  FD_TEST( replay->pool );

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
  if( args->snapshot ) {
    if( !args->incremental_snapshot )
      FD_LOG_WARNING( ( "Running without incremental snapshot. This only makes sense if you're "
                        "using a local validator." ) );
    const char * p = strstr( args->snapshot, "snapshot-" );
    if( p == NULL ) FD_LOG_ERR( ( "--snapshot-file value is badly formatted" ) );
    do {
      const char * p2 = strstr( p + 1, "snapshot-" );
      if( p2 == NULL ) break;
      p = p2;
    } while( 1 );
    if( sscanf( p, "snapshot-%lu", &snapshot_slot ) < 1 )
      FD_LOG_ERR( ( "--snapshot-file value is badly formatted" ) );

    if( args->incremental_snapshot ) {
      p = strstr( args->incremental_snapshot, "snapshot-" );
      if( p == NULL ) FD_LOG_ERR( ( "--incremental value is badly formatted" ) );
      do {
        const char * p2 = strstr( p + 1, "snapshot-" );
        if( p2 == NULL ) break;
        p = p2;
      } while( 1 );
      ulong i, j;
      if( sscanf( p, "snapshot-%lu-%lu", &i, &j ) < 2 )
        FD_LOG_ERR( ( "--incremental value is badly formatted" ) );
      if( i != snapshot_slot )
        FD_LOG_ERR( ( "--snapshot-file slot number does not match --incremental" ) );
      snapshot_slot = j;
    }

    const char * snapshotfiles[3];
    snapshotfiles[0] = args->snapshot;
    snapshotfiles[1] = args->incremental_snapshot;
    snapshotfiles[2] = NULL;
    fd_snapshot_load( snapshotfiles, slot_ctx, strcasecmp( args->validate_snapshot, "true" ) == 0 );

  } else {
    fd_runtime_recover_banks( slot_ctx, 0 );
  }

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
    FD_LOG_NOTICE( ( "adding %lu replay_slot->slot", replay_slot->slot ) );
    fd_replay_frontier_ele_insert( replay->frontier, replay_slot, replay->pool );

    /* fake the snapshot slot's block and mark it as executed */
    fd_blockstore_block_map_t * block = fd_blockstore_block_map_insert(
        fd_wksp_laddr_fast( wksp, blockstore->block_map_gaddr ), snapshot_slot );
    block->block.flags = fd_uint_mask_bit( FD_BLOCKSTORE_BLOCK_FLAG_EXECUTED );

    repair_ctx->replay = replay;
    gossip_ctx->replay = replay;

    fd_replay_pending_push_tail( replay->pending, snapshot_slot + 1 );
  } // if (runtime_ctx->live)

  replay_slot->slot    = slot_ctx->slot_bank.slot;
  replay->turbine_slot = snapshot_slot + 100;

  /* FIXME epoch boundary stuff when replaying */
  fd_features_restore( slot_ctx );
  fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( slot_ctx );

  if( FD_LIKELY( snapshot_slot != 0 ) ) {
    blockstore->root = snapshot_slot;
    blockstore->min  = snapshot_slot;
  }
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
  args->load           = fd_env_strip_cmdline_cstr( &argc, &argv, "--load", NULL, NULL );
  args->my_gossip_addr = fd_env_strip_cmdline_cstr( &argc, &argv, "--my_gossip_addr", NULL, ":0" );
  args->my_repair_addr = fd_env_strip_cmdline_cstr( &argc, &argv, "--my-repair-addr", NULL, ":0" );
  args->repair_peer_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-addr", NULL, ":1032" );
  args->repair_peer_id = fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-id", NULL, NULL );
  args->tvu_addr       = fd_env_strip_cmdline_cstr( &argc, &argv, "--tvu", NULL, ":0" );
  args->tvu_fwd_addr   = fd_env_strip_cmdline_cstr( &argc, &argv, "--tvu_fwd", NULL, ":0" );
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
  fd_exec_epoch_ctx_free( tvu_args->epoch_ctx );

  fd_replay_t * replay = repair_ctx->replay;
  if( NULL != replay ) {
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
