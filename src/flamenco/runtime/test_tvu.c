// /home/asiegel/solana/test-ledger

/* This is an attempt to wire together all the components of runtime...

   Start with a non-consensus participating, non-fork tracking tile that can
     1. receive shreds from Repair
     2. put them in the Blockstore
     3. validate and execute them

   ./build/native/gcc/unit-test/test_tvu \
      --rpc-port 8124 \
      --gossip-peer-addr 86.109.3.165:8000 \
      --repair-peer-addr 86.109.3.165:8008 \
      --repair-peer-id F7SW17yGN7UUPQ519nxaDt26UMtvwJPSFVu9kBMBQpW \
      --snapshot snapshot-24* \
      --incremental-snapshot incremental-snapshot-24* \
      --log-level-logfile 0 \
      --log-level-stderr 0

      More sample commands:

      rm -f *.zst ; wget --trust-server-names http://localhost:8899/snapshot.tar.bz2 ; wget --trust-server-names http://localhost:8899/incremental-snapshot.tar.bz2

      build/native/gcc/bin/fd_frank_ledger --cmd ingest --snapshotfile snapshot-24* --incremental incremental-snapshot-24* --rocksdb /data/testnet/ledger/rocksdb --txnstatus true --pages 100 --backup /data/asiegel/test_backup --slothistory 100

      build/native/gcc/unit-test/test_tvu --peer_addr :8000 --repair-peer-identity F7SW17yGN7UUPQ519nxaDt26UMtvwJPSFVu9kBMBQpW --load /data/asiegel/test_backup --repair-peer-addr :8008 --rpc-port 8123

*/

#define _GNU_SOURCE /* See feature_test_macros(7) */

#define FD_TVU_TILE_SLOT_DELAY 32

#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../fd_flamenco.h"
#include "../gossip/fd_gossip.h"
#include "../repair/fd_repair.h"
#include "../rpc/fd_rpc_service.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#ifdef FD_HAS_LIBMICROHTTP
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

#ifdef FD_HAS_LIBMICROHTTP
static fd_rpc_ctx_t * rpc_ctx = NULL;
#endif

static int gossip_sockfd = -1;

struct fd_repair_peer {
  fd_pubkey_t id;
  uint        hash;
  ulong       first_slot;
  ulong       last_slot;
};
typedef struct fd_repair_peer fd_repair_peer_t;

static fd_pubkey_t pubkey_null = { 0 };

#define MAP_NAME                fd_repair_peer
#define MAP_T                   fd_repair_peer_t
#define MAP_LG_SLOT_CNT         10 /* 1kb peers */
#define MAP_KEY                 id
#define MAP_KEY_T               fd_pubkey_t
#define MAP_KEY_NULL            pubkey_null
#define MAP_KEY_INVAL( k )      !( memcmp( &k, &pubkey_null, sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( &k0 ), ( &k1 ), sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL_IS_SLOW   1
#define MAP_KEY_HASH( key )     ( (uint)( fd_hash( 0UL, &key, sizeof( fd_pubkey_t ) ) ) )
#include "../../util/tmpl/fd_map.c"

static bool has_peer                              = 0;
static bool requested_highest                     = 0;
static bool requested_idxs[FD_SHRED_MAX_PER_SLOT] = { 0 };

typedef struct {
  fd_repair_t *        repair;
  fd_repair_peer_t *   repair_peers;
  fd_blockstore_t *    blockstore;
  fd_exec_slot_ctx_t * slot_ctx;
  bool                 requested_highest;
  bool                 requested_idxs[FD_SHRED_MAX_PER_SLOT];
  // TODO fd_set
} fd_tvu_repair_ctx_t;

typedef struct {
  fd_gossip_t *      gossip;
  fd_repair_peer_t * repair_peers;
  fd_repair_t *      repair;
} fd_tvu_gossip_ctx_t;

static void
repair_missing_shreds( fd_repair_t *      repair,
                       fd_blockstore_t *  blockstore,
                       fd_repair_peer_t * repair_peers ) {
  ulong slot = blockstore->root + 1;

  fd_pubkey_t * peer  = NULL;
  bool          found = 0;
  for( ulong i = 0; i < fd_repair_peer_slot_cnt(); i++ ) {
    if( FD_UNLIKELY( memcmp( &repair_peers[i].id, &pubkey_null, sizeof( fd_pubkey_t ) ) ) ) {
      if( FD_UNLIKELY( slot >= repair_peers[i].first_slot && slot <= repair_peers[i].last_slot ) ) {
        peer  = &repair_peers[i].id;
        found = 1;
        break;
      }
    }
  }
  if( FD_UNLIKELY( !found ) ) {
    FD_LOG_WARNING( ( "unable to find any peers shreds in range of requested slot %lu", slot ) );
    return;
  }

  // fd_blockstore_shred_idx_set_t missing_shreds = { 0 };
  // rc = fd_blockstore_missing_shreds_query( blockstore, slot, &missing_shreds );

  fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( blockstore, slot );
  if( FD_UNLIKELY( !slot_meta ) ) {
    if( requested_highest ) return;
    FD_LOG_NOTICE( ( "requesting highest shred - slot: %lu", slot ) );
    if( FD_UNLIKELY( fd_repair_need_highest_window_index( repair, peer, slot, 0 ) ) ) {
      FD_LOG_ERR( ( "error requesting highest window idx shred for slot %lu", slot ) );
    };
    requested_highest = true;
  } else {
    // placeholder to only request missing shreds in the future... for now request all since we
    // know we aren't plugged into turbine this can also probably be windowed to be made more
    // efficient max # of shreds is 32K... maintain a bitmap of missing shreds for( ulong idx =
    // fd_blockstore_missing_shreds_iter_init( &missing_shreds );
    //      !fd_blockstore_missing_shreds_iter_done( idx );
    //      idx = fd_blockstore_missing_shreds_iter_next( &missing_shreds, idx ) ) {
    //   fd_shred_t shred = { 0 };
    //   shred.slot       = blockstore->root_slot;
    //   shred.idx        = (uint)idx;
    //   shred.data.flags = 0;
    //   fd_repair_need_window_index( repair, epoch_slots );
    // }
    fd_blockstore_slot_meta_map_t * slot_meta_map =
        fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->slot_meta_map_gaddr );
    fd_blockstore_slot_meta_map_t * slot_meta_entry =
        fd_blockstore_slot_meta_map_query( slot_meta_map, slot, NULL );
    fd_slot_meta_t * slot_meta = &slot_meta_entry->slot_meta;
    for( ulong shred_idx = slot_meta->consumed; shred_idx <= slot_meta->last_index; shred_idx++ ) {
      if( requested_idxs[shred_idx] ) continue;
      if( fd_blockstore_shred_query( blockstore, slot, (uint)shred_idx ) ) continue;
      FD_LOG_DEBUG( ( "requesting shred - slot: %lu, idx: %u", slot, shred_idx ) );
      if( FD_UNLIKELY( fd_repair_need_window_index( repair, peer, slot, (uint)shred_idx ) ) ) {
        FD_LOG_ERR( ( "error requesting shreds" ) );
      };
      requested_idxs[shred_idx] = true;
    }
  }
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
          fd_repair_peer_query( gossip_ctx->repair_peers, data->inner.contact_info_v1.id, NULL );
      if( FD_UNLIKELY( peer ) ) {
        peer->first_slot = slots.first_slot;
        peer->last_slot  = slots.first_slot + slots.num;
      }
    }
  } else if( data->discriminant == fd_crds_data_enum_contact_info_v1 ) {
    if( FD_LIKELY( fd_repair_peer_query(
            gossip_ctx->repair_peers, data->inner.contact_info_v1.id, NULL ) ) ) {
      return;
    }

    fd_gossip_set_shred_version( gossip_ctx->gossip, data->inner.contact_info_v1.shred_version );
    fd_repair_peer_addr_t repair_peer_addr = { 0 };
    fd_gossip_from_soladdr( &repair_peer_addr, &data->inner.contact_info_v1.serve_repair );
    if( FD_UNLIKELY( fd_repair_add_active_peer(
            gossip_ctx->repair, &repair_peer_addr, &data->inner.contact_info_v1.id ) ) ) {
      FD_LOG_ERR( ( "error adding peer" ) );
    };

    fd_repair_peer_t * peer =
        fd_repair_peer_insert( gossip_ctx->repair_peers, data->inner.contact_info_v1.id );
    peer->first_slot = 0;
    peer->last_slot  = 0;
    has_peer         = 1;
  }
}

static void
repair_deliver_fun( fd_shred_t const *                            shred,
                    FD_PARAM_UNUSED ulong                         shred_sz,
                    FD_PARAM_UNUSED fd_repair_peer_addr_t const * from,
                    void *                                        arg ) {
  FD_LOG_DEBUG( ( "received shred - slot: %lu idx: %u", shred->slot, shred->idx ) );
  int                   rc;
  fd_tvu_repair_ctx_t * repair_ctx = (fd_tvu_repair_ctx_t *)arg;
  fd_blockstore_t *     blockstore = repair_ctx->blockstore;
  if( FD_UNLIKELY( rc = fd_blockstore_shred_insert( blockstore, NULL, shred ) != FD_BLOCKSTORE_OK ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_upsert_shred error: slot %lu, reason: %02x", rc ) );
  };
  fd_blockstore_slot_meta_map_t * slot_meta_map =
      fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->slot_meta_map_gaddr );
  fd_blockstore_slot_meta_map_t * slot_meta_entry;
  if( FD_UNLIKELY( !( slot_meta_entry = fd_blockstore_slot_meta_map_query(
                          slot_meta_map, shred->slot, NULL ) ) ) ) {
    FD_LOG_ERR( ( "no slot meta despite just inserting a shred for that slot" ) );
  }
  fd_slot_meta_t * slot_meta = &slot_meta_entry->slot_meta;
  // block is complete
  if( FD_UNLIKELY( slot_meta->consumed == slot_meta->last_index ) ) {
    FD_LOG_NOTICE(
        ( "received all shreds for slot %lu! now executing, and verifying...", slot_meta->slot ) );
    fd_blockstore_block_t * block = fd_blockstore_block_query( blockstore, slot_meta->slot );
    if( FD_UNLIKELY( !block ) ) FD_LOG_ERR( ( "block is missing after receiving all shreds" ) );

    // TODO move this somewhere more reasonable... separate replay tile that reads off mcache /
    // dcache?
    // FD_TEST(
    // FIXME multi thread once it works
    ulong txn_cnt = 0;
    FD_TEST(fd_runtime_block_eval_tpool( repair_ctx->slot_ctx, NULL, fd_blockstore_block_data_laddr( blockstore, block ), block->sz, NULL, 1, &txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS);
    (void)txn_cnt;

    FD_LOG_NOTICE( ( "bank hash for slot %lu: %32J",
                     slot_meta->slot,
                     repair_ctx->slot_ctx->slot_bank.banks_hash.hash ) );

    /* progress to next slot */
    requested_highest = 0;
    memset( requested_idxs, 0, sizeof( requested_idxs ) );
    blockstore->root++;
    repair_ctx->slot_ctx->slot_bank.prev_slot = repair_ctx->slot_ctx->slot_bank.slot;
    repair_ctx->slot_ctx->slot_bank.slot++;

#if 0
    fd_hash_t const * known_bank_hash =
        fd_get_bank_hash( repair_ctx->slot_ctx->acc_mgr->funk, slot_meta->slot );
    FD_LOG_NOTICE( ( "got bank hash %32J for slot %lu", known_bank_hash->uc, slot_meta->slot ) );
    if( known_bank_hash ) {
      FD_LOG_NOTICE( ( "comparing bank hash %32J with %32J for slot %lu",
                       known_bank_hash->uc,
                       repair_ctx->slot_ctx->slot_bank.banks_hash.hash,
                       slot_meta->slot ) );
      if( FD_UNLIKELY( 0 != memcmp( repair_ctx->slot_ctx->slot_bank.banks_hash.hash,
                                    known_bank_hash->hash,
                                    32UL ) ) ) {
        FD_LOG_WARNING( ( "Bank hash mismatch! slot=%lu expected=%32J, got=%32J",
                          slot_meta->slot,
                          known_bank_hash->hash,
                          repair_ctx->slot_ctx->slot_bank.banks_hash.hash ) );
        fd_solcap_writer_fini( repair_ctx->slot_ctx->capture );
        kill( getpid(), SIGTRAP );
        return;
      }
    } else {
      FD_LOG_ERR( ( "bank hash is NULL" ) );
    }
#endif
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
  requested_highest = false;
  for( uint i = 0; i < FD_SHRED_MAX_PER_SLOT; i++ ) {
    requested_idxs[i] = false;
  }
}

// SIGINT signal handler
volatile int stopflag = 0;
static void
stop( int sig ) {
  (void)sig;
  stopflag = 1;
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
  if( sendto( gossip_sockfd,
              data,
              sz,
              MSG_DONTWAIT,
              (const struct sockaddr *)saddr,
              (socklen_t)saddrlen ) < 0 ) {
    FD_LOG_WARNING( ( "sendto failed: %s", strerror( errno ) ) );
  }
}

static int repair_sockfd = -1;

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
  if( i == 0 ) /* :port means $HOST:port */
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

static int
tvu_main( fd_gossip_t *        gossip,
          fd_gossip_config_t * gossip_config,
          fd_repair_t *        repair,
          fd_repair_config_t * repair_config,
          fd_repair_peer_t *   repair_peers,
          fd_blockstore_t *    blockstore,
          volatile int *       stopflag,
          int                  argc,
          char **              argv ) {

  /* initialize gossip */
  int gossip_fd;
  if( ( gossip_fd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {
    FD_LOG_ERR( ( "socket failed: %s", strerror( errno ) ) );
    return -1;
  }
  gossip_sockfd     = gossip_fd;
  int gossip_optval = 1 << 20;
  if( setsockopt( gossip_fd, SOL_SOCKET, SO_RCVBUF, (char *)&gossip_optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR( ( "setsocketopt failed: %s", strerror( errno ) ) );
    return -1;
  }

  if( setsockopt( gossip_fd, SOL_SOCKET, SO_SNDBUF, (char *)&gossip_optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR( ( "setsocketopt failed: %s", strerror( errno ) ) );
    return -1;
  }

  uchar gossip_saddr[sizeof( struct sockaddr_in6 )];
  int   gossip_addrlen = gossip_to_sockaddr( gossip_saddr, &gossip_config->my_addr );
  if( gossip_addrlen < 0 ||
      bind( gossip_fd, (struct sockaddr *)gossip_saddr, (uint)gossip_addrlen ) < 0 ) {
    FD_LOG_ERR( ( "bind failed: %s", strerror( errno ) ) );
    return -1;
  }
  if( getsockname( gossip_fd, (struct sockaddr *)gossip_saddr, (uint *)&gossip_addrlen ) < 0 ) {
    FD_LOG_ERR( ( "getsockname failed: %s", strerror( errno ) ) );
    return -1;
  }
  gossip_from_sockaddr( &gossip_config->my_addr, gossip_saddr );
  fd_gossip_update_addr( gossip, &gossip_config->my_addr );

  fd_gossip_settime( gossip, fd_log_wallclock() );
  fd_gossip_start( gossip );

#define VLEN 32U
  struct mmsghdr gossip_msgs[VLEN];
  struct iovec   gossip_iovecs[VLEN];
  uchar          gossip_bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar          gossip_sockaddrs[VLEN]
                        [sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */

  /* initialize repair */
  int repair_fd;
  if( ( repair_fd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {
    FD_LOG_ERR( ( "socket failed: %s", strerror( errno ) ) );
    return -1;
  }
  repair_sockfd     = repair_fd;
  int repair_optval = 1 << 20;
  if( setsockopt( repair_fd, SOL_SOCKET, SO_RCVBUF, (char *)&repair_optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR( ( "setsocketopt failed: %s", strerror( errno ) ) );
    return -1;
  }
  if( setsockopt( repair_fd, SOL_SOCKET, SO_SNDBUF, (char *)&repair_optval, sizeof( int ) ) < 0 ) {
    FD_LOG_ERR( ( "setsocketopt failed: %s", strerror( errno ) ) );
    return -1;
  }
  uchar repair_saddr[sizeof( struct sockaddr_in6 )];
  int   repair_saddrlen = repair_to_sockaddr( repair_saddr, &repair_config->my_addr );
  if( repair_saddrlen < 0 ||
      bind( repair_fd, (struct sockaddr *)repair_saddr, (uint)repair_saddrlen ) < 0 ) {
    FD_LOG_ERR( ( "bind failed: %s", strerror( errno ) ) );
    return -1;
  }
  if( getsockname( repair_fd, (struct sockaddr *)repair_saddr, (uint *)&repair_saddrlen ) < 0 ) {
    FD_LOG_ERR( ( "getsockname failed: %s", strerror( errno ) ) );
    return -1;
  }

  gossip_from_sockaddr( &repair_config->my_addr, repair_saddr );
  fd_repair_update_addr( repair, &repair_config->my_addr );

  fd_repair_settime( repair, fd_log_wallclock() );
  fd_repair_start( repair );

  /* optionally specify a repair peer identity to skip waiting for a contact info to come through */
  char const * repair_peer_id_ =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-id", NULL, NULL );
  char const * repair_peer_addr_ =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--repair-peer-addr", NULL, "127.0.0.1:1032" );
  if( repair_peer_id_ ) {
    fd_pubkey_t repair_peer_id;
    fd_base58_decode_32( repair_peer_id_, repair_peer_id.uc );
    fd_repair_peer_addr_t repair_peer_addr = { 0 };
    if( FD_UNLIKELY(
            fd_repair_add_active_peer( repair,
                                       resolve_hostport( repair_peer_addr_, &repair_peer_addr ),
                                       &repair_peer_id ) ) ) {
      FD_LOG_ERR( ( "error adding repair active peer" ) );
    }
    fd_repair_peer_t * peer = fd_repair_peer_insert( repair_peers, repair_peer_id );
    // FIXME hack to be able to immediately send a msg for the CLI-specified peer
    peer->first_slot = blockstore->root + 1;
    peer->last_slot  = ULONG_MAX;
    has_peer         = 1;
  }

  // char const * skip_gossip =
  //     fd_env_strip_cmdline_char( &argc, &argv, "--skip-gossip", NULL, 0 );

#define VLEN 32U
  struct mmsghdr repair_msgs[VLEN];
  struct iovec   repair_iovecs[VLEN];
  uchar          repair_bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar          repair_sockaddrs[VLEN]
                        [sizeof( struct sockaddr_in6 )]; /* sockaddr is smaller than sockaddr_in6 */

  long last_call = fd_log_wallclock();
  while( !*stopflag ) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( has_peer && ( now - last_call ) > (long)10e6 ) ) {
      repair_missing_shreds( repair, blockstore, repair_peers );
      last_call = now;
    }

    /* Loop gossip */
    fd_gossip_settime( gossip, fd_log_wallclock() );
    fd_gossip_continue( gossip );

    fd_memset( gossip_msgs, 0, sizeof( gossip_msgs ) );
    for( uint i = 0; i < VLEN; i++ ) {
      gossip_iovecs[i].iov_base          = gossip_bufs[i];
      gossip_iovecs[i].iov_len           = FD_ETH_PAYLOAD_MAX;
      gossip_msgs[i].msg_hdr.msg_iov     = &gossip_iovecs[i];
      gossip_msgs[i].msg_hdr.msg_iovlen  = 1;
      gossip_msgs[i].msg_hdr.msg_name    = gossip_sockaddrs[i];
      gossip_msgs[i].msg_hdr.msg_namelen = sizeof( struct sockaddr_in6 );
    }

    /* Read more packets */
    int gossip_rc = recvmmsg( gossip_fd, gossip_msgs, VLEN, MSG_DONTWAIT, NULL );
    if( gossip_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) goto repair_loop;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      return -1;
    }

    for( uint i = 0; i < (uint)gossip_rc; ++i ) {
      fd_gossip_peer_addr_t from;
      gossip_from_sockaddr( &from, gossip_msgs[i].msg_hdr.msg_name );
      fd_gossip_recv_packet( gossip, gossip_bufs[i], gossip_msgs[i].msg_len, &from );
    }

  repair_loop:
    /* Loop repair */
    fd_repair_settime( repair, fd_log_wallclock() );
    fd_repair_continue( repair );

    fd_memset( repair_msgs, 0, sizeof( repair_msgs ) );
    for( uint i = 0; i < VLEN; i++ ) {
      repair_iovecs[i].iov_base          = repair_bufs[i];
      repair_iovecs[i].iov_len           = FD_ETH_PAYLOAD_MAX;
      repair_msgs[i].msg_hdr.msg_iov     = &repair_iovecs[i];
      repair_msgs[i].msg_hdr.msg_iovlen  = 1;
      repair_msgs[i].msg_hdr.msg_name    = repair_sockaddrs[i];
      repair_msgs[i].msg_hdr.msg_namelen = sizeof( struct sockaddr_in6 );
    }

    /* Read more packets */
    int repair_rc = recvmmsg( repair_fd, repair_msgs, VLEN, MSG_DONTWAIT, NULL );
    if( repair_rc < 0 ) {
      if( errno == EINTR || errno == EWOULDBLOCK ) continue;
      FD_LOG_ERR( ( "recvmmsg failed: %s", strerror( errno ) ) );
      return -1;
    }

    for( uint i = 0; i < (uint)repair_rc; ++i ) {
      fd_repair_peer_addr_t from;
      repair_from_sockaddr( &from, repair_msgs[i].msg_hdr.msg_name );
      // FD_LOG_HEXDUMP_NOTICE( ( "recv: ", repair_bufs[i], repair_msgs[i].msg_len ) );
      fd_repair_recv_packet( repair, repair_bufs[i], repair_msgs[i].msg_len, &from );
    }
  }

  close( gossip_fd );
  close( repair_fd );
  return 0;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );
  fd_valloc_t valloc = fd_libc_alloc_virtual();

  /**********************************************************************/
  /* Wksp                                                               */
  /**********************************************************************/

  ulong  page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 128UL);
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /**********************************************************************/
  /* Scratch                                                            */
  /**********************************************************************/

  ulong  smax   = 1 << 26UL; /* 64 MiB scratch memory */
  ulong  sdepth = 128;       /* 128 scratch frames */
  void * smem   = fd_wksp_alloc_laddr(
      wksp, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ), 421UL );
  void * fmem = fd_wksp_alloc_laddr(
      wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ), 421UL );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  /**********************************************************************/
  /* funk */
  /**********************************************************************/

  char const * snapshot = fd_env_strip_cmdline_cstr( &argc, &argv, "--snapshot", NULL, NULL );
  char const * load = fd_env_strip_cmdline_cstr( &argc, &argv, "--load", NULL, NULL );

  char hostname[64];
  gethostname( hostname, sizeof( hostname ) );
  ulong hashseed = fd_hash( 0, hostname, strnlen( hostname, sizeof( hostname ) ) );

  char const * peer_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--gossip-peer-addr", NULL, ":1024" );

  fd_wksp_t *  funk_wksp = NULL;
  ulong        def_index_max;
  char const * funk_wksp_name =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--funk-wksp", NULL, NULL );
  if( funk_wksp_name == NULL ) {
    funk_wksp     = wksp;
    def_index_max = 100000000;
  } else {
    funk_wksp = fd_wksp_attach( funk_wksp_name );
    if( funk_wksp == NULL ) FD_LOG_ERR( ( "failed to attach to workspace %s", funk_wksp_name ) );
    def_index_max = 350000000;
  }
  FD_TEST( funk_wksp );

  if( snapshot ) { /* Start from scratch */
    fd_wksp_reset( funk_wksp, (uint)hashseed );
  } else if( load ) {
    FD_LOG_NOTICE(("loading %s", load));
    int err = fd_wksp_restore(funk_wksp, load, (uint)hashseed);
    if (err)
      FD_LOG_ERR(("load failed: error %d", err));

  } else {
    FD_LOG_WARNING(("using --snapshot or --load is recommended"));
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
    ulong index_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--indexmax", NULL, def_index_max );
    ulong xactions_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--txnmax", NULL, 1000 );
    funk               = fd_funk_join( fd_funk_new( shmem, 1, hashseed, xactions_max, index_max ) );
    if( funk == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR( ( "failed to allocate a funky" ) );
    }
  }

  /**********************************************************************/
  /* Blockstore                                                         */
  /**********************************************************************/

  char const * blockstore_wksp_name =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--blockstore-wksp", NULL, NULL );

  fd_wksp_t * blockstore_wksp = NULL;
  if( blockstore_wksp == NULL ) {
    blockstore_wksp = wksp;
  } else {
    blockstore_wksp = fd_wksp_attach( blockstore_wksp_name );
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
    ulong tmp_shred_max = 1UL << 20;
    int   lg_txn_max    = 20;
    ulong slot_history_max = FD_DEFAULT_SLOT_HISTORY_MAX;
    blockstore          = fd_blockstore_join(fd_blockstore_new( shmem, 1, hashseed, tmp_shred_max, lg_txn_max, slot_history_max ) );
    if( blockstore == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR( ( "failed to allocate a blockstorey" ) );
    }
  }

  /**********************************************************************/
  /* slot_ctx                                                           */
  /**********************************************************************/

  uchar epoch_ctx_mem[FD_EXEC_EPOCH_CTX_FOOTPRINT]
      __attribute__( ( aligned( FD_EXEC_EPOCH_CTX_ALIGN ) ) );
  fd_exec_epoch_ctx_t * epoch_ctx =
      fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem ) );

  uchar slot_ctx_mem[FD_EXEC_SLOT_CTX_FOOTPRINT]
      __attribute__( ( aligned( FD_EXEC_SLOT_CTX_ALIGN ) ) );
  fd_exec_slot_ctx_t * slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem ) );
  slot_ctx->epoch_ctx           = epoch_ctx;

  epoch_ctx->valloc = valloc;
  slot_ctx->valloc  = valloc;

  fd_acc_mgr_t _acc_mgr[1];
  slot_ctx->acc_mgr = fd_acc_mgr_new( _acc_mgr, funk, blockstore );

  /**********************************************************************/
  /* snapshots                                                          */
  /**********************************************************************/

  char const * incremental = fd_env_strip_cmdline_cstr( &argc, &argv, "--incremental-snapshot", NULL, NULL );

  ulong snapshot_slot = 0;
  if( snapshot ) {
    if (!incremental )
      FD_LOG_WARNING(("Running without incremental snapshot. This only makes sense if you're using a local validator."));
    const char * p = strstr( snapshot, "snapshot-" );
    if( p == NULL ) FD_LOG_ERR( ( "--snapshot-file value is badly formatted" ) );
    do {
      const char * p2 = strstr( p + 1, "snapshot-" );
      if( p2 == NULL ) break;
      p = p2;
    } while( 1 );
    if( sscanf( p, "snapshot-%lu", &snapshot_slot ) < 1 )
      FD_LOG_ERR( ( "--snapshot-file value is badly formatted" ) );

    if( incremental ) {
      p = strstr( incremental, "snapshot-" );
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
    snapshotfiles[0] = snapshot;
    snapshotfiles[1] = incremental;
    snapshotfiles[2] = NULL;
    fd_snapshot_load( snapshotfiles, slot_ctx, 1 );

  } else {
    {
      FD_LOG_NOTICE(("reading epoch bank record"));
      fd_funk_rec_key_t id = fd_runtime_epoch_bank_key();
      fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, NULL, &id);
      if ( rec == NULL )
        FD_LOG_ERR(("failed to read banks record"));
      void * val = fd_funk_val( rec, fd_funk_wksp(funk) );
      fd_bincode_decode_ctx_t ctx2;
      ctx2.data = val;
      ctx2.dataend = (uchar*)val + fd_funk_val_sz( rec );
      ctx2.valloc  = slot_ctx->valloc;
      FD_TEST( fd_epoch_bank_decode(&epoch_ctx->epoch_bank, &ctx2 )==FD_BINCODE_SUCCESS );

      FD_LOG_NOTICE(( "decoded epoch" ));
    }

    {
      FD_LOG_NOTICE(("reading slot bank record"));
      fd_funk_rec_key_t id = fd_runtime_slot_bank_key();
      fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, NULL, &id);
      if ( rec == NULL )
        FD_LOG_ERR(("failed to read banks record"));
      void * val = fd_funk_val( rec, fd_funk_wksp(funk) );
      fd_bincode_decode_ctx_t ctx2;
      ctx2.data = val;
      ctx2.dataend = (uchar*)val + fd_funk_val_sz( rec );
      ctx2.valloc  = slot_ctx->valloc;
      FD_TEST( fd_slot_bank_decode(&slot_ctx->slot_bank, &ctx2 )==FD_BINCODE_SUCCESS );

      FD_LOG_NOTICE(( "decoded slot=%ld banks_hash=%32J poh_hash %32J",
                      (long)slot_ctx->slot_bank.slot,
                      slot_ctx->slot_bank.banks_hash.hash,
                      slot_ctx->slot_bank.poh.hash ));

      slot_ctx->slot_bank.collected_fees = 0;
      slot_ctx->slot_bank.collected_rent = 0;
    }
  }
  
  snapshot_slot                 = slot_ctx->slot_bank.slot;
  slot_ctx->slot_bank.prev_slot = snapshot_slot;
  slot_ctx->slot_bank.slot++;

  slot_ctx->slot_bank.collected_fees = 0;
  slot_ctx->slot_bank.collected_rent = 0;

  fd_features_restore( slot_ctx );
  fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( slot_ctx );

  if( FD_UNLIKELY( snapshot_slot != 0 ) ) {
    blockstore->root = snapshot_slot;
    blockstore->min  = snapshot_slot;
  }

  /**********************************************************************/
  /* Identity                                                           */
  /**********************************************************************/

  uchar private_key[32];
  FD_TEST( 32UL == getrandom( private_key, 32UL, 0 ) );
  fd_sha512_t sha[1];
  fd_pubkey_t public_key;
  FD_TEST( fd_ed25519_public_from_private( public_key.uc, private_key, sha ) );

#ifdef FD_HAS_LIBMICROHTTP
  /**********************************************************************/
  /* rpc service                                                        */
  /**********************************************************************/
  rpc_ctx         = fd_rpc_alloc_ctx( funk, blockstore, &public_key, slot_ctx, valloc );
  ushort rpc_port = fd_env_strip_cmdline_ushort( &argc, &argv, "--rpc-port", NULL, 8899U );
  fd_rpc_start_service( rpc_port, rpc_ctx );
#endif

  /**********************************************************************/
  /* Peers                                                           */
  /**********************************************************************/

  void * repair_peers_mem =
      (uchar *)fd_wksp_alloc_laddr( wksp, fd_repair_peer_align(), fd_repair_peer_footprint(), 1UL );
  fd_repair_peer_t * repair_peers = fd_repair_peer_join( fd_repair_peer_new( repair_peers_mem ) );

  /**********************************************************************/
  /* Repair                                                             */
  /**********************************************************************/

  fd_repair_config_t repair_config;
  fd_memset( &repair_config, 0, sizeof( repair_config ) );

  repair_config.private_key = private_key;
  repair_config.public_key  = &public_key;

  char const * my_repair_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--my-repair-addr", NULL, ":0" );
  FD_TEST( resolve_hostport( my_repair_addr, &repair_config.my_addr ) );

  repair_config.deliver_fun      = repair_deliver_fun;
  repair_config.deliver_fail_fun = repair_deliver_fail_fun;

  ulong tcnt = fd_tile_cnt();
  uchar tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t * tpool = NULL;
  if( tcnt > 1 ) {
    tpool = fd_tpool_init( tpool_mem, tcnt );
    if( tpool == NULL ) FD_LOG_ERR( ( "failed to create thread pool" ) );
    for( ulong i = 1; i < tcnt; ++i ) {
      if( fd_tpool_worker_push( tpool, i, NULL, 0UL ) == NULL )
        FD_LOG_ERR( ( "failed to launch worker" ) );
    }
  }

  void *        repair_mem = fd_valloc_malloc( valloc, fd_repair_align(), fd_repair_footprint() );
  fd_repair_t * repair     = fd_repair_join( fd_repair_new( repair_mem, hashseed, valloc ) );

  fd_tvu_repair_ctx_t repair_ctx = { .repair            = repair,
                                     .repair_peers      = repair_peers,
                                     .blockstore        = blockstore,
                                     .slot_ctx          = slot_ctx,
                                     .requested_highest = 0,
                                     .requested_idxs    = { 0 } };
  repair_config.fun_arg          = &repair_ctx;
  repair_config.send_fun         = send_packet;

  if( fd_repair_set_config( repair, &repair_config ) ) return 1;

  /**********************************************************************/
  /* Gossip                                                             */
  /**********************************************************************/

  fd_gossip_config_t gossip_config;
  fd_memset( &gossip_config, 0, sizeof( gossip_config ) );

  gossip_config.private_key = private_key;
  gossip_config.public_key  = &public_key;

  char const * my_gossip_addr =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--my_gossip_addr", NULL, ":0" );
  FD_TEST( resolve_hostport( my_gossip_addr, &gossip_config.my_addr ) );

  gossip_config.shred_version = 0;
  gossip_config.deliver_fun   = gossip_deliver_fun;
  gossip_config.send_fun      = gossip_send_packet;

  ulong seed = fd_hash( 0, hostname, strnlen( hostname, sizeof( hostname ) ) );

  void *        gossip_mem = fd_valloc_malloc( valloc, fd_gossip_align(), fd_gossip_footprint() );
  fd_gossip_t * gossip     = fd_gossip_join( fd_gossip_new( gossip_mem, seed, valloc ) );

  fd_tvu_gossip_ctx_t gossip_ctx = {
      .gossip = gossip, .repair_peers = repair_peers, .repair = repair };
  gossip_config.fun_arg = &gossip_ctx;
  if( fd_gossip_set_config( gossip, &gossip_config ) )
    FD_LOG_ERR( ( "error setting gossip config" ) );

  fd_gossip_peer_addr_t gossip_peer_addr;
  if( fd_gossip_add_active_peer( gossip, resolve_hostport( peer_addr, &gossip_peer_addr ) ) )
    FD_LOG_ERR( ( "error adding gossip active peer" ) );

  /**********************************************************************/
  /* Tile                                                               */
  /**********************************************************************/

  signal( SIGINT, stop );
  signal( SIGPIPE, SIG_IGN );

  if( tvu_main( gossip,
                &gossip_config,
                repair,
                &repair_config,
                repair_peers,
                blockstore,
                &stopflag,
                argc,
                argv ) ) {
    return 1;
  }

  /***********************************************************************/
  /* Cleanup                                                             */
  /***********************************************************************/

#ifdef FD_HAS_LIBMICROHTTP
  fd_rpc_stop_service( rpc_ctx );
  fd_valloc_free( valloc, rpc_ctx );
#endif
  fd_valloc_free( valloc, fd_gossip_delete( fd_gossip_leave( gossip ), valloc ) );
  fd_valloc_free( valloc, fd_repair_delete( fd_repair_leave( repair ), valloc ) );
  fd_halt();
  return 0;

  //   /**********************************************************************/
  //   /* Outgoing shreds                                                    */
  //   /**********************************************************************/

  //   uchar const * pod = fd_wksp_pod_attach( "fd1_shred_store.wksp:4096" );
  //   FD_TEST( pod );

  //   fd_frag_meta_t * in_mcache = fd_mcache_join( fd_wksp_pod_map( pod, "mcache_shred_store_0" )
  //   ); FD_TEST( in_mcache ); uchar * in_dcache = fd_dcache_join( fd_wksp_pod_map( pod,
  //   "dcache_shred_store_0" ) ); FD_TEST( in_dcache ); ulong * in_fseq = fd_fseq_join(
  //   fd_wksp_pod_map( pod, "fseq_shred_store_0_store_0" ) ); FD_TEST( in_fseq );

  //   /*
  //   const char* config_file = fd_env_strip_cmdline_cstr ( &argc, &argv, "--config", NULL, NULL
  //   ); if ( config_file == NULL ) {
  //     fprintf( stderr, "--config flag required\n" );
  //     usage( argv[0] );
  //     return 1;
  //   }
  //   */
}
