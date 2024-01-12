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

    build/native/gcc/bin/fd_frank_ledger --cmd ingest --snapshotfile snapshot-24* --incremental incremental-snapshot-24* --rocksdb /data/testnet/ledger/rocksdb --genesis /data/testnet/ledger/genesis.bin --txnstatus true --pages 100 --backup /data/asiegel/test_backup --slothistory 100

    build/native/gcc/unit-test/test_tvu --load /data/asiegel/test_backup --rpc-port 8123 --page-cnt 100 \
      --gossip-peer-addr :8000 \
      --repair-peer-addr :8008 \
      --repair-peer-id F7SW17yGN7UUPQ519nxaDt26UMtvwJPSFVu9kBMBQpW \
      --log-level-stderr 0

*/

#define _GNU_SOURCE /* See feature_test_macros(7) */

#define FD_TVU_TILE_SLOT_DELAY 32

#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../fd_flamenco.h"
#include "fd_tvu.h"
// #include "../gossip/fd_gossip.h"
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

static fd_pubkey_t pubkey_null = { 0 };

#define MAP_NAME                fd_repair_peer
#define MAP_T                   fd_repair_peer_t
#define MAP_LG_SLOT_CNT         12 /* 4kb peers */
#define MAP_KEY                 id
#define MAP_KEY_T               fd_pubkey_t
#define MAP_KEY_NULL            pubkey_null
#define MAP_KEY_INVAL( k )      !( memcmp( &k, &pubkey_null, sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( &k0 ), ( &k1 ), sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL_IS_SLOW   1
#define MAP_KEY_HASH( key )     ( (uint)( fd_hash( 0UL, &key, sizeof( fd_pubkey_t ) ) ) )
#include "../../util/tmpl/fd_map.c"

static bool has_peer                              = 0;

static void
eval_complete_blocks( fd_tvu_repair_ctx_t * repair_ctx ) {
  while( 1 ) {
    /* Search for the next block to execute */
    ulong slot = repair_ctx->slot_ctx->slot_bank.slot;
    for( ulong skip = 0; 1; ++skip ) {
      if( skip > 32U ) return; /* searching too far */
      ulong par = fd_blockstore_slot_parent_query( repair_ctx->blockstore, slot + skip );
      if( par == ULONG_MAX ) continue; /* not found/no metadata */
      if( par > repair_ctx->slot_ctx->slot_bank.prev_slot ) return; /* wait for missing blocks */
      if( par < repair_ctx->slot_ctx->slot_bank.prev_slot ) { /* wrong fork executed, roll back */
        if( fd_runtime_rollback_to( repair_ctx->slot_ctx, par ) ) {
          FD_LOG_WARNING(( "failed to roll back to %lu", par ));
          /* keep trying to make progress */
          continue;
        }
      }
      /* we should have the right parent now */
      FD_TEST( par == repair_ctx->slot_ctx->slot_bank.prev_slot );
      if( skip > 0 ) {
        FD_LOG_NOTICE(("skipping from block %lu to %lu", slot, slot+skip));
        for( ulong i = slot+1; i < slot+skip; ++i )
          /* Discard incomplete blocks. We will never request the rest of the shreds */
          fd_blockstore_discard_shreds( repair_ctx->blockstore, i );
        slot += skip;
      }
      repair_ctx->slot_ctx->slot_bank.slot = slot;
      break;
    }
    
    fd_blockstore_block_t * blk = fd_blockstore_block_query( repair_ctx->blockstore, slot );
    if( blk == NULL ) /* we have the metadata but not the actual block */
      return;
    ulong txn_cnt = 0;
    FD_TEST(fd_runtime_block_eval_tpool( repair_ctx->slot_ctx, NULL, fd_blockstore_block_data_laddr( repair_ctx->blockstore, blk ), blk->sz, NULL, 1, &txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS);
    (void)txn_cnt;

    FD_LOG_NOTICE( ( "bank hash for slot %lu: %32J",
                     slot,
                     repair_ctx->slot_ctx->slot_bank.banks_hash.hash ) );
  }
}

static void
repair_missing_shreds( fd_tvu_repair_ctx_t * repair_ctx ) {
  eval_complete_blocks( repair_ctx );

#define LOOK_AHEAD_HIGHEST 20
#define LOOK_AHEAD_SHREDS 2
  
  for( ulong slot = repair_ctx->slot_ctx->slot_bank.slot;
       slot - repair_ctx->slot_ctx->slot_bank.slot < LOOK_AHEAD_HIGHEST
         && !fd_repair_is_full( repair_ctx->repair );
       ++slot ) {
    if( fd_blockstore_block_query( repair_ctx->blockstore, slot ) != NULL)
      continue;

    /* Find up to 32 possible targets for the request */
    fd_repair_peer_t * peers[32];
    ulong npeers = 0;
    for( ulong i = 0; npeers < 32U && i < fd_repair_peer_slot_cnt(); i++ ) {
      fd_repair_peer_t * peer = &repair_ctx->repair_peers[i];
      if( memcmp( &peer->id, &pubkey_null, sizeof( fd_pubkey_t ) ) == 0 )
        continue;
      if( !( slot >= peer->first_slot && slot <= peer->last_slot ) )
        continue;
      if ( peer->request_cnt > 100U && peer->reply_cnt*3U < peer->request_cnt ) /* 2/3 fails */
        continue;
      peers[npeers++]  = peer;
    }
    if( FD_UNLIKELY( !npeers ) ) {
      FD_LOG_DEBUG( ( "unable to find any peers shreds in range of requested slot %lu", slot ) );
      break;
    }
#define GET_PEER \
    fd_repair_peer_t * peer = peers[repair_ctx->peer_iter % npeers]; \
    repair_ctx->peer_iter += 17077

    fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( repair_ctx->blockstore, slot );
    if( FD_UNLIKELY( !slot_meta ) ) {
      /* Spread out the requests */
      GET_PEER;
      FD_LOG_DEBUG( ( "requesting highest shred from %32J - slot: %lu", peer, slot ) );
      peer->request_cnt++;
      if( FD_UNLIKELY( fd_repair_need_highest_window_index( repair_ctx->repair, &peer->id, slot, 0 ) ) ) {
        FD_LOG_ERR( ( "error requesting highest window idx shred for slot %lu", slot ) );
      };
    } else if( slot - repair_ctx->slot_ctx->slot_bank.slot < LOOK_AHEAD_SHREDS ) {
      FD_LOG_DEBUG( ( "requesting all shreds from %lu peers - slot: %lu last: %lu", npeers, slot, slot_meta->last_index ) );
      for( ulong shred_idx = slot_meta->consumed + 1UL;
           shred_idx <= slot_meta->last_index && !fd_repair_is_full( repair_ctx->repair );
           shred_idx++ ) {
        if( fd_blockstore_shred_query( repair_ctx->blockstore, slot, (uint)shred_idx ) ) continue;
        /* Spread out the requests */
        GET_PEER;
        peer->request_cnt++;
        if( FD_UNLIKELY( fd_repair_need_window_index( repair_ctx->repair, &peer->id, slot, (uint)shred_idx ) ) ) {
          FD_LOG_ERR( ( "error requesting shreds" ) );
        };
      }
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
          fd_repair_peer_query( gossip_ctx->repair_peers, epoch_slots->from, NULL );
      if( FD_UNLIKELY( peer ) ) {
        peer->first_slot = slots.first_slot;
        peer->last_slot  = slots.first_slot + slots.num;
      }
    } else if( epoch_slots->slots->discriminant == fd_gossip_slots_enum_enum_flate2 ) {
      fd_gossip_flate2_slots_t slots = epoch_slots->slots->inner.flate2;
      fd_repair_peer_t *       peer =
          fd_repair_peer_query( gossip_ctx->repair_peers, epoch_slots->from, NULL );
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
      FD_LOG_DEBUG( ( "error adding peer" ) ); /* Probably filled up the table */
      return;
    };

    fd_repair_peer_t * peer =
        fd_repair_peer_insert( gossip_ctx->repair_peers, data->inner.contact_info_v1.id );
    peer->first_slot  = 0;
    peer->last_slot   = 0;
    peer->request_cnt = 0;
    peer->reply_cnt   = 0;
    has_peer          = 1;

    FD_LOG_DEBUG(("adding repair peer %32J", peer->id.uc));
  }
}

static void
repair_deliver_fun( fd_shred_t const *                            shred,
                    FD_PARAM_UNUSED ulong                         shred_sz,
                    FD_PARAM_UNUSED fd_repair_peer_addr_t const * from,
                    fd_pubkey_t const *                           id,
                    void *                                        arg ) {
  FD_LOG_DEBUG( ( "received shred - slot: %lu idx: %u", shred->slot, shred->idx ) );

  fd_tvu_repair_ctx_t * repair_ctx = (fd_tvu_repair_ctx_t *)arg;
  fd_repair_peer_t * peer = fd_repair_peer_query( repair_ctx->repair_peers, *id, NULL );
  if( FD_LIKELY( peer ) )
    peer->reply_cnt++;
    
  if( shred->slot < repair_ctx->slot_ctx->slot_bank.slot ||
      fd_blockstore_block_query( repair_ctx->blockstore, shred->slot ) != NULL )
    return;
  
  int                   rc;
  if( FD_UNLIKELY( rc = fd_blockstore_shred_insert( repair_ctx->blockstore, NULL, shred ) != FD_BLOCKSTORE_OK ) ) {
    FD_LOG_WARNING( ( "fd_blockstore_upsert_shred error: slot %lu, reason: %02x", shred->slot, rc ) );
  };
  eval_complete_blocks( repair_ctx );
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

static void
print_stats( fd_tvu_repair_ctx_t * repair_ctx ) {
  ulong slot = repair_ctx->slot_ctx->slot_bank.slot;
  ulong peer_cnt = 0;
  ulong good_peer_cnt = 0;
  for( ulong i = 0; i < fd_repair_peer_slot_cnt(); i++ ) {
    fd_repair_peer_t * peer = &repair_ctx->repair_peers[i];
    if( memcmp( &peer->id, &pubkey_null, sizeof( fd_pubkey_t ) ) == 0 )
      continue;
    ++peer_cnt;
    if( slot >= peer->first_slot && slot <= peer->last_slot &&
        !( peer->request_cnt > 100U && peer->reply_cnt*3U < peer->request_cnt ) ) /* 2/3 fails */
      ++good_peer_cnt;
    if( peer->request_cnt )
      FD_LOG_NOTICE(( "peer %32J - avg requests: %lu, avg responses: %lu, ratio: %f, first_slot: %lu, last_slot: %lu",
                      &peer->id, peer->request_cnt, peer->reply_cnt, ((double)peer->reply_cnt)/((double)peer->request_cnt),
                      peer->first_slot, peer->last_slot ));
    /* Do a moving average over several minutes */
    peer->request_cnt >>= 1;
    peer->reply_cnt >>= 1;
  }
  FD_LOG_NOTICE(( "current slot: %lu, transactions: %lu, peer count: %lu, 'good' peer count: %lu",
                  slot, repair_ctx->slot_ctx->slot_bank.transaction_count, peer_cnt, good_peer_cnt ));
}

int
tvu_main( fd_gossip_t *        gossip,
          fd_gossip_config_t * gossip_config,
          fd_tvu_repair_ctx_t * repair_ctx,
          fd_repair_config_t * repair_config,
          volatile int *       stopflag,
          char const * repair_peer_id_,
          char const * repair_peer_addr_ ) {

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
  fd_repair_update_addr( repair_ctx->repair, &repair_config->my_addr );

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
    fd_repair_peer_t * peer = fd_repair_peer_insert( repair_ctx->repair_peers, repair_peer_id );
    // FIXME hack to be able to immediately send a msg for the CLI-specified peer
    peer->first_slot  = repair_ctx->blockstore->root + 1;
    peer->last_slot   = ULONG_MAX;
    peer->request_cnt = 0;
    peer->reply_cnt   = 0;
    has_peer          = 1;
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
  long last_stats = last_call;
  while( !*stopflag ) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( has_peer && ( now - last_call ) > (long)100e6 ) ) {
      repair_missing_shreds( repair_ctx );
      last_call = now;
    }
    if( FD_UNLIKELY( ( now - last_stats ) > (long)30e9 ) ) {
      print_stats( repair_ctx );
      last_stats = now;
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
    fd_repair_settime( repair_ctx->repair, fd_log_wallclock() );
    fd_repair_continue( repair_ctx->repair );

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
      fd_repair_recv_packet( repair_ctx->repair, repair_bufs[i], repair_msgs[i].msg_len, &from );
    }
  }

  close( gossip_fd );
  close( repair_fd );
  return 0;
}

void
tvu_main_setup( tvu_main_args_t * tvu_args,
                fd_valloc_t valloc,
                fd_wksp_t  * _wksp,
                char const * blockstore_wksp_name,
                char const * funk_wksp_name,
                char const * peer_addr,
                char const * incremental,
                char const * load,
                char const * my_gossip_addr,
                char const * my_repair_addr,
                char const * snapshot,
                ulong  index_max,
                ulong  page_cnt,
                ulong  tcnt,
                ulong  xactions_max,
                ushort rpc_port ) {
  
  fd_memset( tvu_args, 0, sizeof( tvu_main_args_t ) );

  /**********************************************************************/
  /* Anonymous wksp                                                     */
  /**********************************************************************/

  fd_wksp_t * wksp;
  if( !_wksp ) {
    char * _page_sz = "gigantic";
    ulong  numa_idx = fd_shmem_numa_idx( 0 );
    FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                    page_cnt,
                    _page_sz,
                    numa_idx ) );
    wksp = fd_wksp_new_anonymous(
        fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );

  } else {
    wksp = _wksp;
  }
  FD_TEST( wksp );

  /**********************************************************************/
  /* funk */
  /**********************************************************************/

  char hostname[64];
  gethostname( hostname, sizeof( hostname ) );
  ulong hashseed = fd_hash( 0, hostname, strnlen( hostname, sizeof( hostname ) ) );

  fd_wksp_t *  funk_wksp = NULL;
  if( funk_wksp_name == NULL ) {
    funk_wksp     = wksp;
    if( index_max == ULONG_MAX ) {
      index_max = 100000000;
    }
  } else {
    funk_wksp = fd_wksp_attach( funk_wksp_name );
    if( funk_wksp == NULL ) FD_LOG_ERR( ( "failed to attach to workspace %s", funk_wksp_name ) );
    if( index_max == ULONG_MAX ) {
      index_max = 350000000;
    }
  }
  FD_TEST( funk_wksp );

  if( snapshot ) {
    if( wksp != funk_wksp )
      /* Start from scratch */
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
    funk               = fd_funk_join( fd_funk_new( shmem, 1, hashseed, xactions_max, index_max ) );
    if( funk == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR( ( "failed to allocate a funky" ) );
    }
  }

  /**********************************************************************/
  /* Blockstore                                                         */
  /**********************************************************************/

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
  /* slot_ctx                                                           */
  /**********************************************************************/

  fd_exec_epoch_ctx_t * epoch_ctx =
    tvu_args->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( tvu_args->epoch_ctx_mem ) );
  fd_exec_slot_ctx_t * slot_ctx =
    tvu_args->slot_ctx  = fd_exec_slot_ctx_join(  fd_exec_slot_ctx_new( tvu_args->slot_ctx_mem ) );

  epoch_ctx->valloc = valloc;
  slot_ctx->valloc  = valloc;

  slot_ctx->acc_mgr = fd_acc_mgr_new( tvu_args->_acc_mgr, funk, blockstore );

  /**********************************************************************/
  /* snapshots                                                          */
  /**********************************************************************/

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

  FD_TEST( 32UL == getrandom( tvu_args->private_key, 32UL, 0 ) );
  fd_sha512_t sha[1];
  FD_TEST( fd_ed25519_public_from_private( tvu_args->public_key.uc, tvu_args->private_key, sha ) );

#ifdef FD_HAS_LIBMICROHTTP
  /**********************************************************************/
  /* rpc service                                                        */
  /**********************************************************************/
  rpc_ctx         = fd_rpc_alloc_ctx( funk, blockstore, &tvu_args->public_key, slot_ctx, valloc );
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

  tvu_args->repair_config.private_key = tvu_args->private_key;
  tvu_args->repair_config.public_key  = &tvu_args->public_key;

  FD_TEST( resolve_hostport( my_repair_addr, &tvu_args->repair_config.my_addr ) );

  tvu_args->repair_config.deliver_fun      = repair_deliver_fun;
  tvu_args->repair_config.deliver_fail_fun = repair_deliver_fail_fun;

  if( tcnt == ULONG_MAX ) {
    tcnt = fd_tile_cnt();
  }
  fd_tpool_t * tpool = NULL;
  if( tcnt > 1 ) {
    tpool = fd_tpool_init( tvu_args->tpool_mem, tcnt );
    if( tpool == NULL ) FD_LOG_ERR( ( "failed to create thread pool" ) );
    for( ulong i = 1; i < tcnt; ++i ) {
      if( fd_tpool_worker_push( tpool, i, NULL, 0UL ) == NULL )
        FD_LOG_ERR( ( "failed to launch worker" ) );
    }
  }

  void *        repair_mem = fd_valloc_malloc( valloc, fd_repair_align(), fd_repair_footprint() );
  fd_repair_t * repair     = fd_repair_join( fd_repair_new( repair_mem, hashseed, valloc ) );
  tvu_args->repair         = repair;

  fd_tvu_repair_ctx_t * repair_ctx = &tvu_args->repair_ctx;
  repair_ctx->repair = repair;
  repair_ctx->repair_peers = repair_peers;
  repair_ctx->blockstore = blockstore;
  repair_ctx->slot_ctx = slot_ctx;
  repair_ctx->peer_iter = 0;

  tvu_args->repair_config.fun_arg  = &repair_ctx;
  tvu_args->repair_config.send_fun = send_packet;

  if( fd_repair_set_config( repair, &tvu_args->repair_config ) ) tvu_args->blowup = 1;

  /**********************************************************************/
  /* Gossip                                                             */
  /**********************************************************************/

  tvu_args->gossip_config.private_key = tvu_args->private_key;
  tvu_args->gossip_config.public_key  = &tvu_args->public_key;

  FD_TEST( resolve_hostport( my_gossip_addr, &tvu_args->gossip_config.my_addr ) );

  tvu_args->gossip_config.shred_version = 0;
  tvu_args->gossip_config.deliver_fun   = gossip_deliver_fun;
  tvu_args->gossip_config.send_fun      = gossip_send_packet;

  ulong seed = fd_hash( 0, hostname, strnlen( hostname, sizeof( hostname ) ) );

  void *        gossip_mem = fd_valloc_malloc( valloc, fd_gossip_align(), fd_gossip_footprint() );
  fd_gossip_t * gossip     = fd_gossip_join( fd_gossip_new( gossip_mem, seed, valloc ) );
  tvu_args->gossip         = gossip;

  fd_tvu_gossip_ctx_t * gossip_ctx = &tvu_args->gossip_ctx;
  gossip_ctx->gossip = gossip;
  gossip_ctx->repair_peers = repair_peers;
  gossip_ctx->repair = repair;
  tvu_args->gossip_config.fun_arg = &gossip_ctx;
  if( fd_gossip_set_config( gossip, &tvu_args->gossip_config ) )
    FD_LOG_ERR( ( "error setting gossip config" ) );

  if( fd_gossip_add_active_peer( gossip, resolve_hostport( peer_addr, &tvu_args->gossip_peer_addr ) ) )
    FD_LOG_ERR( ( "error adding gossip active peer" ) );
}
