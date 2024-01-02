#include "tiles.h"

#include "../../../../flamenco/runtime/fd_tvu.h"

#include "generated/tvu_seccomp.h"

#include <linux/unistd.h>

////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////

#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU

#define FD_TVU_TILE_SLOT_DELAY 32

#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../flamenco/runtime/fd_blockstore.h"
#include "../../../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../../../flamenco/types/fd_types.h"
#include "../../../../util/fd_util.h"
#include "../../../../util/net/fd_eth.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../flamenco/gossip/fd_gossip.h"
#include "../../../../flamenco/repair/fd_repair.h"
#include "../../../../flamenco/rpc/fd_rpc_service.h"
#ifdef FD_HAS_LIBMICROHTTP
#endif
#include <arpa/inet.h>
#include <errno.h>
#define __USE_MISC
#include <netdb.h>
#undef __USE_MISC
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

fd_wksp_t *g_wksp = NULL;
char   g_repair_peer_id[ FD_BASE58_ENCODED_32_SZ ];
char   g_repair_peer_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char   g_gossip_peer_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char   g_snapshot[ PATH_MAX ];
uint   g_page_cnt;
ushort g_rpc_port = 12000;

static int gossip_sockfd = -1;

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
#include "../../../../util/tmpl/fd_map.c"

static bool has_peer                              = 0;

static void
eval_complete_blocks( fd_tvu_repair_ctx_t * repair_ctx ) {
  ulong slot = repair_ctx->slot_ctx->slot_bank.slot;
  while( 1 ) {
    fd_blockstore_block_t * blk = fd_blockstore_block_query( repair_ctx->blockstore, slot );

    if ( blk == NULL ) {
      /* Determine if we should skip blocks */
      for( ulong skip = 0; skip < 20; ++skip ) {
        ulong par = fd_blockstore_slot_parent_query( repair_ctx->blockstore, slot + skip );
        if( par == ULONG_MAX ) /* not found */ continue;
        if( par != repair_ctx->slot_ctx->slot_bank.prev_slot ) return;
        if( skip ) {
          FD_LOG_NOTICE(("skipping from block %lu to %lu", slot, slot + skip));
          repair_ctx->slot_ctx->slot_bank.slot = slot + skip;
        }
        break;
      }
      return;
    }
    
    /* We already have the block in the ledger somehow */
    fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( repair_ctx->blockstore, slot );
    if( FD_UNLIKELY( !slot_meta ) )
      FD_LOG_ERR(("missing meta for slot %lu", slot ));

    ulong txn_cnt = 0;
    FD_TEST(fd_runtime_block_eval_tpool( repair_ctx->slot_ctx, NULL, fd_blockstore_block_data_laddr( repair_ctx->blockstore, blk ), blk->sz, NULL, 1, &txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS);
    (void)txn_cnt;

    FD_LOG_NOTICE( ( "bank hash for slot %lu: %32J",
                     slot,
                     repair_ctx->slot_ctx->slot_bank.banks_hash.hash ) );

    /* progress to next slot */
    repair_ctx->blockstore->root++;
    repair_ctx->slot_ctx->slot_bank.prev_slot = slot;
    repair_ctx->slot_ctx->slot_bank.slot = ++slot;
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
      peers[npeers++]  = peer;
    }
    if( FD_UNLIKELY( !npeers ) ) {
      FD_LOG_DEBUG( ( "unable to find any peers shreds in range of requested slot %lu", slot ) );
      break;
    }

    fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( repair_ctx->blockstore, slot );
    if( FD_UNLIKELY( !slot_meta ) ) {
      /* Spread out the requests */
      fd_repair_peer_t * peer = peers[(repair_ctx->peer_iter++) % npeers];
      FD_LOG_DEBUG( ( "requesting highest shred from %32J - slot: %lu", peer, slot ) );
      peer->request_cnt++;
      if( FD_UNLIKELY( fd_repair_need_highest_window_index( repair_ctx->repair, &peer->id, slot, 0 ) ) ) {
        FD_LOG_ERR( ( "error requesting highest window idx shred for slot %lu", slot ) );
      };
    } else if( slot - repair_ctx->slot_ctx->slot_bank.slot < LOOK_AHEAD_SHREDS ) {
      FD_LOG_NOTICE( ( "requesting all shreds from %lu peers - slot: %lu last: %lu", npeers, slot, slot_meta->last_index ) );
      for( ulong shred_idx = slot_meta->consumed + 1UL;
           shred_idx <= slot_meta->last_index && !fd_repair_is_full( repair_ctx->repair );
           shred_idx++ ) {
        if( fd_blockstore_shred_query( repair_ctx->blockstore, slot, (uint)shred_idx ) ) continue;
        /* Spread out the requests */
        fd_repair_peer_t * peer = peers[(repair_ctx->peer_iter++) % npeers];
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
      FD_LOG_ERR( ( "error adding peer" ) );
    };

    fd_repair_peer_t * peer =
        fd_repair_peer_insert( gossip_ctx->repair_peers, data->inner.contact_info_v1.id );
    peer->first_slot  = 0;
    peer->last_slot   = 0;
    peer->request_cnt = 0;
    peer->reply_cnt   = 0;
    has_peer          = 1;

    FD_LOG_NOTICE(("adding repair peer %32J", peer->id.uc));
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
    FD_LOG_WARNING( ( "fd_blockstore_upsert_shred error: slot %lu, reason: %02x", rc ) );
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

static volatile int stopflag = 0;

static int
doit() {
  fd_valloc_t valloc = fd_libc_alloc_virtual();
  tvu_main_args_t tvu_main_args = tvu_main_setup( valloc,
                                                  g_wksp,
                                                  NULL,
                                                  NULL,
                                                  g_gossip_peer_addr,
                                                  NULL,
                                                  NULL,
                                                  ":0",
                                                  ":0",
                                                  g_snapshot,
                                                  ULONG_MAX,
                                                  g_page_cnt,
                                                  1,
                                                  1000, // TODO: LML add --txnmax to default.toml
                                                  g_rpc_port );
  if( tvu_main_args.blowup ) FD_LOG_ERR(( "blowup" ));

  /**********************************************************************/
  /* Tile                                                               */
  /**********************************************************************/

  if( tvu_main( tvu_main_args.gossip,
                tvu_main_args.gossip_config,
                tvu_main_args.repair_ctx,
                tvu_main_args.repair_config,
                tvu_main_args.stopflag,
                g_repair_peer_id,
                g_repair_peer_addr ) ) {
    return 1;
  }
  return 0;
}

static int
maaaain( int argc, char ** argv ) {
  FD_LOG_NOTICE(( "starting tvu" ));
  // fd_boot( &argc, &argv );
  FD_LOG_NOTICE(( "starting tvu 1" ));
  fd_flamenco_boot( &argc, &argv );
  FD_LOG_NOTICE(( "starting tvu 2" ));
  fd_valloc_t valloc = fd_libc_alloc_virtual();
  FD_LOG_NOTICE(( "starting tvu 3" ));

  /**********************************************************************/
  /* Anonymous wksp                                                     */
  /**********************************************************************/
  fd_wksp_t *wksp = g_wksp;
  FD_LOG_NOTICE(("starting tvu 4"));

  /**********************************************************************/
  /* funk */
  /**********************************************************************/

  char const * snapshot = g_snapshot;

  char hostname[64];
  gethostname( hostname, sizeof( hostname ) );
  ulong hashseed = fd_hash( 0, hostname, strnlen( hostname, sizeof( hostname ) ) );

  fd_wksp_t *  funk_wksp = g_wksp;
  ulong        def_index_max = 100000000;
  FD_TEST( funk_wksp );

  FD_LOG_NOTICE(("starting tvu 5"));

  void * shmem =
      fd_wksp_alloc_laddr( funk_wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
  if( shmem == NULL ) FD_LOG_ERR( ( "failed to allocate a funky" ) );
  fd_funk_t * funk = fd_funk_join( fd_funk_new( shmem, 1, hashseed, 1000, def_index_max ) );
  if( funk == NULL ) {
    fd_wksp_free_laddr( shmem );
    FD_LOG_ERR( ( "failed to allocate a funky" ) );
  }

  /**********************************************************************/
  /* Blockstore                                                         */
  /**********************************************************************/

  fd_wksp_t * blockstore_wksp = wksp;
  FD_TEST( blockstore_wksp );

  shmem = fd_wksp_alloc_laddr(
      blockstore_wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
  if( shmem == NULL ) FD_LOG_ERR( ( "failed to allocate a blockstorey" ) );

  // Sensible defaults for an anon blockstore:
  // - 1mb of shreds
  // - 64 slots of history (~= finalized = 31 slots on top of a confirmed block)
  // - 1mb of txns
  ulong tmp_shred_max = 1UL << 20;
  int   lg_txn_max    = 20;
  ulong slot_history_max = FD_DEFAULT_SLOT_HISTORY_MAX;
  fd_blockstore_t * blockstore = fd_blockstore_join(fd_blockstore_new( shmem, 1, hashseed, tmp_shred_max, lg_txn_max, slot_history_max ) );
  if( blockstore == NULL ) {
    fd_wksp_free_laddr( shmem );
    FD_LOG_ERR( ( "failed to allocate a blockstorey" ) );
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

  FD_LOG_NOTICE(("starting tvu 6"));

  /**********************************************************************/
  /* snapshots                                                          */
  /**********************************************************************/

  ulong snapshot_slot = 0;
  const char * p = strstr( snapshot, "snapshot-" );
  if( p == NULL ) FD_LOG_ERR( ( "--snapshot-file value is badly formatted" ) );
  do {
    const char * p2 = strstr( p + 1, "snapshot-" );
    if( p2 == NULL ) break;
    p = p2;
  } while( 1 );
  if( sscanf( p, "snapshot-%lu", &snapshot_slot ) < 1 )
    FD_LOG_ERR( ( "--snapshot-file value is badly formatted" ) );

  const char *snapshotfiles[3];
  snapshotfiles[0] = snapshot;
  snapshotfiles[1] = NULL;
  snapshotfiles[2] = NULL;
  fd_snapshot_load( snapshotfiles, slot_ctx, 1 );
  
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

  FD_LOG_NOTICE(("starting tvu 7"));

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
  ushort rpc_port = 8899;
  fd_rpc_start_service( rpc_port, rpc_ctx );
#endif

  /**********************************************************************/
  /* Peers                                                           */
  /**********************************************************************/

  void * repair_peers_mem =
      (uchar *)fd_wksp_alloc_laddr( wksp, fd_repair_peer_align(), fd_repair_peer_footprint(), 1UL );
  fd_repair_peer_t * repair_peers = fd_repair_peer_join( fd_repair_peer_new( repair_peers_mem ) );

  FD_LOG_NOTICE(("starting tvu 8"));

  /**********************************************************************/
  /* Repair                                                             */
  /**********************************************************************/

  fd_repair_config_t repair_config;
  fd_memset( &repair_config, 0, sizeof( repair_config ) );

  repair_config.private_key = private_key;
  repair_config.public_key  = &public_key;

  char const * my_repair_addr = ":0";
  FD_TEST( resolve_hostport( my_repair_addr, &repair_config.my_addr ) );

  repair_config.deliver_fun      = repair_deliver_fun;
  repair_config.deliver_fail_fun = repair_deliver_fail_fun;

  ulong tcnt = 1; // TODO: LML 
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

  fd_tvu_repair_ctx_t repair_ctx = { .repair                 = repair,
                                     .repair_peers           = repair_peers,
                                     .blockstore             = blockstore,
                                     .slot_ctx               = slot_ctx,
                                     .peer_iter              = 0 };
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

  char const * my_gossip_addr = ":0";
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

  char const * peer_addr = g_gossip_peer_addr;
  fd_gossip_peer_addr_t gossip_peer_addr;
  if( fd_gossip_add_active_peer( gossip, resolve_hostport( peer_addr, &gossip_peer_addr ) ) )
    FD_LOG_ERR( ( "error adding gossip active peer" ) );

  /**********************************************************************/
  /* Tile                                                               */
  /**********************************************************************/

  // signal( SIGINT, stop );
  // signal( SIGPIPE, SIG_IGN );

  // if( tvu_main( gossip,
  //               &gossip_config,
  //               &repair_ctx,
  //               &repair_config,
  //               &stopflag,
  //               argc,
  //               argv ) ) {
  //   return 1;
  // }

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



////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////
////////////////////////

int
fd_tvu_tile( fd_cnc_t *              cnc,
             ulong                   flags,
             ulong                   in_cnt,
             fd_frag_meta_t const ** in_mcache,
             ulong **                in_fseq,
             fd_frag_meta_t *        mcache,
             ulong                   out_cnt,
             ulong **                _out_fseq,
             ulong                   burst,
             ulong                   cr_max,
             long                    lazy,
             fd_rng_t *              rng,
             void *                  scratch,
             void *                  ctx,
             fd_mux_callbacks_t *    callbacks ) {
  (void)cnc;
  (void)flags;
  (void)in_cnt;
  (void)in_mcache;
  (void)in_fseq;
  (void)mcache;
  (void)out_cnt;
  (void)_out_fseq;
  (void)burst;
  (void)cr_max;
  (void)lazy;
  (void)rng;
  (void)scratch;
  (void)ctx;
  (void)callbacks;

  // maaaain( 0, NULL );
  (void)maaaain;
  doit();
  return 0;
}

typedef struct {
  int socket_fd;
} fd_tvu_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  // TODO: to get around defined and not used
  (void)has_peer;
  (void)gossip_sockfd;
  (void)rpc_ctx;
  (void)resolve_hostport;
  (void)send_packet;
  (void)repair_from_sockaddr;
  (void)gossip_send_packet;
  (void)gossip_from_sockaddr;
  (void)repair_deliver_fail_fun;
  (void)repair_deliver_fun;
  (void)gossip_deliver_fun;
  (void)repair_missing_shreds;
  (void)maaaain;
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t *tile ) {
  return tile->tvu.page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t *tile ) {
  (void)tile;
  return 4096UL;
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_tvu_ctx_t ) );
}

static void
during_frag( void * ctx,
             ulong  in_idx,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)ctx;
  (void)in_idx;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)opt_filter;
}

static void
after_frag( void *             ctx,
            ulong              in_idx,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)ctx;
  (void)in_idx;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_filter;
  (void)mux;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  g_wksp = topo->workspaces[ tile->wksp_id ].wksp;
  // struct fd_wksp_usage usage;
  // fd_wksp_usage( g_wksp, 1, 1, &usage );
  // fd_wksp_reset( g_wksp, 0 );
  // fd_wksp_rebuild( g_wksp, 0 );

  strncpy( g_repair_peer_id, tile->tvu.repair_peer_id, sizeof(g_repair_peer_id) );
  strncpy( g_repair_peer_addr, tile->tvu.repair_peer_addr, sizeof(g_repair_peer_addr) );
  strncpy( g_gossip_peer_addr, tile->tvu.gossip_peer_addr, sizeof(g_gossip_peer_addr) );
  strncpy( g_snapshot, tile->tvu.snapshot, sizeof(g_snapshot) );
  g_page_cnt = tile->tvu.page_cnt;
  (void)topo;
  (void)tile;
  (void)scratch;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_tvu( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_tvu_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_tile_config_t fd_tile_tvu = {
  .mux_flags                = FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
