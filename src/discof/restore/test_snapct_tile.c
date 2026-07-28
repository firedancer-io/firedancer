#define FD_TILE_TEST 1
#include "fd_snapct_tile.c"
#include <stdlib.h>

static void
send_contact_info( fd_snapct_tile_t *           ctx,
                   fd_gossip_update_message_t * msg,
                   ulong                        idx,
                   fd_pubkey_t const *          pubkey ) {
  fd_memset( msg, 0, sizeof(*msg) );
  msg->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
  fd_memcpy( msg->origin, pubkey->uc, sizeof(fd_pubkey_t) );
  msg->contact_info->idx = idx;
  gossip_frag( ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, FD_GOSSIP_UPDATE_SZ_CONTACT_INFO, 0UL );
}

static void
send_contact_info_remove( fd_snapct_tile_t *           ctx,
                          fd_gossip_update_message_t * msg,
                          ulong                        idx,
                          fd_pubkey_t const *          pubkey ) {
  fd_memset( msg, 0, sizeof(*msg) );
  msg->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  fd_memcpy( msg->origin, pubkey->uc, sizeof(fd_pubkey_t) );
  msg->contact_info_remove->idx = idx;
  gossip_frag( ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE, FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE, 0UL );
}

static void
setup_gossip_only_snapct( void *                       scratch,
                          fd_snapct_tile_t **          ctx_out,
                          fd_gossip_update_message_t * msg ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapct_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapct_tile_t),  sizeof(fd_snapct_tile_t)       );
  memset( ctx, 0, sizeof(fd_snapct_tile_t) );
  gossip_ci_entry_t * ci_table = FD_SCRATCH_ALLOC_APPEND( l, alignof(gossip_ci_entry_t), sizeof(gossip_ci_entry_t)*GOSSIP_PEERS_MAX );
  void *              ci_map   = FD_SCRATCH_ALLOC_APPEND( l, gossip_ci_map_align(),      gossip_ci_map_footprint( gossip_ci_map_chain_cnt_est( GOSSIP_PEERS_MAX ) ) );

  fd_memset( ci_table, 0, sizeof(gossip_ci_entry_t)*GOSSIP_PEERS_MAX );
  ctx->gossip.ci_table = ci_table;
  ctx->gossip.ci_map   = gossip_ci_map_join( gossip_ci_map_new( ci_map, gossip_ci_map_chain_cnt_est( GOSSIP_PEERS_MAX ), 0UL ) );
  FD_TEST( ctx->gossip.ci_map );

  ctx->gossip_in_mem = msg;

  ctx->gossip_enabled = 1;
  ctx->config.sources.gossip.allow_any      = 0;
  ctx->config.sources.gossip.allow_list_cnt = 0UL;
  ctx->config.sources.gossip.block_list_cnt = 0UL;

  *ctx_out = ctx;
}

static fd_pubkey_t
test_pubkey( uchar first_byte ) {
  fd_pubkey_t pubkey = {0};
  pubkey.uc[ 0 ] = first_byte;
  return pubkey;
}

static fd_sspeer_key_t
test_key( uchar first_byte ) {
  fd_sspeer_key_t key = {0};
  key.is_url = 0;
  key.pubkey->uc[ 0 ] = first_byte;
  return key;
}

/* Construct an fd_ip4_port_t from host-order values.  It converts to
   network byte order internally. */
static fd_ip4_port_t
test_addr( uint ip, ushort port ) {
  fd_ip4_port_t addr;
  addr.addr = fd_uint_bswap( ip );
  addr.port = fd_ushort_bswap( port );
  return addr;
}

static void
on_ping_stub( void * _ctx, fd_ip4_port_t addr, ulong latency ) {
  (void)_ctx; (void)addr; (void)latency;
}

static void
setup_blacklist_snapct( void *              scratch,
                        fd_ssping_t *       ssping,
                        ulong               bl_max,
                        fd_snapct_tile_t ** ctx_out ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapct_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapct_tile_t), sizeof(fd_snapct_tile_t) );
  memset( ctx, 0, sizeof(fd_snapct_tile_t) );

  void * _selector = FD_SCRATCH_ALLOC_APPEND( l, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( TOTAL_PEERS_MAX )                  );
  void * _bl_pool  = FD_SCRATCH_ALLOC_APPEND( l, blacklist_pool_align(),     blacklist_pool_footprint( bl_max )                               );
  void * _bl_map   = FD_SCRATCH_ALLOC_APPEND( l, blacklist_map_align(),      blacklist_map_footprint( blacklist_map_chain_cnt_est( bl_max ) ) );

  /* Shared ssping: fd_ssping_new opens real sockets and has no
     teardown, so it is created once in main() and passed in here. */
  ctx->ssping         = ssping;
  ctx->selector       = fd_sspeer_selector_join( fd_sspeer_selector_new( _selector, TOTAL_PEERS_MAX, 42UL ) );
  ctx->blacklist_pool = blacklist_pool_join( blacklist_pool_new( _bl_pool, bl_max ) );
  ctx->blacklist_map  = blacklist_map_join( blacklist_map_new( _bl_map, blacklist_map_chain_cnt_est( bl_max ), 42UL ) );

  FD_TEST( ctx->ssping );
  FD_TEST( ctx->selector );
  FD_TEST( ctx->blacklist_pool );
  FD_TEST( ctx->blacklist_map );

  *ctx_out = ctx;
}

static void
test_allow_any_contact_info_insert_and_update( void ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_gossip_update_message_t msg[1] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapct_tile_t * ctx;
  setup_gossip_only_snapct( scratch, &ctx, msg );

  ulong const idx = 3UL;
  fd_pubkey_t peer = test_pubkey( 0x11 );

  ctx->config.sources.gossip.allow_any = 1;

  send_contact_info( ctx, msg, idx, &peer );
  FD_TEST( fd_pubkey_eq( &ctx->gossip.ci_table[ idx ].pubkey, &peer ) );
  FD_TEST( ctx->gossip.ci_table[ idx ].allowed );
  FD_TEST( ctx->gossip.allowed_cnt==1UL );
  FD_TEST( idx==gossip_ci_map_idx_query_const( ctx->gossip.ci_map, &peer, ULONG_MAX, ctx->gossip.ci_table ) );

  /* Updating the same peer at the same contact-info index should not
     create a second map entry or increment allowed_cnt again. */
  send_contact_info( ctx, msg, idx, &peer );
  FD_TEST( fd_pubkey_eq( &ctx->gossip.ci_table[ idx ].pubkey, &peer ) );
  FD_TEST( ctx->gossip.ci_table[ idx ].allowed );
  FD_TEST( ctx->gossip.allowed_cnt==1UL );
  FD_TEST( idx==gossip_ci_map_idx_query_const( ctx->gossip.ci_map, &peer, ULONG_MAX, ctx->gossip.ci_table ) );

  free( scratch );
}

static void
test_allow_any_contact_info_remove( void ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_gossip_update_message_t msg[1] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapct_tile_t * ctx;
  setup_gossip_only_snapct( scratch, &ctx, msg );

  ulong const idx = 4UL;
  fd_pubkey_t peer = test_pubkey( 0x22 );

  ctx->config.sources.gossip.allow_any = 1;

  send_contact_info( ctx, msg, idx, &peer );
  FD_TEST( ctx->gossip.ci_table[ idx ].allowed );
  FD_TEST( ctx->gossip.allowed_cnt==1UL );

  send_contact_info_remove( ctx, msg, idx, &peer );
  FD_TEST( fd_pubkey_check_zero( &ctx->gossip.ci_table[ idx ].pubkey ) );
  FD_TEST( !ctx->gossip.ci_table[ idx ].allowed );
  FD_TEST( ctx->gossip.allowed_cnt==0UL );
  FD_TEST( ULONG_MAX==gossip_ci_map_idx_query_const( ctx->gossip.ci_map, &peer, ULONG_MAX, ctx->gossip.ci_table ) );

  free( scratch );
}

static void
test_allow_list_contact_info_insert( void ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_gossip_update_message_t msg[1] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapct_tile_t * ctx;
  setup_gossip_only_snapct( scratch, &ctx, msg );

  ulong const idx = 5UL;
  fd_pubkey_t peer = test_pubkey( 0x33 );

  ctx->config.sources.gossip.allow_any = 0;
  ctx->config.sources.gossip.allow_list_cnt = 1UL;
  ctx->config.sources.gossip.allow_list[ 0 ] = peer;

  send_contact_info( ctx, msg, idx, &peer );
  FD_TEST( fd_pubkey_eq( &ctx->gossip.ci_table[ idx ].pubkey, &peer ) );
  FD_TEST( ctx->gossip.ci_table[ idx ].allowed );
  FD_TEST( ctx->gossip.allowed_cnt==1UL );
  FD_TEST( ctx->gossip.saturated );
  FD_TEST( idx==gossip_ci_map_idx_query_const( ctx->gossip.ci_map, &peer, ULONG_MAX, ctx->gossip.ci_table ) );

  free( scratch );
}

static void
test_block_list_contact_info_insert( void ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_gossip_update_message_t msg[1] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapct_tile_t * ctx;
  setup_gossip_only_snapct( scratch, &ctx, msg );

  ulong const idx = 6UL;
  fd_pubkey_t peer = test_pubkey( 0x44 );

  ctx->config.sources.gossip.allow_any = 1;
  ctx->config.sources.gossip.block_list_cnt = 1UL;
  ctx->config.sources.gossip.block_list[ 0 ] = peer;

  send_contact_info( ctx, msg, idx, &peer );
  FD_TEST( fd_pubkey_eq( &ctx->gossip.ci_table[ idx ].pubkey, &peer ) );
  FD_TEST( !ctx->gossip.ci_table[ idx ].allowed );
  FD_TEST( ctx->gossip.allowed_cnt==0UL );
  FD_TEST( ULONG_MAX==gossip_ci_map_idx_query_const( ctx->gossip.ci_map, &peer, ULONG_MAX, ctx->gossip.ci_table ) );

  free( scratch );
}

static void
test_load_complete_signal( void ) {
  fd_snapct_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_snapct_tile_t) );

  /* snapld_frag never dereferences stem in the paths below. */

  /* READING_FULL_FILE with matching bytes sets load_complete */
  ctx->state                    = FD_SNAPCT_STATE_READING_FULL_FILE;
  ctx->metrics.full.bytes_read  = 1000UL;
  ctx->metrics.full.bytes_total = 1000UL;
  snapld_frag( ctx, FD_SNAPSHOT_MSG_LOAD_COMPLETE, 0UL, 0UL, NULL );
  FD_TEST( ctx->load_complete==1 );
  ctx->load_complete = 0;

  /* READING_INCREMENTAL_HTTP with matching bytes sets load_complete */
  ctx->state                           = FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP;
  ctx->metrics.incremental.bytes_read  = 500UL;
  ctx->metrics.incremental.bytes_total = 500UL;
  snapld_frag( ctx, FD_SNAPSHOT_MSG_LOAD_COMPLETE, 0UL, 0UL, NULL );
  FD_TEST( ctx->load_complete==1 );
  ctx->load_complete = 0;

  /* Ignored during reset states */
  ctx->state = FD_SNAPCT_STATE_FLUSHING_FULL_FILE_RESET;
  snapld_frag( ctx, FD_SNAPSHOT_MSG_LOAD_COMPLETE, 0UL, 0UL, NULL );
  FD_TEST( ctx->load_complete==0 );

  ctx->state = FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_RESET;
  snapld_frag( ctx, FD_SNAPSHOT_MSG_LOAD_COMPLETE, 0UL, 0UL, NULL );
  FD_TEST( ctx->load_complete==0 );

  /* Ignored when already malformed */
  ctx->state                    = FD_SNAPCT_STATE_READING_FULL_HTTP;
  ctx->malformed                = 1;
  ctx->metrics.full.bytes_read  = 1000UL;
  ctx->metrics.full.bytes_total = 1000UL;
  snapld_frag( ctx, FD_SNAPSHOT_MSG_LOAD_COMPLETE, 0UL, 0UL, NULL );
  FD_TEST( ctx->load_complete==0 );
  ctx->malformed = 0;
}

static void
test_contact_info_slot_reuse_after_unallowed_peer_expires( void ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_gossip_update_message_t msg[1] __attribute__((aligned(FD_CHUNK_ALIGN)));
  fd_snapct_tile_t * ctx;
  setup_gossip_only_snapct( scratch, &ctx, msg );

  ulong const idx = 7UL;
  fd_pubkey_t peer_x = test_pubkey( 0xbb );
  fd_pubkey_t peer_y = test_pubkey( 0xcc );

  /* Peer X is not allowed, so snapct tracks the table slot but does not
     add X to the allowed-peer map. */
  send_contact_info( ctx, msg, idx, &peer_x );
  FD_TEST( fd_pubkey_eq( &ctx->gossip.ci_table[ idx ].pubkey, &peer_x ) );
  FD_TEST( !ctx->gossip.ci_table[ idx ].allowed );
  FD_TEST( ctx->gossip.allowed_cnt==0UL );
  FD_TEST( ULONG_MAX==gossip_ci_map_idx_query_const( ctx->gossip.ci_map, &peer_x, ULONG_MAX, ctx->gossip.ci_table ) );

  /* Removing X must clear the table slot even though X was not in the
     allowed-peer map.  Otherwise the next peer reusing idx would trip
     the "new slot must be zero" FD_TEST in gossip_frag. */
  send_contact_info_remove( ctx, msg, idx, &peer_x );
  FD_TEST( fd_pubkey_check_zero( &ctx->gossip.ci_table[ idx ].pubkey ) );
  FD_TEST( !ctx->gossip.ci_table[ idx ].allowed );
  FD_TEST( ctx->gossip.allowed_cnt==0UL );

  /* The same CRDS contact-info index can now be reused for peer Y
     without aborting. */
  send_contact_info( ctx, msg, idx, &peer_y );
  FD_TEST( fd_pubkey_eq( &ctx->gossip.ci_table[ idx ].pubkey, &peer_y ) );
  FD_TEST( !ctx->gossip.ci_table[ idx ].allowed );
  FD_TEST( ctx->gossip.allowed_cnt==0UL );

  free( scratch );
}

static void
test_blacklist_peer_basic( fd_ssping_t * ssping ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  fd_sspeer_key_t key  = test_key( 0xAA );
  fd_ip4_port_t   addr = test_addr( 0x01020304, 8899 );

  fd_ssping_add( ctx->ssping, addr );
  ulong score = fd_sspeer_selector_add( ctx->selector, &key, addr, 5000UL,
                                        100UL, 200UL, NULL, NULL );
  FD_TEST( score!=FD_SSPEER_SCORE_INVALID );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );

  fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr.l );

  ctx->peer.addr = addr;
  ctx->peer.key  = key;
  blacklist_peer( ctx );

  /* Removed from selector, added to blacklist, invalidated in ssping. */
  best = fd_sspeer_selector_best( ctx->selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.score==FD_SSPEER_SCORE_INVALID );
  FD_TEST( fd_sspeer_selector_peer_map_by_key_ele_cnt( ctx->selector )==0UL );
  FD_TEST( blacklist_pool_used( ctx->blacklist_pool )==1UL );
  FD_TEST( blacklist_map_ele_query( ctx->blacklist_map, &key, NULL, ctx->blacklist_pool ) );
  FD_TEST( fd_ssping_is_invalidated( ctx->ssping, addr ) );

  fd_ssping_remove( ctx->ssping, addr );

  free( scratch );
}

static void
test_blacklist_peer_dedup( fd_ssping_t * ssping ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  fd_sspeer_key_t key  = test_key( 0xBB );
  fd_ip4_port_t   addr = test_addr( 0x05060708, 9900 );

  fd_ssping_add( ctx->ssping, addr );
  fd_sspeer_selector_add( ctx->selector, &key, addr, 5000UL, 100UL, 200UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );

  ctx->peer.addr = addr;
  ctx->peer.key  = key;
  blacklist_peer( ctx );
  FD_TEST( blacklist_pool_used( ctx->blacklist_pool )==1UL );

  /* Second blacklist of same identity must not double-insert. */
  blacklist_peer( ctx );
  FD_TEST( blacklist_pool_used( ctx->blacklist_pool )==1UL );

  fd_ssping_remove( ctx->ssping, addr );

  free( scratch );
}

static void
test_blacklist_peer_cluster_slot_regression( fd_ssping_t * ssping ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  fd_sspeer_key_t key_honest     = test_key( 0xCC );
  fd_ip4_port_t   addr_honest    = test_addr( 0x0A0B0C0D, 1111 );
  fd_sspeer_key_t key_malicious  = test_key( 0xDD );
  fd_ip4_port_t   addr_malicious = test_addr( 0x0E0F1011, 2222 );

  fd_ssping_add( ctx->ssping, addr_honest );
  fd_sspeer_selector_add( ctx->selector, &key_honest, addr_honest, 3000UL,
                          500UL, 600UL, NULL, NULL );

  /* Malicious peer poisons the cluster slot. */
  fd_ssping_add( ctx->ssping, addr_malicious );
  fd_sspeer_selector_add( ctx->selector, &key_malicious, addr_malicious, 3000UL,
                          9999UL, 9999UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );
  FD_TEST( fd_sspeer_selector_cluster_slot( ctx->selector ).full==9999UL );

  /* Blacklisting the malicious peer should regress the cluster slot. */
  ctx->peer.addr = addr_malicious;
  ctx->peer.key  = key_malicious;
  blacklist_peer( ctx );

  fd_sscluster_slot_t cluster = fd_sspeer_selector_cluster_slot( ctx->selector );
  FD_TEST( cluster.full==500UL );
  FD_TEST( cluster.incremental==600UL );

  fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, FD_SSPEER_SLOT_UNKNOWN );
  FD_TEST( best.addr.l==addr_honest.l );
  FD_TEST( best.score!=FD_SSPEER_SCORE_INVALID );

  FD_TEST(  blacklist_map_ele_query( ctx->blacklist_map, &key_malicious, NULL, ctx->blacklist_pool ) );
  FD_TEST( !blacklist_map_ele_query( ctx->blacklist_map, &key_honest,    NULL, ctx->blacklist_pool ) );

  fd_ssping_remove( ctx->ssping, addr_honest );
  fd_ssping_remove( ctx->ssping, addr_malicious );

  free( scratch );
}

static void
test_blacklist_peer_readd_blocked( fd_ssping_t * ssping ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  fd_sspeer_key_t key  = test_key( 0xEE );
  fd_ip4_port_t   addr = test_addr( 0x12131415, 3333 );

  fd_ssping_add( ctx->ssping, addr );
  fd_sspeer_selector_add( ctx->selector, &key, addr, 5000UL, 100UL, 200UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );

  ctx->peer.addr = addr;
  ctx->peer.key  = key;
  blacklist_peer( ctx );
  FD_TEST( fd_sspeer_selector_peer_map_by_key_ele_cnt( ctx->selector )==0UL );

  /* Both blacklist map and ssping should block re-addition. */
  FD_TEST( blacklist_map_ele_query( ctx->blacklist_map, &key, NULL, ctx->blacklist_pool ) );
  FD_TEST( fd_ssping_is_invalidated( ctx->ssping, addr ) );

  /* The selector itself has no blacklist knowledge (external gate). */
  ulong score = fd_sspeer_selector_add( ctx->selector, &key, addr, 5000UL,
                                        100UL, 200UL, NULL, NULL );
  FD_TEST( score!=FD_SSPEER_SCORE_INVALID );

  fd_sspeer_selector_remove( ctx->selector, &key );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );
  fd_ssping_remove( ctx->ssping, addr );

  free( scratch );
}

/* ---- slot gap / turbine tip tests ----------------------------------- */

static void
test_shred_frag_tracks_turbine_tip( void ) {
  fd_snapct_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );
  ctx->turbine_tip_slot = ULONG_MAX;

  /* sig now carries the slot directly. */
  shred_frag( ctx, 100UL );
  FD_TEST( ctx->turbine_tip_slot==100UL );

  shred_frag( ctx, 200UL );
  FD_TEST( ctx->turbine_tip_slot==200UL );

  /* Lower slot must NOT regress the tip. */
  shred_frag( ctx, 150UL );
  FD_TEST( ctx->turbine_tip_slot==200UL );

  /* Equal slot stays unchanged. */
  shred_frag( ctx, 200UL );
  FD_TEST( ctx->turbine_tip_slot==200UL );
}

static void
test_slot_gap_from_tip_disabled( fd_ssping_t * ssping ) {
  /* When snapshot_max_slot_gap==0 the feature is disabled; all checks
     should return ULONG_MAX (= "cannot determine"). */
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );
  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  ctx->config.snapshot_max_slot_gap = 0;
  ctx->turbine_tip_slot            = 5000UL;
  FD_TEST( slot_gap_from_tip( ctx, 1000UL )==ULONG_MAX );
  FD_TEST( !slot_gap_exceeds( ctx, 1000UL ) );

  free( scratch );
}

static void
test_slot_gap_from_tip_unknown_tip( fd_ssping_t * ssping ) {
  /* When turbine tip is unknown, cannot compute gap. */
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );
  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  ctx->config.snapshot_max_slot_gap = 10000UL;
  ctx->turbine_tip_slot            = ULONG_MAX;
  FD_TEST( slot_gap_from_tip( ctx, 1000UL )==ULONG_MAX );
  FD_TEST( !slot_gap_exceeds( ctx, 1000UL ) );

  free( scratch );
}

static void
test_slot_gap_from_tip_unknown_snapshot_slot( fd_ssping_t * ssping ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );
  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  ctx->config.snapshot_max_slot_gap = 10000UL;
  ctx->turbine_tip_slot            = 5000UL;
  FD_TEST( slot_gap_from_tip( ctx, FD_SSPEER_SLOT_UNKNOWN )==ULONG_MAX );
  FD_TEST( !slot_gap_exceeds( ctx, FD_SSPEER_SLOT_UNKNOWN ) );

  free( scratch );
}

static void
test_slot_gap_from_tip_tip_below_cluster( fd_ssping_t * ssping ) {
  /* The turbine tip is the source of truth (cryptographically grounded
     via leader-signed FEC completions).  Gossip cluster slots are
     unauthenticated and must not override the turbine tip.  Even when
     the tip is below the cluster slot, the gap is computed directly. */
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );
  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  /* Add a peer so the cluster slot is defined. */
  fd_sspeer_key_t key  = test_key( 0xF1 );
  fd_ip4_port_t   addr = test_addr( 0x0A0A0A0A, 5555 );
  fd_ssping_add( ctx->ssping, addr );
  fd_sspeer_selector_add( ctx->selector, &key, addr, 3000UL, 8000UL, 9000UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );
  FD_TEST( fd_sspeer_selector_cluster_slot( ctx->selector ).full==8000UL );

  ctx->config.snapshot_max_slot_gap = 10000UL;
  ctx->turbine_tip_slot            = 100UL; /* below cluster.full of 8000, gap still computed */
  FD_TEST( slot_gap_from_tip( ctx, 50UL )==50UL );

  fd_ssping_remove( ctx->ssping, addr );
  free( scratch );
}

static void
test_slot_gap_from_tip_no_cluster_peers( fd_ssping_t * ssping ) {
  /* When no peers are in the selector the gap is computed directly
     from the turbine tip. */
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );
  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  /* No peers added — cluster.full defaults to 0. */
  ctx->config.snapshot_max_slot_gap = 10000UL;
  ctx->turbine_tip_slot            = 5000UL;

  /* gap = 5000 - 3000 = 2000 */
  FD_TEST( slot_gap_from_tip( ctx, 3000UL )==2000UL );
  FD_TEST( !slot_gap_exceeds( ctx, 3000UL ) );

  free( scratch );
}

static void
test_slot_gap_from_tip_normal( fd_ssping_t * ssping ) {
  /* Normal case: tip is above cluster slot, gap is computable. */
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );
  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  /* Add a peer with cluster.full below the tip. */
  fd_sspeer_key_t key  = test_key( 0xF2 );
  fd_ip4_port_t   addr = test_addr( 0x0B0B0B0B, 6666 );
  fd_ssping_add( ctx->ssping, addr );
  fd_sspeer_selector_add( ctx->selector, &key, addr, 3000UL, 1000UL, 2000UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );

  ctx->config.snapshot_max_slot_gap = 10000UL;
  ctx->turbine_tip_slot            = 5000UL;

  /* snapshot_slot=4000 → gap=1000 */
  FD_TEST( slot_gap_from_tip( ctx, 4000UL )==1000UL );
  FD_TEST( !slot_gap_exceeds( ctx, 4000UL ) );

  /* snapshot_slot=100 → gap=4900 (still within 10000) */
  FD_TEST( slot_gap_from_tip( ctx, 100UL )==4900UL );
  FD_TEST( !slot_gap_exceeds( ctx, 100UL ) );

  /* snapshot_slot far behind tip: gap exceeds max_gap. */
  ctx->turbine_tip_slot = 100000UL;
  /* gap = 100000 - 4000 = 96000 > 10000 */
  FD_TEST( slot_gap_from_tip( ctx, 4000UL )==96000UL );
  FD_TEST( slot_gap_exceeds( ctx, 4000UL ) );

  /* Exactly at the boundary: gap == max_gap should NOT exceed. */
  ctx->turbine_tip_slot = 14000UL;
  /* gap = 14000 - 4000 = 10000 == max_gap */
  FD_TEST( slot_gap_from_tip( ctx, 4000UL )==10000UL );
  FD_TEST( !slot_gap_exceeds( ctx, 4000UL ) );

  /* One beyond: gap = max_gap + 1 should exceed. */
  ctx->turbine_tip_slot = 14001UL;
  FD_TEST( slot_gap_from_tip( ctx, 4000UL )==10001UL );
  FD_TEST( slot_gap_exceeds( ctx, 4000UL ) );

  /* Saturating subtraction: snapshot_slot > tip → gap = 0. */
  ctx->turbine_tip_slot = 3000UL;
  FD_TEST( slot_gap_from_tip( ctx, 4000UL )==0UL );
  FD_TEST( !slot_gap_exceeds( ctx, 4000UL ) );

  fd_ssping_remove( ctx->ssping, addr );
  free( scratch );
}

static void
test_slot_gap_exceeds_blacklists_stale_peer( fd_ssping_t * ssping ) {
  /* Verify that slot_gap_exceeds correctly identifies a stale peer so
     the caller can blacklist it. */
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );
  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  fd_sspeer_key_t key  = test_key( 0xF5 );
  fd_ip4_port_t   addr = test_addr( 0x0E0E0E0E, 9999 );
  fd_ssping_add( ctx->ssping, addr );
  fd_sspeer_selector_add( ctx->selector, &key, addr, 3000UL, 1000UL, 2000UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );

  ctx->config.snapshot_max_slot_gap = 5000UL;
  ctx->turbine_tip_slot            = 100000UL;

  /* Peer at slot 1000 is 99000 behind tip — exceeds 5000. */
  FD_TEST( slot_gap_exceeds( ctx, 1000UL ) );

  /* Simulate what the state machine does: blacklist the peer. */
  ctx->peer.addr = addr;
  ctx->peer.key  = key;
  blacklist_peer( ctx );

  FD_TEST( blacklist_map_ele_query( ctx->blacklist_map, &key, NULL, ctx->blacklist_pool ) );

  fd_ssping_remove( ctx->ssping, addr );
  free( scratch );
}

/* ---- fini_decision tests -------------------------------------------- */

static void
test_fini_decision_local_incr( void ) {
  /* When incremental_snapshots=1 and a local incremental is available,
     fini_decision should return FINI_NEXT without touching the
     selector. */
  fd_snapct_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );
  ctx->config.incremental_snapshots = 1;

  FD_TEST( fini_decision( ctx, 0L, 1 )==FINI_NEXT );
}

static void
test_fini_decision_download_peer_available( fd_ssping_t * ssping ) {
  /* When incremental_snapshots=1, no local file, download enabled,
     and a peer is available, should return FINI_NEXT. */
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );
  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  ctx->config.incremental_snapshots = 1;
  ctx->download_enabled             = 1;
  ctx->predicted_incremental.full_slot = 5000UL;

  fd_sspeer_key_t key  = test_key( 0xA1 );
  fd_ip4_port_t   addr = test_addr( 0x10101010, 7777 );
  fd_ssping_add( ctx->ssping, addr );
  fd_sspeer_selector_add( ctx->selector, &key, addr, 3000UL, 5000UL, 6000UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );

  FD_TEST( fini_decision( ctx, 0L, 0 )==FINI_NEXT );

  fd_ssping_remove( ctx->ssping, addr );
  free( scratch );
}

static void
test_fini_decision_no_peer_waits( fd_ssping_t * ssping ) {
  /* When incremental_snapshots=1, download enabled, but no peer is
     available, should return FINI_WAIT and arm the deadline. */
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );
  fd_snapct_tile_t * ctx;
  setup_blacklist_snapct( scratch, ssping, TOTAL_PEERS_MAX, &ctx );

  ctx->config.incremental_snapshots         = 1;
  ctx->download_enabled                     = 1;
  ctx->config.wait_for_peers_timeout_nanos  = 30L*1000L*1000L*1000L;
  ctx->predicted_incremental.full_slot      = 5000UL;
  /* No peers added to selector. */

  long now = 1000L*1000L*1000L;
  FD_TEST( fini_decision( ctx, now, 0 )==FINI_WAIT );
  FD_TEST( ctx->waiting_for_incr_peers==1 );
  FD_TEST( ctx->deadline_nanos==now + ctx->config.wait_for_peers_timeout_nanos );

  /* Second call within deadline should still wait, and not reset the
     deadline. */
  long deadline = ctx->deadline_nanos;
  long now2 = now + 1L*1000L*1000L*1000L;
  FD_TEST( fini_decision( ctx, now2, 0 )==FINI_WAIT );
  FD_TEST( ctx->deadline_nanos==deadline );

  free( scratch );
}

static void
test_fini_decision_no_download_no_local( void ) {
  /* When incremental_snapshots=1 but no local file and download is
     disabled, should fall through to full-only and return FINI_DONE. */
  fd_snapct_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );
  ctx->config.incremental_snapshots    = 1;
  ctx->download_enabled                = 0;
  ctx->config.snapshot_max_slot_gap    = 0; /* disabled */
  ctx->predicted_incremental.full_slot = 5000UL;

  FD_TEST( fini_decision( ctx, 0L, 0 )==FINI_DONE );
}

static void
test_fini_decision_full_only_gap_ok( void ) {
  /* When incremental_snapshots=0 and gap is within tolerance, should
     return FINI_DONE. */
  fd_snapct_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );
  ctx->config.incremental_snapshots    = 0;
  ctx->config.snapshot_max_slot_gap    = 10000UL;
  ctx->turbine_tip_slot                = 6000UL;
  ctx->predicted_incremental.full_slot = 5000UL;

  FD_TEST( fini_decision( ctx, 0L, 0 )==FINI_DONE );
}

static void
test_fini_decision_full_only_gap_exceeds( void ) {
  /* When incremental_snapshots=0 and the full snapshot is too far
     behind the turbine tip, should return FINI_REJECT. */
  fd_snapct_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );
  ctx->config.incremental_snapshots    = 0;
  ctx->config.snapshot_max_slot_gap    = 5000UL;
  ctx->turbine_tip_slot                = 100000UL;
  ctx->predicted_incremental.full_slot = 1000UL;

  FD_TEST( fini_decision( ctx, 0L, 0 )==FINI_REJECT );
}

static void
test_fini_decision_full_only_tip_unknown( void ) {
  /* When incremental_snapshots=0 and the turbine tip is unknown,
     gap check is indeterminate — should return FINI_DONE (fail-open). */
  fd_snapct_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );
  ctx->config.incremental_snapshots    = 0;
  ctx->config.snapshot_max_slot_gap    = 5000UL;
  ctx->turbine_tip_slot                = ULONG_MAX;
  ctx->predicted_incremental.full_slot = 1000UL;

  FD_TEST( fini_decision( ctx, 0L, 0 )==FINI_DONE );
}

static void
test_blacklist_pool_exhaustion( fd_ssping_t * ssping ) {
  void * scratch = aligned_alloc( scratch_align(), scratch_footprint( NULL ) ); FD_TEST( scratch );

  fd_snapct_tile_t * ctx;
  /* Create a blacklist pool with capacity 2. */
  setup_blacklist_snapct( scratch, ssping, 2UL, &ctx );

  fd_sspeer_key_t key_a  = test_key( 0x01 );
  fd_ip4_port_t   addr_a = test_addr( 0x01010101, 1111 );
  fd_sspeer_key_t key_b  = test_key( 0x02 );
  fd_ip4_port_t   addr_b = test_addr( 0x02020202, 2222 );
  fd_sspeer_key_t key_c  = test_key( 0x03 );
  fd_ip4_port_t   addr_c = test_addr( 0x03030303, 3333 );

  /* Add and blacklist two peers, filling the pool. */
  fd_ssping_add( ctx->ssping, addr_a );
  fd_sspeer_selector_add( ctx->selector, &key_a, addr_a, 5000UL, 100UL, 200UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );
  ctx->peer.addr = addr_a;
  ctx->peer.key  = key_a;
  blacklist_peer( ctx );

  fd_ssping_add( ctx->ssping, addr_b );
  fd_sspeer_selector_add( ctx->selector, &key_b, addr_b, 5000UL, 100UL, 200UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );
  ctx->peer.addr = addr_b;
  ctx->peer.key  = key_b;
  blacklist_peer( ctx );

  FD_TEST( blacklist_pool_free( ctx->blacklist_pool )==0UL );
  FD_TEST( blacklist_pool_used( ctx->blacklist_pool )==2UL );

  /* Third blacklist: pool is full, falls back to ssping-only ban. */
  fd_ssping_add( ctx->ssping, addr_c );
  fd_sspeer_selector_add( ctx->selector, &key_c, addr_c, 5000UL, 100UL, 200UL, NULL, NULL );
  fd_sspeer_selector_process_cluster_slot( ctx->selector );
  ctx->peer.addr = addr_c;
  ctx->peer.key  = key_c;
  blacklist_peer( ctx );

  /* Peer C should NOT be in the blacklist map (pool was full). */
  FD_TEST( !blacklist_map_ele_query( ctx->blacklist_map, &key_c, NULL, ctx->blacklist_pool ) );
  /* But peer C should still be invalidated in ssping. */
  FD_TEST( fd_ssping_is_invalidated( ctx->ssping, addr_c ) );
  /* And removed from the selector. */
  FD_TEST( fd_sspeer_selector_peer_map_by_key_ele_cnt( ctx->selector )==0UL );

  /* Peers A and B should still be in the blacklist map. */
  FD_TEST( blacklist_map_ele_query( ctx->blacklist_map, &key_a, NULL, ctx->blacklist_pool ) );
  FD_TEST( blacklist_map_ele_query( ctx->blacklist_map, &key_b, NULL, ctx->blacklist_pool ) );

  fd_ssping_remove( ctx->ssping, addr_a );
  fd_ssping_remove( ctx->ssping, addr_b );
  fd_ssping_remove( ctx->ssping, addr_c );

  free( scratch );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  (void)privileged_init;
  (void)unprivileged_init;
  (void)populate_allowed_fds;
  (void)populate_allowed_seccomp;
  (void)rlimit_file_cnt;

  test_allow_any_contact_info_insert_and_update();
  test_allow_any_contact_info_remove();
  test_allow_list_contact_info_insert();
  test_block_list_contact_info_insert();
  test_contact_info_slot_reuse_after_unallowed_peer_expires();
  test_load_complete_signal();

  /* Shared ssping: can only be created once (opens real sockets). */
  ulong ssping_max = 16UL;
  void * _ssping_mem = aligned_alloc( fd_ssping_align(), fd_ssping_footprint( ssping_max ) );
  FD_TEST( _ssping_mem );
  fd_ssping_t * ssping = fd_ssping_join( fd_ssping_new( _ssping_mem, ssping_max, 42UL, on_ping_stub, NULL ) );
  FD_TEST( ssping );

  test_blacklist_peer_basic( ssping );
  test_blacklist_peer_dedup( ssping );
  test_blacklist_peer_cluster_slot_regression( ssping );
  test_blacklist_peer_readd_blocked( ssping );
  test_blacklist_pool_exhaustion( ssping );

  test_shred_frag_tracks_turbine_tip();
  test_slot_gap_from_tip_disabled( ssping );
  test_slot_gap_from_tip_unknown_tip( ssping );
  test_slot_gap_from_tip_unknown_snapshot_slot( ssping );
  test_slot_gap_from_tip_tip_below_cluster( ssping );
  test_slot_gap_from_tip_no_cluster_peers( ssping );
  test_slot_gap_from_tip_normal( ssping );
  test_slot_gap_exceeds_blacklists_stale_peer( ssping );
  test_fini_decision_download_peer_available( ssping );
  test_fini_decision_no_peer_waits( ssping );

  fd_ssping_delete( fd_ssping_leave( ssping ) );
  free( _ssping_mem );

  test_fini_decision_local_incr();
  test_fini_decision_no_download_no_local();
  test_fini_decision_full_only_gap_ok();
  test_fini_decision_full_only_gap_exceeds();
  test_fini_decision_full_only_tip_unknown();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
