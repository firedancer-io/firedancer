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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
