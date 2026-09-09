#include "fd_failover_tile.c"
#include "../../util/net/fd_ip4.h"
#include "../../choreo/tower/fd_tower.h"

static uchar ch_mem[ 8UL<<20 ] __attribute__((aligned(128)));
static fd_topo_tile_t         tile[1];
static fd_failover_tile_ctx_t ctx[1];

static void
test_pool_layout( void ) {
  fd_memset( tile, 0, sizeof(tile) );
  tile->failov.member_cnt = 3UL;
  for( ulong i=0UL; i<3UL; i++ ) fd_memset( tile->failov.member_junk_pubkey[ i ], (int)(i+1UL), 32UL );

  /* The middle member accepts from the first and dials the last. */
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 1 ] ) );
  FD_TEST( ctx->member_cnt==3UL && ctx->self_idx==1UL && ctx->peer_cnt==2UL );
  FD_TEST( ctx->peers[ 0 ].member_idx==0UL && !ctx->peers[ 0 ].dial );
  FD_TEST( ctx->peers[ 1 ].member_idx==2UL &&  ctx->peers[ 1 ].dial );

  /* The first member only dials, the last only accepts. */
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 0 ] ) );
  FD_TEST( ctx->self_idx==0UL && ctx->peer_cnt==2UL && ctx->peers[ 0 ].dial && ctx->peers[ 1 ].dial );
  FD_TEST( ctx->peers[ 0 ].member_idx==1UL && ctx->peers[ 1 ].member_idx==2UL );
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 2 ] ) );
  FD_TEST( ctx->self_idx==2UL && ctx->peer_cnt==2UL && !ctx->peers[ 0 ].dial && !ctx->peers[ 1 ].dial );

  /* A junk key that is unlisted or listed twice is refused. */
  uchar other[ 32 ];
  fd_memset( other, 9, 32UL );
  FD_TEST( pool_layout( ctx, tile, other )==-1 );
  fd_memcpy( tile->failov.member_junk_pubkey[ 2 ], tile->failov.member_junk_pubkey[ 0 ], 32UL );
  FD_TEST( pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 0 ] )==-1 );

  /* A two-member pool is one dialer and one listener. */
  fd_memset( tile->failov.member_junk_pubkey[ 2 ], 3, 32UL );
  tile->failov.member_cnt = 2UL;
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 0 ] ) );
  FD_TEST( ctx->peer_cnt==1UL && ctx->peers[ 0 ].member_idx==1UL && ctx->peers[ 0 ].dial );
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 1 ] ) );
  FD_TEST( ctx->peer_cnt==1UL && ctx->peers[ 0 ].member_idx==0UL && !ctx->peers[ 0 ].dial );
  FD_LOG_NOTICE(( "pass: pool layout, self index and dial direction from list order" ));
}

static void
test_listen_fd( void ) {
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->peer_cnt        = 2UL;
  ctx->peers[ 0 ].dial = 1;
  ctx->peers[ 1 ].dial = 0;
  FD_TEST( pool_listen_fd( ctx )==-1 );

  FD_TEST( fd_failover_channel_footprint()<=sizeof(ch_mem) );
  fd_failover_channel_t * ch = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( ch );
  ctx->peers[ 1 ].channel = ch;
  FD_TEST( pool_listen_fd( ctx )==-1 );

  fd_failover_channel_init_listener( ch, FD_IP4_ADDR(127,0,0,1), 0 );
  int fd = fd_failover_channel_listen_fd( ch );
  FD_TEST( fd!=-1 && pool_listen_fd( ctx )==fd );

  /* A dialing peer never contributes a listener, whatever its channel holds. */
  ctx->peers[ 0 ].channel = ch;
  ctx->peers[ 1 ].channel = NULL;
  FD_TEST( pool_listen_fd( ctx )==-1 );

  fd_failover_channel_fini( ch );
  FD_LOG_NOTICE(( "pass: the listener descriptor comes from the accepting peer only" ));
}

static void
test_footprint( void ) {
  fd_memset( tile, 0, sizeof(tile) );
  tile->failov.member_cnt = 2UL;
  ulong one = scratch_footprint( tile );
  tile->failov.member_cnt = 3UL;
  ulong two = scratch_footprint( tile );
  FD_TEST( one>=sizeof(fd_failover_tile_ctx_t)+fd_failover_channel_footprint() );
  FD_TEST( two>=one+fd_failover_channel_footprint() );
  FD_LOG_NOTICE(( "pass: one channel per peer in the scratch footprint" ));
}

static void
test_slot_done_bookkeeping( void ) {
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->role           = FD_FAILOVER_ROLE_STANDBY;
  ctx->replay_slot    = FD_FAILOVER_SLOT_NULL;
  ctx->root_slot      = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot = FD_FAILOVER_SLOT_NULL;

  fd_tower_slot_done_t done;
  fd_memset( &done, 0, sizeof(done) );
  done.replay_slot = 100UL;
  done.root_slot   = FD_FAILOVER_SLOT_NULL;
  done.vote_slot   = FD_FAILOVER_SLOT_NULL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->replay_slot==100UL && ctx->root_slot==FD_FAILOVER_SLOT_NULL && ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL );

  /* A fork can report an older slot, the replay slot never regresses. */
  done.replay_slot = 90UL;
  done.root_slot   = 60UL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->replay_slot==100UL && ctx->root_slot==60UL );

  /* Without a vote transaction the vote slot is ignored, a standby never
     prepares a consensus frame. */
  done.replay_slot  = 101UL;
  done.vote_slot    = 101UL;
  done.has_vote_txn = 0;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL && !ctx->cs_valid );
  done.has_vote_txn = 1;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->last_vote_slot==101UL && !ctx->cs_valid );

  /* The local STATUS mirrors the slot view and raises the lag bit only
     past the configured limit. */
  ctx->replication_lag_limit = 8UL;
  ctx->peer_cnt              = 1UL;
  fd_failover_peer_t * peer  = &ctx->peers[ 0 ];
  peer->channel   = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  peer->lag_slots = 8UL;
  fd_failover_status_t status = local_status( ctx, peer );
  FD_TEST( status.role==FD_FAILOVER_ROLE_STANDBY && status.replay_slot==101UL && status.root_slot==60UL && status.last_vote_slot==101UL );
  FD_TEST( status.turbine_slot==FD_FAILOVER_SLOT_NULL && !(status.status & FD_FAILOVER_STATUS_REPLAG) );
  peer->lag_slots = 9UL;
  status = local_status( ctx, peer );
  FD_TEST( status.status & FD_FAILOVER_STATUS_REPLAG );
  peer->lag_slots = FD_FAILOVER_SLOT_NULL;
  status = local_status( ctx, peer );
  FD_TEST( !(status.status & FD_FAILOVER_STATUS_REPLAG) );
  fd_failover_channel_fini( peer->channel );
  FD_LOG_NOTICE(( "pass: slot bookkeeping and the local status view" ));
}

/* The active side turns the tower's vote transaction into the frame every
   spare receives.  Encode a real vote and require the decoder on the
   other side to accept it, so producer and consumer cannot drift. */
static void
test_consensus_producer( fd_wksp_t * wksp ) {
  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( 2, 2 ), 1UL );
  FD_TEST( tower_mem );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem, 2, 2, 0 ) );
  FD_TEST( tower );
  /* Confirmation counts decrease toward the tip, the way a real tower
     stacks them. */
  for( ulong i=1UL; i<=31UL; i++ ) {
    fd_tower_vote_t vote = { .slot=i, .conf=32UL-i };
    fd_tower_vote_push_tail( tower->votes, vote );
  }
  tower->root = 0UL;

  fd_hash_t   bank_hash        = { .ul = { 1 } };
  fd_hash_t   block_id         = { .ul = { 2 } };
  fd_hash_t   recent_blockhash = { .ul = { 3 } };
  fd_pubkey_t identity         = { .ul = { 4 } };
  fd_pubkey_t vote_acct        = { .ul = { 5 } };
  static fd_txn_p_t txnp[1];
  fd_tower_to_vote_txn( tower, &bank_hash, &block_id, &recent_blockhash, &identity, &identity, &vote_acct, txnp );
  FD_TEST( txnp->payload_sz && txnp->payload_sz<=FD_TPU_MTU );

  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->role           = FD_FAILOVER_ROLE_ACTIVE;
  ctx->peer_cnt       = 1UL;
  ctx->replay_slot    = FD_FAILOVER_SLOT_NULL;
  ctx->root_slot      = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot = FD_FAILOVER_SLOT_NULL;
  ctx->slot_done_seq  = 7UL;

  static fd_tower_slot_done_t done;
  fd_memset( &done, 0, sizeof(done) );
  done.replay_slot  = 31UL;
  done.root_slot    = 1UL;
  done.vote_slot    = 31UL;
  done.has_vote_txn = 1;
  done.vote_txn_sz  = txnp->payload_sz;
  fd_memcpy( done.vote_txn, txnp->payload, txnp->payload_sz );

  consume_slot_done( ctx, &done );
  FD_TEST( ctx->cs_valid && !ctx->peers[ 0 ].cs_sent );
  FD_TEST( ctx->cs_sz>sizeof(fd_failover_consensus_state_t) && ctx->cs_sz<=sizeof(ctx->cs_buf) );
  fd_failover_consensus_state_t msg;
  fd_memcpy( &msg, ctx->cs_buf, sizeof(msg) );
  FD_TEST( msg.vote_slot==31UL && msg.link_seq==7UL && msg.mode==(uchar)FD_FAILOVER_MODE_TOWER );
  FD_TEST( (ulong)msg.state_len==ctx->cs_sz-sizeof(msg) );

  /* A standby with this active peer accepts the frame. */
  static fd_failover_consensus_cache_t cache;
  fd_failover_hello_t peer = { .role=(uchar)FD_FAILOVER_ROLE_ACTIVE, .term=0UL, .boot_id=11UL };
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, ctx->cs_buf, ctx->cs_sz ) );
  FD_TEST( cache.valid && cache.msg.vote_slot==31UL );

  /* A truncated frame and a wrong local role are both refused. */
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, ctx->cs_buf, ctx->cs_sz-1UL ) );
  FD_TEST( !fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_ACTIVE,  &peer, ctx->cs_buf, ctx->cs_sz ) );

  /* A malformed vote transaction leaves the previous frame in place. */
  ulong good_sz = ctx->cs_sz;
  done.vote_txn_sz = 3UL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->cs_valid && ctx->cs_sz==good_sz );

  /* A standby never produces a frame at all. */
  ctx->cs_valid = 0;
  ctx->role     = FD_FAILOVER_ROLE_STANDBY;
  done.vote_txn_sz = txnp->payload_sz;
  consume_slot_done( ctx, &done );
  FD_TEST( !ctx->cs_valid );

  fd_wksp_free_laddr( tower_mem );
  FD_LOG_NOTICE(( "pass: the active encodes a tower frame the standby decoder accepts" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_pool_layout();
  test_listen_fd();
  test_footprint();
  test_slot_done_bookkeeping();

  ulong  page_cnt = 2UL;
  char * page_sz  = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0UL );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );
  test_consensus_producer( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
