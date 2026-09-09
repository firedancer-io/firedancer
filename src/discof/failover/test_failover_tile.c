/* The channel internals are reached directly so a session can be posed
   as paired without a socket. */
#include "fd_failover_channel.c"
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

/* A stem stand-in so the bus response path can be driven without a
   topology: publishing records the frag instead of touching an mcache. */
static fd_frag_meta_t    pub_mcache[ 8 ];
static ulong             pub_cr_avail;
static ulong             pub_min_cr_avail;
static int               pub_reliable;
static fd_stem_context_t stem[1];
static uchar             bus_mem[ 4096 ] __attribute__((aligned(128)));
static ulong             metrics[ FD_METRICS_TOTAL_SZ/sizeof(ulong) ];

static void
stem_init( void ) {
  static fd_frag_meta_t * mcaches[ 1 ];
  static ulong            seqs[ 1 ];
  static ulong            depths[ 1 ];
  mcaches[ 0 ]     = pub_mcache;
  seqs[ 0 ]        = 0UL;
  depths[ 0 ]      = 8UL;
  pub_cr_avail     = 64UL;
  pub_min_cr_avail = 64UL;
  pub_reliable     = 0;
  *stem = (fd_stem_context_t){
    .mcaches = mcaches, .seqs = seqs, .depths = depths,
    .cr_avail = &pub_cr_avail, .min_cr_avail = &pub_min_cr_avail,
    .cr_decrement_amount = 1UL, .out_reliable = &pub_reliable,
  };
}

/* One peer, paired, with a fresh authenticated status from it. */
static fd_failover_peer_t *
healthy_peer( long now ) {
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->member_cnt            = 2UL;
  ctx->self_idx              = 0UL;
  ctx->peer_cnt              = 1UL;
  ctx->role                  = FD_FAILOVER_ROLE_ACTIVE;
  ctx->replay_slot           = 100UL;
  ctx->root_slot             = 90UL;
  ctx->last_vote_slot        = 99UL;
  ctx->status_interval       = 800L*1000000L;
  ctx->replication_lag_limit = 8UL;

  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->member_idx   = 1UL;
  peer->dial         = 1;
  peer->channel      = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( peer->channel );
  peer->status_valid = 1;
  peer->status_time  = now;
  peer->lag_slots    = 2UL;
  peer->status.role  = FD_FAILOVER_ROLE_STANDBY;
  peer->status.term  = 0UL;
  /* The channel reports PAIRED only with a live session, so the tests
     that need a paired verdict set the state directly. */
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;
  return peer;
}

static void
test_status_snapshot( void ) {
  long now = 1000000000L;
  fd_adminctl_failover_status_resp_t resp;
  fd_failover_peer_t * peer = healthy_peer( now );

  status_snapshot( ctx, 0UL, now, &resp );
  FD_TEST( resp.version==FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION && resp.enabled );
  FD_TEST( resp.member_cnt==2U && resp.self_idx==0U && resp.peer_idx==0U && resp.peers_paired==1U );
  FD_TEST( resp.role==FD_FAILOVER_ROLE_ACTIVE && resp.peer_role==FD_FAILOVER_ROLE_STANDBY && resp.peer_status_valid );
  FD_TEST( resp.replay_slot==100UL && resp.root_slot==90UL && resp.last_vote_slot==99UL );
  FD_TEST( resp.replication_lag_slots==2UL && resp.link_state==FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( resp.pool_healthy && resp.readiness_reason==FD_FAILOVER_READINESS_POOL_HEALTHY );

  /* A stale peer status, a role conflict and a down link each have their
     own verdict, and none of them is healthy. */
  status_snapshot( ctx, 0UL, now+10L*ctx->status_interval, &resp );
  FD_TEST( !resp.pool_healthy && resp.readiness_reason==FD_FAILOVER_READINESS_STATUS_STALE );
  peer->status.role = FD_FAILOVER_ROLE_ACTIVE;
  status_snapshot( ctx, 0UL, now, &resp );
  FD_TEST( !resp.pool_healthy && resp.readiness_reason==FD_FAILOVER_READINESS_ROLE_CONFLICT );
  peer->status.role = FD_FAILOVER_ROLE_STANDBY;
  peer->status.term = 7UL;
  status_snapshot( ctx, 0UL, now, &resp );
  FD_TEST( resp.readiness_reason==FD_FAILOVER_READINESS_ROLE_CONFLICT );
  peer->status.term = 0UL;

  /* A spare behind on replication is reported as behind, not unhealthy. */
  peer->status.status = FD_FAILOVER_STATUS_REPLAG;
  status_snapshot( ctx, 0UL, now, &resp );
  FD_TEST( resp.readiness_reason==FD_FAILOVER_READINESS_STANDBY_BEHIND );
  peer->status.status = 0U;

  peer->channel->state = FD_FAILOVER_SESSION_BACKOFF;
  status_snapshot( ctx, 0UL, now, &resp );
  FD_TEST( !resp.pool_healthy && resp.readiness_reason==FD_FAILOVER_READINESS_LINK_DOWN && !resp.peers_paired );

  fd_failover_channel_fini( peer->channel );
  FD_LOG_NOTICE(( "pass: the pool status snapshot and its health ladder" ));
}

static void
test_status_metrics( void ) {
  /* metrics_write reads the real monotonic clock, so the peer status is
     stamped from it to stay inside the freshness window. */
  long now = fd_failover_clock();
  fd_failover_peer_t * peer = healthy_peer( now );
  peer->channel->metrics = (fd_failover_channel_metrics_t){
    .connection_attempt_cnt=11UL, .paired_cnt=2UL, .frames_sent=13UL, .frames_received=17UL,
    .tls_fail_cnt=19UL, .admission_drop_cnt=23UL, .handshake_timeout_cnt=29UL,
    .wire_fatal_cnt=31UL, .hello_reject_cnt=37UL
  };
  /* Synthetic descriptors are inspected only, never passed to I/O. */
  peer->channel->candidates[0].fd = INT_MAX;
  peer->channel->candidates[1].fd = INT_MAX;
  peer->channel->candidates[2].fd = INT_MAX;
  peer->channel->active = 1;

  fd_adminctl_failover_status_resp_t resp;
  status_snapshot( ctx, 0UL, now, &resp );
  FD_TEST( resp.connection_attempts==11UL && resp.sessions_paired==2UL && resp.pending_handshakes==2UL );
  FD_TEST( resp.frames_sent==13UL && resp.frames_received==17UL && resp.tls_failures==19UL );
  FD_TEST( resp.admission_drops==23UL && resp.handshake_timeouts==29UL );
  FD_TEST( resp.wire_failures==31UL && resp.hello_rejections==37UL );

  fd_metrics_tl = metrics;
  metrics_write( ctx );
  FD_TEST( FD_MCNT_GET  ( FAILOV, CONNECTION_ATTEMPTS )==resp.connection_attempts );
  FD_TEST( FD_MCNT_GET  ( FAILOV, SESSIONS_PAIRED     )==resp.sessions_paired );
  FD_TEST( FD_MGAUGE_GET( FAILOV, PENDING_HANDSHAKES  )==resp.pending_handshakes );
  FD_TEST( FD_MCNT_GET  ( FAILOV, TLS_FAILURES        )==resp.tls_failures );
  FD_TEST( FD_MCNT_GET  ( FAILOV, ADMISSION_DROPS     )==resp.admission_drops );
  FD_TEST( FD_MCNT_GET  ( FAILOV, HANDSHAKE_TIMEOUTS  )==resp.handshake_timeouts );
  FD_TEST( FD_MGAUGE_GET( FAILOV, MEMBER_CNT          )==resp.member_cnt );
  FD_TEST( FD_MGAUGE_GET( FAILOV, PEERS_PAIRED        )==resp.peers_paired );
  FD_TEST( FD_MGAUGE_GET( FAILOV, POOL_HEALTHY        )==resp.pool_healthy );
  fd_metrics_tl = NULL;
  fd_failover_channel_fini( peer->channel );
  FD_LOG_NOTICE(( "pass: the status payload and the metrics expose the same counters" ));
}

static void
test_bus_request( void ) {
  long now = 1000000000L;
  fd_failover_peer_t * peer = healthy_peer( now );
  ctx->admin_out_idx    = 0UL;
  ctx->admin_out_mem    = (fd_wksp_t *)bus_mem; /* chunk 0 maps to bus_mem */
  ctx->admin_out_chunk0 = 0UL;
  ctx->admin_out_wmark  = 0UL;
  ctx->admin_out_chunk  = 0UL;

  /* A request for the one peer is answered with its snapshot, and the
     nonce is echoed so a late answer can be recognized. */
  fd_memset( &ctx->bus_req, 0, sizeof(ctx->bus_req) );
  ctx->bus_req.nonce = 42UL;
  ((fd_adminctl_failover_status_req_t *)ctx->bus_req.payload)->version  = FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION;
  ((fd_adminctl_failover_status_req_t *)ctx->bus_req.payload)->peer_idx = 0UL;
  serve_bus_request( ctx, stem, now );
  fd_failover_bus_msg_t * out = (fd_failover_bus_msg_t *)bus_mem;
  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_STATUS_RESP && pub_mcache[ 0 ].sz==sizeof(*out) );
  FD_TEST( out->nonce==42UL && out->result==FD_ADMINCTL_RESULT_SUCCESS );
  fd_adminctl_failover_status_resp_t * resp = (fd_adminctl_failover_status_resp_t *)out->payload;
  FD_TEST( resp->enabled && resp->member_cnt==2U && resp->pool_healthy );

  /* A peer index beyond the pool is refused without a snapshot. */
  ((fd_adminctl_failover_status_req_t *)ctx->bus_req.payload)->peer_idx = 1UL;
  ctx->bus_req.nonce = 43UL;
  serve_bus_request( ctx, stem, now );
  FD_TEST( out->nonce==43UL && out->result==FD_FAILOVER_STATUS_RESULT_NO_SUCH_PEER );
  FD_TEST( !((fd_adminctl_failover_status_resp_t *)out->payload)->enabled );

  fd_failover_channel_fini( peer->channel );
  FD_LOG_NOTICE(( "pass: a bus request is answered for one peer, an unknown peer is refused" ));
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
  stem_init();
  test_pool_layout();
  test_listen_fd();
  test_footprint();
  test_slot_done_bookkeeping();
  test_status_snapshot();
  test_status_metrics();
  test_bus_request();

  ulong  page_cnt = 2UL;
  ulong  numa_idx = fd_shmem_numa_idx( 0UL );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "gigantic" ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );
  test_consensus_producer( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
