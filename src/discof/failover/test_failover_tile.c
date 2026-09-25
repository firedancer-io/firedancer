/* The tests reach into the channel so a session can be marked paired
   without a socket. */
#include "fd_failover_channel.c"
#include "fd_failover_tile.c"
#include "../../util/net/fd_ip4.h"
#include "../../choreo/tower/fd_tower.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

static uchar ch_mem[ 8UL<<20 ] __attribute__((aligned(128)));
static fd_topo_tile_t         tile[1];
static fd_failover_tile_ctx_t ctx[1];

static void
write_boot_key( char const * path,
                uchar const * key ) {
  FILE * file = fopen( path, "w" );
  FD_TEST( file );
  FD_TEST( fputc( '[', file )!=EOF );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( fprintf( file, "%s%u", i ? "," : "", (uint)key[ i ] )>0 );
  FD_TEST( fputc( ']', file )!=EOF );
  FD_TEST( !fclose( file ) );
}

/* Exercise the actual startup path repeatedly.  A received confirmation
   must never become an outgoing grant when a passive boot rewrites the
   interrupted PROMOTING role as STANDBY. */
static void
test_restart_confirmation( void ) {
  char base[] = "/tmp/fd_failover_restart.XXXXXX";
  FD_TEST( mkdtemp( base ) );
  fd_memset( tile, 0, sizeof(tile) );
  fd_cstr_ncpy( tile->failov.base_path, base, sizeof(tile->failov.base_path) );
  FD_TEST( fd_cstr_printf_check( tile->failov.junk_identity_path, sizeof(tile->failov.junk_identity_path), NULL, "%s/junk.json", base ) );
  FD_TEST( fd_cstr_printf_check( tile->failov.staked_identity_path, sizeof(tile->failov.staked_identity_path), NULL, "%s/staked.json", base ) );
  fd_cstr_ncpy( tile->failov.identity_key_path, tile->failov.junk_identity_path, sizeof(tile->failov.identity_key_path) );
  fd_cstr_ncpy( tile->failov.vote_account_path, tile->failov.staked_identity_path, sizeof(tile->failov.vote_account_path) );
  tile->failov.target_uid = (uint)geteuid();
  tile->failov.target_gid = (uint)getegid();
  tile->failov.member_cnt = 2UL;
  tile->failov.status_interval_millis = 800UL;
  uchar junk[ 64 ];
  uchar staked[ 64 ];
  uchar peer[ 64 ];
  fd_sha512_t sha[ 1 ];
  fd_memset( junk,   1, 32UL );
  fd_memset( staked, 2, 32UL );
  fd_memset( peer,   3, 32UL );
  fd_ed25519_public_from_private( junk+32UL,   junk,   sha );
  fd_ed25519_public_from_private( staked+32UL, staked, sha );
  fd_ed25519_public_from_private( peer+32UL,   peer,   sha );
  write_boot_key( tile->failov.junk_identity_path, junk );
  write_boot_key( tile->failov.staked_identity_path, staked );
  fd_memcpy( tile->failov.member_junk_pubkey[ 0 ], junk+32UL, 32UL );
  fd_memcpy( tile->failov.member_junk_pubkey[ 1 ], peer+32UL, 32UL );

  int dir = role_dir_open( base, (uint)geteuid(), (uint)getegid() );
  int file = fcntl( dir, F_DUPFD_CLOEXEC, 0 );
  FD_TEST( file>=0 );
  fd_failover_role_file_t role = { .version=FD_FAILOVER_ROLE_VERSION,
                                  .role=FD_FAILOVER_STATE_PROMOTING, .term=7UL };
  fd_memcpy( role.staked_pubkey, staked+32UL, 32UL );
  FD_TEST( !fd_failover_role_store( dir, file, 0, UINT_MAX, UINT_MAX, &role ) );
  fd_failover_demoted_record_t record = { .demoted={ .term=7UL, .last_vote_slot=99UL,
                                                   .watermark=5UL, .mode=FD_FAILOVER_MODE_TOWER,
                                                   .state_len=5U } };
  fd_memcpy( record.state, "tower", 5UL );
  fd_sha256_hash( record.state, 5UL, record.digest );
  /* Write a literal version 1 image.  Startup must migrate its source
     before rewriting PROMOTING to STANDBY. */
  uchar legacy[ FD_FAILOVER_DEMOTED_FILE_MAX ];
  ulong legacy_sz = fd_failover_demoted_ser( &record, legacy )-1UL;
  FD_STORE( uint, legacy, 1U );
  fd_sha256_hash( legacy, legacy_sz-32UL, legacy+legacy_sz-32UL );
  int legacy_fd = openat( dir, FD_FAILOVER_DEMOTED_PATH, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600 );
  FD_TEST( legacy_fd>=0 );
  FD_TEST( write( legacy_fd, legacy, legacy_sz )==(long)legacy_sz );
  FD_TEST( !close( legacy_fd ) );
  FD_TEST( !close( file ) );

  static fd_topo_t topo;
  ulong footprint = scratch_footprint( tile );
  void * mem = aligned_alloc( scratch_align(), footprint+scratch_align() );
  FD_TEST( mem );
  topo.objs[ 0 ].offset = scratch_align();
  topo.workspaces[ 0 ].wksp = mem;
  for( ulong restart=0UL; restart<3UL; restart++ ) {
    privileged_init( &topo, tile );
    fd_failover_tile_ctx_t * boot = fd_topo_obj_laddr( &topo, 0UL );
    FD_LOG_NOTICE(( "restart %lu: state %lu, term %lu, send_demoted %i", restart+1UL, boot->state, boot->hello.term, boot->send_demoted ));
    FD_TEST( boot->state==FD_FAILOVER_STATE_STANDBY && boot->hello.term==7UL );
    FD_TEST( boot->demoted_valid && !boot->send_demoted && !boot->pending_valid );
    FD_TEST( boot->action==FD_FAILOVER_ACTION_IDLE && boot->demoted_accept_term==7UL );
    fd_failover_channel_fini( boot->peers[ 0 ].channel );
    FD_TEST( !close( boot->role_file_fd ) );
    FD_TEST( !close( boot->role_dir_fd ) );
  }
  free( mem );
  FD_TEST( !unlinkat( dir, FD_FAILOVER_ROLE_PATH, 0 ) );
  FD_TEST( !unlinkat( dir, FD_FAILOVER_DEMOTED_PATH, 0 ) );
  FD_TEST( !close( dir ) );
  char role_dir[ 256 ];
  FD_TEST( fd_cstr_printf_check( role_dir, sizeof(role_dir), NULL, "%s/failover", base ) );
  FD_TEST( !rmdir( role_dir ) );
  FD_TEST( !unlink( tile->failov.junk_identity_path ) );
  FD_TEST( !unlink( tile->failov.staked_identity_path ) );
  FD_TEST( !rmdir( base ) );
  FD_LOG_NOTICE(( "pass: repeated passive restarts preserve confirmation direction" ));
}

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

  /* A dialing peer has no listener even if its channel has a socket. */
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

  /* The replay slot does not go backwards when a fork reports an older slot. */
  done.replay_slot = 90UL;
  done.root_slot   = 60UL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->replay_slot==100UL && ctx->root_slot==60UL );

  /* The vote slot is ignored without a vote transaction, and a standby
     does not build a consensus frame. */
  done.replay_slot  = 101UL;
  done.vote_slot    = 101UL;
  done.has_vote_txn = 0;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL && !ctx->cs_valid );
  done.has_vote_txn = 1;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->last_vote_slot==101UL && !ctx->cs_valid );

  /* The local STATUS copies the slot view and sets the lag bit only above
     the configured limit. */
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

  /* If we sent a slot view that cannot be right the peer would drop the
     session, so we clamp it first.  Here the restored last vote is ahead
     of replay, as it is right after a restart. */
  fd_failover_hello_t self = { .role=FD_FAILOVER_ROLE_STANDBY, .term=0UL };
  fd_failover_status_t decoded;
  ctx->replay_slot    = 1000UL;
  ctx->last_vote_slot = 1200UL;
  ctx->root_slot      = 900UL;
  status = local_status( ctx, peer );
  FD_TEST( ( status.status & FD_FAILOVER_STATUS_CATCHUP ) &&
           status.last_vote_slot==FD_FAILOVER_SLOT_NULL && status.root_slot==900UL );
  status.ack_seq = ULONG_MAX;
  FD_TEST( fd_failover_status_decode( &decoded, &self, 1UL, (uchar const *)&status, sizeof(status) ) );

  /* Here the root is past the last vote, as on a machine that stopped
     voting but keeps rooting.  The decoder rejects that too. */
  ctx->replay_slot    = 1400UL;
  ctx->last_vote_slot = 1000UL;
  ctx->root_slot      = 1300UL;
  status = local_status( ctx, peer );
  FD_TEST( !( status.status & FD_FAILOVER_STATUS_CATCHUP ) &&
           status.last_vote_slot==1000UL && status.root_slot==FD_FAILOVER_SLOT_NULL );
  status.ack_seq = ULONG_MAX;
  FD_TEST( fd_failover_status_decode( &decoded, &self, 1UL, (uchar const *)&status, sizeof(status) ) );

  /* A consistent view goes out unchanged. */
  ctx->replay_slot    = 1400UL;
  ctx->last_vote_slot = 1300UL;
  ctx->root_slot      = 1200UL;
  status = local_status( ctx, peer );
  FD_TEST( !( status.status & FD_FAILOVER_STATUS_CATCHUP ) &&
           status.last_vote_slot==1300UL && status.root_slot==1200UL );
  fd_failover_channel_fini( peer->channel );
  FD_LOG_NOTICE(( "pass: slot bookkeeping and the local status view" ));
}

/* A fake stem for driving the bus response path without a topology.
   Publishing records the frag instead of writing an mcache. */
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

/* Set up one paired peer with a fresh status from it. */
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
  /* The channel only reports PAIRED with a live session, so tests that
     need one set the state directly. */
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

  /* A stale peer status, a role conflict and a down link each get their
     own reason, and none of them counts as healthy. */
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
  /* metrics_write uses the real monotonic clock, so stamp the peer status
     with it to stay inside the freshness window. */
  long now = fd_failover_clock();
  fd_failover_peer_t * peer = healthy_peer( now );
  peer->channel->metrics = (fd_failover_channel_metrics_t){
    .connection_attempt_cnt=11UL, .paired_cnt=2UL, .frames_sent=13UL, .frames_received=17UL,
    .tls_fail_cnt=19UL, .admission_drop_cnt=23UL, .handshake_timeout_cnt=29UL,
    .wire_fatal_cnt=31UL, .hello_reject_cnt=37UL
  };
  /* Fake descriptors, only inspected and never used for I/O. */
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

  /* A request for the one peer gets its snapshot back, with the nonce
     echoed so a late answer can be told apart. */
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

/* The active encodes the tower's vote transaction into the frame the
   spares receive.  Encode a real vote and check that the decoder on the
   other side accepts it, so the two sides cannot drift apart. */
static void
test_consensus_producer( fd_wksp_t * wksp ) {
  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( 2, 2 ), 1UL );
  FD_TEST( tower_mem );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem, 2, 2, 0 ) );
  FD_TEST( tower );
  /* Confirmation counts decrease toward the tip, as in a real tower. */
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

  /* A standby does not produce a frame. */
  ctx->cs_valid = 0;
  ctx->role     = FD_FAILOVER_ROLE_STANDBY;
  done.vote_txn_sz = txnp->payload_sz;
  consume_slot_done( ctx, &done );
  FD_TEST( !ctx->cs_valid );

  /* The first signed vote can arrive before admin's switch answer.
     Preserve it for replication and for an immediate return handoff. */
  ctx->state               = FD_FAILOVER_STATE_PROMOTING;
  ctx->action              = FD_FAILOVER_ACTION_PROMOTE_SWITCH;
  ctx->hello.term          = 9UL;
  ctx->peers[ 0 ].cs_sent   = 1;
  ctx->last_vote_slot      = 30UL;
  ctx->slot_done_seq       = 8UL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->cs_valid && !ctx->peers[ 0 ].cs_sent );
  fd_memcpy( &msg, ctx->cs_buf, sizeof(msg) );
  FD_TEST( msg.term==9UL && msg.vote_slot==31UL && msg.link_seq==8UL );
  peer.term = 9UL;
  FD_TEST( fd_failover_consensus_decode( &cache, FD_FAILOVER_ROLE_STANDBY, &peer, ctx->cs_buf, ctx->cs_sz ) );
  FD_TEST( cache.valid && cache.msg.vote_slot==ctx->last_vote_slot );

  fd_wksp_free_laddr( tower_mem );
  FD_LOG_NOTICE(( "pass: the active encodes a tower frame the standby decoder accepts" ));
}

/* request_switch publishes one request at a time and switch_answer
   accepts only the matching nonce. */
static void
test_switch_request( void ) {
  stem_init(); /* the frag lands on the first mcache line again */
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->admin_out_idx      = 0UL;
  ctx->admin_out_mem      = (fd_wksp_t *)bus_mem; /* chunk 0 maps to bus_mem */
  ctx->admin_out_chunk0   = 0UL;
  ctx->admin_out_wmark    = 0UL;
  ctx->admin_out_chunk    = 0UL;

  ulong id = request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED );
  FD_TEST( id==1UL && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  fd_failover_bus_msg_t * out = (fd_failover_bus_msg_t *)bus_mem;
  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_SWITCH_REQ && out->nonce==1UL );
  fd_failover_switch_req_t req;
  fd_memcpy( &req, out->payload, sizeof(req) );
  FD_TEST( req.key==FD_FAILOVER_SWITCH_KEY_STAKED );

  /* Only one request at a time, a second is refused while one is out. */
  FD_TEST( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_JUNK )==ULONG_MAX );

  /* A stale answer is dropped and the request stays outstanding. */
  switch_answer( ctx, 99UL );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED && !ctx->switch_result_fresh );

  /* The matching answer completes it and frees the slot. */
  switch_answer( ctx, id );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  FD_TEST( ctx->switch_result_fresh && ctx->switch_result_id==id );

  /* An answer with nothing outstanding is dropped. */
  ctx->switch_result_fresh = 0;
  switch_answer( ctx, id );
  FD_TEST( !ctx->switch_result_fresh );
  FD_LOG_NOTICE(( "pass: an identity switch picks a resident key and only its own answer counts" ));
}


/* before_frag must let switch replies through.  If one were dropped the
   switch would never finish and no new one could start. */
static void
test_before_frag_admits( void ) {
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->tower_in_idx = 0UL;
  ctx->admin_in_idx = 1UL;
  ctx->adopt_in_idx = ULONG_MAX;

  FD_TEST( !before_frag( ctx, 0UL, 0UL, FD_TOWER_SIG_SLOT_DONE ) );
  FD_TEST(  before_frag( ctx, 0UL, 0UL, FD_TOWER_SIG_SLOT_DONE+1UL ) );

  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_STATUS_REQ ) );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_RESP ) );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_STATE ) );
  /* This tile publishes these two, it never receives them. */
  FD_TEST(  before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_STATUS_RESP ) );
  FD_TEST(  before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_REQ ) );
  FD_TEST(  before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_QUERY ) );
  FD_LOG_NOTICE(( "pass: before_frag admits every frame the tile acts on" ));
}

/* Set up a controller with a real role directory so the file writes
   actually happen. */
static char ctl_dir[] = "/tmp/fd_failover_ctl.XXXXXX";

static void
controller_init( ulong saved_state,
                 ulong saved_term ) {
  stem_init();
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->member_cnt            = 2UL;
  ctx->self_idx              = 0UL;
  ctx->peer_cnt              = 1UL;
  ctx->status_interval       = 800L*1000000L;
  ctx->replication_lag_limit = 8UL;
  ctx->min_slots_to_leader   = 150UL;
  ctx->deadline_slots        = 64UL;
  ctx->catchup_gap_limit     = 8UL;
  ctx->accept_peer_requests  = 1;
  ctx->replay_slot           = 100UL;
  ctx->last_vote_slot        = 99UL;
  ctx->root_slot             = 90UL;
  ctx->switch_pending_key    = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->demoted_accept_term   = ULONG_MAX;
  ctx->deadline_slot         = FD_FAILOVER_SLOT_NULL;
  ctx->handoff_code          = (uchar)FD_FAILOVER_HANDOFF_CODE_CNT;
  ctx->admin_out_idx         = 0UL;
  ctx->admin_out_mem         = (fd_wksp_t *)bus_mem;
  ctx->adopt_out_idx         = 0UL;
  ctx->adopt_out_mem         = (fd_wksp_t *)bus_mem;
  fd_memset( ctx->hello.staked_pubkey, 0x5A, 32UL );

  ctx->role_dir_fd  = open( ctl_dir, O_RDONLY|O_DIRECTORY|O_CLOEXEC );
  FD_TEST( ctx->role_dir_fd>=0 );
  ctx->role_file_fd = fcntl( ctx->role_dir_fd, F_DUPFD_CLOEXEC, 0 );
  FD_TEST( ctx->role_file_fd>=0 );
  ctx->role_sandboxed = 0;

  ctx->role_file.version = FD_FAILOVER_ROLE_VERSION;
  ctx->state             = saved_state;
  ctx->action            = FD_FAILOVER_ACTION_IDLE;
  ctx->action_term       = saved_term;
  ctx->hello.term        = saved_term;
  ctx->role              = saved_state==FD_FAILOVER_STATE_ACTIVE ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY;
  ctx->hello.role        = (uchar)ctx->role;
  persist( ctx, saved_state, saved_term );

  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->member_idx = 1UL;
  peer->dial       = 1;
  peer->channel    = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( peer->channel );
}

static void
controller_fini( void ) {
  fd_failover_channel_fini( ctx->peers[ 0 ].channel );
  FD_TEST( !close( ctx->role_file_fd ) );
  FD_TEST( !close( ctx->role_dir_fd ) );
  (void)unlink( "/tmp/unused" );
}

static fd_failover_peer_t *
first_use_peer( ulong self_idx,
                 long now ) {
  ctx->member_cnt = 2UL;
  ctx->self_idx = self_idx;
  ctx->step_stem = stem;
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->member_idx = 1UL-self_idx;
  peer->status_valid = 1;
  peer->status_time = now;
  peer->status.role = FD_FAILOVER_ROLE_STANDBY;
  peer->status.term = 0UL;
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;
  peer->channel->peer_hello.role = FD_FAILOVER_ROLE_STANDBY;
  peer->channel->peer_hello.term = 0UL;
  peer->channel->peer_hello.boot_id = 77UL;
  return peer;
}

static void
test_first_use_boot_guard( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 0UL );
  first_use_peer( 0UL, 1000L );
  FD_BASE58_ENCODE_32_BYTES( ctx->hello.staked_pubkey, pubkey );
  FD_TEST( first_use_check( ctx, pubkey, 0, ENOENT ) );
  FD_TEST( first_use_check( ctx, pubkey, ENOENT, ENOENT ) );
  FD_TEST( !first_use_check( ctx, "not a public key", 0, ENOENT ) );
  for( int err=0; err<3; err++ ) {
    int errors[] = { EPROTO, EACCES, EIO };
    FD_TEST( !first_use_check( ctx, pubkey, errors[ err ], ENOENT ) );
    FD_TEST( !first_use_check( ctx, pubkey, 0, errors[ err ] ) );
  }
  FD_TEST( !first_use_check( ctx, pubkey, 0, 0 ) );
  ctx->self_idx = 1UL;
  FD_TEST( !first_use_check( ctx, pubkey, 0, ENOENT ) );
  ctx->self_idx = 0UL;
  ctx->hello.staked_pubkey[ 0 ] ^= 1U;
  FD_TEST( !first_use_check( ctx, pubkey, 0, ENOENT ) );
  ctx->hello.staked_pubkey[ 0 ] ^= 1U;
  for( ulong state=1UL; state<FD_FAILOVER_STATE_CNT; state++ ) {
    ctx->role_file.role = (uchar)state;
    FD_TEST( !first_use_check( ctx, pubkey, 0, ENOENT ) );
  }
  ctx->role_file.role = FD_FAILOVER_STATE_STANDBY;
  ctx->role_file.term = 1UL;
  FD_TEST( !first_use_check( ctx, pubkey, 0, ENOENT ) );
  controller_fini();
  FD_LOG_NOTICE(( "pass: first use requires member zero, the exact identity and unused controller records" ));
}

static void
test_first_use_exchange( void ) {
  static fd_failover_tile_ctx_t claimant;
  fd_failover_reclaim_t req;
  fd_failover_confirm_t confirm;

  controller_init( FD_FAILOVER_STATE_STANDBY, 0UL );
  first_use_peer( 0UL, 1000L );
  maybe_first_use( ctx, 1000L );
  FD_TEST( !ctx->pending_valid && ctx->action==FD_FAILOVER_ACTION_IDLE );
  ctx->first_use_authorized = 1;
  maybe_first_use( ctx, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->role_file.term==0UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_FIRST_USE_WAIT && ctx->first_use_pending );
  FD_TEST( ctx->pending_type==FD_FAILOVER_MSG_RECLAIM && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  fd_memcpy( &req, ctx->pending, sizeof(req) );
  FD_TEST( req.term==1UL && req.nonce );
  claimant = *ctx;
  controller_fini();

  controller_init( FD_FAILOVER_STATE_STANDBY, 0UL );
  fd_failover_peer_t * peer = first_use_peer( 1UL, 1000L );
  fd_memcpy( ctx->rx, &req, sizeof(req) );
  handle_control( ctx, peer, FD_FAILOVER_MSG_RECLAIM, sizeof(req), 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_CONFIRM_WAIT_QUERY && ctx->switch_query_pending );
  FD_TEST( !ctx->pending_valid && ctx->role_file.term==0UL );
  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_SWITCH_QUERY );
  FD_TEST( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED )==ULONG_MAX );

  /* A query result cannot complete an identity switch.  A stale query
     answer cannot release the first-use grant either. */
  ctx->admin_in_idx    = 1UL;
  ctx->adopt_in_idx    = ULONG_MAX;
  ctx->admin_in_mem    = (fd_wksp_t *)bus_mem;
  ctx->admin_in_chunk0 = 0UL;
  ctx->admin_in_wmark  = 0UL;
  fd_failover_bus_msg_t * answer = (fd_failover_bus_msg_t *)bus_mem;
  fd_memset( answer, 0, sizeof(*answer) );
  fd_failover_switch_resp_t state = { .result=FD_FAILOVER_SWITCH_STATE_JUNK, .tower_watermark=ULONG_MAX };
  fd_memcpy( state.identity, ctx->hello.junk_pubkey, 32UL );
  fd_memcpy( answer->payload, &state, sizeof(state) );
  answer->nonce = ctx->switch_query_id+1UL;
  during_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_STATE, 0UL, sizeof(*answer), 0UL );
  after_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_STATE, sizeof(*answer), 0UL, 0UL, stem );
  step_controller( ctx, stem, 1100L );
  FD_TEST( ctx->switch_query_pending && !ctx->pending_valid );
  answer->nonce = ctx->switch_query_id;
  during_frag( ctx, 1UL, 1UL, FD_FAILOVER_BUS_SWITCH_STATE, 0UL, sizeof(*answer), 0UL );
  after_frag( ctx, 1UL, 1UL, FD_FAILOVER_BUS_SWITCH_STATE, sizeof(*answer), 0UL, 0UL, stem );
  FD_TEST( !ctx->bus_req_fresh );
  step_controller( ctx, stem, 1200L );
  FD_TEST( !ctx->switch_result_fresh && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->role_file.term==1UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->pending_type==FD_FAILOVER_MSG_CONFIRM );
  fd_memcpy( &confirm, ctx->pending, sizeof(confirm) );
  FD_TEST( confirm.code==FD_FAILOVER_RECLAIM_CONFIRMED && confirm.nonce==req.nonce );
  fd_failover_role_file_t saved;
  FD_TEST( !fd_failover_role_load( ctx->role_dir_fd, &saved ) );
  FD_TEST( saved.term==1UL && saved.role==FD_FAILOVER_STATE_STANDBY );

  /* Same attempt after a dropped answer is idempotent.  A new claimant
     boot or a new nonce cannot reuse the durable term. */
  ctx->pending_valid = 0;
  handle_control( ctx, peer, FD_FAILOVER_MSG_RECLAIM, sizeof(req), 1300L );
  FD_TEST( fd_memeq( &confirm, ctx->pending, sizeof(confirm) ) );
  ctx->pending_valid = 0;
  ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_STAKED;
  handle_control( ctx, peer, FD_FAILOVER_MSG_RECLAIM, sizeof(req), 1350L );
  FD_TEST( ((fd_failover_confirm_t *)ctx->pending)->code==FD_FAILOVER_RECLAIM_REFUSED );
  FD_TEST( ((fd_failover_confirm_t *)ctx->pending)->reason==FD_FAILOVER_REJECT_SWITCH_PENDING );
  ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->pending_valid = 0;
  peer->channel->peer_hello.boot_id++;
  handle_control( ctx, peer, FD_FAILOVER_MSG_RECLAIM, sizeof(req), 1400L );
  FD_TEST( ((fd_failover_confirm_t *)ctx->pending)->code==FD_FAILOVER_RECLAIM_STALE_TERM );
  peer->channel->peer_hello.boot_id--;
  ctx->pending_valid = 0;
  fd_failover_reclaim_t other = req;
  other.nonce++;
  fd_memcpy( ctx->rx, &other, sizeof(other) );
  handle_control( ctx, peer, FD_FAILOVER_MSG_RECLAIM, sizeof(other), 1500L );
  FD_TEST( ((fd_failover_confirm_t *)ctx->pending)->code==FD_FAILOVER_RECLAIM_STALE_TERM );
  controller_fini();

  controller_init( FD_FAILOVER_STATE_STANDBY, 0UL );
  peer = first_use_peer( 0UL, 1600L );
  ctx->first_use_authorized = claimant.first_use_authorized;
  ctx->first_use_tried = claimant.first_use_tried;
  ctx->first_use_pending = claimant.first_use_pending;
  ctx->first_use_req = claimant.first_use_req;
  ctx->first_use_peer_boot = claimant.first_use_peer_boot;
  ctx->claim_deadline = claimant.claim_deadline;
  ctx->action = claimant.action;
  ctx->action_term = claimant.action_term;
  fd_failover_confirm_t stale = confirm;
  stale.nonce++;
  fd_memcpy( ctx->rx, &stale, sizeof(stale) );
  handle_control( ctx, peer, FD_FAILOVER_MSG_CONFIRM, sizeof(stale), 1700L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_FIRST_USE_WAIT && ctx->role_file.term==0UL );

  fd_memcpy( ctx->rx, &confirm, sizeof(confirm) );
  handle_control( ctx, peer, FD_FAILOVER_MSG_CONFIRM, sizeof(confirm), 1800L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->role_file.term==1UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  FD_TEST( !ctx->first_use_authorized && !ctx->demoted_valid );
  FD_TEST( !fd_failover_role_load( ctx->role_dir_fd, &saved ) && saved.role==FD_FAILOVER_STATE_PROMOTING );
  step_controller( ctx, stem, 1900L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING );
  ctx->switch_result.result = FD_FAILOVER_SWITCH_OK;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 2000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_ACTIVE && ctx->role_file.term==1UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->first_use_promoting && !ctx->pending_valid );
  FD_TEST( fd_failover_state_boot( ctx->role_file.role )==FD_FAILOVER_STATE_RECLAIMING );
  controller_fini();
  FD_LOG_NOTICE(( "pass: a passive pair becomes one holder only after durable peer proof and completed key installation" ));
}

static void
test_first_use_refusals( void ) {
  for( ulong mode=0UL; mode<7UL; mode++ ) {
    controller_init( FD_FAILOVER_STATE_STANDBY, 0UL );
    fd_failover_peer_t * peer = first_use_peer( 1UL, 1000L );
    fd_failover_reclaim_t req = { .term=1UL, .nonce=77UL };
    fd_memcpy( ctx->rx, &req, sizeof(req) );
    if( mode==0UL ) ctx->paused = 1;
    if( mode==1UL ) ctx->state = FD_FAILOVER_STATE_ACTIVE;
    if( mode==2UL ) ctx->send_demoted = 1;
    if( mode==3UL ) ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_STAKED;
    if( mode==4UL ) peer->status_time = 1000L-3L*ctx->status_interval;
    handle_control( ctx, peer, FD_FAILOVER_MSG_RECLAIM, sizeof(req), 1000L );
    if( mode>=5UL ) {
      FD_TEST( ctx->switch_query_pending && !ctx->pending_valid );
      ctx->switch_state.result = FD_FAILOVER_SWITCH_STATE_STAKED;
      ctx->switch_state.tower_watermark = ULONG_MAX;
      if( mode==5UL ) switch_state_answer( ctx, ctx->switch_query_id );
      step_controller( ctx, stem, mode==6UL ? ctx->claim_deadline : 1100L );
    }
    FD_TEST( ctx->role_file.term==0UL && ctx->pending_valid );
    FD_TEST( ((fd_failover_confirm_t *)ctx->pending)->code!=FD_FAILOVER_RECLAIM_CONFIRMED );
    controller_fini();
  }
  for( ulong mode=0UL; mode<4UL; mode++ ) {
    controller_init( FD_FAILOVER_STATE_STANDBY, 0UL );
    fd_failover_peer_t * peer = first_use_peer( 0UL, 1000L );
    ctx->first_use_authorized = 1;
    ctx->replay_slot = FD_FAILOVER_SLOT_NULL;
    maybe_first_use( ctx, 1000L );
    fd_failover_confirm_t confirm = { .term=ctx->first_use_req.term, .nonce=ctx->first_use_req.nonce, .code=FD_FAILOVER_RECLAIM_CONFIRMED };
    if( mode==0UL ) ctx->paused = 1;
    if( mode==1UL ) peer->channel->peer_hello.boot_id++;
    if( mode==2UL ) confirm.code = FD_FAILOVER_RECLAIM_HELD;
    fd_memcpy( ctx->rx, &confirm, sizeof(confirm) );
    handle_control( ctx, peer, FD_FAILOVER_MSG_CONFIRM, sizeof(confirm), mode==3UL ? ctx->claim_deadline : 1100L );
    FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->role_file.term==0UL && ctx->stuck );
    FD_TEST( !ctx->first_use_pending && !ctx->first_use_authorized && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
    handle_control( ctx, peer, FD_FAILOVER_MSG_CONFIRM, sizeof(confirm), 1200L );
    FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY );
    controller_fini();
  }
  FD_LOG_NOTICE(( "pass: first use refuses absent proof, active peers, pause, stale replies and expired attempts" ));
}

/* Test that we only tell the peer to promote after we have actually
   given up the identity. */
static void
test_demotion_order( void ) {
  controller_init( FD_FAILOVER_STATE_ACTIVE, 4UL );

  /* Start as the active with a tower to hand over. */
  fd_failover_consensus_state_t hdr = { .vote_slot=99UL, .mode=(uchar)FD_FAILOVER_MODE_TOWER, .state_len=16U };
  fd_memcpy( ctx->cs_buf, &hdr, sizeof(hdr) );
  ctx->cs_valid = 1;
  ctx->cs_sz    = sizeof(fd_failover_consensus_state_t)+16UL;
  fd_memset( ctx->cs_buf+sizeof(fd_failover_consensus_state_t), 0xC5, 16UL );

  start_demotion( ctx, stem, 5UL, ctx->deadline_slots, 1 );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_DEMOTING && ctx->role_file.role==(uchar)FD_FAILOVER_STATE_DEMOTING );
  FD_TEST( ctx->role_file.term==5UL && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  /* Nothing has been sent to the peer yet. */
  FD_TEST( !ctx->pending_valid && !ctx->demoted_valid );

  /* If the switch fails we still have the identity, so nothing goes to the
     peer and we flag stuck. */
  ctx->switch_result.result = FD_FAILOVER_SWITCH_ERR_DISABLED;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_ACTIVE && ctx->stuck );
  FD_TEST( !ctx->pending_valid && !ctx->demoted_valid );

  /* When the switch succeeds we write the record and send the
     confirmation, with the watermark the switch gave us. */
  start_demotion( ctx, stem, 6UL, ctx->deadline_slots, 1 );
  ctx->switch_result.result          = FD_FAILOVER_SWITCH_OK;
  ctx->switch_result.tower_watermark = 777UL;
  ctx->tower_seen_seq                = 776UL; /* the stream reached the halt */
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->role==FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( ctx->demoted_valid && ctx->demoted_record.demoted.term==6UL );
  FD_TEST( ctx->demoted_record.demoted.watermark==777UL );
  FD_TEST( ctx->demoted_record.demoted.last_vote_slot==99UL );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_DEMOTED );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );

  /* The record is on disk and comes back after a restart. */
  fd_failover_demoted_record_t loaded;
  FD_TEST( !fd_failover_demoted_load( ctx->role_dir_fd, &loaded ) );
  FD_TEST( loaded.demoted.term==6UL && loaded.demoted.watermark==777UL );

  /* A cached tower that is not the one of our last vote confirms nothing. */
  ctx->pending_valid = 0;
  hdr.vote_slot = 98UL;
  fd_memcpy( ctx->cs_buf, &hdr, sizeof(hdr) );
  start_demotion( ctx, stem, 7UL, ctx->deadline_slots, 1 );
  ctx->switch_result.result = FD_FAILOVER_SWITCH_OK;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->stuck );
  FD_TEST( !ctx->demoted_valid && !ctx->pending_valid );

  controller_fini();
  FD_LOG_NOTICE(( "pass: a demotion confirms only after the identity is gone" ));
}

/* Test that a handoff asked on the active reads the spare's last status
   before giving the identity up. */
static void
test_active_handoff_checks( void ) {
  fd_adminctl_failover_control_t req;
  fd_memset( &req, 0, sizeof(req) );
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_HANDOFF;

  /* A healthy spare at our term, the demotion starts. */
  controller_init( FD_FAILOVER_STATE_ACTIVE, 4UL );
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;
  peer->status_valid   = 1;
  peer->status.role    = (uchar)FD_FAILOVER_ROLE_STANDBY;
  peer->status.term    = 4UL;
  ctx->stuck = 1;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE );
  ctx->stuck = 0;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_DEMOTING && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  controller_fini();

  /* A spare that is stuck, behind, or at another term is refused and the
     identity stays put.  A paused pool answers paused, as before. */
  uint   statuses[] = { FD_FAILOVER_STATUS_STUCK, FD_FAILOVER_STATUS_REPLAG, 0U,   FD_FAILOVER_STATUS_PAUSED };
  ulong  terms[]    = { 4UL,                      4UL,                       5UL,  4UL };
  ulong  expected[] = { FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY, FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY,
                        FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY, FD_FAILOVER_CONTROL_RESULT_PAUSED };
  for( ulong i=0UL; i<4UL; i++ ) {
    controller_init( FD_FAILOVER_STATE_ACTIVE, 4UL );
    peer = &ctx->peers[ 0 ];
    peer->channel->state  = FD_FAILOVER_SESSION_PAIRED;
    peer->status_valid    = 1;
    peer->status.role     = (uchar)FD_FAILOVER_ROLE_STANDBY;
    peer->status.term     = terms[ i ];
    peer->status.status   = statuses[ i ];
    FD_TEST( apply_control( ctx, stem, &req, 1000L )==expected[ i ] );
    FD_TEST( ctx->state==FD_FAILOVER_STATE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE );
    controller_fini();
  }
  /* A status older than two intervals is stale, whatever it says. */
  controller_init( FD_FAILOVER_STATE_ACTIVE, 4UL );
  peer = &ctx->peers[ 0 ];
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;
  peer->status_valid   = 1;
  peer->status_time    = 1000L-3L*ctx->status_interval;
  peer->status.role    = (uchar)FD_FAILOVER_ROLE_STANDBY;
  peer->status.term    = 4UL;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE );
  controller_fini();
  FD_LOG_NOTICE(( "pass: the active asks the spare's status before handing off" ));
}

/* Test that a demotion takes the final tower only once the tower stream
   has reached the halt watermark, and confirms nothing when it never gets
   there or a frag was skipped. */
static void
test_demotion_drain( void ) {
  controller_init( FD_FAILOVER_STATE_ACTIVE, 4UL );
  fd_failover_consensus_state_t hdr = { .vote_slot=99UL, .mode=(uchar)FD_FAILOVER_MODE_TOWER, .state_len=16U };
  fd_memcpy( ctx->cs_buf, &hdr, sizeof(hdr) );
  ctx->cs_valid = 1;
  ctx->cs_sz    = sizeof(fd_failover_consensus_state_t)+16UL;
  fd_memset( ctx->cs_buf+sizeof(fd_failover_consensus_state_t), 0xC5, 16UL );

  /* The junk key is in, the stream is three frags short of the halt. */
  start_demotion( ctx, stem, 5UL, ctx->deadline_slots, 1 );
  ctx->switch_result.result          = FD_FAILOVER_SWITCH_OK;
  ctx->switch_result.tower_watermark = 800UL;
  ctx->tower_seen_seq                = 796UL;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_DEMOTING && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  FD_TEST( !ctx->demoted_valid && !ctx->pending_valid && !ctx->stuck );

  /* The last frag before the halt arrives, the confirmation goes out. */
  ctx->tower_seen_seq = 799UL;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  FD_TEST( ctx->demoted_valid && ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_DEMOTED );

  /* A stream that never reaches the halt confirms nothing at the deadline. */
  controller_init( FD_FAILOVER_STATE_ACTIVE, 6UL );
  fd_memcpy( ctx->cs_buf, &hdr, sizeof(hdr) );
  ctx->cs_valid = 1;
  ctx->cs_sz    = sizeof(fd_failover_consensus_state_t)+16UL;
  start_demotion( ctx, stem, 7UL, ctx->deadline_slots, 1 );
  ctx->switch_result.result          = FD_FAILOVER_SWITCH_OK;
  ctx->switch_result.tower_watermark = 800UL;
  ctx->tower_seen_seq                = 700UL;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_DEMOTING );
  ctx->replay_slot = 1000UL;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( !ctx->demoted_valid && !ctx->pending_valid );

  /* A skipped tower frag since the cached tower confirms nothing either. */
  controller_init( FD_FAILOVER_STATE_ACTIVE, 8UL );
  fd_memcpy( ctx->cs_buf, &hdr, sizeof(hdr) );
  ctx->cs_valid  = 1;
  ctx->cs_sz     = sizeof(fd_failover_consensus_state_t)+16UL;
  ctx->tower_gap = 1;
  start_demotion( ctx, stem, 9UL, ctx->deadline_slots, 1 );
  ctx->switch_result.result          = FD_FAILOVER_SWITCH_OK;
  ctx->switch_result.tower_watermark = 800UL;
  ctx->tower_seen_seq                = 799UL;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->stuck && !ctx->demoted_valid && !ctx->pending_valid );

  /* A slot done counts once after_frag has it, one the stem abandons to
     an overrun never does.  Other frags count at once, and a skipped one
     is noticed either way. */
  ctx->tower_seen_seq = ULONG_MAX;
  ctx->tower_gap      = 0;
  ctx->tower_in_idx   = 3UL;
  FD_TEST(  before_frag( ctx, 3UL, 10UL, FD_TOWER_SIG_SLOT_DONE+1UL ) && ctx->tower_seen_seq==10UL && !ctx->tower_gap );
  FD_TEST( !before_frag( ctx, 3UL, 11UL, FD_TOWER_SIG_SLOT_DONE ) && ctx->tower_seen_seq==10UL && !ctx->tower_gap );
  after_frag( ctx, 3UL, 11UL, FD_TOWER_SIG_SLOT_DONE, sizeof(fd_tower_msg_t), 0UL, 0UL, stem );
  FD_TEST( ctx->tower_seen_seq==11UL && !ctx->tower_gap );
  ctx->slot_done_fresh = 0;
  FD_TEST( !before_frag( ctx, 3UL, 12UL, FD_TOWER_SIG_SLOT_DONE ) && ctx->tower_seen_seq==11UL && !ctx->tower_gap );
  FD_TEST(  before_frag( ctx, 3UL, 14UL, FD_TOWER_SIG_SLOT_DONE+1UL ) && ctx->tower_seen_seq==14UL && ctx->tower_gap );

  controller_fini();
  FD_LOG_NOTICE(( "pass: the final tower waits for the halt watermark" ));
}

/* Exercise the actual input callbacks while the accepted switch result
   remains live across controller steps.  A rejected or abandoned frame
   must never overwrite the watermark we are still draining toward. */
static void
test_switch_response_integrity( void ) {
  for( ulong fault=0UL; fault<4UL; fault++ ) {
    controller_init( FD_FAILOVER_STATE_ACTIVE, 4UL );
    ctx->admin_in_idx = 1UL;
    ctx->adopt_in_idx = ULONG_MAX;
    ctx->tower_in_idx = 2UL;
    ctx->admin_in_mem = (fd_wksp_t *)bus_mem;
    fd_failover_consensus_state_t hdr = { .vote_slot=99UL, .mode=FD_FAILOVER_MODE_TOWER, .state_len=16U };
    fd_memcpy( ctx->cs_buf, &hdr, sizeof(hdr) );
    fd_memset( ctx->cs_buf+sizeof(hdr), 0xC5, 16UL );
    ctx->cs_valid = 1;
    ctx->cs_sz = sizeof(hdr)+16UL;
    ctx->switch_request_id = 8UL;
    start_demotion( ctx, stem, 5UL, ctx->deadline_slots, 1 );
    ctx->tower_seen_seq = 796UL;
    fd_failover_bus_msg_t * answer = (fd_failover_bus_msg_t *)bus_mem;
    fd_failover_switch_resp_t result = { .result=FD_FAILOVER_SWITCH_OK, .tower_watermark=800UL };
    answer->nonce = ctx->switch_request_id;
    fd_memcpy( answer->payload, &result, sizeof(result) );
    during_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_RESP, 0UL, sizeof(*answer), 0UL );
    after_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_RESP, sizeof(*answer), 0UL, 0UL, stem );
    step_controller( ctx, stem, 1000L );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->switch_result_fresh );

    /* Old nonce, duplicate answer, unrelated query, or a copy the stem
       abandons before after_frag.  All carry an incorrect lower watermark. */
    if( fault==0UL ) answer->nonce--;
    result.tower_watermark = 100UL;
    fd_memcpy( answer->payload, &result, sizeof(result) );
    ulong sig = fault==2UL ? FD_FAILOVER_BUS_SWITCH_STATE : FD_FAILOVER_BUS_SWITCH_RESP;
    during_frag( ctx, 1UL, 1UL, sig, 0UL, sizeof(*answer), 0UL );
    if( fault!=3UL ) after_frag( ctx, 1UL, 1UL, sig, sizeof(*answer), 0UL, 0UL, stem );
    step_controller( ctx, stem, 1001L );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->switch_result_fresh );
    FD_TEST( ctx->switch_result.tower_watermark==800UL && !ctx->demoted_valid );

    ctx->tower_seen_seq = 799UL;
    step_controller( ctx, stem, 1002L );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && ctx->demoted_valid );
    FD_TEST( ctx->demoted_record.demoted.watermark==800UL );
    demoted_remove( ctx );
    controller_fini();
  }
  FD_LOG_NOTICE(( "pass: stale, duplicate, unrelated and abandoned input preserves the accepted halt watermark" ));
}

/* Test that a switch whose answer is overdue is waited for, on both
   sides.  Standing down would tell the peer nobody promoted while the
   staked key may be installed. */
static void
test_switch_overdue( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 6UL );

  fd_failover_demoted_record_t record;
  fd_memset( &record, 0, sizeof(record) );
  record.demoted.term           = 7UL;
  record.demoted.last_vote_slot = 99UL;
  record.demoted.watermark      = 5UL;
  record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  record.demoted.state_len      = 16U;
  fd_memset( record.state, 0xD7, 16UL );
  fd_sha256_hash( record.state, 16UL, record.digest );

  /* Adopt the tower, then ask for the staked key. */
  start_promotion( ctx, &record, 7UL );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  ctx->adopt_result.result    = FD_TOWER_ADOPT_SUCCESS;
  ctx->adopt_result.vote_slot = 99UL;
  ctx->adopt_result_id        = ctx->adopt_expected_id;
  ctx->adopt_result_fresh     = 1;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );

  /* Replay runs past the deadline with no answer.  We stay PROMOTING, keep
     the request open, send nothing to the peer and raise stuck. */
  ctx->replay_slot = 1000UL;
  step_controller( ctx, stem, 1000L );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED && ctx->stuck && ctx->switch_overdue );
  FD_TEST( ctx->switch_overdue_cnt==1UL ); /* said and counted once */
  FD_TEST( !ctx->pending_valid && ctx->demoted_valid );

  /* The late answer is consumed, not dropped, and finishes the promotion. */
  ctx->switch_result.result = FD_FAILOVER_SWITCH_OK;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_ACTIVE && ctx->role==FD_FAILOVER_ROLE_ACTIVE && !ctx->stuck );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK );

  /* Same on the demotion side: an overdue switch to the junk key is waited
     for and the late answer completes the demotion. */
  ctx->pending_valid = 0;
  fd_failover_consensus_state_t hdr = { .vote_slot=99UL, .mode=(uchar)FD_FAILOVER_MODE_TOWER, .state_len=16U };
  fd_memcpy( ctx->cs_buf, &hdr, sizeof(hdr) );
  ctx->cs_valid      = 1;
  ctx->cs_sz         = sizeof(fd_failover_consensus_state_t)+16UL;
  fd_memset( ctx->cs_buf+sizeof(fd_failover_consensus_state_t), 0xC5, 16UL );
  start_demotion( ctx, stem, 8UL, ctx->deadline_slots, 1 );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  ctx->replay_slot = 2000UL;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_DEMOTING && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_JUNK && ctx->stuck && !ctx->pending_valid );
  FD_TEST( ctx->switch_overdue_cnt==2UL );
  ctx->switch_result.result          = FD_FAILOVER_SWITCH_OK;
  ctx->switch_result.tower_watermark = 9UL;
  ctx->tower_seen_seq                = 8UL;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_DEMOTED );

  controller_fini();
  FD_LOG_NOTICE(( "pass: an overdue switch is waited for, not abandoned" ));
}

/* Test that a promotion whose tower cannot be adopted stands down at a
   new term and tells the peer. */
static void
test_promotion_reject( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 6UL );

  fd_failover_demoted_record_t record;
  fd_memset( &record, 0, sizeof(record) );
  record.demoted.term           = 7UL;
  record.demoted.last_vote_slot = 99UL;
  record.demoted.watermark      = 5UL;
  record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  record.demoted.state_len      = 16U;
  fd_memset( record.state, 0xD7, 16UL );
  fd_sha256_hash( record.state, 16UL, record.digest );

  start_promotion( ctx, &record, 7UL );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  FD_TEST( ctx->adopt_state_len==16UL && ctx->demoted_valid );

  /* Replay is past the final vote, so we hand the tower to the tower tile. */
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_expected_id );

  /* The tower tile refuses it, so we do not take the identity and we tell
     the peer. */
  ctx->adopt_result.result = FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH;
  ctx->adopt_result_id     = ctx->adopt_expected_id;
  ctx->adopt_result_fresh  = 1;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->role==FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( ctx->hello.term==8UL && ctx->stuck && !ctx->demoted_valid );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED );

  controller_fini();
  FD_LOG_NOTICE(( "pass: a promotion that cannot adopt stands down and says why" ));
}

/* Test the checks on an incoming confirmation. */
static void
test_demoted_payload( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];

  /* A real one vote tower ending at slot 42. */
  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root                             = 40UL;
  serde.lockouts_cnt                     = 1;
  serde.lockouts[ 0 ].offset             = 2UL;
  serde.lockouts[ 0 ].confirmation_count = 1;
  ulong state_sz;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, payload+sizeof(fd_failover_demoted_t), FD_FAILOVER_TOWER_STATE_MAX, &state_sz ) );

  fd_failover_demoted_t msg;
  fd_memset( &msg, 0, sizeof(msg) );
  msg.term           = 3UL;
  msg.last_vote_slot = 42UL;
  msg.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  msg.state_len      = (ushort)state_sz;
  fd_memcpy( payload, &msg, sizeof(msg) );

  fd_failover_demoted_record_t out;
  FD_TEST( !demoted_payload_decode( payload, sizeof(msg)+state_sz, &out ) );
  FD_TEST( out.demoted.term==3UL && out.demoted.state_len==state_sz );

  /* Wrong length, empty tower, unknown mode, a sentinel vote, a tower that
     ends at another slot and a tower that does not decode must all be
     rejected. */
  FD_TEST( demoted_payload_decode( payload, sizeof(msg)+state_sz-1UL, &out ) );
  msg.state_len = 0U;
  fd_memcpy( payload, &msg, sizeof(msg) );
  FD_TEST( demoted_payload_decode( payload, sizeof(msg), &out ) );
  msg.state_len = (ushort)state_sz;
  msg.mode      = 9U;
  fd_memcpy( payload, &msg, sizeof(msg) );
  FD_TEST( demoted_payload_decode( payload, sizeof(msg)+state_sz, &out ) );
  msg.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  msg.last_vote_slot = FD_FAILOVER_SLOT_NULL;
  fd_memcpy( payload, &msg, sizeof(msg) );
  FD_TEST( demoted_payload_decode( payload, sizeof(msg)+state_sz, &out ) );
  msg.last_vote_slot = 43UL;
  fd_memcpy( payload, &msg, sizeof(msg) );
  FD_TEST( demoted_payload_decode( payload, sizeof(msg)+state_sz, &out ) );
  msg.last_vote_slot = 42UL;
  fd_memcpy( payload, &msg, sizeof(msg) );
  fd_memset( payload+sizeof(msg), 0xAB, state_sz );
  FD_TEST( demoted_payload_decode( payload, sizeof(msg)+state_sz, &out ) );
  FD_LOG_NOTICE(( "pass: a demotion confirmation is validated before it is believed" ));
}

/* Build a wire demotion confirmation with a real one vote tower so the
   decoder accepts it, and return the payload size. */
static ulong
make_demoted_payload( uchar * payload,
                      ulong   term,
                      ulong   tip ) {
  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root                             = tip-2UL;
  serde.lockouts_cnt                     = 1;
  serde.lockouts[ 0 ].offset             = 2UL;
  serde.lockouts[ 0 ].confirmation_count = 1;
  ulong state_sz;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, payload+sizeof(fd_failover_demoted_t),
                                       FD_FAILOVER_TOWER_STATE_MAX, &state_sz ) );

  fd_failover_demoted_t msg;
  fd_memset( &msg, 0, sizeof(msg) );
  msg.term           = term;
  msg.last_vote_slot = tip;
  msg.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  msg.state_len      = (ushort)state_sz;
  fd_memcpy( payload, &msg, sizeof(msg) );
  return sizeof(msg)+state_sz;
}

/* A promotion outcome is resent when the peer misses the reply.  Both sides
   key the retry on the confirmation's term, so a resent confirmation gets
   the same answer again instead of dropping the session or waiting forever. */
static void
test_promotion_outcome_resent( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];

  /* We promote at term 7 and the ack goes out.  When the peer resends the
     confirmation we are active, so the drop path would ignore it and leave
     the peer waiting.  We send the ack again instead. */
  controller_init( FD_FAILOVER_STATE_STANDBY, 6UL );
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;

  fd_failover_demoted_record_t record;
  fd_memset( &record, 0, sizeof(record) );
  record.demoted.term           = 7UL;
  record.demoted.last_vote_slot = 99UL;
  record.demoted.watermark      = 5UL;
  record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  record.demoted.state_len      = 16U;
  fd_memset( record.state, 0xD7, 16UL );
  fd_sha256_hash( record.state, 16UL, record.digest );

  start_promotion( ctx, &record, 7UL );
  step_controller( ctx, stem, 1000L );
  ctx->adopt_result.result    = FD_TOWER_ADOPT_SUCCESS;
  ctx->adopt_result.vote_slot = 99UL;
  ctx->adopt_result_id        = ctx->adopt_expected_id;
  ctx->adopt_result_fresh     = 1;
  step_controller( ctx, stem, 1000L );
  ctx->switch_result.result = FD_FAILOVER_SWITCH_OK;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_ACTIVE );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK );

  /* The ack went out, free the slot, then the peer resends the confirmation
     at the same term. */
  ctx->pending_valid = 0;
  ulong dropped    = peer->channel->metrics.wire_fatal_cnt;
  ulong payload_sz = make_demoted_payload( payload, 7UL, 42UL );
  fd_memcpy( ctx->rx, payload, payload_sz );
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_DEMOTED, payload_sz, 1000L );

  FD_TEST( ctx->state==FD_FAILOVER_STATE_ACTIVE );
  FD_TEST( peer->channel->metrics.wire_fatal_cnt==dropped );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK );
  fd_failover_promote_ack_t ack;
  fd_memcpy( &ack, ctx->pending, sizeof(ack) );
  FD_TEST( ack.term==7UL );
  controller_fini();

  /* We refuse at term 4, which moves us to term 5.  When the peer resends
     the old confirmation it no longer passes the term check, so the drop
     path would kill the session.  We send the refusal again instead. */
  controller_init( FD_FAILOVER_STATE_STANDBY, 4UL );
  peer = &ctx->peers[ 0 ];
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;

  ctx->action_term = 4UL;
  reject_promotion( ctx, FD_FAILOVER_REJECT_PAUSED, 1000L );
  FD_TEST( ctx->hello.term==5UL && ctx->reply_dem_term==4UL );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED );

  ctx->pending_valid = 0;
  dropped    = peer->channel->metrics.wire_fatal_cnt;
  payload_sz = make_demoted_payload( payload, 4UL, 42UL );
  fd_memcpy( ctx->rx, payload, payload_sz );
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_DEMOTED, payload_sz, 1000L );

  FD_TEST( peer->channel->metrics.wire_fatal_cnt==dropped );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED );
  fd_failover_promote_rejected_t rej;
  fd_memcpy( &rej, ctx->pending, sizeof(rej) );
  FD_TEST( rej.term==5UL && rej.reason==FD_FAILOVER_REJECT_PAUSED );
  controller_fini();

  FD_LOG_NOTICE(( "pass: a promotion outcome is resent when the peer misses the reply" ));
}

/* A promotion outcome the peer is waiting on must not be lost because the
   one control slot already holds a pause.  It stays owed and goes out once
   the slot drains, the peer sends its confirmation only once per session
   so nothing else would ask for it again. */
static void
test_promotion_outcome_owed( void ) {
  /* A refusal.  The pause takes the slot, then the same pause stands the
     promotion down, and the refusal has nowhere to go. */
  controller_init( FD_FAILOVER_STATE_STANDBY, 4UL );
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;

  fd_failover_demoted_record_t record;
  fd_memset( &record, 0, sizeof(record) );
  record.demoted.term           = 5UL;
  record.demoted.last_vote_slot = 99UL;
  record.demoted.watermark      = 5UL;
  record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  record.demoted.state_len      = 16U;
  fd_memset( record.state, 0xD7, 16UL );
  fd_sha256_hash( record.state, 16UL, record.digest );

  start_promotion( ctx, &record, 5UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  ctx->replay_slot = 2000UL; /* replay is ready, so only the pause stops it */
  /* The operator's pause, the flag here and the frame for the peer still
     waiting in the slot. */
  ctx->paused = 1;
  fd_failover_control_t pause = { .term=ctx->hello.term };
  FD_TEST( !queue_control( ctx, (ushort)FD_FAILOVER_MSG_PAUSE, &pause, sizeof(pause) ) );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PAUSE );

  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->hello.term==6UL );
  FD_TEST( ctx->reject_reason==FD_FAILOVER_REJECT_PAUSED );
  /* The pause still holds the slot, the refusal did not push it out. */
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PAUSE );

  /* The pause goes out and the slot is free.  The refusal follows on the
     next step without anyone asking for it. */
  ctx->pending_valid = 0;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED );
  fd_failover_promote_rejected_t rej;
  fd_memcpy( &rej, ctx->pending, sizeof(rej) );
  FD_TEST( rej.term==6UL && rej.reason==FD_FAILOVER_REJECT_PAUSED );

  /* Sent once, it is not sent again. */
  ctx->pending_valid = 0;
  step_controller( ctx, stem, 1000L );
  FD_TEST( !ctx->pending_valid );
  controller_fini();

  /* An ack.  The promotion completes while a pause holds the slot, the
     switch already in flight is not stood down by it. */
  controller_init( FD_FAILOVER_STATE_STANDBY, 6UL );
  peer = &ctx->peers[ 0 ];
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;
  record.demoted.term = 7UL;
  start_promotion( ctx, &record, 7UL );
  step_controller( ctx, stem, 1000L );
  ctx->adopt_result.result    = FD_TOWER_ADOPT_SUCCESS;
  ctx->adopt_result.vote_slot = 99UL;
  ctx->adopt_result_id        = ctx->adopt_expected_id;
  ctx->adopt_result_fresh     = 1;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  ctx->paused = 1;
  pause.term = ctx->hello.term;
  FD_TEST( !queue_control( ctx, (ushort)FD_FAILOVER_MSG_PAUSE, &pause, sizeof(pause) ) );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PAUSE );
  ctx->switch_result.result = FD_FAILOVER_SWITCH_OK;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PAUSE );

  ctx->pending_valid = 0;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK );
  fd_failover_promote_ack_t ack;
  fd_memcpy( &ack, ctx->pending, sizeof(ack) );
  FD_TEST( ack.term==7UL );
  controller_fini();

  FD_LOG_NOTICE(( "pass: a promotion outcome held back by a busy control slot goes out once the slot drains" ));
}


/* A pause accepted while a promotion is still waiting, before the key
   switch is requested, stands the promotion down. */
static void
test_pause_stops_pending_promotion( void ) {
  ulong states[] = { FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY, FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT };
  for( ulong i=0UL; i<2UL; i++ ) {
    controller_init( FD_FAILOVER_STATE_PROMOTING, 5UL );
    ctx->peers[ 0 ].channel->state = FD_FAILOVER_SESSION_PAIRED;
    ctx->action      = states[ i ];
    ctx->action_term = 5UL;
    ctx->replay_slot = 2000UL; /* replay is ready, so only the pause stops it */
    ctx->paused      = 1;
    step_controller( ctx, stem, 1000L );
    FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY );                 /* stood down */
    FD_TEST( ctx->action!=FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY &&
             ctx->action!=FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT &&
             ctx->action!=FD_FAILOVER_ACTION_PROMOTE_SWITCH );        /* not promoting */
    FD_TEST( ctx->reject_reason==FD_FAILOVER_REJECT_PAUSED );
    controller_fini();
  }
  FD_LOG_NOTICE(( "pass: a pause stands a pending promotion down before the key switch" ));
}

/* A pause or resume queued on a down link coalesces to the latest intent,
   so the peer never receives a stale one after the link recovers. */
static void
test_pause_resume_coalesce( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 4UL );
  ctx->peers[ 0 ].channel->state = FD_FAILOVER_SESSION_PAIRED;
  fd_adminctl_failover_control_t req;
  fd_memset( &req, 0, sizeof(req) );

  /* A pause fills the slot but the link cannot flush it. */
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_PAUSE;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->paused && ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PAUSE );

  /* A later resume replaces the queued pause rather than being dropped. */
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_RESUME;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( !ctx->paused && ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_RESUME );
  controller_fini();
  FD_LOG_NOTICE(( "pass: a queued pause or resume coalesces to the latest intent" ));
}

/* A final tower older than the one the peer streamed is refused, a
   replayed or regressed confirmation must not overwrite newer lockouts. */
static void
test_final_tower_regression( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 4UL );
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->channel->state              = FD_FAILOVER_SESSION_PAIRED;
  peer->channel->peer_hello.role    = (uchar)FD_FAILOVER_ROLE_STANDBY;
  peer->channel->peer_hello.term    = 5UL;
  peer->channel->peer_hello.boot_id = 7UL;

  /* We already streamed a newer tower ending at slot 100, and the session
     then dropped and re-paired, so the live cache is empty but the durable
     floor keeps the history. */
  peer->consensus.valid               = 0;
  peer->consensus_floor.valid         = 1;
  peer->consensus_floor.peer_boot_id  = 7UL;
  peer->consensus_floor.msg.term      = 5UL;
  peer->consensus_floor.msg.vote_slot = 100UL;

  /* A real DEMOTED whose final tower ends at 50, older than the stream. */
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root                             = 48UL;
  serde.lockouts_cnt                     = 1;
  serde.lockouts[ 0 ].offset             = 2UL;
  serde.lockouts[ 0 ].confirmation_count = 1;
  ulong state_sz;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, payload+sizeof(fd_failover_demoted_t), FD_FAILOVER_TOWER_STATE_MAX, &state_sz ) );
  fd_failover_demoted_t msg;
  fd_memset( &msg, 0, sizeof(msg) );
  msg.term           = 5UL;
  msg.last_vote_slot = 50UL;
  msg.watermark      = 90UL;
  msg.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  msg.state_len      = (ushort)state_sz;
  fd_memcpy( payload, &msg, sizeof(msg) );
  fd_memcpy( ctx->rx, payload, sizeof(msg)+state_sz );

  ulong dropped = peer->channel->metrics.wire_fatal_cnt;
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_DEMOTED, sizeof(msg)+state_sz, 1000L );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE ); /* did not promote */
  FD_TEST( peer->channel->metrics.wire_fatal_cnt==dropped+1UL );                            /* session dropped */
  FD_TEST( ctx->tower_rollback_cnt==1UL );                                                  /* and counted */
  controller_fini();
  FD_LOG_NOTICE(( "pass: a final tower older than the streamed one is refused" ));
}

/* The operator's promote runs the same check against the durable floor
   and refuses with its own result, so a confirmation kept on disk cannot
   roll the streamed tower back either.  With no floor there is nothing to
   compare against and the promotion goes ahead. */
static void
test_promote_refuses_rollback( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 4UL );
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->channel->state              = FD_FAILOVER_SESSION_PAIRED;
  peer->channel->peer_hello.role    = (uchar)FD_FAILOVER_ROLE_STANDBY;
  peer->channel->peer_hello.term    = 4UL;
  peer->channel->peer_hello.boot_id = 7UL;
  peer->consensus_floor.valid         = 1;
  peer->consensus_floor.peer_boot_id  = 7UL;
  peer->consensus_floor.msg.term      = 4UL;
  peer->consensus_floor.msg.vote_slot = 100UL;

  /* A confirmation on disk whose final tower ends at 50. */
  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root                             = 48UL;
  serde.lockouts_cnt                     = 1;
  serde.lockouts[ 0 ].offset             = 2UL;
  serde.lockouts[ 0 ].confirmation_count = 1;
  ulong state_sz;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, ctx->demoted_record.state, FD_FAILOVER_TOWER_STATE_MAX, &state_sz ) );
  ctx->demoted_valid                         = 1;
  ctx->demoted_historical                    = 0;
  ctx->send_demoted                          = 0;
  ctx->demoted_record.source                 = FD_FAILOVER_DEMOTED_SOURCE_PEER;
  ctx->demoted_record.demoted.term           = 4UL;
  ctx->demoted_record.demoted.last_vote_slot = 50UL;
  ctx->demoted_record.demoted.watermark      = 90UL;
  ctx->demoted_record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  ctx->demoted_record.demoted.state_len      = (ushort)state_sz;
  fd_sha256_hash( ctx->demoted_record.state, state_sz, ctx->demoted_record.digest );

  fd_adminctl_failover_control_t req;
  fd_memset( &req, 0, sizeof(req) );
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_PROMOTE;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_TOWER_ROLLBACK );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->tower_rollback_cnt==1UL );

  /* Nothing was ever streamed, so there is nothing to roll back. */
  peer->consensus_floor.valid = 0;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING && ctx->tower_rollback_cnt==1UL );
  controller_fini();
  FD_LOG_NOTICE(( "pass: the operator's promote refuses a final tower that rolls the stream back" ));
}

/* Test that a role or term change reaches the channel.  The peer checks
   every frame against the HELLO it paired on and drops the session on a
   mismatch. */
static void
test_hello_refresh( void ) {
  controller_init( FD_FAILOVER_STATE_ACTIVE, 4UL );
  fd_failover_channel_t * ch = ctx->peers[ 0 ].channel;
  ch->self_hello = ctx->hello;
  FD_TEST( ch->self_hello.role==FD_FAILOVER_ROLE_ACTIVE && ch->self_hello.term==4UL );

  persist( ctx, FD_FAILOVER_STATE_DEMOTING, 5UL );
  FD_TEST( ch->self_hello.term==5UL );

  set_role( ctx, FD_FAILOVER_ROLE_STANDBY, 1000L );
  FD_TEST( ch->self_hello.role==FD_FAILOVER_ROLE_STANDBY && ch->self_hello.term==5UL );

  /* A status built now must decode fine against the updated HELLO. */
  fd_failover_status_t status = local_status( ctx, &ctx->peers[ 0 ] );
  status.ack_seq = ULONG_MAX;
  fd_failover_status_t out;
  FD_TEST( fd_failover_status_decode( &out, &ch->self_hello, 1UL, (uchar const *)&status, sizeof(status) ) );
  controller_fini();
  FD_LOG_NOTICE(( "pass: a role or term change reaches the advertised HELLO" ));
}

/* Test that a wait started before the first replay slot still times out. */
static void
test_deadline_arms_late( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 4UL );
  ctx->replay_slot   = FD_FAILOVER_SLOT_NULL;
  ctx->deadline_slot = FD_FAILOVER_SLOT_NULL;
  ctx->action        = FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK;
  ctx->action_term   = 4UL;

  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->deadline_slot==FD_FAILOVER_SLOT_NULL && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );

  ctx->replay_slot = 500UL;
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->deadline_slot==500UL+ctx->deadline_slots );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );

  ctx->replay_slot = 500UL+ctx->deadline_slots+1UL;
  step_controller( ctx, stem, 1000L );
  /* The confirmation is still owed, so we stay in the wait and keep
     retrying while flagging stuck, rather than give up. */
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && ctx->stuck );
  controller_fini();
  FD_LOG_NOTICE(( "pass: a wait started before replay reported still reaches its deadline" ));
}

/* Test that a refusal bumps the term on both sides and drops the
   confirmation for the old term. */
static void
test_promotion_refused_term( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 4UL );
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;

  ctx->demoted_valid                         = 1;
  ctx->send_demoted                          = 1;
  ctx->action                                = FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK;
  ctx->action_term                           = 4UL;
  ctx->demoted_record.demoted.term           = 4UL;
  ctx->demoted_record.demoted.state_len      = 8U;
  ctx->demoted_record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  ctx->demoted_record.demoted.last_vote_slot = 99UL;
  fd_memset( ctx->demoted_record.state, 0xE1, 8UL );
  fd_sha256_hash( ctx->demoted_record.state, 8UL, ctx->demoted_record.digest );

  /* A refusal for a different attempt is ignored and does not drop the
     session. */
  ulong dropped = peer->channel->metrics.wire_fatal_cnt;
  fd_failover_promote_rejected_t rej = { .term=6UL, .reason=FD_FAILOVER_REJECT_ADOPTION_MISMATCH };
  fd_memcpy( ctx->rx, &rej, sizeof(rej) );
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, sizeof(rej), 1000L );
  FD_TEST( ctx->send_demoted && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  FD_TEST( peer->channel->metrics.wire_fatal_cnt==dropped );

  rej.term = 5UL;
  fd_memcpy( ctx->rx, &rej, sizeof(rej) );
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, sizeof(rej), 1000L );
  FD_TEST( !ctx->send_demoted && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( ctx->hello.term==5UL && ctx->role_file.term==5UL );
  FD_TEST( !ctx->demoted_valid );
  controller_fini();
  FD_LOG_NOTICE(( "pass: a refusal takes its term to both sides and retires the confirmation" ));
}

/* Test that an ack arriving after we stopped waiting is still accepted. */
static void
test_late_promote_ack( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 4UL );
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;
  ulong dropped = peer->channel->metrics.wire_fatal_cnt;

  ctx->demoted_valid                    = 1;
  ctx->send_demoted                     = 1;
  ctx->action                           = FD_FAILOVER_ACTION_IDLE; /* the deadline fired */
  ctx->stuck                            = 1;
  ctx->action_term                      = 4UL;
  ctx->demoted_record.demoted.term      = 4UL;
  ctx->demoted_record.demoted.state_len = 8U;

  fd_failover_promote_ack_t ack = { .term=4UL };
  fd_memcpy( ctx->rx, &ack, sizeof(ack) );
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK, sizeof(ack), 1000L );
  FD_TEST( !ctx->send_demoted && !ctx->demoted_valid && !ctx->stuck );
  FD_TEST( peer->channel->metrics.wire_fatal_cnt==dropped );

  /* We are not waiting for an ack, so this one is ignored. */
  fd_memcpy( ctx->rx, &ack, sizeof(ack) );
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK, sizeof(ack), 1000L );
  FD_TEST( peer->channel->metrics.wire_fatal_cnt==dropped );
  controller_fini();
  FD_LOG_NOTICE(( "pass: a late acknowledgement is acted on and an unowed one is ignored" ));
}

/* Refused commands report why, and nothing that moves the identity works
   without the peer's confirmation. */
static void
test_operator_commands( void ) {
  fd_adminctl_failover_control_t req;

  /* promote without a confirmation on disk, and --force without a pubkey. */
  controller_init( FD_FAILOVER_STATE_STANDBY, 3UL );
  fd_memset( &req, 0, sizeof(req) );
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_PROMOTE;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE );

  /* A full confirmation with tower and digest, as the peer would send it. */
  persist( ctx, FD_FAILOVER_STATE_STANDBY, 4UL );
  ctx->demoted_valid                         = 1;
  ctx->demoted_record.source                 = FD_FAILOVER_DEMOTED_SOURCE_PEER;
  ctx->demoted_record.demoted.term           = 4UL;
  ctx->demoted_record.demoted.state_len      = 8U;
  ctx->demoted_record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  ctx->demoted_record.demoted.last_vote_slot = 99UL;
  fd_memset( ctx->demoted_record.state, 0xE1, 8UL );
  fd_sha256_hash( ctx->demoted_record.state, 8UL, ctx->demoted_record.digest );
  req.force = 1U;
  fd_memset( req.staked_pubkey, 0x11, 32UL );
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_BAD_IDENTITY );
  fd_memcpy( req.staked_pubkey, ctx->hello.staked_pubkey, 32UL );
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING );

  /* Everything is refused while a transition is in flight. */
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_BUSY );
  controller_fini();

  /* pause gets written to disk and sent to the peer, and blocks anything
     that moves the identity. */
  controller_init( FD_FAILOVER_STATE_ACTIVE, 5UL );
  fd_memset( &req, 0, sizeof(req) );
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_PAUSE;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->paused && ctx->role_file.paused );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PAUSE );
  ctx->pending_valid = 0;
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_DEMOTE;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_PAUSED );
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_RESUME;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( !ctx->paused && !ctx->role_file.paused );
  ctx->pending_valid = 0;

  /* demote on the active bumps the term and drops the identity, nobody is
     asked to promote. */
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_DEMOTE;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_DEMOTING && ctx->role_file.term==6UL && !ctx->send_demoted );
  controller_fini();

  /* A spare cannot demote, and cannot send a handoff request without a
     paired peer. */
  controller_init( FD_FAILOVER_STATE_STANDBY, 7UL );
  fd_memset( &req, 0, sizeof(req) );
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_DEMOTE;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_HANDOFF;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_NOT_PAIRED );

  /* Once paired the request goes out, with the drill flag set for drill. */
  ctx->peers[ 0 ].channel->state = FD_FAILOVER_SESSION_PAIRED;
  ctx->peers[ 0 ].status_valid   = 1;
  ctx->peers[ 0 ].status.term    = 7UL;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_HANDOFF_REQ );
  fd_failover_handoff_req_t sent;
  fd_memcpy( &sent, ctx->pending, sizeof(sent) );
  FD_TEST( sent.proposed_term==8UL && !sent.drill );
  ctx->pending_valid = 0;
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_DRILL;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_BUSY );
  fd_failover_handoff_resp_t response = { .proposed_term=sent.proposed_term,
                                         .deadline_slots=sent.deadline_slots,
                                         .code=FD_FAILOVER_HANDOFF_ALREADY_STANDBY };
  fd_memcpy( ctx->rx, &response, sizeof(response) );
  handle_control( ctx, &ctx->peers[ 0 ], FD_FAILOVER_MSG_HANDOFF_RESP, sizeof(response), 1000L );
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  fd_memcpy( &sent, ctx->pending, sizeof(sent) );
  FD_TEST( sent.drill );
  controller_fini();
  FD_LOG_NOTICE(( "pass: refused commands report why" ));
}


/* The switch request and the command response share a link, make sure
   they land in different chunks. */
static void
test_bus_control_ordering( void ) {
  controller_init( FD_FAILOVER_STATE_ACTIVE, 4UL );
  ctx->admin_out_chunk0 = 0UL;
  ctx->admin_out_wmark  = 16UL;
  ctx->admin_out_chunk  = 0UL;
  ctx->cs_valid = 1;
  ctx->cs_sz    = sizeof(fd_failover_consensus_state_t)+8UL;

  fd_memset( &ctx->bus_req, 0, sizeof(ctx->bus_req) );
  ctx->bus_req.nonce = 77UL;
  fd_adminctl_failover_control_t * req = (fd_adminctl_failover_control_t *)ctx->bus_req.payload;
  req->version = FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION;
  req->cmd    = FD_ADMINCTL_FAILOVER_CMD_DEMOTE;
  ctx->bus_req_sig = FD_FAILOVER_BUS_CONTROL_REQ;
  serve_bus_request( ctx, stem, 1000L );

  /* Two frames, switch request then response, different chunks. */
  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_SWITCH_REQ );
  FD_TEST( pub_mcache[ 1 ].sig==FD_FAILOVER_BUS_CONTROL_RESP );
  FD_TEST( pub_mcache[ 0 ].chunk!=pub_mcache[ 1 ].chunk );

  fd_failover_bus_msg_t const * sw = fd_chunk_to_laddr_const( ctx->admin_out_mem, pub_mcache[ 0 ].chunk );
  fd_failover_switch_req_t sreq;
  fd_memcpy( &sreq, sw->payload, sizeof(sreq) );
  FD_TEST( sreq.key==FD_FAILOVER_SWITCH_KEY_JUNK );
  FD_TEST( sw->nonce==ctx->switch_request_id );

  fd_failover_bus_msg_t const * ans = fd_chunk_to_laddr_const( ctx->admin_out_mem, pub_mcache[ 1 ].chunk );
  FD_TEST( ans->nonce==77UL && ans->result==FD_ADMINCTL_RESULT_SUCCESS );
  fd_adminctl_failover_control_resp_t answer;
  fd_memcpy( &answer, ans->payload, sizeof(answer) );
  FD_TEST( answer.version==FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION );
  FD_TEST( answer.state==(uchar)FD_FAILOVER_STATE_DEMOTING && answer.term==5UL );
  controller_fini();
  stem_init();
  FD_LOG_NOTICE(( "pass: a command's switch request and its answer take different frames" ));
}

/* Handoff answers get matched against our outstanding request and never
   count as unknown frames. */
static void
test_handoff_response( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 7UL );
  fd_failover_peer_t * peer = &ctx->peers[ 0 ];
  peer->channel->state = FD_FAILOVER_SESSION_PAIRED;
  peer->status_valid   = 1;
  peer->status.term    = 7UL;
  ulong dropped = peer->channel->metrics.wire_fatal_cnt;

  /* Answer with no request outstanding, ignored. */
  fd_failover_handoff_resp_t resp = {
    .proposed_term  = 8UL,
    .deadline_slots = (uint)ctx->deadline_slots,
    .code           = FD_FAILOVER_HANDOFF_REJECTED,
    .reason         = FD_FAILOVER_REJECT_PEER_BEHIND,
  };
  fd_memcpy( ctx->rx, &resp, sizeof(resp) );
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_HANDOFF_RESP, sizeof(resp), 1000L );
  FD_TEST( ctx->handoff_code==(uchar)FD_FAILOVER_HANDOFF_CODE_CNT );
  FD_TEST( peer->channel->metrics.wire_fatal_cnt==dropped );

  /* Matching answer, accepted. */
  fd_adminctl_failover_control_t req;
  fd_memset( &req, 0, sizeof(req) );
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_HANDOFF;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->handoff_pending && ctx->handoff_req.proposed_term==8UL );
  ctx->pending_valid = 0;

  fd_memcpy( ctx->rx, &resp, sizeof(resp) );
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_HANDOFF_RESP, sizeof(resp), 1000L );
  FD_TEST( ctx->handoff_code==FD_FAILOVER_HANDOFF_REJECTED );
  FD_TEST( ctx->handoff_reason==FD_FAILOVER_REJECT_PEER_BEHIND );
  FD_TEST( ctx->handoff_term==8UL && !ctx->handoff_pending );
  FD_TEST( peer->channel->metrics.wire_fatal_cnt==dropped );

  /* Mismatched answer, ignored, session stays up. */
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  ctx->pending_valid = 0;
  resp.proposed_term = 9UL;
  fd_memcpy( ctx->rx, &resp, sizeof(resp) );
  handle_control( ctx, peer, (ushort)FD_FAILOVER_MSG_HANDOFF_RESP, sizeof(resp), 1000L );
  FD_TEST( ctx->handoff_pending && ctx->handoff_term==8UL );
  FD_TEST( peer->channel->metrics.wire_fatal_cnt==dropped );
  controller_fini();
  FD_LOG_NOTICE(( "pass: a handoff answer is matched to its request and never dropped as unknown" ));
}

/* Bound lost requests even when replay has not started.  Every boundary
   leaves authority unchanged and permits a fresh first-use exchange. */
static void
test_handoff_request_lifetime( void ) {
  for( ulong fault=0UL; fault<6UL; fault++ ) {
    controller_init( FD_FAILOVER_STATE_STANDBY, 0UL );
    long now = 1000L;
    fd_failover_peer_t * peer = first_use_peer( 0UL, now );
    if( fault==1UL ) ctx->replay_slot = FD_FAILOVER_SLOT_NULL;
    fd_adminctl_failover_control_t req = { .cmd=FD_ADMINCTL_FAILOVER_CMD_DRILL };
    FD_TEST( apply_control( ctx, stem, &req, now )==FD_ADMINCTL_RESULT_SUCCESS );
    FD_TEST( apply_control( ctx, stem, &req, now )==FD_FAILOVER_CONTROL_RESULT_BUSY );
    fd_adminctl_failover_status_resp_t status;
    status_snapshot( ctx, 0UL, now, &status );
    FD_TEST( status.status&FD_FAILOVER_STATUS_BUSY );
    /* The request reached the peer but the answer was lost.  One case
       leaves the unsent request in the slot to check it is canceled too. */
    if( fault!=5UL ) ctx->pending_valid = 0;
    ctx->first_use_authorized = 1;
    maybe_first_use( ctx, now );
    FD_TEST( !ctx->first_use_pending );
    step_controller( ctx, stem, ctx->handoff_deadline-1L );
    FD_TEST( ctx->handoff_pending );
    if( fault==0UL || fault==5UL ) ctx->replay_slot += ctx->deadline_slots+1UL;
    else if( fault==1UL ) now = ctx->handoff_deadline;
    else if( fault==2UL ) peer->channel->state = FD_FAILOVER_SESSION_BACKOFF;
    else if( fault==3UL ) peer->channel->metrics.paired_cnt++;
    else ctx->paused = 1;
    step_controller( ctx, stem, now );
    FD_TEST( !ctx->handoff_pending && !ctx->pending_valid );
    FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->hello.term==0UL && !ctx->stuck );
    FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
    status_snapshot( ctx, 0UL, now, &status );
    FD_TEST( !(status.status&FD_FAILOVER_STATUS_BUSY) );

    /* A late matching response grants nothing. */
    fd_failover_handoff_resp_t response = { .proposed_term=ctx->handoff_req.proposed_term,
                                            .deadline_slots=ctx->handoff_req.deadline_slots,
                                            .drill=1U, .code=FD_FAILOVER_HANDOFF_PROCEED };
    fd_memcpy( ctx->rx, &response, sizeof(response) );
    handle_control( ctx, peer, FD_FAILOVER_MSG_HANDOFF_RESP, sizeof(response), now );
    FD_TEST( ctx->handoff_code==FD_FAILOVER_HANDOFF_CODE_CNT && !ctx->first_use_pending );
    ctx->paused = 0;
    first_use_peer( 0UL, now );
    peer->channel->metrics.paired_cnt++;
    maybe_first_use( ctx, now );
    FD_TEST( ctx->first_use_pending && ctx->action==FD_FAILOVER_ACTION_FIRST_USE_WAIT );
    controller_fini();
  }

  controller_init( FD_FAILOVER_STATE_STANDBY, 0UL );
  fd_failover_peer_t * peer = first_use_peer( 1UL, 1000L );
  fd_failover_handoff_resp_t response = { .proposed_term=1UL, .deadline_slots=64U, .drill=1U,
                                          .code=FD_FAILOVER_HANDOFF_ALREADY_STANDBY };
  FD_TEST( !queue_control( ctx, FD_FAILOVER_MSG_HANDOFF_RESP, &response, sizeof(response) ) );
  peer->channel->metrics.paired_cnt++;
  pending_flush( ctx, peer, 1001L );
  FD_TEST( !ctx->pending_valid );
  controller_fini();
  FD_LOG_NOTICE(( "pass: lost requests expire without authority and old answers never cross sessions" ));
}

/* Our own unsent confirmation must not count for promote.  It only
   proves we stopped, not that the peer did. */
static void
test_promote_evidence( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 4UL );
  ctx->demoted_valid                         = 1;
  ctx->send_demoted                          = 1;
  ctx->action_term                           = 4UL;
  ctx->stuck                                 = 1; /* the wait timed out */
  ctx->demoted_record.demoted.term           = 4UL;
  ctx->demoted_record.demoted.state_len      = 8U;
  ctx->demoted_record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  ctx->demoted_record.demoted.last_vote_slot = 99UL;
  fd_memset( ctx->demoted_record.state, 0xE1, 8UL );
  fd_sha256_hash( ctx->demoted_record.state, 8UL, ctx->demoted_record.digest );

  fd_adminctl_failover_control_t req;
  fd_memset( &req, 0, sizeof(req) );
  req.cmd = FD_ADMINCTL_FAILOVER_CMD_PROMOTE;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE );
  req.force = 1U;
  fd_memcpy( req.staked_pubkey, ctx->hello.staked_pubkey, 32UL );
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE );

  /* The same record coming from the peer is fine. */
  ctx->send_demoted = 0;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE );
  ctx->demoted_record.source = FD_FAILOVER_DEMOTED_SOURCE_LOCAL;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE );
  ctx->demoted_record.source = FD_FAILOVER_DEMOTED_SOURCE_PEER;
  ctx->demoted_record.demoted.term = 3UL;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE );
  ctx->demoted_record.demoted.term = 4UL;
  FD_TEST( apply_control( ctx, stem, &req, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->state==FD_FAILOVER_STATE_PROMOTING );
  controller_fini();
  FD_LOG_NOTICE(( "pass: promote needs the peer's confirmation" ));
}

/* The second tenure can start and end before it produces a new vote.
   Its final tower must be the one adopted from the peer, even if this
   process still has an older stream cached from its first tenure. */
static void
test_repeated_handoff_tower( void ) {
  controller_init( FD_FAILOVER_STATE_STANDBY, 6UL );
  fd_failover_consensus_state_t old = { .term=5UL, .vote_slot=99UL,
                                       .mode=FD_FAILOVER_MODE_TOWER, .state_len=5U };
  fd_memcpy( ctx->cs_buf, &old, sizeof(old) );
  fd_memcpy( ctx->cs_buf+sizeof(old), "older", 5UL );
  ctx->cs_valid = 1;
  ctx->cs_sz = sizeof(old)+5UL;

  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong payload_sz = make_demoted_payload( payload, 7UL, 120UL );
  fd_failover_demoted_record_t record;
  FD_TEST( !demoted_payload_decode( payload, payload_sz, &record ) );
  ctx->replay_slot = 120UL;
  start_promotion( ctx, &record, 7UL );
  step_controller( ctx, stem, 1000L );
  ctx->adopt_result = (fd_tower_adopt_result_t){ .result=FD_TOWER_ADOPT_SUCCESS, .vote_slot=120UL };
  ctx->adopt_result_id = ctx->adopt_expected_id;
  ctx->adopt_result_fresh = 1;
  step_controller( ctx, stem, 1000L );
  ctx->switch_result.result = FD_FAILOVER_SWITCH_OK;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE );
  ctx->pending_valid = 0;
  FD_TEST( ctx->last_vote_slot==120UL );

  start_demotion( ctx, stem, 8UL, 64UL, 1 );
  ctx->switch_result.result = FD_FAILOVER_SWITCH_OK;
  ctx->switch_result.tower_watermark = 20UL;
  ctx->tower_seen_seq = 19UL;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem, 1000L );
  FD_TEST( ctx->demoted_valid && ctx->send_demoted );
  FD_TEST( ctx->demoted_record.demoted.last_vote_slot==120UL );
  FD_TEST( ctx->demoted_record.demoted.state_len==record.demoted.state_len );
  FD_TEST( fd_memeq( ctx->demoted_record.state, record.state, record.demoted.state_len ) );
  controller_fini();
  FD_LOG_NOTICE(( "pass: immediate repeated handoff retains the adopted final tower" ));
}

static void
test_record_sources( void ) {
  uchar sources[] = { FD_FAILOVER_DEMOTED_SOURCE_LOCAL, FD_FAILOVER_DEMOTED_SOURCE_PEER,
                       FD_FAILOVER_DEMOTED_SOURCE_UNKNOWN };
  for( ulong i=0UL; i<3UL; i++ ) {
    controller_init( FD_FAILOVER_STATE_STANDBY, 7UL );
    fd_failover_demoted_record_t record = { .demoted={ .term=7UL, .last_vote_slot=99UL,
                                                     .mode=FD_FAILOVER_MODE_TOWER, .state_len=5U },
                                           .source=sources[ i ] };
    fd_memcpy( record.state, "tower", 5UL );
    fd_sha256_hash( record.state, 5UL, record.digest );
    FD_TEST( !fd_failover_demoted_store( ctx->role_dir_fd, ctx->role_file_fd, 0, UINT_MAX, UINT_MAX, &record ) );
    fd_failover_channel_fini( ctx->peers[ 0 ].channel );
    for( ulong restart=0UL; restart<3UL; restart++ ) {
      /* Keep only the descriptors and local identity, as passive boot
         does.  The actual privileged_init loop above covers key/TLS setup. */
      int dir = ctx->role_dir_fd;
      int file = ctx->role_file_fd;
      fd_memset( ctx, 0, sizeof(*ctx) );
      ctx->role_dir_fd = dir;
      ctx->role_file_fd = file;
      ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
      fd_memset( ctx->hello.staked_pubkey, 0x5A, 32UL );
      int role_err = role_file_read( ctx );
      int demoted_err = fd_failover_demoted_load( dir, &ctx->demoted_record );
      restore_records( ctx, role_err, demoted_err, UINT_MAX, UINT_MAX );
      FD_TEST( ctx->state==FD_FAILOVER_STATE_STANDBY && ctx->demoted_valid );
      FD_TEST( ctx->send_demoted==(sources[ i ]==FD_FAILOVER_DEMOTED_SOURCE_LOCAL) );
      FD_TEST( ctx->demoted_historical==(sources[ i ]==FD_FAILOVER_DEMOTED_SOURCE_UNKNOWN) );
      if( sources[ i ]==FD_FAILOVER_DEMOTED_SOURCE_PEER ) FD_TEST( ctx->demoted_accept_term==7UL );
      /* Maintenance must not change the durable source. */
      ctx->paused = !ctx->paused;
      persist( ctx, ctx->state, ctx->hello.term );
    }
    demoted_remove( ctx );
    FD_TEST( !close( ctx->role_file_fd ) && !close( ctx->role_dir_fd ) );
  }
  FD_LOG_NOTICE(( "pass: outgoing, received, and ambiguous records survive repeated boot and maintenance" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  stem_init();
  test_restart_confirmation();
  test_pool_layout();
  test_listen_fd();
  test_footprint();
  test_slot_done_bookkeeping();
  test_status_snapshot();
  test_status_metrics();
  test_bus_request();
  test_switch_request();
  test_before_frag_admits();
  FD_TEST( mkdtemp( ctl_dir ) );
  test_first_use_boot_guard();
  test_first_use_exchange();
  test_first_use_refusals();
  test_demoted_payload();
  test_final_tower_regression();
  test_promote_refuses_rollback();
  test_pause_stops_pending_promotion();
  test_pause_resume_coalesce();
  test_demotion_order();
  test_promotion_reject();
  test_switch_overdue();
  test_demotion_drain();
  test_switch_response_integrity();
  test_active_handoff_checks();
  test_operator_commands();
  test_bus_control_ordering();
  test_handoff_response();
  test_handoff_request_lifetime();
  test_promote_evidence();
  test_repeated_handoff_tower();
  test_record_sources();
  test_hello_refresh();
  test_deadline_arms_late();
  test_promotion_refused_term();
  test_late_promote_ack();
  test_promotion_outcome_resent();
  test_promotion_outcome_owed();

  ulong  page_cnt = 2UL;
  ulong  numa_idx = fd_shmem_numa_idx( 0UL );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "gigantic" ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );
  test_consensus_producer( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
