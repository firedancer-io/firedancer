#include "../failover/fd_failover_channel.c"
#include "fd_admin_tile.c"

static fd_admin_tile_ctx_t ctx;
static fd_admin_tile_ctx_t saved;
static uchar ctl_mem[ 2048 ] __attribute__((aligned(FD_ADMINCTL_ALIGN)));
static uchar channel_mem[ 8UL<<20 ] __attribute__((aligned(128)));
static ulong metrics[ FD_METRICS_TOTAL_SZ/sizeof(ulong) ];

static ulong
request( ulong cmd, void const * data, ulong sz, void ** payload ) {
  ulong max;
  ulong idx = fd_adminctl_reserve( ctx.adminctl, payload, &max );
  FD_TEST( idx!=ULONG_MAX && sz<=max );
  fd_memcpy( *payload, data, sz );
  fd_adminctl_publish( ctx.adminctl, idx, cmd, sz );
  for( ulong i=0UL; i<FD_ADMINCTL_SLOT_CNT; i++ ) {
    ulong got_idx;
    ulong got_sz;
    ulong got_cmd = fd_adminctl_poll( ctx.adminctl, &got_idx, payload, &got_sz );
    if( got_cmd==FD_ADMINCTL_CMD_IDLE ) continue;
    FD_TEST( got_cmd==cmd && got_idx==idx && got_sz==sz );
    return idx;
  }
  FD_LOG_ERR(( "command was not polled" ));
}

static void
test_identity_guard( void ) {
  fd_adminctl_set_identity_t req = { .version=FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION, .keypair={1} };
  fd_ed25519_public_from_private( req.keypair+32UL, req.keypair, ctx.sha512 );
  for( uint flags=1U; flags<4U; flags++ ) {
    ctx.failover_enabled   = !!(flags & 1U);
    ctx.tower_file_enabled = !!(flags & 2U);
    void * payload;
    ulong idx = request( FD_ADMINCTL_CMD_SET_IDENTITY, &req, sizeof(req), &payload );
    saved = ctx;
    /* A valid key must be refused before any topology or keyswitch
       access.  The context intentionally has no topology attached. */
    set_identity( &ctx, idx, payload, sizeof(req) );
    FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_UNSUPPORTED );
    FD_TEST( !memcmp( &ctx, &saved, sizeof(ctx) ) );
    for( ulong i=0UL; i<sizeof(req); i++ ) FD_TEST( !((uchar *)payload)[i] );
  }
  ctx.failover_enabled = ctx.tower_file_enabled = 0;
  req.keypair[32] ^= 1U;
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_SET_IDENTITY, &req, sizeof(req), &payload );
  set_identity( &ctx, idx, payload, sizeof(req) );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH );
  FD_LOG_NOTICE(( "pass: failover and tower-file identity guards, ordinary key validation" ));
}

static void
test_status_abi( void ) {
  ulong versions[] = { 1UL, FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION, ULONG_MAX };
  ulong sizes[] = { 0UL, 7UL, 8UL, 9UL, FD_ADMINCTL_PAYLOAD_MAX };
  for( ulong v=0UL; v<sizeof(versions)/sizeof(versions[0]); v++ ) {
    for( ulong s=0UL; s<sizeof(sizes)/sizeof(sizes[0]); s++ ) {
      uchar data[ FD_ADMINCTL_PAYLOAD_MAX ] = {0};
      FD_STORE( ulong, data, versions[v] );
      void * payload;
      ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_STATUS, data, sizes[s], &payload );
      failover_status( &ctx, idx, payload, sizes[s] );
      fd_adminctl_failover_status_resp_t resp;
      fd_memset( &resp, 0xA5, sizeof(resp) );
      ulong out_sz;
      ulong result = fd_adminctl_wait_response( ctx.adminctl, idx, &resp, sizeof(resp), &out_sz );
      ulong expected = sizes[s]<8UL ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH
                     : versions[v]!=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION ? FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH
                     : sizes[s]!=8UL ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH
                     : FD_ADMINCTL_RESULT_SUCCESS;
      FD_TEST( result==expected );
      if( expected ) { FD_TEST( !out_sz ); continue; }
      FD_TEST( out_sz==sizeof(resp) && resp.version==FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION );
      FD_TEST( !resp.enabled && !resp.pending_handshakes && !resp.connection_attempts );
      FD_TEST( !resp.tls_failures && !resp.sessions_paired && !resp.admission_drops && !resp.handshake_timeouts );
      FD_TEST( resp.peer_status_age_nanos==ULONG_MAX && resp.replication_lag_slots==ULONG_MAX );
      FD_TEST( !resp.reserved0 );
      for( ulong i=0UL; i<sizeof(resp.reserved1); i++ ) FD_TEST( !resp.reserved1[i] );
    }
  }
  FD_LOG_NOTICE(( "pass: failover status ABI rejects old versions and malformed sizes" ));
}

static void
test_status_metrics( void ) {
  FD_TEST( fd_failover_channel_footprint()<=sizeof(channel_mem) );
  ctx.failover = fd_failover_channel_join( fd_failover_channel_new( channel_mem ) );
  FD_TEST( ctx.failover );
  ctx.failover_enabled = 1;
  ctx.failover_role = FD_FAILOVER_ROLE_ACTIVE;
  ctx.failover->metrics = (fd_failover_channel_metrics_t){
    .connection_attempt_cnt=11UL, .paired_cnt=2UL, .frames_sent=13UL, .frames_received=17UL,
    .tls_fail_cnt=19UL, .admission_drop_cnt=23UL, .handshake_timeout_cnt=29UL,
    .wire_fatal_cnt=31UL, .hello_reject_cnt=37UL
  };
  /* Synthetic descriptors are inspected only, never passed to I/O. */
  ctx.failover->candidates[0].fd = INT_MAX;
  ctx.failover->candidates[1].fd = INT_MAX;
  ctx.failover->candidates[2].fd = INT_MAX;
  ctx.failover->active = 1;
  fd_adminctl_failover_status_req_t req = { .version=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION };
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_STATUS, &req, sizeof(req), &payload );
  failover_status( &ctx, idx, payload, sizeof(req) );
  fd_adminctl_failover_status_resp_t resp;
  ulong sz;
  FD_TEST( !fd_adminctl_wait_response( ctx.adminctl, idx, &resp, sizeof(resp), &sz ) );
  FD_TEST( sz==sizeof(resp) && resp.enabled );
  FD_TEST( resp.connection_attempts==11UL && resp.sessions_paired==2UL && resp.pending_handshakes==2UL );
  FD_TEST( resp.frames_sent==13UL && resp.frames_received==17UL && resp.tls_failures==19UL );
  FD_TEST( resp.admission_drops==23UL && resp.handshake_timeouts==29UL );
  FD_TEST( resp.wire_failures==31UL && resp.hello_rejections==37UL );
  fd_metrics_tl = metrics;
  metrics_write( &ctx );
  FD_TEST( FD_MCNT_GET( ADMIN, FAILOVER_CONNECTION_ATTEMPTS )==resp.connection_attempts );
  FD_TEST( FD_MCNT_GET( ADMIN, FAILOVER_SESSIONS_PAIRED )==resp.sessions_paired );
  FD_TEST( FD_MGAUGE_GET( ADMIN, FAILOVER_PENDING_HANDSHAKES )==resp.pending_handshakes );
  FD_TEST( FD_MCNT_GET( ADMIN, FAILOVER_TLS_FAILURES )==resp.tls_failures );
  FD_TEST( FD_MCNT_GET( ADMIN, FAILOVER_ADMISSION_DROPS )==resp.admission_drops );
  FD_TEST( FD_MCNT_GET( ADMIN, FAILOVER_HANDSHAKE_TIMEOUTS )==resp.handshake_timeouts );
  ctx.failover_enabled = 0;
  fd_memset( metrics, 0, sizeof(metrics) );
  metrics_write( &ctx );
  FD_TEST( !FD_MGAUGE_GET( ADMIN, FAILOVER_ENABLED ) );
  FD_TEST( !FD_MCNT_GET( ADMIN, FAILOVER_TLS_FAILURES ) );
  FD_TEST( !FD_MGAUGE_GET( ADMIN, FAILOVER_PENDING_HANDSHAKES ) );
  fd_metrics_tl = NULL;
  FD_LOG_NOTICE(( "pass: adminctl and metrics expose the same TLS admission counters" ));
}

static void
test_slot_done_bookkeeping( void ) {
  /* Replay can complete a fork block below the last vote after that
     vote.  The reported replay slot must not fall below it, or the
     peer rejects the STATUS and drops the session. */
  ctx.failover_enabled        = 1;
  ctx.failover_role           = FD_FAILOVER_ROLE_STANDBY;
  ctx.failover_replay_slot    = FD_FAILOVER_SLOT_NULL;
  ctx.failover_root_slot      = FD_FAILOVER_SLOT_NULL;
  ctx.failover_last_vote_slot = FD_FAILOVER_SLOT_NULL;
  fd_tower_slot_done_t done = { .replay_slot=101UL, .root_slot=90UL, .vote_slot=101UL, .has_vote_txn=1 };
  failover_consume_slot_done( &ctx, &done );
  FD_TEST( ctx.failover_replay_slot==101UL && ctx.failover_root_slot==90UL && ctx.failover_last_vote_slot==101UL );
  done = (fd_tower_slot_done_t){ .replay_slot=100UL, .root_slot=FD_FAILOVER_SLOT_NULL, .vote_slot=FD_FAILOVER_SLOT_NULL, .has_vote_txn=0 };
  failover_consume_slot_done( &ctx, &done );
  FD_TEST( ctx.failover_replay_slot==101UL && ctx.failover_root_slot==90UL && ctx.failover_last_vote_slot==101UL );
  done = (fd_tower_slot_done_t){ .replay_slot=102UL, .root_slot=91UL, .vote_slot=FD_FAILOVER_SLOT_NULL, .has_vote_txn=0 };
  failover_consume_slot_done( &ctx, &done );
  FD_TEST( ctx.failover_replay_slot==102UL && ctx.failover_root_slot==91UL );
  fd_failover_status_t local = failover_local_status( &ctx );
  fd_failover_hello_t peer = { .role=(uchar)ctx.failover_role, .term=ctx.failover_hello.term };
  fd_failover_status_t decoded;
  FD_TEST( fd_failover_status_decode( &decoded, &peer, ULONG_MAX, (uchar const *)&local, sizeof(local) ) );
  FD_TEST( decoded.replay_slot==102UL && decoded.last_vote_slot==101UL && decoded.root_slot==91UL );
  ctx.failover_enabled = 0;
  FD_LOG_NOTICE(( "pass: replay slot never regresses below the last vote in STATUS" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_adminctl_footprint()<=sizeof(ctl_mem) );
  ctx.adminctl = fd_adminctl_join( fd_adminctl_new( ctl_mem ) );
  FD_TEST( ctx.adminctl );
  fd_sha512_join( fd_sha512_new( ctx.sha512 ) );
  test_identity_guard();
  test_status_abi();
  test_status_metrics();
  test_slot_done_bookkeeping();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
