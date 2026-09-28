/* Coverage retained from the persistent MVP 0 controller tests.  The
   request now starts on the standby; the local safety rules still hold. */

static ulong
pending_handoff_result( fd_failover_tile_ctx_t const * ctx,
                        ulong                        id ) {
  fd_failover_handoff_result_t result;
  FD_TEST( ctx->pending_valid && ctx->pending_type==FD_FAILOVER_MSG_HANDOFF_RESULT );
  FD_TEST( fd_failover_handoff_result_decode( &result, ctx->pending, ctx->pending_sz ) );
  FD_TEST( result.handoff_id==id );
  return result.result;
}

static void
test_request_guards( void ) {
  for( ulong variant=0UL; variant<8UL; variant++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
    pair( ctx, 77UL, variant==3UL ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY, 1000L );
    if( variant ) make_tower( &ctx->cs, 99UL );
    if( variant==1UL ) ctx->tower_gap = 1;
    if( variant==2UL ) ctx->last_vote_slot = 100UL;
    if( variant==4UL ) set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
    if( variant==5UL ) ctx->action = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
    if( variant==6UL ) ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_JUNK;
    if( variant==7UL ) ctx->close_after_send = 1;
    ulong role = ctx->role;
    ulong action = ctx->action;
    ulong key = ctx->switch_pending_key;
    request_from_peer( ctx, 42UL );
    ulong want = variant<3UL ? FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER :
                 variant<5UL ? FD_FAILOVER_CONTROL_RESULT_BAD_ROLE : FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
    FD_TEST( pending_handoff_result( ctx, 42UL )==want );
    FD_TEST( ctx->role==role && ctx->action==action && ctx->switch_pending_key==key );
    FD_TEST( !ctx->handoff_id && !ctx->send_demoted && !ctx->switch_request_id );
    controller_fini( ctx );
  }
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 99UL );
  fd_failover_handoff_request_t request = { .handoff_id=42UL, .target_boot_id=OUR_BOOT_ID+1UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &request, sizeof(request) );
  FD_TEST( pending_handoff_result( ctx, 42UL )==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->handoff_id );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: an unready active refuses REQUEST without giving up its identity" ));
}

static void
test_command_clears_stuck( void ) {
  fd_adminctl_failover_status_resp_t status;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_INVALID, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  status_snapshot( ctx, 2000L, &status );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && status.stuck );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL, 2000L )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  status_snapshot( ctx, 2000L, &status );
  FD_TEST( !ctx->stuck && !status.stuck );
  controller_fini( ctx );

  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  start_demotion( ctx, 0 );
  step_controller( ctx, stem );
  ctx->replay_slot = ctx->deadline_slot+1UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->stuck && ctx->switch_overdue );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL, 2000L )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  FD_TEST( ctx->stuck && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a new command clears a finished failure, never an unknown switch" ));
}

static void
test_dedup_in_progress( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( !ctx->pending_valid && !ctx->adopt_expected_id );
  step_controller( ctx, stem );
  ulong asked = ctx->adopt_expected_id;
  FD_TEST( asked && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( !ctx->pending_valid && ctx->adopt_expected_id==asked );
  unpair( ctx );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( !ctx->pending_valid && !ctx->reply_valid && ctx->promote_boot_id==77UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_expected_id==asked );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && pending_ack( ctx )==42UL );
  FD_TEST( ctx->reply_boot_id==77UL && ctx->adopt_expected_id==asked );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: duplicate and replacement-boot final state cannot adopt or switch twice" ));
}

static fd_failover_tile_ctx_t *
stored_tower_ctx( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ctx->replay_slot = 120UL;
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 42UL, OUR_BOOT_ID, 110UL ) );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_UNREPLAYED, 90UL );
  step_controller( ctx, stem );
  ctx->replay_slot = 1000UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->peer_tower.valid );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED );
  fd_failover_handoff_result_t result = { .handoff_id=42UL, .result=FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_RESULT, &result, sizeof(result) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->peer_tower.tip==110UL && !ctx->request_id );
  unpair( ctx );
  return ctx;
}

static void
test_stored_tower( void ) {
  long now = fd_failover_clock();
  fd_failover_tile_ctx_t * ctx = stored_tower_ctx();
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, now );
  FD_TEST( ctx->peer_tower.valid );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_PEER && !ctx->promote_peer && ctx->adopt.tip==110UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && pub_mcache[0].sz==ctx->peer_tower.sz );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 110UL );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && !ctx->peer_tower.valid && !ctx->pending_valid );
  controller_fini( ctx );

  ctx = stored_tower_ctx();
  ctx->root_slot = 110UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
  controller_fini( ctx );
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->own_tower, 99UL );
  ctx->root_slot = 99UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a failed handoff retains its final tower for recovery only above the root" ));
}

static void
test_demoted_refusals( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  for( ulong variant=0UL; variant<3UL; variant++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( variant ? FD_FAILOVER_ROLE_STANDBY : FD_FAILOVER_ROLE_ACTIVE );
    pair_demoter( ctx, 77UL, 1000L );
    if( variant==1UL ) ctx->action = FD_FAILOVER_ACTION_DEMOTE_SWITCH;
    if( variant==2UL ) ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_JUNK;
    ulong action = ctx->action;
    ulong key = ctx->switch_pending_key;
    deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
    fd_failover_promote_rejected_t rejected = pending_rejected( ctx );
    FD_TEST( rejected.handoff_id==42UL );
    FD_TEST( rejected.reason==(variant ? FD_FAILOVER_REJECT_BUSY : FD_FAILOVER_REJECT_HOLDS_IDENTITY) );
    FD_TEST( ctx->action==action && ctx->switch_pending_key==key && !ctx->peer_tower.valid && !ctx->promote_peer );
    controller_fini( ctx );
  }
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  sz = demoted_payload( payload, 42UL, OUR_BOOT_ID+1UL, 99UL );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( ctx->channel->metrics.wire_fatal_cnt==1UL && !ctx->peer_tower.valid );
  FD_TEST( ctx->request_id==42UL && ctx->request_boot_id==77UL && !ctx->reply_valid );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a bound DEMOTED cannot bypass role, busy, switch or target-boot checks" ));
}

static void
test_floor_wait_retry( void ) {
  ulong yes = FD_ADMINCTL_FAILOVER_FLAG_YES;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->peer_floor = 150UL;
  ctx->replay_slot = 200UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  FD_TEST( ctx->deadline_slot==150UL+FD_FAILOVER_FLOOR_SLACK_SLOTS+FD_FAILOVER_DEADLINE_SLOTS );
  ulong asked = ctx->adopt_expected_id;
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_retry && ctx->floor_logged && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id==asked );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id!=asked );
  asked = ctx->adopt_expected_id;
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 145UL );
  step_controller( ctx, stem );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id!=asked );
  asked = ctx->adopt_expected_id;
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 145UL );
  step_controller( ctx, stem );
  for( ulong i=0UL; i<8UL; i++ ) { ctx->replay_slot++; step_controller( ctx, stem ); }
  FD_TEST( ctx->adopt_expected_id==asked && ctx->adopt_retry && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  ctx->replay_slot = 150UL+FD_FAILOVER_FLOOR_SLACK_SLOTS;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id==asked );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id!=asked );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 145UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  controller_fini( ctx );

  /* The account's vote counts even after our root discarded that vote. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->own_floor = 160UL;
  ctx->root_slot = 180UL;
  ctx->replay_slot = 200UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 160UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL );
  controller_fini( ctx );

  /* A final tower cannot acquire missing votes just by retrying it. */
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ctx->own_floor = 150UL;
  ctx->replay_slot = 200UL;
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 42UL, OUR_BOOT_ID, 140UL ) );
  step_controller( ctx, stem );
  asked = ctx->adopt_expected_id;
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 140UL );
  step_controller( ctx, stem );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_retry && ctx->adopt_expected_id==asked && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  ctx->replay_slot = 200UL+FD_FAILOVER_DEADLINE_SLOTS+1UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->adopt_expected_id==asked );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: floor retries track changed account votes, exact slack and fixed final-state deadlines" ));
}

static void
test_promote_force_retained( void ) {
  long now = fd_failover_clock();
  ulong yes = FD_ADMINCTL_FAILOVER_FLAG_YES;
  ulong force = FD_ADMINCTL_FAILOVER_FLAG_FORCE;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, now );
  ctx->taken = 1;
  ctx->taken_boot_id = 77UL;
  ctx->staked_seen_at = now;
  ctx->peer_floor = 150UL;
  ctx->replay_slot = 200UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, force, now )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_retry );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  ctx->staked_seen_at = now+1L;
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 150UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->promote_force );
  controller_fini( ctx );

  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  make_tower( &ctx->cs, 99UL );
  demote_through( ctx, 1 );
  ulong id = pending_demoted( ctx ).handoff_id;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, force, now )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && ctx->send_demoted && ctx->pending_valid );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && !ctx->own_tower.valid && !ctx->peer_tower.valid );
  FD_TEST( !ctx->pending_valid && !ctx->send_demoted && ctx->handoff_result==FD_FAILOVER_HANDOFF_CANCELLED );
  deliver_ack( ctx, id );
  FD_TEST( ctx->handoff_result==FD_FAILOVER_HANDOFF_CANCELLED && !ctx->taken );
  controller_fini( ctx );

  /* Force belongs to one promotion, never to the next handoff. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_INVALID, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->promote_force );
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  pair_demoter( ctx, 77UL, now );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL ) );
  FD_TEST( ctx->promote_peer && !ctx->promote_force );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: force cancels only network waits and never bypasses floor, adoption or later operations" ));
}

static void
test_status_snapshot_retained( void ) {
  long now = fd_failover_clock();
  fd_adminctl_failover_status_resp_t status;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->port = (ushort)8010;
  status_snapshot( ctx, now, &status );
  FD_TEST( status.version==FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION && status.enabled );
  FD_TEST( status.role==FD_FAILOVER_ROLE_STANDBY && status.action==FD_FAILOVER_ACTION_IDLE && !status.stuck );
  FD_TEST( !status.peer_role_valid && !status.peer_boot_id && !status.peer_addr && status.peer_port==8010 );
  FD_TEST( !status.handoff_id && status.handoff_result==FD_FAILOVER_HANDOFF_NONE );
  FD_TEST( status.promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && status.promote_floor==FD_FAILOVER_SLOT_NULL );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  make_tower( &ctx->own_tower, 99UL );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.promote_source==FD_FAILOVER_SOURCE_OWN && status.promote_result==FD_ADMINCTL_RESULT_SUCCESS );
  fd_memcpy( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL );
  ctx->gossip_socket.addr = FD_IP4_ADDR(10,0,0,9);
  ctx->gossip_socket.port = ctx->own_gossip.port;
  gossip_commit( ctx, now );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,9) && !status.peer_addr_cfg );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN );
  ctx->config_addr = FD_IP4_ADDR(10,0,0,5);
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_addr==ctx->config_addr && status.peer_addr_cfg );
  ctx->staked_seen_at = 0L;
  pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, now );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_role_valid && status.peer_role==FD_FAILOVER_ROLE_ACTIVE && status.peer_boot_id==77UL );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE );
  ctx->own_floor = 170UL;
  status_snapshot( ctx, now, &status );
  FD_TEST( status.promote_floor==170UL && status.promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
  unpair( ctx );
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
  ctx->stuck = 1;
  status_snapshot( ctx, now, &status );
  FD_TEST( status.action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && status.stuck && !status.peer_role_valid );
  FD_TEST( status.peer_boot_id==77UL && status.promote_result==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  controller_fini( ctx );

  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  make_tower( &ctx->cs, 99UL );
  demote_through( ctx, 1 );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.role==FD_FAILOVER_ROLE_STANDBY && status.action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  FD_TEST( status.handoff_id==5001UL && status.handoff_result==FD_FAILOVER_HANDOFF_PENDING );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING );
  deliver_ack( ctx, 5001UL );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.action==FD_FAILOVER_ACTION_IDLE && status.handoff_result==FD_FAILOVER_HANDOFF_TAKEN );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: operator status preserves address, boot, floor, source and handoff outcomes" ));
}

static void
test_holder_recheck( void ) {
  long now = fd_failover_clock();
  /* A promotion can start before another member authenticates.  Its
     ACTIVE HELLO must still stop us before the staked switch. */
  for( int force=0; force<2; force++ ) for( int drop=0; drop<2; drop++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    ulong flags = FD_ADMINCTL_FAILOVER_FLAG_YES | (force ? FD_ADMINCTL_FAILOVER_FLAG_FORCE : 0UL);
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, flags, now )==FD_ADMINCTL_RESULT_SUCCESS );
    step_controller( ctx, stem );
    ctx->channel->state = FD_FAILOVER_SESSION_PAIRED;
    ctx->channel->peer_hello.boot_id = 77UL;
    ctx->channel->peer_hello.role = FD_FAILOVER_ROLE_ACTIVE;
    sync_session( ctx );
    if( drop ) unpair( ctx );
    acct_answer( ctx, FD_FAILOVER_SLOT_NULL, FD_FAILOVER_SLOT_NULL );
    step_controller( ctx, stem );
    FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY );
    FD_TEST( ctx->action==(force ? FD_FAILOVER_ACTION_PROMOTE_SWITCH : FD_FAILOVER_ACTION_IDLE) );
    FD_TEST( ctx->switch_pending_key==(force ? FD_FAILOVER_SWITCH_KEY_STAKED : FD_FAILOVER_SWITCH_KEY_CNT) );
    FD_TEST( force || ctx->stuck );
    controller_fini( ctx );
  }
  /* A requested handoff carries positive demotion.  Its original
     ACTIVE HELLO and old gossip are superseded by the bound DEMOTED. */
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, now );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL ) );
  step_controller( ctx, stem );
  ctx->staked_seen_at = now+1L;
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  controller_fini( ctx );

  /* A later ACTIVE HELLO is not the demoter's old role.  Retain that
     evidence even if the new session disappears before adoption. */
  for( int drop=0; drop<2; drop++ ) {
    ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    pair_demoter( ctx, 77UL, now );
    deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL ) );
    step_controller( ctx, stem );
    unpair( ctx );
    pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, now+1L );
    if( drop ) unpair( ctx );
    adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
    step_controller( ctx, stem );
    FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
    FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT && ctx->stuck );
    FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: operator promotion rechecks an ACTIVE HELLO; final demotion supersedes the handoff's old HELLO" ));
}

static void
test_status_peer_evidence( void ) {
  long now = fd_failover_clock();
  fd_adminctl_failover_status_resp_t status;
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, now );
  ulong sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_role_valid && status.peer_role==FD_FAILOVER_ROLE_STANDBY );
  step_controller( ctx, stem );
  unpair( ctx );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, now );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_role_valid && status.peer_role==FD_FAILOVER_ROLE_ACTIVE );
  /* Repeated final state belongs to the earlier demotion and cannot
     replace a newer authenticated role while adoption is in progress. */
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_role_valid && status.peer_role==FD_FAILOVER_ROLE_ACTIVE );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.stuck && status.action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
  FD_TEST( status.peer_role_valid && status.peer_role==FD_FAILOVER_ROLE_ACTIVE );
  unpair( ctx );
  status_snapshot( ctx, now, &status );
  FD_TEST( !status.peer_role_valid && status.peer_boot_id==77UL );
  controller_fini( ctx );

  /* TAKEN is a durable recovery guard, not the role of a later boot. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->taken = 1;
  ctx->taken_boot_id = 77UL;
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, now );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_role_valid && status.peer_role==FD_FAILOVER_ROLE_STANDBY && status.peer_boot_id==78UL );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: status follows authenticated peer evidence without weakening the retained holder guard" ));
}

static void
test_gossip_request_address( void ) {
  for( ulong role=0UL; role<2UL; role++ ) for( int configured=0; configured<2; configured++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( role );
    ctx->config_addr = configured ? FD_IP4_ADDR(10,0,0,5) : 0U;
    ctx->port = (ushort)8010;
    fd_memcpy( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL );
    ctx->gossip_socket = ctx->own_gossip;
    gossip_commit( ctx, 1000L );
    FD_TEST( !ctx->staked_addr && !ctx->staked_seen_at );
    /* Our IP at a different gossip port is another member. */
    ctx->gossip_socket.port++;
    gossip_commit( ctx, 1001L );
    FD_TEST( ctx->staked_seen_at==1001L );
    FD_TEST( ctx->staked_addr==(configured ? 0U : OWN_GOSSIP_ADDR) );
    ctx->gossip_socket.addr = FD_IP4_ADDR(10,0,0,9);
    gossip_commit( ctx, 1002L );
    gossip_commit( ctx, 1003L );
    FD_TEST( ctx->staked_seen_at==1003L );
    FD_TEST( ctx->staked_addr==(configured ? 0U : FD_IP4_ADDR(10,0,0,9)) );
    ctx->gossip_socket.addr = 0U;
    gossip_commit( ctx, 1004L );
    FD_TEST( ctx->staked_seen_at==1003L && !ctx->channel->peer_addr && !ctx->channel->dial_peer );
    set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
    FD_TEST( !ctx->channel->peer_addr && !ctx->channel->dial_peer );
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, 1005L )==FD_ADMINCTL_RESULT_SUCCESS );
    uint target = configured ? ctx->config_addr : ctx->staked_addr;
    FD_TEST( ctx->request_addr==target && ctx->channel->peer_addr==target && ctx->channel->dial_peer );
    FD_TEST( ctx->channel->peer_port==ctx->port );
    ctx->gossip_socket.addr = FD_IP4_ADDR(10,0,0,7);
    gossip_commit( ctx, 1006L );
    FD_TEST( ctx->request_addr==target && ctx->channel->peer_addr==target );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: gossip caches without dialing, config wins, and an open request keeps its target" ));
}

static void
test_preserved( void ) {
  test_gossip_request_address();
  test_request_guards();
  test_command_clears_stuck();
  test_dedup_in_progress();
  test_stored_tower();
  test_demoted_refusals();
  test_floor_wait_retry();
  test_promote_force_retained();
  test_status_snapshot_retained();
  test_holder_recheck();
  test_status_peer_evidence();
}
