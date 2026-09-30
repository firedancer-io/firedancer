/* Coverage retained from the persistent controller tests.  The
   request now starts on the standby, the local safety rules still hold. */

static ulong
pending_handoff_result( fd_failover_tile_ctx_t const * ctx,
                        ulong                        id ) {
  fd_failover_handoff_result_t result;
  FD_TEST( ctx->tx.valid && ctx->tx.type==FD_FAILOVER_MSG_HANDOFF_RESULT );
  FD_TEST( fd_failover_handoff_result_decode( &result, ctx->tx.payload, ctx->tx.sz ) );
  FD_TEST( result.handoff_id==id );
  return result.result;
}

static void
test_request_guards( void ) {
  for( ulong variant=0UL; variant<8UL; variant++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
    pair( ctx, 77UL, variant==3UL ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY, 1000L );
    if( variant ) make_tower( &ctx->current_tower, 99UL );
    if( variant==1UL ) ctx->tower_gap = 1;
    if( variant==2UL ) ctx->last_vote_slot = 100UL;
    if( variant==4UL ) set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
    if( variant==5UL ) ctx->action = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
    if( variant==6UL ) ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_JUNK;
    if( variant==7UL ) ctx->session.close_after_send = 1;
    ulong role = ctx->role;
    ulong action = ctx->action;
    ulong key = ctx->id_switch.pending_key;
    request_from_peer( ctx, 42UL );
    ulong want = variant<3UL ? FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER :
                 variant<5UL ? FD_FAILOVER_CONTROL_RESULT_BAD_ROLE : FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
    FD_TEST( pending_handoff_result( ctx, 42UL )==want );
    FD_TEST( ctx->role==role && ctx->action==action && ctx->id_switch.pending_key==key );
    FD_TEST( !ctx->handoff.id && ctx->handoff.delivery==FD_FAILOVER_DELIVERY_NONE && !ctx->id_switch.request_id );
    controller_fini( ctx );
  }
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->current_tower, 99UL );
  fd_failover_handoff_request_t request = { .handoff_id=42UL, .target_boot_id=OUR_BOOT_ID+1UL, .replay_slot=99UL };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &request, sizeof(request) );
  FD_TEST( pending_handoff_result( ctx, 42UL )==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->handoff.id );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: an unready active refuses REQUEST without giving up its identity" ));
}

static void
test_command_clears_stuck( void ) {
  fd_adminctl_failover_status_resp_t status;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_INVALID, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->promotion.empty && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_INVALID, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  status_snapshot( ctx, 2000L, &status );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && status.stuck );
  /* A refused command leaves the failure standing, an accepted one
     clears it. */
#ifdef FD_ADMINCTL_FAILOVER_CMD_DEMOTE
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL, 2000L )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  status_snapshot( ctx, 2000L, &status );
  FD_TEST( ctx->stuck && status.stuck );
#endif
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE, 2000L )==FD_ADMINCTL_RESULT_SUCCESS );
  status_snapshot( ctx, 2000L, &status );
  FD_TEST( !ctx->stuck && !status.stuck );
  controller_fini( ctx );

#ifdef FD_ADMINCTL_FAILOVER_CMD_DEMOTE
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  begin_demotion( ctx, 0 );
  step_controller( ctx, stem );
  ctx->replay_slot = ctx->deadline_slot+1UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->stuck && ctx->id_switch.overdue );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL, 2000L )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  FD_TEST( ctx->stuck && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  controller_fini( ctx );
#endif
  FD_LOG_NOTICE(( "pass: an accepted command clears a finished failure, never an unknown switch" ));
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
  FD_TEST( !ctx->tx.valid && !ctx->promotion.adopt_id );
  step_controller( ctx, stem );
  ulong asked = ctx->promotion.adopt_id;
  FD_TEST( asked && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( !ctx->tx.valid && ctx->promotion.adopt_id==asked );
  unpair( ctx );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( !ctx->tx.valid && ctx->reply.state==FD_FAILOVER_REPLY_NONE && ctx->promotion.peer.boot_id==77UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->promotion.adopt_id==asked );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && pending_ack( ctx )==42UL );
  FD_TEST( ctx->reply.peer.boot_id==77UL && ctx->promotion.adopt_id==asked );
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
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && !ctx->peer_tower.valid );
  FD_TEST( ctx->promotion.adopt.valid && ctx->promotion.adopt.tip==110UL && ctx->peer_floor==110UL );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED );
  fd_failover_handoff_result_t result = { .handoff_id=42UL, .result=FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_RESULT, &result, sizeof(result) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->peer_tower.valid && !ctx->request.id );
  unpair( ctx );
  return ctx;
}

static void
test_stored_tower( void ) {
  long now = fd_failover_clock();
  fd_failover_tile_ctx_t * ctx = stored_tower_ctx();
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, now );
  FD_TEST( !ctx->peer_tower.valid && ctx->peer_floor==110UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && !ctx->promotion.from_peer && !ctx->promotion.adopt.sz );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  acct_answer( ctx, 110UL, 110UL );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && !ctx->peer_tower.valid && !ctx->tx.valid );
  controller_fini( ctx );

  ctx = stored_tower_ctx();
  ctx->root_slot = 110UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
  controller_fini( ctx );
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->peer_tower, 99UL );
  ctx->root_slot = 99UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a declined handoff retires saved state, retains coverage, and automatically selects account recovery" ));
}

static void
test_demoted_refusals( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  for( ulong variant=0UL; variant<3UL; variant++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( variant ? FD_FAILOVER_ROLE_STANDBY : FD_FAILOVER_ROLE_ACTIVE );
    pair_demoter( ctx, 77UL, 1000L );
    if( variant==1UL ) ctx->action = FD_FAILOVER_ACTION_DEMOTE_SWITCH;
    if( variant==2UL ) ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_JUNK;
    ulong action = ctx->action;
    ulong key = ctx->id_switch.pending_key;
    deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
    fd_failover_promote_rejected_t rejected = pending_rejected( ctx );
    FD_TEST( rejected.handoff_id==42UL );
    FD_TEST( rejected.reason==(variant ? FD_FAILOVER_REJECT_BUSY : FD_FAILOVER_REJECT_HOLDS_IDENTITY) );
    FD_TEST( ctx->action==action && ctx->id_switch.pending_key==key && !ctx->peer_tower.valid && !ctx->promotion.from_peer );
    controller_fini( ctx );
  }
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ctx->channel->paired_idx = 0;
  sz = demoted_payload( payload, 42UL, OUR_BOOT_ID+1UL, 99UL );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( ctx->channel->state!=FD_FAILOVER_SESSION_PAIRED && !ctx->peer_tower.valid );
  FD_TEST( ctx->request.id==42UL && ctx->request.peer.boot_id==77UL && ctx->reply.state==FD_FAILOVER_REPLY_NONE );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a bound DEMOTED cannot bypass role, busy, switch or target-boot checks" ));
}

static void
test_floor_wait_retry( void ) {
  ulong yes = FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE;
  fd_failover_tile_ctx_t * ctx;
  ulong asked;
  /* An operator with verified peer authority gets an asynchronous
     refusal for incomplete history. FORCE can explicitly take it. */
  for( int force=0; force<2; force++ ) for( int empty=0; empty<2; empty++ ) {
    ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    ctx->peer_floor = 150UL;
    ctx->replay_slot = 200UL;
    start_promotion( ctx, FD_FAILOVER_SOURCE_VOTE_ACCOUNT, NULL, 0UL, 0 );
    ctx->promotion.force = force;
    step_controller( ctx, stem );
    acct_answer( ctx, FD_FAILOVER_SLOT_NULL, empty ? FD_FAILOVER_SLOT_NULL : 140UL );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==(force ? FD_FAILOVER_ACTION_PROMOTE_SWITCH : FD_FAILOVER_ACTION_IDLE) );
    FD_TEST( ctx->stuck==!force && !ctx->promotion.retry );
    FD_TEST( ctx->id_switch.pending_key==(force ? FD_FAILOVER_SWITCH_KEY_STAKED : FD_FAILOVER_SWITCH_KEY_CNT) );
    FD_TEST( ctx->promotion.floor==150UL && ctx->peer_floor==150UL );
    controller_fini( ctx );
  }

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
  asked = ctx->promotion.adopt_id;
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 140UL );
  step_controller( ctx, stem );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->promotion.retry && ctx->promotion.adopt_id==asked && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  ctx->replay_slot = 200UL+FD_FAILOVER_DEADLINE_SLOTS+1UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->promotion.adopt_id==asked );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: incomplete history requires force, rooted account votes cover the floor, and final-state deadlines remain strict" ));
}

static void
test_promote_force_retained( void ) {
  long now = fd_failover_clock();
  ulong yes = FD_ADMINCTL_FAILOVER_FLAG_YES;
  ulong force = FD_ADMINCTL_FAILOVER_FLAG_FORCE;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, now );
  ctx->taken = 1;

  ctx->staked_seen_at = now;
  ctx->peer_floor = 150UL;
  ctx->replay_slot = 200UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->promotion.force );
  controller_fini( ctx );

  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  make_tower( &ctx->current_tower, 99UL );
  demote_through( ctx, 1 );
  ulong id = pending_demoted( ctx ).handoff_id;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE && ctx->tx.valid );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && !ctx->peer_tower.valid );
  FD_TEST( !ctx->tx.valid && ctx->handoff.delivery==FD_FAILOVER_DELIVERY_NONE && ctx->handoff.result==FD_FAILOVER_HANDOFF_CANCELLED );
  deliver_ack( ctx, id );
  FD_TEST( ctx->handoff.result==FD_FAILOVER_HANDOFF_CANCELLED && !ctx->taken );
  controller_fini( ctx );

  /* Force belongs to one promotion, never to the next handoff. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_INVALID, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promotion.empty );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_INVALID, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->promotion.force );
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  pair_demoter( ctx, 77UL, now );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL ) );
  FD_TEST( ctx->promotion.from_peer && !ctx->promotion.force );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: force accepts incomplete history, cancels network waits, and cannot overlap adoption or leak into a handoff" ));
}

static void
test_status_snapshot_retained( void ) {
  long now = fd_failover_clock();
  fd_adminctl_failover_status_resp_t status;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->port = (ushort)8010;
  status_snapshot( ctx, now, &status );
  FD_TEST( status.version==FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION && status.enabled );
  FD_TEST( status.role==FD_FAILOVER_ROLE_STANDBY && status.action==FD_FAILOVER_ACTION_IDLE && !status.stuck );
  FD_TEST( !status.peer_role_valid && !status.peer_boot_id && !status.peer_addr && status.peer_port==8010 );
  FD_TEST( !status.handoff_id && status.handoff_result==FD_FAILOVER_HANDOFF_NONE );
  FD_TEST( status.promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && status.promote_floor==FD_FAILOVER_SLOT_NULL );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
  make_tower( &ctx->peer_tower, 99UL );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.promote_source==FD_FAILOVER_SOURCE_PEER && status.promote_result==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
  fd_memcpy( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL );
  ctx->gossip_socket.addr = FD_IP4_ADDR(10,0,0,9);
  ctx->gossip_socket.port = ctx->own_gossip.port;
  gossip_commit( ctx, now );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,9) && !status.peer_addr_cmd );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN );
  /* The address `failover promote --address` gave shows only while
     its request is open. */
  ctx->cmd_addr = FD_IP4_ADDR(10,0,0,5);
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,9) && !status.peer_addr_cmd );
  ctx->request.id   = 1UL;
  ctx->request.addr = ctx->cmd_addr; /* as the request opened with it */
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_addr==ctx->cmd_addr && status.peer_addr_cmd && status.peer_port==8010 );
  ctx->request.id = 0UL;
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
  make_tower( &ctx->current_tower, 99UL );
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
    if( !force ) {
      FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, flags, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
      /* Preserve the final guard's independent test even though the on-demand
         operator API can no longer enter this unfenced path. */
      start_promotion( ctx, FD_FAILOVER_SOURCE_VOTE_ACCOUNT, NULL, 0UL, 0 );
    } else {
      FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, flags, now )==FD_ADMINCTL_RESULT_SUCCESS );
    }
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
    FD_TEST( ctx->id_switch.pending_key==(force ? FD_FAILOVER_SWITCH_KEY_STAKED : FD_FAILOVER_SWITCH_KEY_CNT) );
    FD_TEST( force || ctx->stuck );
    controller_fini( ctx );
  }
  /* A requested handoff ends in a bound DEMOTED, which supersedes the
     demoter's original ACTIVE HELLO and its old gossip. */
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

  /* A later ACTIVE HELLO is not the demoter's old role.  We remember
     it even if the new session disappears before adoption. */
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
    FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && ctx->stuck );
    FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: operator promotion rechecks an ACTIVE HELLO, final demotion supersedes the handoff's old HELLO" ));
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

  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, now );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_role_valid && status.peer_role==FD_FAILOVER_ROLE_STANDBY && status.peer_boot_id==78UL );
  FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: status follows the authenticated peer without weakening the retained holder guard" ));
}

static void
test_gossip_request_address( void ) {
  for( ulong role=0UL; role<2UL; role++ ) for( int given=0; given<2; given++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( role );
    ctx->port = (ushort)8010;
    fd_memcpy( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL );
    ctx->gossip_socket = ctx->own_gossip;
    gossip_commit( ctx, 1000L );
    FD_TEST( !ctx->staked_addr && !ctx->staked_seen_at );
    /* Our IP at a different gossip port is another member. */
    ctx->gossip_socket.port++;
    gossip_commit( ctx, 1001L );
    FD_TEST( ctx->staked_seen_at==1001L );
    FD_TEST( ctx->staked_addr==OWN_GOSSIP_ADDR );
    ctx->gossip_socket.addr = FD_IP4_ADDR(10,0,0,9);
    gossip_commit( ctx, 1002L );
    gossip_commit( ctx, 1003L );
    FD_TEST( ctx->staked_seen_at==1003L );
    FD_TEST( ctx->staked_addr==FD_IP4_ADDR(10,0,0,9) );
    ctx->gossip_socket.addr = 0U;
    gossip_commit( ctx, 1004L );
    FD_TEST( ctx->staked_seen_at==1003L && !ctx->channel->peer_addr && !ctx->channel->dial_peer );
    set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
    FD_TEST( !ctx->channel->peer_addr && !ctx->channel->dial_peer );
    uint   target      = given ? FD_IP4_ADDR(10,0,0,5) : ctx->staked_addr;
    ushort target_port = given ? (ushort)9010         : ctx->port;
    FD_TEST( handoff_to( ctx, given ? target : 0U, given ? target_port : (ushort)0, 1005L )==FD_ADMINCTL_RESULT_SUCCESS );
    FD_TEST( ctx->request.addr==target && ctx->channel->peer_addr==target && ctx->channel->dial_peer );
    FD_TEST( ctx->channel->peer_port==target_port );
    ctx->gossip_socket.addr = FD_IP4_ADDR(10,0,0,7);
    gossip_commit( ctx, 1006L );
    FD_TEST( ctx->request.addr==target && ctx->channel->peer_addr==target );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: gossip caches without dialing, --address wins, and an open request keeps its target" ));
}

/* A paused request resumes at the address it was given.  A given
   address or port replaces only its own part, also on a request bound
   to a peer, and once the request ends a plain promote goes back to
   gossip. */
static void
test_request_address_resume( void ) {
  long now = 1000L;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->port        = (ushort)8010;
  ctx->staked_addr = FD_IP4_ADDR(10,0,0,9);
  fd_adminctl_failover_status_resp_t status;

  FD_TEST( handoff_to( ctx, FD_IP4_ADDR(10,0,0,5), (ushort)9010, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,5) && ctx->channel->peer_port==9010 );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,5) && status.peer_port==9010 && status.peer_addr_cmd );

  request_pause( ctx, now, "test" );
  FD_TEST( handoff_to( ctx, 0U, 0, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,5) && ctx->channel->peer_addr==FD_IP4_ADDR(10,0,0,5) && ctx->channel->peer_port==9010 );

  request_pause( ctx, now, "test" );
  FD_TEST( handoff_to( ctx, FD_IP4_ADDR(10,0,0,6), 0, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,6) && ctx->channel->peer_addr==FD_IP4_ADDR(10,0,0,6) && ctx->channel->peer_port==9010 );

  ctx->request.peer.boot_id = 77UL;
  request_pause( ctx, now, "test" );
  FD_TEST( handoff_to( ctx, FD_IP4_ADDR(10,0,0,8), (ushort)9020, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,8) && ctx->channel->peer_addr==FD_IP4_ADDR(10,0,0,8) && ctx->channel->peer_port==9020 );
  FD_TEST( ctx->request.peer.boot_id==77UL );

  request_end( ctx, now, 1 );
  FD_TEST( handoff_to( ctx, 0U, 0, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.addr==FD_IP4_ADDR(10,0,0,9) && ctx->channel->peer_port==8010 );
  status_snapshot( ctx, now, &status );
  FD_TEST( status.peer_addr==FD_IP4_ADDR(10,0,0,9) && status.peer_port==8010 && !status.peer_addr_cmd );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a request keeps the address it was given across resumes, a given part replaces its own" ));
}

static void
test_preserved( void ) {
  test_gossip_request_address();
  test_request_address_resume();
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
