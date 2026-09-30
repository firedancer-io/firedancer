/* Exercises the request protocol and the existing controller together. */

static void
request_from_peer( fd_failover_tile_ctx_t * ctx,
                   ulong                    id ) {
  fd_failover_handoff_request_t req = { .handoff_id=id, .target_boot_id=ctx->hello.boot_id };
  deliver( ctx, FD_FAILOVER_MSG_HANDOFF_REQUEST, &req, sizeof(req) );
}

static void
test_request_controls( void ) {
  long now = fd_failover_clock();
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS );
  FD_TEST( !ctx->request.id && !ctx->channel->peer_addr );
  ctx->staked_addr = FD_IP4_ADDR(127,0,0,2);
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, now )==FD_ADMINCTL_RESULT_SUCCESS );
  ulong id = ctx->request.id;
  FD_TEST( id && ctx->channel->peer_addr==ctx->staked_addr && ctx->channel->dial_peer );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER );
  FD_TEST( !ctx->request.peer.boot_id && !ctx->request.send_cnt );
  FD_TEST( strstr( request_wait( ctx ), "no peer authenticated, no handoff request sent" ) );
  fd_adminctl_failover_status_resp_t snap;
  status_snapshot( ctx, now, &snap );
  FD_TEST( snap.handoff_id==id && snap.handoff_result==FD_FAILOVER_HANDOFF_PENDING );
  int busy = 0;
  peer_poll( ctx, ctx->request.until, &busy );
  FD_TEST( ctx->request.id==id && !ctx->request.until && ctx->stuck );
  FD_TEST( !ctx->channel->peer_addr && !ctx->channel->dial_peer );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES, now )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.id==id && ctx->request.until && !ctx->stuck );
  controller_fini( ctx );

  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  ctx->staked_addr = FD_IP4_ADDR(127,0,0,2);
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  FD_TEST( !ctx->channel->peer_addr && !ctx->request.id );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  request_from_peer( ctx, 42UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->role==FD_FAILOVER_ROLE_ACTIVE );
  FD_TEST( ctx->tx.valid && ctx->tx.type==FD_FAILOVER_MSG_HANDOFF_RESULT );
  ctx->tx.valid = 0;
  ctx->session.close_after_send = 0;
  make_tower( &ctx->current_tower, 99UL );
  request_from_peer( ctx, 43UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->handoff.id==43UL );
  step_controller( ctx, stem );
  ulong nonce = ctx->id_switch.request_id;
  request_from_peer( ctx, 43UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->id_switch.request_id==nonce && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && pending_demoted( ctx ).handoff_id==43UL );
  ctx->tx.valid         = 0;
  ctx->handoff.delivery = FD_FAILOVER_DELIVERY_SENT;
  request_from_peer( ctx, 43UL );
  FD_TEST( pending_demoted( ctx ).handoff_id==43UL && ctx->id_switch.request_id==nonce );
  deliver_ack( ctx, 43UL );
  FD_TEST( ctx->taken && ctx->handoff.result==FD_FAILOVER_HANDOFF_TAKEN );
  ctx->tx.valid = 0;
  request_from_peer( ctx, 43UL );
  FD_TEST( ctx->tx.type==FD_FAILOVER_MSG_HANDOFF_RESULT && ctx->id_switch.request_id==nonce );
  FD_TEST( promote_guard( ctx, now, 0 )==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: standby requests, bounded dialing, same-id retry and duplicate request" ));
}

static void
test_request_recovery( void ) {
  long now = fd_failover_clock();
  ulong force = FD_ADMINCTL_FAILOVER_FLAG_FORCE;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->staked_addr = FD_IP4_ADDR(127,0,0,2);
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, now )==FD_ADMINCTL_RESULT_SUCCESS );
  ulong id = ctx->request.id;
  request_pause( ctx, now, "test pause" );
  ctx->staked_addr = FD_IP4_ADDR(127,0,0,3);
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->request.id==id && ctx->request.addr==ctx->staked_addr );
  /* A refused recovery command must not erase the resumable request. */
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  FD_TEST( ctx->request.id==id && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER );
  fd_adminctl_failover_status_resp_t snap;
  status_snapshot( ctx, now, &snap );
  FD_TEST( snap.handoff_id==id && snap.handoff_result==FD_FAILOVER_HANDOFF_PENDING );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, force|FD_ADMINCTL_FAILOVER_FLAG_YES, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( !ctx->request.id && ctx->request.result==FD_FAILOVER_HANDOFF_CANCELLED );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promotion.force );
  status_snapshot( ctx, now, &snap );
  FD_TEST( snap.handoff_id==id && snap.handoff_result==FD_FAILOVER_HANDOFF_CANCELLED );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  status_snapshot( ctx, now, &snap );
  FD_TEST( snap.handoff_id==id && snap.handoff_result==FD_FAILOVER_HANDOFF_CANCELLED );
  acct_answer( ctx, 99UL, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, force, now )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  status_snapshot( ctx, now, &snap );
  FD_TEST( snap.handoff_id==id && snap.handoff_result==FD_FAILOVER_HANDOFF_CANCELLED );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->role==FD_FAILOVER_ROLE_ACTIVE );
  status_snapshot( ctx, now, &snap );
  FD_TEST( snap.handoff_id==id && snap.handoff_result==FD_FAILOVER_HANDOFF_CANCELLED );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL, now )==FD_ADMINCTL_RESULT_SUCCESS );
  status_snapshot( ctx, now, &snap );
  FD_TEST( snap.handoff_id && snap.handoff_id!=id && snap.handoff_result==FD_FAILOVER_HANDOFF_NONE );
  controller_fini( ctx );

  /* Force cannot abandon adoption, or a switch with an unknown result. */
  ulong actions[] = { FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY, FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT,
                      FD_FAILOVER_ACTION_PROMOTE_SWITCH, FD_FAILOVER_ACTION_DEMOTE_SWITCH };
  for( ulong i=0UL; i<sizeof(actions)/sizeof(actions[0]); i++ ) {
    ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    pair_demoter( ctx, 77UL, now );
    ctx->action = actions[i];
    if( i>=2UL ) ctx->id_switch.pending_key = i==2UL ? FD_FAILOVER_SWITCH_KEY_STAKED : FD_FAILOVER_SWITCH_KEY_JUNK;
    ulong key = ctx->id_switch.pending_key;
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, force|FD_ADMINCTL_FAILOVER_FLAG_YES, now )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
    FD_TEST( ctx->request.id==42UL && ctx->action==actions[i] && ctx->id_switch.pending_key==key );
    controller_fini( ctx );
  }

  /* A new active may demote locally while its confirmation is lost. */
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  ctx->request.id = 42UL;
  ctx->request.until = now+FD_FAILOVER_CHANNEL_IDLE_NANOS;
  ctx->action = FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT;
  make_tower( &ctx->current_tower, 99UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( !ctx->request.id && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->handoff.delivery==FD_FAILOVER_DELIVERY_NONE );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: recovery cancels only accepted idle waits, never an unknown switch or adoption" ));
}

static void
test_request_binding( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, 1000L );
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->peer_tower.valid && ctx->reply.state==FD_FAILOVER_REPLY_NONE );
  pair_demoter( ctx, 77UL, 1000L );
  ctx->channel->peer_hello.junk_pubkey[0] ^= 1U;
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER && !ctx->peer_tower.valid );
  ctx->channel->peer_hello.junk_pubkey[0] ^= 1U;
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  /* Even a changed boot during the switch cannot abandon it. */
  ctx->request.sent = 0;
  ctx->request.until = fd_failover_clock()+FD_FAILOVER_CHANNEL_IDLE_NANOS;
  ctx->channel->peer_hello.boot_id++;
  int busy = 0;
  peer_poll( ctx, fd_failover_clock(), &busy );
  FD_TEST( ctx->request.id==42UL && ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, 2000L )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
  FD_TEST( pending_ack( ctx )==42UL );
  ctx->tx.valid = 0;
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 2000L );
  ctx->channel->peer_hello.junk_pubkey[0] ^= 1U;
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( !ctx->tx.valid && ctx->reply.state!=FD_FAILOVER_REPLY_OWED );
  ctx->channel->peer_hello.junk_pubkey[0] ^= 1U;
  deliver( ctx, FD_FAILOVER_MSG_DEMOTED, payload, sz );
  FD_TEST( pending_ack( ctx )==42UL );
  controller_fini( ctx );

  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->current_tower, 99UL );
  demote_through( ctx, 1 );
  ctx->tx.valid = 0;
  unpair( ctx );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, 2000L );
  ctx->channel->peer_hello.junk_pubkey[0] ^= 1U;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && !ctx->taken );
  deliver_ack( ctx, ctx->handoff.id );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && !ctx->taken );
  ctx->channel->peer_hello.junk_pubkey[0] ^= 1U;
  step_controller( ctx, stem );
  FD_TEST( ctx->handoff.result==FD_FAILOVER_HANDOFF_RESTARTED );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: member and boot binding precedes replies and restart resolution" ));
}

static void
test_drain_clock( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->current_tower, 99UL );
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  ctx->handoff.until = fd_failover_clock()-1L;
  step_controller( ctx, stem );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_JUNK && ctx->id_switch.overdue );
  switch_ok( ctx, 800UL );
  ctx->tower_seen_seq = 700UL;
  step_controller( ctx, stem );
  /* The drain gets a whole deadline of its own, the clock bounds it too. */
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN );
  FD_TEST( ctx->handoff.until>fd_failover_clock() );
  ctx->handoff.until = fd_failover_clock()-1L;
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( ctx->stuck && ctx->handoff.delivery==FD_FAILOVER_DELIVERY_NONE );
  FD_TEST( pending_result( ctx ).result==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: frozen replay bounds a known-success drain without abandoning an unknown switch" ));
}

static void
test_socket_handoffs( void ) {
  char dir[ PATH_MAX ];
  char const * tmp = getenv( "TMPDIR" );
  FD_TEST( tmp && fd_cstr_printf_check( dir, sizeof(dir), NULL, "%s/failover-unit.XXXXXX", tmp ) );
  FD_TEST( mkdtemp( dir ) );
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( keys[i], (int)(i+1UL), 32UL );
    fd_ed25519_public_from_private( keys[i]+32UL, keys[i], sha );
    FD_TEST( fd_cstr_printf_check( key_paths[i], PATH_MAX, NULL, "%s/key%lu.json", dir, i ) );
    write_key( key_paths[i], keys[i] );
  }
  uchar vote[32];
  fd_memset( vote, 0xBB, 32UL );
  fd_base58_encode_32( vote, NULL, vote_account );
  ulong footprint = scratch_footprint( &tiles[0] );
  void * mem = aligned_alloc( scratch_align(), 3UL*footprint );
  FD_TEST( mem );
  topo.workspaces[0].wksp = mem;
  for( ulong i=0UL; i<2UL; i++ ) {
    topo.objs[i].id = i;
    topo.objs[i].offset = (i+1UL)*footprint;
  }
  links_init();
  test_listen_address();
  fd_failover_tile_ctx_t * a = boot( 0UL );
  fd_failover_tile_ctx_t * b = boot( 1UL );
  test_gossip_filter( a );
  set_role( a, FD_FAILOVER_ROLE_ACTIVE );
  contact_info( b, b->hello.staked_pubkey, FD_IP4_ADDR(127,0,0,1), 8001 );
  contact_info( a, a->hello.staked_pubkey, FD_IP4_ADDR(127,0,0,1), 8001 );
  long now = fd_failover_clock();
  for( ulong i=0UL; i<100UL; i++ ) {
    int busy = 0;
    peer_poll( a, now+(long)i*1000000000L, &busy );
    peer_poll( b, now+(long)i*1000000000L, &busy );
  }
  FD_TEST( !a->channel->generation && !b->channel->generation );
  FD_TEST( !fd_failover_channel_pending( a->channel ) && !fd_failover_channel_pending( b->channel ) );
  FD_TEST( !a->channel->dial_peer && !b->channel->dial_peer );
  FD_TEST( !a->channel->peer_addr && !b->channel->peer_addr );
  stem_init();
  fd_failover_tile_ctx_t * nodes[2] = { a, b };
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_failover_tile_ctx_t * c = nodes[i];
    c->admin_out_idx = c->adopt_out_idx = 0UL;
    c->admin_out_mem = c->adopt_out_mem = (fd_wksp_t *)bus_mem;
    c->replay_slot = 100UL;
    c->root_slot = 90UL;
    c->last_vote_slot = 99UL;
    c->tower_seen_seq = 9UL;
    c->channel->backoff_min = c->channel->backoff_max = 1000000L;
    c->channel->backoff = 1000000L;
  }
  make_tower( &a->current_tower, 99UL );
  /* Alternate the requester over real TLS, including an immediate
     handoff back before the new active has produced a vote. */
  for( ulong round=0UL; round<4UL; round++ ) {
    fd_failover_tile_ctx_t * src = nodes[round%2UL];
    fd_failover_tile_ctx_t * dst = nodes[1UL-round%2UL];
    dst->port = fd_failover_channel_listen_port( src->channel );
    now = fd_failover_clock();
    FD_TEST( control( src, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
    FD_TEST( control( dst, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, now )==FD_ADMINCTL_RESULT_SUCCESS );
    long until = now+5000000000L;
    int cut = 0;
    do {
      now = fd_failover_clock();
      FD_TEST( now<until );
      for( ulong i=0UL; i<2UL; i++ ) {
        fd_failover_tile_ctx_t * c = nodes[i];
        int busy = 0;
        peer_poll( c, now, &busy );
        step_controller( c, stem );
        if( c->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT ) switch_ok( c, 10UL );
        if( c->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT ) adopt_answer( c, FD_TOWER_ADOPT_SUCCESS, 99UL );
        /* Lose the channel once while the final tower, ACK or result is
           queued.  The same request must finish after reconnecting. */
        ushort fault = round==1UL ? FD_FAILOVER_MSG_DEMOTED : round==2UL ? FD_FAILOVER_MSG_PROMOTE_ACK : FD_FAILOVER_MSG_HANDOFF_RESULT;
        if( round && !cut && c->tx.valid && c->tx.type==fault ) {
          fd_failover_channel_hangup( c->channel, now );
          sync_session( c );
          cut = 1;
        }
        pending_flush( c, now );
      }
    } while( dst->request.id || src->channel->state==FD_FAILOVER_SESSION_PAIRED || dst->channel->state==FD_FAILOVER_SESSION_PAIRED );
    FD_TEST( src->role==FD_FAILOVER_ROLE_STANDBY && dst->role==FD_FAILOVER_ROLE_ACTIVE );
    FD_TEST( src->handoff.result==FD_FAILOVER_HANDOFF_TAKEN && dst->request.result==FD_FAILOVER_HANDOFF_TAKEN );
    FD_TEST( !src->channel->peer_addr && !dst->channel->peer_addr );
    FD_TEST( !round || cut );
  }
  shutdown_pair( a, b );
  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !unlink( key_paths[i] ) );
  FD_TEST( !rmdir( dir ) );
  fd_wksp_delete_anonymous( wksp );
  free( mem );
  FD_LOG_NOTICE(( "pass: gossip is idle, TLS handoffs reconnect after lost tower, ACK and result, then close" ));
}

static void
test_ondemand( void ) {
  test_request_controls();
  test_request_recovery();
  test_request_binding();
  test_drain_clock();
  test_socket_handoffs();
}
