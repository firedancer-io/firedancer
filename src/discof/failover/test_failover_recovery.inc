/* Independent boundary checks for the retained consensus and operator
   rules, shared by the connection variants. */
static void
test_floor_boundaries( void ) {
  ulong values[] = { FD_FAILOVER_SLOT_NULL, 0UL, 1UL, 99UL, 100UL, ULONG_MAX-1UL };
  for( ulong i=0UL; i<6UL; i++ ) for( ulong j=0UL; j<6UL; j++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    ctx->peer_floor=values[i];
    ctx->own_floor=values[j];
    ulong expected = values[i]==ULONG_MAX ? values[j] : values[j]==ULONG_MAX ? values[i] : values[i]>values[j] ? values[i] : values[j];
    FD_TEST( coverage_floor( ctx )==expected );
    ctx->promote_floor=100UL;
    ctx->promote_source=FD_FAILOVER_SOURCE_PEER;
    ctx->adopt_result.vote_slot=99UL;
    ctx->replay_slot=1000UL;
    FD_TEST( !floor_covered( ctx ) );
    ctx->adopt_result.vote_slot=100UL;
    FD_TEST( floor_covered( ctx ) );
    ctx->promote_source=FD_FAILOVER_SOURCE_VOTE_ACCOUNT;
    ctx->adopt_result.acct_vote_slot=99UL;
    ctx->replay_slot=612UL;
    FD_TEST( !floor_covered( ctx ) );
    ctx->replay_slot=613UL;
    FD_TEST( floor_covered( ctx ) );
    ctx->replay_slot=ULONG_MAX;
    FD_TEST( !floor_covered( ctx ) );
    ctx->adopt_result.acct_vote_slot=100UL;
    FD_TEST( floor_covered( ctx ) );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: independent signed-floor maximum, root/source separation and exact slack boundary" ));
}

static void
test_recovery_guard_matrix( void ) {
  long now=fd_failover_clock();
  ulong yes=FD_ADMINCTL_FAILOVER_FLAG_YES;
  ulong force=yes|FD_ADMINCTL_FAILOVER_FLAG_FORCE;
  for( ulong action=0UL; action<FD_FAILOVER_ACTION_CNT; action++ ) for( ulong key=0UL; key<3UL; key++ ) {
    fd_failover_tile_ctx_t * ctx=controller_init( FD_FAILOVER_ROLE_STANDBY );
    ctx->action=action;
    ctx->switch_pending_key=key;
    int can=key==FD_FAILOVER_SWITCH_KEY_CNT && (action==FD_FAILOVER_ACTION_IDLE || action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK);
    FD_TEST( (control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, force, now )==FD_ADMINCTL_RESULT_SUCCESS)==can );
    if( !can ) FD_TEST( ctx->action==action && ctx->switch_pending_key==key );
    controller_fini( ctx );
  }
  for( int force_on=0; force_on<2; force_on++ ) {
    fd_failover_tile_ctx_t * ctx=controller_init( FD_FAILOVER_ROLE_STANDBY );
    ctx->staked_seen_at=now;
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, force_on ? force : yes, now+14999999999L )==
             (force_on ? FD_ADMINCTL_RESULT_SUCCESS : FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN) );
    if( !force_on ) FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now+15000000000L )==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
    controller_fini( ctx );
  }
  fd_failover_tile_ctx_t * ctx=controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->own_tower, 99UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
  /* Independently retain the last-moment gossip defense for an unfenced
     promotion state; the MVP 0 operator API now refuses its admission. */
  start_promotion( ctx, FD_FAILOVER_SOURCE_OWN, 0 );
  step_controller( ctx, stem );
  ctx->staked_seen_at=now+1L;
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: force/action/switch matrix, gossip freshness and holder check after adoption" ));
}

static void
test_recovery_sources( void ) {
  fd_failover_tile_ctx_t * ctx=controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->own_tower, 99UL );
  make_tower( &ctx->peer_tower, 100UL );
  ctx->own_floor=100UL;
  FD_TEST( promote_source( ctx )==FD_FAILOVER_SOURCE_PEER );
  ctx->own_floor=101UL;
  FD_TEST( promote_source( ctx )==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
  ctx->own_floor=FD_FAILOVER_SLOT_NULL;
  ctx->root_slot=100UL;
  FD_TEST( promote_source( ctx )==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
  ctx->root_slot=99UL;
  FD_TEST( promote_source( ctx )==FD_FAILOVER_SOURCE_PEER );
  ctx->peer_tower.valid=0;
  ctx->root_slot=98UL;
  FD_TEST( promote_source( ctx )==FD_FAILOVER_SOURCE_OWN );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: sources below the signed floor or at the root are excluded" ));
}

static void
test_recovery( void ) {
  fd_failover_tile_ctx_t * ctx=controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, fd_failover_clock() );
  ctx->request_sent=1;
  ctx->channel->peer_hello.boot_id=78UL;
  ctx->channel->metrics.paired_cnt++;
  sync_session( ctx );
  FD_TEST( !ctx->request_sent && ctx->peer_boot_id==78UL && ctx->request_boot_id==77UL );
  controller_fini( ctx );
  test_floor_boundaries();
  test_recovery_guard_matrix();
  test_recovery_sources();
}
