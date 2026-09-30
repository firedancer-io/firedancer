/* Automatic sources and the operator's explicit history override. */
static void
test_automatic_recovery( void ) {
  static uchar res_mem[ sizeof(fd_tower_adopt_result_t) ] __attribute__((aligned(128)));
  ulong errors[] = { FD_TOWER_ADOPT_ERR_DECODE, FD_TOWER_ADOPT_ERR_INVALID,
                     FD_TOWER_ADOPT_ERR_UNREPLAYED_ROOT, FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH,
                     FD_TOWER_ADOPT_ERR_UNREPLAYED, FD_TOWER_ADOPT_SUCCESS };
  for( ulong i=0UL; i<sizeof(errors)/sizeof(errors[0]); i++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    ctx->adopt_in_idx = 2UL;
    ctx->adopt_in_mem = (fd_wksp_t *)res_mem;
    make_tower( &ctx->peer_tower, 99UL );
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, fd_failover_clock() )==FD_ADMINCTL_RESULT_SUCCESS );
    FD_TEST( ctx->promotion.source==FD_FAILOVER_SOURCE_PEER );
    step_controller( ctx, stem );
    ulong first = ctx->promotion.adopt_id;
    adopt_answer( ctx, errors[i], 98UL ); /* SUCCESS with a short prefix also falls back */
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promotion.force && !ctx->promotion.empty );
    FD_TEST( ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && !ctx->promotion.adopt.sz );
    FD_TEST( !ctx->peer_tower.valid );
    step_controller( ctx, stem );
    ulong second = ctx->promotion.adopt_id;
    FD_TEST( second!=first && !pub_mcache[1].sz && !pub_mcache[1].ctl );
    adopt_frag( ctx, first, FD_TOWER_ADOPT_SUCCESS, 99UL );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
    acct_answer( ctx, 99UL, 99UL );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && !ctx->promotion.empty );
    controller_fini( ctx );
  }

  /* No usable vote account means refusal without FORCE, including
     unreplayed account blocks.  An operator can retry after replay
     catches up, no local request remains outstanding at this point. */
  for( ulong i=0UL; i<sizeof(errors)/sizeof(errors[0])-1UL; i++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    start_promotion( ctx, FD_FAILOVER_SOURCE_VOTE_ACCOUNT, NULL, 0UL, 0 );
    step_controller( ctx, stem );
    adopt_answer( ctx, errors[i], FD_FAILOVER_SLOT_NULL );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck && !ctx->promotion.empty && !ctx->promotion.retry );
    FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT && stem->seqs[ 0 ]==1UL );
    controller_fini( ctx );
  }

  /* A saved tip ahead of replay is not currently adoptable.  Falling
     back before publishing sends only the account request. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->peer_tower, 10000UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, fd_failover_clock() )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !stem->seqs[ 0 ] );
  FD_TEST( ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && stem->seqs[ 0 ]==1UL && !pub_mcache[0].ctl );
  controller_fini( ctx );

  /* Only the matching account failure allows a forced empty request.
     Force still cannot overlap the original request or a key switch. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->peer_floor = 10000UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, fd_failover_clock() )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  ulong account = ctx->promotion.adopt_id;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, fd_failover_clock() )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->promotion.empty && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  step_controller( ctx, stem );
  FD_TEST( ctx->promotion.adopt_id!=account && !pub_mcache[1].sz && pub_mcache[1].ctl==FD_TOWER_ADOPT_CTL_EMPTY );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->promotion.floor==10000UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, fd_failover_clock() )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  controller_fini( ctx );

  /* An unfenced source check may not use the empty escape hatch.  This
     state also covers a persistent session's independently verified standby peer. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  start_promotion( ctx, FD_FAILOVER_SOURCE_VOTE_ACCOUNT, NULL, 0UL, 0 );
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck && !ctx->promotion.empty );
  FD_TEST( ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  controller_fini( ctx );

  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->own_floor = 99UL;
  start_promotion( ctx, FD_FAILOVER_SOURCE_VOTE_ACCOUNT, NULL, 0UL, 0 );
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && !ctx->promotion.force );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: automatic saved/account fallback, forced empty history and matching adoption before switch" ));
}
