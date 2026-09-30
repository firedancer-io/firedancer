/* Unilateral promote never obtains a fresh demotion from the peer. */
static void
test_unilateral_permissions( void ) {
  long now = fd_failover_clock();
  for( int paired=0; paired<2; paired++ ) for( ulong flags=0UL; flags<4UL; flags++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    if( paired ) pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
    ctx->staked_seen_at = now-FD_FAILOVER_GOSSIP_FRESH_NANOS;
    fd_adminctl_failover_status_resp_t status;
    status_snapshot( ctx, now, &status );
    int unverified = 1;
    if( unverified ) FD_TEST( status.promote_result==FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED );
    ulong want = unverified && !(flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE) ? FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED : FD_ADMINCTL_RESULT_SUCCESS;
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, flags, now )==want );
    FD_TEST( !ctx->request.id && !ctx->tx.valid && ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
    if( want ) FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->promotion.adopt_id );
    else FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY &&
                  ctx->promotion.force==!!(flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE) &&
                  ctx->promotion.source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
    controller_fini( ctx );
  }
  char const * hint;
  FD_TEST( !strcmp( control_refusal( FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED, &hint ), "PEER_UNVERIFIED" ) );
  FD_TEST( strstr( hint, "--force" ) && strstr( hint, "handoff" ) );
  FD_LOG_NOTICE(( "pass: confirmation is separate from force, recovery sources are selected automatically" ));
}
