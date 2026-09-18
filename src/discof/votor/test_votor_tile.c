#include "fd_votor_tile.c"
#include <stdlib.h>

static void
test_sign( void * ctx FD_PARAM_UNUSED, fd_bls_sig_t * sig, uchar const * payload FD_PARAM_UNUSED, ulong sz FD_PARAM_UNUSED ) {
  memset( sig, 0, sizeof(*sig) );
}

static void *
test_alloc( ulong align, ulong sz ) {
  void * mem = aligned_alloc( align, fd_ulong_align_up( sz, align ) );
  FD_TEST( mem );
  return mem;
}

static void
complete( fd_votor_tile_t * ctx, ulong idx, ulong slot, ulong parent ) {
  fd_replay_message_t msg = {0};
  msg.slot_completed.bank_idx = idx;
  msg.slot_completed.bank_seq = 100UL+idx;
  msg.slot_completed.slot = slot;
  msg.slot_completed.parent_slot = parent;
  msg.slot_completed.block_id.ul[0] = slot;
  msg.slot_completed.parent_block_id.ul[0] = parent;
  handle_replay( ctx, REPLAY_SIG_SLOT_COMPLETED, &msg );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  static fd_votor_tile_t ctx[1];
  bank_lease_t leases[16] = {0};
  void * pool_mem = test_alloc( ag_pool_align(), ag_pool_footprint( 16UL ) );
  void * votor_mem = test_alloc( ag_votor_align(), ag_votor_footprint( 16UL ) );
  void * pub_mem = test_alloc( publishes_align(), publishes_footprint( 68UL ) );
  ctx->pool = ag_pool_join( ag_pool_new( pool_mem, 16UL, 42UL ) );
  ctx->votor = ag_votor_join( ag_votor_new( votor_mem, 16UL, 42UL ) );
  ctx->publishes = publishes_join( publishes_new( pub_mem, 68UL ) );
  ctx->bank_leases = leases;
  ctx->bank_lease_cnt = 16UL;
  ag_pool_init( ctx->pool, 0UL );
  ag_votor_init( ctx->votor, 0UL, 0L, 1U, test_sign, NULL );
  ag_votor_set_bank_callback( ctx->votor, bank_decision, ctx );

  /* An out-of-order completion retains its lease until its parent
     becomes notarized.  Decisions precede the matching release. */
  complete( ctx, 2UL, 2UL, 1UL );
  FD_TEST( leases[2].held && publishes_empty( ctx->publishes ) );
  complete( ctx, 1UL, 1UL, 0UL );
  for( ulong idx=1UL; idx<=2UL; idx++ ) {
    publish_t selected = publishes_pop( ctx->publishes );
    publish_t released = publishes_pop( ctx->publishes );
    FD_TEST( selected.sig==FD_VOTOR_SIG_PROCESSED && selected.msg.processed.bank_idx==idx );
    FD_TEST( released.sig==FD_VOTOR_SIG_BANK_RELEASE && released.msg.bank_release.bank_idx==idx );
    FD_TEST( selected.msg.processed.bank_seq==released.msg.bank_release.bank_seq );
  }
  FD_TEST( publishes_empty( ctx->publishes ) );

  /* A duplicate completion owns a fresh lease, but cannot select the
     same local notarization a second time. */
  complete( ctx, 2UL, 2UL, 1UL );
  FD_TEST( publishes_pop( ctx->publishes ).sig==FD_VOTOR_SIG_BANK_RELEASE );
  FD_TEST( publishes_empty( ctx->publishes ) );

  complete( ctx, 4UL, 4UL, 3UL );
  FD_TEST( leases[4].held );
  fd_replay_message_t eviction = { .bank_eviction = { .bank_idx=4UL, .bank_seq=104UL, .slot=4UL } };
  eviction.bank_eviction.block_id.ul[0] = 4UL;
  handle_replay( ctx, REPLAY_SIG_BANK_EVICT_REQUEST, &eviction );
  publish_t released = publishes_pop( ctx->publishes );
  publish_t ack = publishes_pop( ctx->publishes );
  FD_TEST( released.sig==FD_VOTOR_SIG_BANK_RELEASE && released.msg.bank_release.bank_idx==4UL && released.msg.bank_release.bank_seq==104UL );
  FD_TEST( ack.sig==FD_VOTOR_SIG_BANK_EVICT_ACK && ack.msg.bank_evict_ack.bank_idx==4UL && ack.msg.bank_evict_ack.bank_seq==104UL && !ack.msg.bank_evict_ack.cancel );
  FD_TEST( !leases[4].held && publishes_empty( ctx->publishes ) );

  ag_event_pool_t ready = { .kind=AG_EVENT_POOL_PARENT_READY, .parent_ready={ .slot=4UL, .parent={ .slot=3UL } } };
  FD_STORE( ulong, ready.parent_ready.parent.hash, 3UL );
  ag_votor_handle_pool_event( ctx->votor, &ready, 0L );
  publish_t restore = publishes_pop( ctx->publishes );
  FD_TEST( restore.sig==FD_VOTOR_SIG_BANK_RESTORE && restore.msg.repair.slot==4UL );
  FD_TEST( publishes_empty( ctx->publishes ) );
  handle_replay( ctx, REPLAY_SIG_BANK_AVAILABLE, &eviction );
  FD_TEST( publishes_pop( ctx->publishes ).sig==FD_VOTOR_SIG_PROCESSED );
  FD_TEST( publishes_pop( ctx->publishes ).sig==FD_VOTOR_SIG_BANK_RELEASE );
  FD_TEST( publishes_empty( ctx->publishes ) && !leases[4].held );

  /* A certificate alone does not retire the replay bank.  Replay's
     actual root retires pending leases while reward history remains. */
  complete( ctx, 8UL, 8UL, 7UL );
  FD_TEST( leases[8].held && publishes_empty( ctx->publishes ) );
  ag_event_pool_t final = { .kind=AG_EVENT_POOL_CERT_CREATED, .cert_created = { .kind=AG_CERT_KIND_FINAL, .final.slot=8UL } };
  ag_votor_handle_pool_event( ctx->votor, &final, 0L );
  release_resolved_banks( ctx );
  FD_TEST( leases[8].held && publishes_empty( ctx->publishes ) );
  fd_replay_message_t root = { .root_advanced = { .slot=8UL } };
  handle_replay( ctx, REPLAY_SIG_ROOT_ADVANCED, &root );
  released = publishes_pop( ctx->publishes );
  FD_TEST( released.sig==FD_VOTOR_SIG_BANK_RELEASE && released.msg.bank_release.bank_idx==8UL );
  FD_TEST( !leases[8].held && publishes_empty( ctx->publishes ) );
  ready.parent_ready.slot = 8UL;
  ready.parent_ready.parent.slot = 7UL;
  FD_STORE( ulong, ready.parent_ready.parent.hash, 7UL );
  ag_votor_handle_pool_event( ctx->votor, &ready, 0L );
  FD_TEST( publishes_empty( ctx->publishes ) );

  free( pub_mem );
  free( votor_mem );
  free( pool_mem );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
