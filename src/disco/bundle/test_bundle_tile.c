#define FD_TILE_TEST
#include "fd_bundle_tile.c"
#include <stdlib.h>

long
fd_bundle_now( void ) {
  return 1L;
}

/* ---- minimal helpers ------------------------------------------------ */

static void *
mock_replay_wksp_new( void ) {
  ulong alloc_sz = fd_ulong_align_up( FD_CHUNK_FOOTPRINT + sizeof(fd_poh_reset_t), FD_CHUNK_ALIGN );
  void * mem = aligned_alloc( FD_CHUNK_ALIGN, alloc_sz );
  FD_TEST( mem );
  memset( mem, 0, alloc_sz );
  return mem;
}

static ulong
mock_replay_write_reset( void * mem,
                         ulong  chunk,
                         ulong  completed_slot,
                         ulong  next_leader_slot ) {
  fd_poh_reset_t * reset = (fd_poh_reset_t *)fd_chunk_to_laddr( mem, chunk );
  memset( reset, 0, sizeof(fd_poh_reset_t) );
  reset->completed_slot   = completed_slot;
  reset->next_leader_slot = next_leader_slot;
  return chunk;
}

static void
inject_replay_reset( fd_bundle_tile_t * ctx,
                     ulong              in_idx,
                     ulong              chunk,
                     ulong              completed_slot,
                     ulong              next_leader_slot ) {
  mock_replay_write_reset( ctx->replay_in.mem, chunk, completed_slot, next_leader_slot );

  during_frag( ctx, in_idx, 0UL, REPLAY_SIG_RESET, chunk, sizeof(fd_poh_reset_t), 0UL );
  after_frag( ctx, in_idx, 0UL, REPLAY_SIG_RESET, sizeof(fd_poh_reset_t), 0UL, 0UL, NULL );
}

/* ---- test: during_frag + after_frag staging/commit ------------------- */

static void
test_replay_frag_ingest( void ) {
  FD_LOG_NOTICE(( "TEST replay frag ingest" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );

  void * wksp = mock_replay_wksp_new();

  ulong const in_idx = 0UL;
  ctx->in_kind[ in_idx ]  = IN_KIND_REPLAY_OUT;
  ctx->replay_in.mem    = wksp;
  ctx->replay_in.chunk0 = 0UL;
  ctx->replay_in.wmark  = 1UL; /* allow chunk 0 and 1 */

  ctx->next_leader_slot = ULONG_MAX;
  ctx->reset_slot       = ULONG_MAX;

  /* Inject a reset: completed_slot=100, next_leader_slot=500 */
  inject_replay_reset( ctx, in_idx, 0UL, 100UL, 500UL );

  FD_TEST( ctx->next_leader_slot==500UL );
  FD_TEST( ctx->reset_slot==100UL );

  /* A non-reset signal should be ignored */
  ulong prev_next = ctx->next_leader_slot;
  ulong prev_rst  = ctx->reset_slot;
  during_frag( ctx, in_idx, 0UL, REPLAY_SIG_RESET+1, 0UL, sizeof(fd_poh_reset_t), 0UL );
  after_frag( ctx, in_idx, 0UL, REPLAY_SIG_RESET+1, sizeof(fd_poh_reset_t), 0UL, 0UL, NULL );
  FD_TEST( ctx->next_leader_slot==prev_next );
  FD_TEST( ctx->reset_slot==prev_rst );

  /* A different in_idx (not replay) should be ignored */
  ctx->in_kind[ 1 ] = 0;
  during_frag( ctx, 1UL, 0UL, REPLAY_SIG_RESET, 0UL, sizeof(fd_poh_reset_t), 0UL );
  after_frag( ctx, 1UL, 0UL, REPLAY_SIG_RESET, sizeof(fd_poh_reset_t), 0UL, 0UL, NULL );
  FD_TEST( ctx->next_leader_slot==prev_next );
  FD_TEST( ctx->reset_slot==prev_rst );

  free( wksp );
}

/* ---- test: maybe_sleep hysteresis ------------------------------------ */

static void
test_maybe_sleep_no_replay( void ) {
  FD_LOG_NOTICE(( "TEST maybe_sleep returns early without replay_in" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );
  ctx->replay_in.mem = NULL;
  ctx->sleep_mode    = 0;

  /* Should be a no-op when replay_in.mem is NULL */
  fd_bundle_tile_maybe_sleep( ctx, 0 );
  FD_TEST( ctx->sleep_mode==0 );
}

static void
test_maybe_sleep_unknown_schedule( void ) {
  FD_LOG_NOTICE(( "TEST maybe_sleep sleeps when leader schedule unknown" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );

  void * wksp = mock_replay_wksp_new();
  ctx->replay_in.mem = wksp;
  ctx->sleep_mode    = 0;
  ctx->sleep_check_ns = 0;

  /* next_leader_slot unknown → should enter sleep */
  ctx->next_leader_slot = ULONG_MAX;
  ctx->reset_slot       = 100UL;
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==1 );

  /* reset_slot unknown → should stay asleep */
  ctx->sleep_mode = 0;
  ctx->sleep_check_ns = 0;
  ctx->next_leader_slot = 100UL;
  ctx->reset_slot       = ULONG_MAX;
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==1 );

  /* Both unknown → should stay asleep */
  ctx->sleep_mode = 0;
  ctx->sleep_check_ns = 0;
  ctx->next_leader_slot = ULONG_MAX;
  ctx->reset_slot       = ULONG_MAX;
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==1 );

  free( wksp );
}

static void
test_maybe_sleep_far_leader( void ) {
  FD_LOG_NOTICE(( "TEST maybe_sleep enters sleep when leader is far" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );

  void * wksp = mock_replay_wksp_new();
  ctx->replay_in.mem    = wksp;
  ctx->sleep_mode       = 0;
  ctx->sleep_check_ns   = 0;

  /* Leader 500 slots away (>450 threshold) → enter sleep */
  ctx->reset_slot       = 100UL;
  ctx->next_leader_slot = 600UL;
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==1 );

  free( wksp );
}

static void
test_maybe_sleep_close_leader( void ) {
  FD_LOG_NOTICE(( "TEST maybe_sleep stays awake when leader is close" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );

  void * wksp = mock_replay_wksp_new();
  ctx->replay_in.mem    = wksp;
  ctx->sleep_mode       = 0;
  ctx->sleep_check_ns   = 0;

  /* Leader 300 slots away (<450 threshold) → stay awake */
  ctx->reset_slot       = 100UL;
  ctx->next_leader_slot = 400UL;
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==0 );

  free( wksp );
}

static void
test_maybe_sleep_hysteresis( void ) {
  FD_LOG_NOTICE(( "TEST maybe_sleep hysteresis between thresholds" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );

  void * wksp = mock_replay_wksp_new();
  ctx->replay_in.mem    = wksp;
  ctx->sleep_mode       = 0;
  ctx->sleep_check_ns   = 0;

  /* Start awake, leader is 425 slots away.
     425 < 450 (sleep threshold) → should stay awake */
  ctx->reset_slot       = 100UL;
  ctx->next_leader_slot = 525UL;
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==0 );

  /* Now push leader to 451 slots away (>450) → enter sleep */
  ctx->sleep_check_ns = 0;
  ctx->next_leader_slot = 551UL;
  fd_bundle_tile_maybe_sleep( ctx, 2 );
  FD_TEST( ctx->sleep_mode==1 );

  /* While sleeping, leader moves to 410 slots away.
     410 > 400 (wake threshold) → stay asleep (hysteresis) */
  ctx->sleep_check_ns = 0;
  ctx->next_leader_slot = 510UL;
  fd_bundle_tile_maybe_sleep( ctx, 3 );
  FD_TEST( ctx->sleep_mode==1 );

  /* Leader moves to 400 slots (<=400 wake threshold) → wake up */
  ctx->sleep_check_ns = 0;
  ctx->next_leader_slot = 500UL;
  fd_bundle_tile_maybe_sleep( ctx, 4 );
  FD_TEST( ctx->sleep_mode==0 );

  /* Now leader is exactly at 450 slots → stay awake (need >450) */
  ctx->sleep_check_ns = 0;
  ctx->next_leader_slot = 550UL;
  fd_bundle_tile_maybe_sleep( ctx, 5 );
  FD_TEST( ctx->sleep_mode==0 );

  /* Leader at 451 → sleep */
  ctx->sleep_check_ns = 0;
  ctx->next_leader_slot = 551UL;
  fd_bundle_tile_maybe_sleep( ctx, 6 );
  FD_TEST( ctx->sleep_mode==1 );

  free( wksp );
}

static void
test_maybe_sleep_check_interval( void ) {
  FD_LOG_NOTICE(( "TEST maybe_sleep respects check interval" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );

  void * wksp = mock_replay_wksp_new();
  ctx->replay_in.mem    = wksp;
  ctx->sleep_mode       = 0;
  ctx->sleep_check_ns   = 0;

  /* Leader far away → should sleep on first check */
  ctx->reset_slot       = 0UL;
  ctx->next_leader_slot = 1000UL;
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==1 );

  /* sleep_check_ns should now be 1 + 5e9 */
  long expected_next = 1 + FD_BUNDLE_SLEEP_CHECK_INTERVAL_NS;
  FD_TEST( ctx->sleep_check_ns==expected_next );

  /* Calling again before interval elapses should be a no-op. */
  ctx->next_leader_slot = 10UL;
  fd_bundle_tile_maybe_sleep( ctx, 2 );
  FD_TEST( ctx->sleep_mode==1 ); /* unchanged, interval not reached */

  /* Advance past interval → check fires, leader close → wake */
  fd_bundle_tile_maybe_sleep( ctx, expected_next + 1 );
  FD_TEST( ctx->sleep_mode==0 );

  free( wksp );
}

static void
test_replay_triggers_sleep_transition( void ) {
  FD_LOG_NOTICE(( "TEST end-to-end: replay reset messages drive sleep" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );

  void * wksp = mock_replay_wksp_new();

  ulong const in_idx = 0UL;
  ctx->in_kind[ in_idx ] = IN_KIND_REPLAY_OUT;
  ctx->replay_in.mem     = wksp;
  ctx->replay_in.chunk0  = 0UL;
  ctx->replay_in.wmark   = 1UL;

  /* Start asleep (mimicking has_replay_in initial state) */
  ctx->next_leader_slot  = ULONG_MAX;
  ctx->reset_slot        = ULONG_MAX;
  ctx->sleep_mode        = 1;
  ctx->sleep_check_ns    = 0;

  /* 1. Replay says: completed_slot=0, next_leader_slot=1000.
        Leader is 1000 slots away (>450) → stay asleep */
  inject_replay_reset( ctx, in_idx, 0UL, 0UL, 1000UL );
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==1 );

  /* 2. Replay says: completed_slot=700, next_leader_slot=1000.
        Leader is 300 slots away (<=400) → wake up */
  inject_replay_reset( ctx, in_idx, 0UL, 700UL, 1000UL );
  ctx->sleep_check_ns = 0;
  fd_bundle_tile_maybe_sleep( ctx, 2 );
  FD_TEST( ctx->sleep_mode==0 );

  /* 3. Replay says: completed_slot=1004, next_leader_slot=2000.
        Leader is 996 slots away (>450) → enter sleep again */
  inject_replay_reset( ctx, in_idx, 0UL, 1004UL, 2000UL );
  ctx->sleep_check_ns = 0;
  fd_bundle_tile_maybe_sleep( ctx, 3 );
  FD_TEST( ctx->sleep_mode==1 );

  /* 4. Replay says: no upcoming leader (ULONG_MAX).
        Should stay asleep. */
  inject_replay_reset( ctx, in_idx, 0UL, 2000UL, ULONG_MAX );
  ctx->sleep_check_ns = 0;
  fd_bundle_tile_maybe_sleep( ctx, 4 );
  FD_TEST( ctx->sleep_mode==1 );

  free( wksp );
}

static void
test_boundary_thresholds( void ) {
  FD_LOG_NOTICE(( "TEST boundary threshold values" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );

  void * wksp = mock_replay_wksp_new();
  ctx->replay_in.mem = wksp;

  /* Exactly at sleep threshold (450): awake should stay awake */
  ctx->sleep_mode       = 0;
  ctx->sleep_check_ns   = 0;
  ctx->reset_slot       = 0;
  ctx->next_leader_slot = FD_BUNDLE_SLEEP_THRESHOLD_SLOTS;
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==0 );

  /* One above sleep threshold (451): awake → sleep */
  ctx->sleep_mode       = 0;
  ctx->sleep_check_ns   = 0;
  ctx->next_leader_slot = FD_BUNDLE_SLEEP_THRESHOLD_SLOTS + 1;
  fd_bundle_tile_maybe_sleep( ctx, 2 );
  FD_TEST( ctx->sleep_mode==1 );

  /* Exactly at wake threshold (400): asleep → wake */
  ctx->sleep_mode       = 1;
  ctx->sleep_check_ns   = 0;
  ctx->next_leader_slot = FD_BUNDLE_WAKE_THRESHOLD_SLOTS;
  fd_bundle_tile_maybe_sleep( ctx, 3 );
  FD_TEST( ctx->sleep_mode==0 );

  /* One above wake threshold (401): asleep → stay asleep */
  ctx->sleep_mode       = 1;
  ctx->sleep_check_ns   = 0;
  ctx->next_leader_slot = FD_BUNDLE_WAKE_THRESHOLD_SLOTS + 1;
  fd_bundle_tile_maybe_sleep( ctx, 4 );
  FD_TEST( ctx->sleep_mode==1 );

  free( wksp );
}

static void
test_saturating_sub( void ) {
  FD_LOG_NOTICE(( "TEST saturating subtraction when reset > leader" ));

  fd_bundle_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_bundle_tile_t) );

  void * wksp = mock_replay_wksp_new();
  ctx->replay_in.mem = wksp;

  /* If reset_slot > next_leader_slot, slots_until_leader saturates
     to 0.  This should wake the tile since 0 <= 400. */
  ctx->sleep_mode       = 1;
  ctx->sleep_check_ns   = 0;
  ctx->reset_slot       = 1000UL;
  ctx->next_leader_slot = 500UL;
  fd_bundle_tile_maybe_sleep( ctx, 1 );
  FD_TEST( ctx->sleep_mode==0 );

  free( wksp );
}

int
main( int     argc,
      char ** argv ) {
  (void)scratch_footprint;
  (void)before_credit;
  (void)after_credit;
  (void)metrics_write;
  (void)populate_sock_filter_policy_fd_bundle_tile;

  fd_boot( &argc, &argv );

  test_replay_frag_ingest();
  test_maybe_sleep_no_replay();
  test_maybe_sleep_unknown_schedule();
  test_maybe_sleep_far_leader();
  test_maybe_sleep_close_leader();
  test_maybe_sleep_hysteresis();
  test_maybe_sleep_check_interval();
  test_replay_triggers_sleep_transition();
  test_boundary_thresholds();
  test_saturating_sub();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
