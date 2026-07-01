/* test_votor_tile drives the Votor tile's consensus core (fd_votor +
   fd_pool) the same way the alpenglow consensus tests do, but THROUGH the
   tile's drive functions (votor_slot_completed / ingest_vote) rather
   than against the core directly.

   Per project convention we set up REAL fd_pool / fd_votor structures via the
   production init path (init_choreo + a real epoch validator set built by
   update_epoch_vtrs).  The only seam is UPDATE_EPOCH_VTRS, which we override
   so the test can install a deterministic validator set (with real BLS-stub
   secret keys) and recover the secret keys for signing synthetic gossip
   votes.  Everything else is exercised end-to-end. */

#define UPDATE_EPOCH_VTRS mock_update_epoch_vtrs

#include "fd_votor_tile.c"

/* ---- mock epoch validator set ---- */

#define TEST_NV (4UL)

static fd_aggsig_sk_t test_sk[ TEST_NV ];

/* Install a TEST_NV-validator unit-stake set into the tile, rebuilding the
   pool and votor against it.  Mirrors update_epoch_vtrs but uses the test's
   own secret keys so the test can sign synthetic votes for any validator.
   own_id is chosen as 0. */

void
mock_update_epoch_vtrs( fd_votor_tile_t *              ctx,
                        fd_epoch_info_msg_t const *    msg,
                        fd_vote_stake_weight_t const * stakes FD_PARAM_UNUSED,
                        ulong                          stake_cnt FD_PARAM_UNUSED ) {

  ulong cnt = TEST_NV;
  ctx->validator_cnt = cnt;
  ctx->epoch         = msg ? msg->epoch : 0UL;
  ctx->own_id        = 0UL;

  for( ulong i=0UL; i<cnt; i++ ) {
    memset( test_sk[ i ].v, (int)(i*7UL+1UL), FD_AGGSIG_SECKEY_SZ );
    fd_validator_info_t * vi = &ctx->validators[ i ];
    memset( vi, 0, sizeof(fd_validator_info_t) );
    vi->id    = i;
    vi->stake = 1UL;
    fd_aggsig_sk_to_pk( &vi->voting_pubkey, &test_sk[ i ] );
  }
  ctx->voting_key[ 0 ] = test_sk[ 0 ];

  /* Reuse the dimensions the scratch regions were allocated for. */

  //fd_epoch_info_join( fd_epoch_info_new( ctx->epoch_mem, ctx->validators, cnt ) );
  //ctx->epoch_info = fd_epoch_info_join( ctx->epoch_mem );
  //FD_TEST( ctx->epoch_info );

  ctx->pool = fd_pool_join( fd_pool_new( fd_pool_leave( ctx->pool ),
                                         ctx->slot_max, ctx->validator_max, ctx->blockid_max,
                                         ctx->own_id, ctx->validators, cnt, ctx->seed, 0UL, NULL ) );
  FD_TEST( ctx->pool );

  fd_votor_out_t out = fresh_votor_out( ctx );
  ctx->votor = fd_votor_join( fd_votor_new( fd_votor_leave( ctx->votor ),
                                            ctx->slot_max, ctx->own_id, ctx->voting_key, ctx->seed, &out ) );
  FD_TEST( ctx->votor );
}

/* ---- harness helpers ---- */

static fd_votor_tile_t *
setup_ctx( fd_wksp_t * wksp ) {
  fd_topo_tile_t tile[1];
  memset( tile, 0, sizeof(*tile) );
  tile->tower.max_live_slots = 1024UL;

  FD_TEST( scratch_align()==128UL );
  ulong footprint = scratch_footprint( tile );
  FD_TEST( footprint );

  void * scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), footprint, 1UL );
  FD_TEST( scratch );

  /* seed must be set before init_choreo (privileged_init does this in prod). */
  ((fd_votor_tile_t *)scratch)->seed = 42UL;
  memset( ((fd_votor_tile_t *)scratch)->voting_key, 0, sizeof(fd_aggsig_sk_t) );

  fd_votor_tile_t * ctx = init_choreo( scratch, tile );
  FD_TEST( ctx );

  memset( ctx->identity_key, 0x11, sizeof(fd_pubkey_t) );

  /* Install the real validator set (epoch ingest). */
  fd_epoch_info_msg_t msg[1];
  memset( msg, 0, sizeof(msg) );
  msg->epoch = 0UL;
  mock_update_epoch_vtrs( ctx, msg, NULL, 0UL );

  return ctx;
}

static fd_hash_t
mk_hash( uchar b ) {
  fd_hash_t h; memset( h.uc, (int)b, sizeof(fd_hash_t) );
  return h;
}

/* drive a completed slot through the tile. */

static void
complete_slot( fd_votor_tile_t * ctx,
               ulong             slot,
               fd_hash_t         block_id,
               ulong             parent_slot,
               fd_hash_t         parent_block_id ) {
  fd_replay_slot_completed_t sc;
  memset( &sc, 0, sizeof(sc) );
  sc.slot            = slot;
  sc.parent_slot     = parent_slot;
  sc.block_id        = block_id;
  sc.parent_block_id = parent_block_id;
  sc.bank_idx        = slot; /* arbitrary */
  votor_slot_completed( ctx, &sc, 0UL, NULL );
}

/* count queued publishes of a given sig. */

static ulong
count_pubs( fd_votor_tile_t * ctx, ulong sig ) {
  ulong n = 0UL;
  for( publishes_iter_t it = publishes_iter_init( ctx->publishes );
       !publishes_iter_done( ctx->publishes, it );
       it = publishes_iter_next( ctx->publishes, it ) ) {
    publish_t const * p = publishes_iter_ele_const( ctx->publishes, it );
    if( p->sig==sig ) n++;
  }
  return n;
}

/* ---- tests ---- */

/* test_vote_emitted: completing slot 1 with the genesis parent should make
   the votor cast a notar vote (queued as FD_VOTOR_SIG_VOTE) and emit a
   slot_done frag. */

static void
test_vote_emitted( fd_wksp_t * wksp ) {
  fd_votor_tile_t * ctx = setup_ctx( wksp );

  fd_hash_t genesis = {0};
  fd_hash_t h1      = mk_hash( 0xA1 );

  complete_slot( ctx, 1UL, h1, 0UL, genesis );

  FD_TEST( ctx->init==1 );
  FD_TEST( count_pubs( ctx, FD_VOTOR_SIG_VOTE      )>=1UL ); /* a notar vote was cast */
  FD_TEST( count_pubs( ctx, FD_VOTOR_SIG_SLOT_DONE )==1UL ); /* exactly one slot_done */

  /* the slot_done frag should echo back the bank_idx and reset onto slot 1. */
  int found_done = 0;
  for( publishes_iter_t it = publishes_iter_init( ctx->publishes );
       !publishes_iter_done( ctx->publishes, it );
       it = publishes_iter_next( ctx->publishes, it ) ) {
    publish_t const * p = publishes_iter_ele_const( ctx->publishes, it );
    if( p->sig==FD_VOTOR_SIG_SLOT_DONE ) {
      FD_TEST( p->msg.slot_done.replay_slot==1UL );
      FD_TEST( p->msg.slot_done.replay_bank_idx==1UL );
      FD_TEST( p->msg.slot_done.reset_slot==1UL );
      found_done = 1;
    }
  }
  FD_TEST( found_done );

  /* the notar vote should be for slot 1. */
  int found_vote = 0;
  for( publishes_iter_t it = publishes_iter_init( ctx->publishes );
       !publishes_iter_done( ctx->publishes, it );
       it = publishes_iter_next( ctx->publishes, it ) ) {
    publish_t const * p = publishes_iter_ele_const( ctx->publishes, it );
    if( p->sig==FD_VOTOR_SIG_VOTE && p->msg.vote.discriminant==FD_VOTE_TYPE_NOTAR ) {
      FD_TEST( fd_vote_slot( &p->msg.vote )==1UL );
      found_vote = 1;
    }
  }
  FD_TEST( found_vote );

  FD_LOG_NOTICE(( "pass: test_vote_emitted" ));
}

/* test_finalization: after our notar vote, ingesting notar votes from the
   other validators (gossip) should create a notar cert, drive a final vote
   from us, and once enough final votes are seen finalize the slot -> a
   FD_VOTOR_SIG_FINALIZED frag is queued and root advances. */

static void
test_finalization( fd_wksp_t * wksp ) {
  fd_votor_tile_t * ctx = setup_ctx( wksp );

  fd_hash_t genesis = {0};
  fd_hash_t h1      = mk_hash( 0xB2 );
  ulong     slot    = 1UL;

  /* Our own notar vote for (slot, h1). */
  complete_slot( ctx, slot, h1, 0UL, genesis );
  FD_TEST( count_pubs( ctx, FD_VOTOR_SIG_VOTE )>=1UL );

  /* Gossip notar votes from validators 1..TEST_NV for the same block.  With
     unit stake this drives notar / fast-final cert thresholds. */
  for( ulong v=1UL; v<TEST_NV; v++ ) {
    fd_vote_t vote;
    fd_vote_new_notar( &vote, slot, &h1, &test_sk[ v ], (ushort)v );
    ingest_vote( ctx, &vote );
    maybe_publish_finalized( ctx );
  }

  /* Gossip final votes from validators 1..TEST_NV (we already final-voted via
     the CertCreated cascade when the notar cert appeared). */
  for( ulong v=1UL; v<TEST_NV; v++ ) {
    fd_vote_t vote;
    fd_vote_new_final( &vote, slot, &test_sk[ v ], (ushort)v );
    ingest_vote( ctx, &vote );
    maybe_publish_finalized( ctx );
  }

  /* The pool should now have finalized slot 1 (fast-final on unanimous notar,
     or slow-final on final votes).  Either way root advanced and a finalized
     frag was queued. */
  FD_TEST( fd_pool_finalized_slot( ctx->pool )>=slot );
  FD_TEST( ctx->root_slot>=slot );
  FD_TEST( count_pubs( ctx, FD_VOTOR_SIG_FINALIZED )>=1UL );

  /* a cert should have been queued for broadcast (notar / fast-final / final). */
  FD_TEST( count_pubs( ctx, FD_VOTOR_SIG_CERT )>=1UL );

  FD_LOG_NOTICE(( "pass: test_finalization" ));
}

/* test_dead_slot: a dead (invalid) slot should drive the votor skip path
   without crashing.  We don't assert a specific vote here (skip behaviour
   depends on parent-ready bookkeeping), only that the drive is well formed. */

static void
test_dead_slot( fd_wksp_t * wksp ) {
  fd_votor_tile_t * ctx = setup_ctx( wksp );

  fd_hash_t genesis = {0};
  fd_hash_t h1      = mk_hash( 0xC3 );
  complete_slot( ctx, 1UL, h1, 0UL, genesis );

  fd_replay_slot_dead_t dead[1];
  memset( dead, 0, sizeof(dead) );
  dead->slot     = 2UL;
  dead->block_id = mk_hash( 0xC4 );
  votor_slot_dead( ctx, dead );

  /* dead slots before the root are ignored. */
  dead->slot = 0UL;
  votor_slot_dead( ctx, dead );

  FD_LOG_NOTICE(( "pass: test_dead_slot" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 4;
  char *      page_sz  = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_wksp_reset( wksp, 1UL ); test_vote_emitted ( wksp );
  fd_wksp_reset( wksp, 1UL ); test_finalization ( wksp );
  fd_wksp_reset( wksp, 1UL ); test_dead_slot    ( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
