/* test_votor_tile drives the Votor tile's consensus core (ag_votor +
   ag_pool) the same way the alpenglow consensus tests do, but THROUGH the
   tile's drive functions (handle_replay_message / ag_pool_add_vote + the
   after_credit-style pool event drain) rather than against the core
   directly.

   The epoch validator set is installed exactly the way production does it:
   by feeding a synthetic EPOCH msg (stake weights + compressed BLS pubkeys)
   through update_epoch_vtrs -- no mock seam.  The test keeps the BLS secret
   keys it generated so it can sign votes for any validator; the production
   ranking is recovered from id_key markers placed in the stake weights. */

#include "fd_votor_tile.c"

/* ---- synthetic epoch validator set ---- */

#define TEST_NV (4UL)

static ag_aggsig_sk_t test_sk   [ TEST_NV ]; /* keyed by msg source index */
static ag_aggsig_sk_t sk_of_rank[ TEST_NV ]; /* keyed by production rank  */
static ushort         own_rank;

/* install_epoch builds a real fd_epoch_info_msg_t for epoch 0 (TEST_NV
   unit-stake voters; source 0 carries our identity and voting key) and
   feeds it through the production update_epoch_vtrs.  The pool / votor are
   rebuilt lazily by handle_replay_message on the first slot completion,
   as in production. */

static void
install_epoch( fd_votor_tile_t * ctx ) {
  static uchar buf[ 16384 ] __attribute__((aligned(64UL)));
  FD_TEST( fd_epoch_info_msg_sz( TEST_NV, 0UL )<=sizeof(buf) );
  memset( buf, 0, sizeof(buf) );

  fd_epoch_info_msg_t * msg = fd_type_pun( buf );
  msg->epoch           = 0UL;
  msg->staked_vote_cnt = TEST_NV;
  msg->staked_id_cnt   = 0UL;
  msg->start_slot      = 0UL;
  msg->slot_cnt        = 432000UL;
  msg->epoch_schedule.slots_per_epoch             = 432000UL;
  msg->epoch_schedule.leader_schedule_slot_offset = 432000UL;
  msg->epoch_schedule.warmup                      = 0;
  msg->epoch_schedule.first_normal_epoch          = 0UL;
  msg->epoch_schedule.first_normal_slot           = 0UL;

  fd_vote_stake_weight_t * stakes = fd_epoch_info_msg_stake_weights( msg );
  uchar *                  bls    = fd_epoch_info_msg_bls_pubkeys  ( msg );
  for( ulong i=0UL; i<TEST_NV; i++ ) {
    memset( test_sk[ i ].v, (int)(i*7UL+1UL), AG_AGGSIG_SECKEY_SZ );
    memset( stakes[ i ].vote_key.uc, 0x40+(int)i, 32UL );
    memset( stakes[ i ].id_key.uc,   (int)(i+1UL), 32UL ); /* rank->source marker */
    stakes[ i ].stake = 1UL;
    ag_aggsig_sk_to_pk_compressed( bls + i*AG_AGGSIG_PUBKEY_COMPRESSED_SZ, &test_sk[ i ] );
  }

  /* source 0 is us: our identity pubkey and our BLS voting key.  The
     tile normally delegates signing to the sign tile; here it signs in
     process with the same key, so the pubkey it advertises has to
     match. */
  memcpy( stakes[ 0 ].id_key.uc, ctx->identity_key->uc, 32UL );
  ag_aggsig_sk_to_pk( ctx->voting_pubkey, &test_sk[ 0 ] );

  update_epoch_vtrs( ctx, msg, stakes, TEST_NV );

  /* Recover the production ranking: update_epoch_vtrs left the ranked set
     in ctx->validators, and validators[r].pubkey is the id_key of the
     source validator that ranked r. */
  vtr_epoch_set_t const * s = epoch_set( ctx, 0UL );
  FD_TEST( s && s->validator_cnt==TEST_NV && s->have_own_id );
  own_rank = s->own_id;
  for( ulong r=0UL; r<TEST_NV; r++ ) {
    ulong m   = (ulong)ctx->validators[ r ].pubkey.uc[ 0 ];
    ulong src = m==(ulong)ctx->identity_key->uc[ 0 ] ? 0UL : m-1UL;
    FD_TEST( src<TEST_NV );
    sk_of_rank[ r ] = test_sk[ src ];
  }
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

  /* seed and signer must be set before init_choreo (privileged_init does
     this in prod).  This tile has no sign tile, so it signs in process
     with test_sk[0] instead of over the keyguard. */
  ((fd_votor_tile_t *)scratch)->seed     = 42UL;
  ((fd_votor_tile_t *)scratch)->sign_fn  = ag_aggsig_sign_local;
  ((fd_votor_tile_t *)scratch)->sign_ctx = &test_sk[ 0 ];

  fd_votor_tile_t * ctx = init_choreo( scratch, tile );
  FD_TEST( ctx );

  memset( ctx->identity_key, 0x11, sizeof(fd_pubkey_t) );

  /* Install the epoch validator set the production way (EPOCH msg ingest). */
  install_epoch( ctx );

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
  handle_replay_message( ctx, REPLAY_SIG_SLOT_COMPLETED, &sc, 0UL, NULL );
}

/* drain the pool's votor event channel through the votor, exactly like
   after_credit (the own-vote loopback in handle_votor_out appends to the
   channel while we iterate). */

static void
drain_pool_events( fd_votor_tile_t * ctx ) {
  ulong i = 0UL;
  while( i<ag_pool_votor_event_cnt( ctx->pool ) ) {
    ag_pool_event_t event = ag_pool_votor_event_channel( ctx->pool )[ i++ ];
    ag_votor_handle_pool_event( ctx->votor, &event );
    handle_votor_out( ctx );
  }
  ag_pool_drain_channels( ctx->pool );
  maybe_publish_finalized( ctx );
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
    if( p->sig==FD_VOTOR_SIG_VOTE && p->msg.vote.kind==AG_VOTE_TYPE_NOTAR ) {
      FD_TEST( ag_vote_slot( &p->msg.vote )==1UL );
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

  /* Gossip notar votes from every other rank for the same block.  With unit
     stake this drives notar / fast-final cert thresholds. */
  for( ulong r=0UL; r<TEST_NV; r++ ) {
    if( r==(ulong)own_rank ) continue;
    ag_vote_t vote;
    ag_vote_new_notar( &vote, slot, &h1, &sk_of_rank[ r ], (ushort)r, ctx->shred_version );
    FD_TEST( ag_pool_add_vote( ctx->pool, &vote )==AG_POOL_SUCCESS );
    drain_pool_events( ctx );
  }

  /* Gossip final votes from every other rank (we already final-voted via the
     CertCreated cascade when the notar cert appeared). */
  for( ulong r=0UL; r<TEST_NV; r++ ) {
    if( r==(ulong)own_rank ) continue;
    ag_vote_t vote;
    ag_vote_new_final( &vote, slot, &sk_of_rank[ r ], (ushort)r, ctx->shred_version );
    int err = ag_pool_add_vote( ctx->pool, &vote );
    FD_TEST( err==AG_POOL_SUCCESS || err==AG_ADD_VOTE_ERR_SLOT_OUT_OF_BOUNDS ); /* fast-final may already have rooted past it */
    drain_pool_events( ctx );
  }

  /* The pool should now have finalized slot 1 (fast-final on unanimous notar,
     or slow-final on final votes).  Either way root advanced and a finalized
     frag was queued. */
  FD_TEST( ag_pool_finalized_slot( ctx->pool )>=slot );
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
  handle_replay_message( ctx, REPLAY_SIG_SLOT_DEAD, dead, 0UL, NULL );

  /* dead slots before the root are ignored. */
  dead->slot = 0UL;
  handle_replay_message( ctx, REPLAY_SIG_SLOT_DEAD, dead, 0UL, NULL );

  FD_LOG_NOTICE(( "pass: test_dead_slot" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 1UL<<20; /* 4 GiB of normal pages; keeps the test runnable without free gigantic pages */
  char *      page_sz  = "normal";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_wksp_reset( wksp, 1UL ); test_vote_emitted ( wksp );
  fd_wksp_reset( wksp, 1UL ); test_finalization ( wksp );
  fd_wksp_reset( wksp, 1UL ); test_dead_slot    ( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
