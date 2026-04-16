#define fd_eqvoc_query       mock_eqvoc_query_fn
#define QUERY_VOTE_ACCS      mock_query_vote_accs

#include "fd_tower_tile.c"

#include <stdio.h>
#include <string.h>

/* mock_vote_txn builds a vote transaction from a tower.  Constructs an
   fd_tower_t with the given (slot, conf) pairs, serializes it via
   fd_tower_to_vote_txn, and returns the parsed fd_txn_t and payload.

   slots and confs are arrays of length cnt.  block_id controls the
   block_id in the serde (null block_id causes count_vote_txn to exit at
   the hash_null check after tower validation). */

static fd_txn_t const *
mock_vote_txn( ulong               root,
               ulong               cnt,
               ulong const *       slots,
               ulong const *       confs,
               fd_hash_t const *   block_id,
               fd_txn_p_t *        txnp,
               uchar               txn_out[ static FD_TXN_MAX_SZ ] ) {

  static uchar tower_mem[ 65536 ] __attribute__((aligned(128)));
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, 2, 2, 0 ) );

  for( ulong i = 0; i < cnt; i++ ) {
    fd_tower_vote_push_tail( tower->votes, (fd_tower_vote_t){ .slot = slots[i], .conf = confs[i] } );
  }
  tower->root = root;

  fd_hash_t     bank_hash          = { .ul = { 0xAA } };
  fd_hash_t     recent_blockhash   = {0};
  fd_pubkey_t   validator_identity = { .ul = { 0x11 } };
  fd_pubkey_t   vote_acc           = { .ul = { 0x22 } };

  fd_tower_to_vote_txn( tower, &bank_hash, block_id, &recent_blockhash, &validator_identity, &validator_identity, &vote_acc, txnp );
  FD_TEST( txnp->payload_sz && txnp->payload_sz<=FD_TPU_MTU );

  FD_TEST( fd_txn_parse_core( txnp->payload, txnp->payload_sz, txn_out, NULL, NULL ) );
  return (fd_txn_t const *)txn_out;
}

static void
test_count_vote_txn( void ) {

  /* Set up a minimal fd_tower_tile_t with just what count_vote_txn needs
     before hitting the tower validation checks: scratch_tower, metrics,
     and compact_tower_sync_serde. */

  static uchar tower_mem2[ 65536 ] __attribute__((aligned(128)));
  static uchar scratch_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ] __attribute__((aligned(FD_TOWER_VOTE_ALIGN)));
  static fd_tower_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );
  ctx->tower         = fd_tower_join( fd_tower_new( tower_mem2, 2, 2, 0 ) );
  ctx->scratch_tower = fd_tower_vote_join( fd_tower_vote_new( scratch_tower_mem ) );
  ctx->tower->root   = 0; /* mark as ready */
  FD_TEST( ctx->tower );
  FD_TEST( ctx->scratch_tower );

  fd_txn_p_t        txnp[1];
  uchar             txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_txn_t const *  txn;
  fd_hash_t         block_id_null    = {0};
  fd_hash_t         block_id_nonnull = { .ul = { 0xBB } };

  /* 1. Valid tower: 3 lockouts, strictly increasing slots, strictly
        decreasing confirmation counts.  Tower validation passes, then
        exits at null block_id check.  txn_bad_tower must stay 0. */

  {
    ulong slots[] = { 52, 57, 60 };
    ulong confs[] = { 31, 20, 1 };
    txn = mock_vote_txn( 42, 3, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==0 );
    FD_TEST( ctx->metrics.votes_unknown_block_id==1 );
  }

  /* 2. confirmation_count > FD_TOWER_VOTE_MAX. */

  {
    ulong slots[] = { 52 };
    ulong confs[] = { FD_TOWER_VOTE_MAX + 1 };
    txn = mock_vote_txn( 42, 1, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==1 );
  }

  /* 3. Non-decreasing confirmation counts (equal). */

  {
    ulong slots[] = { 52, 57 };
    ulong confs[] = { 10, 10 };
    txn = mock_vote_txn( 42, 2, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==1 );
  }

  /* 4. Increasing confirmation counts. */

  {
    ulong slots[] = { 52, 57, 60 };
    ulong confs[] = { 10, 5, 7 };
    txn = mock_vote_txn( 42, 3, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==1 );
  }

  /* 5. Valid 1-lockout tower. */

  {
    ulong slots[] = { 10 };
    ulong confs[] = { 1 };
    txn = mock_vote_txn( 0, 1, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==0 );
  }

  /* 6. Single valid lockout — edge case with exactly 1 vote. */

  {
    ulong slots[] = { 1 };
    ulong confs[] = { FD_TOWER_VOTE_MAX };
    txn = mock_vote_txn( 0, 1, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==0 );
  }

  /* 7. Empty tower (0 lockouts) — not a bad tower, hits
        txn_empty_tower.  Needs non-null block_id to get past the
        hash_null check. */

  {
    txn = mock_vote_txn( 42, 0, NULL, NULL, &block_id_nonnull, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==0 );
    FD_TEST( ctx->metrics.txn_empty_tower==1 );
  }

  /* 8. Max lockouts (FD_TOWER_VOTE_MAX), strictly decreasing confs. */

  {
    ulong slots[FD_TOWER_VOTE_MAX];
    ulong confs[FD_TOWER_VOTE_MAX];
    for( ulong i = 0; i < FD_TOWER_VOTE_MAX; i++ ) {
      slots[i] = i + 1;
      confs[i] = FD_TOWER_VOTE_MAX - i;
    }
    txn = mock_vote_txn( 0, FD_TOWER_VOTE_MAX, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==0 );
  }

  FD_LOG_NOTICE(( "pass: test_count_vote_txn_tower_checks" ));
}

/* ---- test_replay_slot_completed ---- */

#define MOCK_SLOT_MAX (64UL)

/* Fixture record layout: vote_acc(32) + id_key(32) + stake(8) +
   data_sz(8) + vote_data(FD_VOTE_STATE_DATA_MAX).  Each fixture file
   contains FIXTURE_VTR_CNT records for a single slot. */

#define FIXTURE_VTR_CNT    (100UL)
#define FIXTURE_RECORD_SZ  (32UL + 32UL + 8UL + 8UL + FD_VOTE_STATE_DATA_MAX)
#define FIXTURE_FILE_SZ    (FIXTURE_VTR_CNT * FIXTURE_RECORD_SZ)

/* mock_query_vote_accs: loads voter data from a fixture file for the
   current slot and calls count_vote_acc for each record. */

ulong
mock_query_vote_accs( fd_tower_tile_t *            ctx,
                      fd_replay_slot_completed_t * slot_completed,
                      fd_ghost_blk_t *             ghost_blk,
                      int *                        found_our_vote_acct,
                      ulong *                      our_vote_acct_bal ) {

  /* Open the fixture file for this slot. */

  char path[256];
  FD_TEST( snprintf( path, sizeof(path), "src/discof/tower/fixtures/voters-%lu.bin", slot_completed->slot ) < (int)sizeof(path) );

  FILE * f = fopen( path, "rb" );
  FD_TEST( f );

  static uchar buf[ FIXTURE_FILE_SZ ];
  FD_TEST( fread( buf, 1, FIXTURE_FILE_SZ, f )==FIXTURE_FILE_SZ );
  fclose( f );

  /* Iterate records. */

  ulong total_stake    = 0UL;
  ulong prev_voter_idx = ULONG_MAX;

  for( ulong i = 0UL; i < FIXTURE_VTR_CNT; i++ ) {
    uchar const * rec = buf + i * FIXTURE_RECORD_SZ;

    fd_pubkey_t vote_acc;
    memcpy( &vote_acc, rec, 32UL );

    ulong stake;
    memcpy( &stake, rec + 64UL, 8UL );

    uchar const * data = rec + 80UL;

    count_vote_acc( ctx, slot_completed, ghost_blk, &vote_acc, stake, data, FD_VOTE_STATE_DATA_MAX );

    total_stake += stake;
    prev_voter_idx = fd_tower_stakes_insert( ctx->tower, slot_completed->slot, &vote_acc, stake, prev_voter_idx );
  }

  /* No reconciliation in mock — just report not found. */

  *found_our_vote_acct = 0;
  *our_vote_acct_bal   = ULONG_MAX;

  return total_stake;
}

static void
test_fixture_replay( fd_wksp_t * wksp ) {

  /* Use scratch_footprint to compute the exact allocation size needed,
     matching the production init path.  We construct a mock
     fd_topo_tile_t with just the fields that scratch_footprint and
     init_choreo access. */

  fd_topo_tile_t tile[1];
  memset( tile, 0, sizeof(*tile) );
  tile->tower.max_live_slots = MOCK_SLOT_MAX;

  FD_TEST( scratch_align()==128UL );

  ulong footprint = scratch_footprint( tile );
  FD_TEST( footprint );

  void * scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), footprint, 1UL );
  FD_TEST( scratch );

  /* Initialize all choreo structures via the production init path.
     init_choreo handles scratch layout, new/join of all
     choreo structures, and state initialization. */

  ((fd_tower_tile_t *)scratch)->seed = 42UL;
  fd_tower_tile_t * ctx = init_choreo( scratch, tile );
  FD_TEST( ctx );

  /* Set fields normally handled by privileged_init. */

  ctx->checkpt_fd = -1;
  ctx->restore_fd = -1;
  memset( ctx->identity_key, 0x11, sizeof(fd_pubkey_t) );
  memset( ctx->vote_account, 0x22, sizeof(fd_pubkey_t) );

  /* Replay each fixture slot. */

  ulong start_slot = 398915634UL;
  ulong num_slots  = 32UL;

  for( ulong slot = start_slot; slot < start_slot + num_slots; slot++ ) {

    fd_replay_slot_completed_t sc;
    memset( &sc, 0, sizeof(sc) );
    sc.slot             = slot;
    sc.parent_slot      = slot - 1;
    sc.epoch            = 0;
    sc.block_id         = (fd_hash_t){ .ul = { slot } };
    sc.parent_block_id  = (fd_hash_t){ .ul = { slot - 1 } };
    sc.bank_hash        = (fd_hash_t){ .ul = { slot } };
    sc.block_hash       = (fd_hash_t){ .ul = { slot } };
    sc.bank_idx         = slot; /* arbitrary */
    sc.is_leader        = 0;

    replay_slot_completed( ctx, &sc, 0UL, NULL );
  }

  /* Verify: init flag set after first slot. */

  FD_TEST( ctx->init==1 );

  /* Verify: ghost root exists. */

  fd_ghost_blk_t * ghost_root = fd_ghost_root( ctx->ghost );
  FD_TEST( ghost_root );

  /* Verify: tower has blocks for all replayed slots. */

  for( ulong slot = start_slot; slot < start_slot + num_slots; slot++ ) {
    fd_tower_blk_t * blk = fd_tower_blocks_query( ctx->tower, slot );
    FD_TEST( blk );
    FD_TEST( blk->replayed==1 );
  }

  /* Verify: tower root set. */

  FD_TEST( ctx->tower->root!=ULONG_MAX );

  /* Verify: ghost has entries for all replayed slots. */

  for( ulong slot = start_slot; slot < start_slot + num_slots; slot++ ) {
    fd_hash_t bid = { .ul = { slot } };
    FD_TEST( fd_ghost_query( ctx->ghost, &bid ) );
  }

  FD_LOG_NOTICE(( "pass: test_fixture_replay" ));
}

/* ---- eqvoc ordering tests ----

   Three events for a slot with equivocation:
     R = first replay_slot_completed (we replay block A)
     E = equivocation detected (publish_slot_duplicate)
     C = CONFIRMED_DUPLICATE reached (publish_slot_confirmed)

   There are 3! = 6 orderings of {R, E, C} and 2 sub-cases for C
   (C=A: confirmed block matches replayed, C=B: differs), giving 12
   total cases.  Six are reducible:

     same (C=A):
       ECR ≡ ERC: E before R makes ghost invalid on replay.  C=A then
                  re-validates.  C and R commute after E, same end state.
       ERC ≡ REC: whether E arrives before or after R, the ghost block
                  is invalidated either way.  C=A then re-validates.
                  Same end state, so ERC is covered by REC.
       → 3 minimal: RCE, REC, CRE

     diff (C=B):
       RCE ≡ REC: after R, ghost A is valid.  C=B sets tower confirmed
                  and invalidates A.  E is then a no-op (already
                  confirmed).  Swapping C and E doesn't change the end
                  state because C=B always invalidates A.
       ECR ≡ CRE: C before R is a forward confirmation.  E before R
                  makes ghost invalid on replay.  Whether E or C comes
                  first doesn't matter — R reconciles both.
       CER ≡ CRE: C then E before R — same as CRE, E is redundant
                  once C has forward-confirmed.
       → 3 minimal: RCE, ERC, CRE

   We test the 6 minimal orderings below. */

static ulong mock_eqvoc_slot = ULONG_MAX;

int
mock_eqvoc_query_fn( fd_eqvoc_t * eqvoc FD_PARAM_UNUSED, ulong slot ) {
  return slot==mock_eqvoc_slot;
}

#define EQVOC_START_SLOT  398915634UL
#define EQVOC_BOOT_CNT   10UL

/* eqvoc_setup bootstraps a fresh choreo context by replaying
   EQVOC_BOOT_CNT slots.  Returns the initialized context. */

static fd_tower_tile_t *
eqvoc_setup( fd_wksp_t * wksp ) {
  fd_topo_tile_t tile[1];
  memset( tile, 0, sizeof(*tile) );
  tile->tower.max_live_slots = MOCK_SLOT_MAX;

  void * scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( tile ), 1UL );
  FD_TEST( scratch );

  ((fd_tower_tile_t *)scratch)->seed = 42UL;
  fd_tower_tile_t * ctx = init_choreo( scratch, tile );
  FD_TEST( ctx );

  ctx->checkpt_fd = -1;
  ctx->restore_fd = -1;
  memset( ctx->identity_key, 0x11, sizeof(fd_pubkey_t) );
  memset( ctx->vote_account, 0x22, sizeof(fd_pubkey_t) );

  for( ulong slot = EQVOC_START_SLOT; slot < EQVOC_START_SLOT + EQVOC_BOOT_CNT; slot++ ) {
    fd_replay_slot_completed_t sc;
    memset( &sc, 0, sizeof(sc) );
    sc.slot            = slot;
    sc.parent_slot     = slot - 1;
    sc.block_id        = (fd_hash_t){ .ul = { slot } };
    sc.parent_block_id = (fd_hash_t){ .ul = { slot - 1 } };
    sc.bank_hash       = (fd_hash_t){ .ul = { slot } };
    sc.block_hash      = (fd_hash_t){ .ul = { slot } };
    sc.bank_idx        = slot;
    replay_slot_completed( ctx, &sc, 0UL, NULL );
  }
  FD_TEST( ctx->init==1 );
  mock_eqvoc_slot = ULONG_MAX;
  return ctx;
}

/* Helpers for simulating R, E, C events. */

static void
mock_replay( fd_tower_tile_t * ctx,
           ulong             slot,
           fd_hash_t const * block_id ) {
  fd_replay_slot_completed_t sc;
  memset( &sc, 0, sizeof(sc) );
  sc.slot            = slot;
  sc.parent_slot     = slot - 1;
  sc.block_id        = *block_id;
  sc.parent_block_id = (fd_hash_t){ .ul = { slot - 1 } };
  sc.bank_hash       = (fd_hash_t){ .ul = { slot } };
  sc.block_hash      = (fd_hash_t){ .ul = { slot } };
  sc.bank_idx        = slot;
  replay_slot_completed( ctx, &sc, 0UL, NULL );
}

static void
mock_confirmed( fd_tower_tile_t * ctx,
              ulong             slot,
              fd_hash_t const * block_id ) {
  /* Create a votes_blk entry for (slot, block_id) if it doesn't
     already exist, then set stake high enough for DUPLICATE (52%). */

  if( !fd_votes_query( ctx->votes, slot, block_id ) ) {
    int err = fd_votes_count_vote( ctx->votes, &ctx->vote_accs[0], slot, block_id );
    FD_TEST( err==FD_VOTES_SUCCESS );
  }
  fd_votes_blk_t * vblk = fd_votes_query( ctx->votes, slot, block_id );
  FD_TEST( vblk );
  vblk->stake = 52;
  publish_slot_confirmed( ctx, slot, block_id, 100 );
}

static void
mock_eqvoc( fd_tower_tile_t * ctx,
          ulong             slot ) {
  static fd_gossip_duplicate_shred_t dummy_chunks[FD_EQVOC_CHUNK_CNT];
  publish_slot_duplicate( ctx, dummy_chunks, slot );
}

/* ---- C=A tests (confirmed block = replayed block) ---- */

static void
test_eqvoc_rce_same( fd_wksp_t * wksp ) {
  fd_tower_tile_t * ctx  = eqvoc_setup( wksp );
  ulong             slot = EQVOC_START_SLOT + EQVOC_BOOT_CNT;
  fd_hash_t         A    = { .ul = { slot } };

  mock_replay    ( ctx, slot, &A );
  mock_confirmed ( ctx, slot, &A );
  mock_eqvoc     ( ctx, slot );

  fd_tower_blk_t * tb = fd_tower_blocks_query( ctx->tower, slot );
  FD_TEST( tb && tb->confirmed==1 );
  FD_TEST( 0==memcmp( &tb->confirmed_block_id, &A, sizeof(fd_hash_t) ) );

  fd_ghost_blk_t * gb = fd_ghost_query( ctx->ghost, &A );
  FD_TEST( gb && gb->valid==1 );

  FD_LOG_NOTICE(( "pass: test_eqvoc_rce_same" ));
}

static void
test_eqvoc_rec_same( fd_wksp_t * wksp ) {
  fd_tower_tile_t * ctx  = eqvoc_setup( wksp );
  ulong             slot = EQVOC_START_SLOT + EQVOC_BOOT_CNT;
  fd_hash_t         A    = { .ul = { slot } };

  mock_replay ( ctx, slot, &A );
  mock_eqvoc  ( ctx, slot );

  /* After eqvoc, ghost A should be invalid. */

  FD_TEST( fd_ghost_query( ctx->ghost, &A )->valid==0 );

  mock_confirmed( ctx, slot, &A );

  /* Bug 1 fix: fd_ghost_confirm re-validates A. */

  fd_tower_blk_t * tb = fd_tower_blocks_query( ctx->tower, slot );
  FD_TEST( tb && tb->confirmed==1 );

  fd_ghost_blk_t * gb = fd_ghost_query( ctx->ghost, &A );
  FD_TEST( gb && gb->valid==1 );

  FD_LOG_NOTICE(( "pass: test_eqvoc_rec_same" ));
}

static void
test_eqvoc_cre_same( fd_wksp_t * wksp ) {
  fd_tower_tile_t * ctx  = eqvoc_setup( wksp );
  ulong             slot = EQVOC_START_SLOT + EQVOC_BOOT_CNT;
  fd_hash_t         A    = { .ul = { slot } };

  mock_confirmed ( ctx, slot, &A );

  /* Forward confirmation: no ghost or tower yet. */

  FD_TEST( !fd_tower_blocks_query( ctx->tower, slot ) );
  FD_TEST( !fd_ghost_query( ctx->ghost, &A ) );

  mock_replay ( ctx, slot, &A );
  mock_eqvoc  ( ctx, slot );

  fd_tower_blk_t * tb = fd_tower_blocks_query( ctx->tower, slot );
  FD_TEST( tb && tb->confirmed==1 );
  FD_TEST( 0==memcmp( &tb->confirmed_block_id, &A, sizeof(fd_hash_t) ) );

  fd_ghost_blk_t * gb = fd_ghost_query( ctx->ghost, &A );
  FD_TEST( gb && gb->valid==1 );

  FD_LOG_NOTICE(( "pass: test_eqvoc_cre_same" ));
}

/* ---- C=B tests (confirmed block differs from replayed block) ---- */

static void
test_eqvoc_rce_diff( fd_wksp_t * wksp ) {
  fd_tower_tile_t * ctx  = eqvoc_setup( wksp );
  ulong             slot = EQVOC_START_SLOT + EQVOC_BOOT_CNT;
  fd_hash_t         A    = { .ul = { slot } };
  fd_hash_t         B    = { .ul = { slot, 0xBB } };

  mock_replay    ( ctx, slot, &A );
  mock_confirmed ( ctx, slot, &B );
  mock_eqvoc     ( ctx, slot );

  fd_tower_blk_t * tb = fd_tower_blocks_query( ctx->tower, slot );
  FD_TEST( tb && tb->confirmed==1 );
  FD_TEST( 0==memcmp( &tb->confirmed_block_id, &B, sizeof(fd_hash_t) ) );

  fd_ghost_blk_t * gb = fd_ghost_query( ctx->ghost, &A );
  FD_TEST( gb && gb->valid==0 );

  FD_LOG_NOTICE(( "pass: test_eqvoc_rce_diff" ));
}

static void
test_eqvoc_erc_diff( fd_wksp_t * wksp ) {
  fd_tower_tile_t * ctx  = eqvoc_setup( wksp );
  ulong             slot = EQVOC_START_SLOT + EQVOC_BOOT_CNT;
  fd_hash_t         A    = { .ul = { slot } };
  fd_hash_t         B    = { .ul = { slot, 0xBB } };

  /* E before R: mock fd_eqvoc_query to return true for this slot. */

  mock_eqvoc_slot = slot;

  mock_replay    ( ctx, slot, &A );

  mock_eqvoc_slot = ULONG_MAX;

  /* Replay detected eqvoc → ghost A invalid. */

  FD_TEST( fd_ghost_query( ctx->ghost, &A )->valid==0 );

  mock_confirmed ( ctx, slot, &B );

  fd_tower_blk_t * tb = fd_tower_blocks_query( ctx->tower, slot );
  FD_TEST( tb && tb->confirmed==1 );
  FD_TEST( 0==memcmp( &tb->confirmed_block_id, &B, sizeof(fd_hash_t) ) );

  fd_ghost_blk_t * gb = fd_ghost_query( ctx->ghost, &A );
  FD_TEST( gb && gb->valid==0 );

  FD_LOG_NOTICE(( "pass: test_eqvoc_erc_diff" ));
}

static void
test_eqvoc_cre_diff( fd_wksp_t * wksp ) {
  fd_tower_tile_t * ctx  = eqvoc_setup( wksp );
  ulong             slot = EQVOC_START_SLOT + EQVOC_BOOT_CNT;
  fd_hash_t         A    = { .ul = { slot } };
  fd_hash_t         B    = { .ul = { slot, 0xBB } };

  mock_confirmed ( ctx, slot, &B );

  /* Forward confirmation for B: no ghost or tower yet. */

  FD_TEST( !fd_tower_blocks_query( ctx->tower, slot ) );

  mock_replay ( ctx, slot, &A );

  /* Bug 2 fix: fd_votes_query(NULL) finds B's fwd entry, sets
     tower confirmed and ghost_eqvoc(A). */

  fd_tower_blk_t * tb = fd_tower_blocks_query( ctx->tower, slot );
  FD_TEST( tb && tb->confirmed==1 );
  FD_TEST( 0==memcmp( &tb->confirmed_block_id, &B, sizeof(fd_hash_t) ) );

  fd_ghost_blk_t * gb = fd_ghost_query( ctx->ghost, &A );
  FD_TEST( gb && gb->valid==0 );

  mock_eqvoc ( ctx, slot );

  /* Eqvoc after confirmed is idempotent. */

  FD_TEST( tb->confirmed==1 );
  FD_TEST( gb->valid==0 );

  FD_LOG_NOTICE(( "pass: test_eqvoc_cre_diff" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_count_vote_txn();

  ulong       page_cnt = 4;
  char *      page_sz  = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_fixture_replay( wksp );

  fd_wksp_reset( wksp, 1UL ); test_eqvoc_rce_same( wksp );
  fd_wksp_reset( wksp, 1UL ); test_eqvoc_rec_same( wksp );
  fd_wksp_reset( wksp, 1UL ); test_eqvoc_cre_same( wksp );
  fd_wksp_reset( wksp, 1UL ); test_eqvoc_rce_diff( wksp );
  fd_wksp_reset( wksp, 1UL ); test_eqvoc_erc_diff( wksp );
  fd_wksp_reset( wksp, 1UL ); test_eqvoc_cre_diff( wksp );

  fd_halt();
}
