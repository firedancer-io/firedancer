#include "fd_tower_tile.c"

#include <string.h>

/* mock_vote_txn builds a vote transaction from a tower.  Constructs an
   fd_tower_t with the given (slot, conf) pairs, serializes it via
   fd_tower_to_vote_txn, and returns the parsed fd_txn_t and payload.

   slots and confs are arrays of length cnt.  block_id controls the
   block_id in the serde (null block_id causes count_vote to exit at
   the hash_null check after tower validation). */

static fd_txn_t const *
mock_vote_txn( ulong               root,
               ulong               cnt,
               ulong const *       slots,
               ulong const *       confs,
               fd_hash_t const *   block_id,
               fd_txn_p_t *        txnp,
               uchar               txn_out[ static FD_TXN_MAX_SZ ] ) {

  static uchar tower_mem[ FD_TOWER_FOOTPRINT ] __attribute__((aligned(FD_TOWER_ALIGN)));
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem ) );

  for( ulong i = 0; i < cnt; i++ ) {
    fd_tower_push_tail( tower, (fd_tower_vote_t){ .slot = slots[i], .conf = confs[i] } );
  }

  fd_hash_t     bank_hash          = { .ul = { 0xAA } };
  fd_hash_t     recent_blockhash   = {0};
  fd_pubkey_t   validator_identity = { .ul = { 0x11 } };
  fd_pubkey_t   vote_acc           = { .ul = { 0x22 } };

  fd_tower_to_vote_txn( tower, root, &bank_hash, block_id, &recent_blockhash, &validator_identity, &validator_identity, &vote_acc, txnp );
  FD_TEST( txnp->payload_sz && txnp->payload_sz<=FD_TPU_MTU );

  FD_TEST( fd_txn_parse_core( txnp->payload, txnp->payload_sz, txn_out, NULL, NULL ) );
  return (fd_txn_t const *)txn_out;
}

static void
test_count_vote_tower_checks( void ) {

  /* Set up a minimal fd_tower_tile_t with just what count_vote needs
     before hitting the tower validation checks: scratch_tower, metrics,
     and compact_tower_sync_serde. */

  static uchar scratch_tower_mem[ FD_TOWER_FOOTPRINT ] __attribute__((aligned(FD_TOWER_ALIGN)));
  static fd_tower_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );
  ctx->scratch_tower = fd_tower_join( fd_tower_new( scratch_tower_mem ) );
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
    count_vote( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==0 );
    FD_TEST( ctx->metrics.votes_unknown_block_id==1 );
  }

  /* 2. confirmation_count > FD_TOWER_VOTE_MAX. */

  {
    ulong slots[] = { 52 };
    ulong confs[] = { FD_TOWER_VOTE_MAX + 1 };
    txn = mock_vote_txn( 42, 1, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==1 );
  }

  /* 3. Non-decreasing confirmation counts (equal). */

  {
    ulong slots[] = { 52, 57 };
    ulong confs[] = { 10, 10 };
    txn = mock_vote_txn( 42, 2, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==1 );
  }

  /* 4. Increasing confirmation counts. */

  {
    ulong slots[] = { 52, 57, 60 };
    ulong confs[] = { 10, 5, 7 };
    txn = mock_vote_txn( 42, 3, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==1 );
  }

  /* 5. Valid 1-lockout tower. */

  {
    ulong slots[] = { 10 };
    ulong confs[] = { 1 };
    txn = mock_vote_txn( 0, 1, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==0 );
  }

  /* 6. Single valid lockout — edge case with exactly 1 vote. */

  {
    ulong slots[] = { 1 };
    ulong confs[] = { FD_TOWER_VOTE_MAX };
    txn = mock_vote_txn( 0, 1, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==0 );
  }

  /* 7. Empty tower (0 lockouts) — not a bad tower, hits
        txn_empty_tower.  Needs non-null block_id to get past the
        hash_null check. */

  {
    txn = mock_vote_txn( 42, 0, NULL, NULL, &block_id_nonnull, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote( ctx, txn, txnp->payload );
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
    count_vote( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.txn_bad_tower==0 );
  }

  FD_LOG_NOTICE(( "pass: test_count_vote_tower_checks" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_count_vote_tower_checks();
  fd_halt();
}
