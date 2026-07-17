#define _GNU_SOURCE
#define QUERY_TOWERS mock_query_towers
#define QUERY_VOTERS mock_query_voters

#include "fd_tower_tile.c"
#include "../../disco/topo/fd_topob.h"

void
mock_query_voters( fd_tower_tile_t *            ctx,
                   fd_replay_slot_completed_t * slot_completed FD_PARAM_UNUSED,
                   ulong                        epoch ) {
  ctx->root_epoch = epoch;
}

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

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

static ulong
mock_vote_account( fd_pubkey_t const * node_pubkey,
                   fd_pubkey_t const * authorized_voter,
                   uchar               vote_state_data[ static FD_VOTE_STATE_DATA_MAX ] ) {
  fd_vote_state_versioned_t versioned[1];
  FD_TEST( fd_vote_state_versioned_new( versioned, fd_vote_state_versioned_enum_v3 ) );
  fd_memset( vote_state_data, 0, FD_VOTE_STATE_DATA_MAX );

  fd_vote_state_v3_t * vote_state   = &versioned->v3;
  vote_state->node_pubkey           = *node_pubkey;
  vote_state->authorized_withdrawer = *authorized_voter;
  vote_state->commission            = 100;
  vote_state->prior_voters.idx      = 31;
  vote_state->prior_voters.is_empty = 1;

  fd_vote_authorized_voter_t * voter = fd_vote_authorized_voters_pool_ele_acquire( vote_state->authorized_voters.pool );
  fd_memset( voter, 0, sizeof(fd_vote_authorized_voter_t) );
  voter->epoch  = 0UL;
  voter->pubkey = *authorized_voter;
  voter->prio   = authorized_voter->uc[0];
  fd_vote_authorized_voters_treap_ele_insert( vote_state->authorized_voters.treap, voter, vote_state->authorized_voters.pool );

  FD_TEST( !fd_vote_state_versioned_serialize( versioned, vote_state_data, FD_VOTE_STATE_DATA_MAX ) );
  return FD_VOTE_STATE_DATA_MAX;
}

static void
test_publish_slot_done_identity_mismatch( void ) {
  static fd_tower_tile_t ctx[1];
  static uchar tower_mem[ 65536 ] __attribute__((aligned(128)));
  static uchar publishes_mem[ 65536 ] __attribute__((aligned(128)));

  memset( ctx, 0, sizeof(*ctx) );
  memset( ctx->identity_key, 0x11, sizeof(fd_pubkey_t) );
  memset( ctx->vote_account, 0x22, sizeof(fd_pubkey_t) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 4096UL, 0UL, "tower_id_test", 0UL );
  FD_TEST( wksp );

  void * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( 2UL, 2UL ), 1UL );
  FD_TEST( ghost_mem );

  ctx->tower     = fd_tower_join( fd_tower_new( tower_mem, 2UL, 2UL, 0UL ) );
  ctx->ghost     = fd_ghost_join( fd_ghost_new( ghost_mem, 2UL, 2UL, 0UL ) );
  ctx->publishes = publishes_join( publishes_new( publishes_mem, 2UL ) );
  FD_TEST( ctx->tower );
  FD_TEST( ctx->ghost );
  FD_TEST( ctx->publishes );

  ctx->tower->root = 0UL;
  fd_tower_blk_t * parent_blk = fd_tower_blocks_insert( ctx->tower, 0UL, ULONG_MAX );
  FD_TEST( parent_blk );
  parent_blk->block_hash = (fd_hash_t){ .ul = { 0x66UL } };
  fd_tower_vote_push_tail( ctx->tower->votes, (fd_tower_vote_t){ .slot = 1UL, .conf = 1UL } );

  fd_replay_slot_completed_t sc;
  memset( &sc, 0, sizeof(sc) );
  sc.slot        = 1UL;
  sc.parent_slot = 0UL;
  sc.epoch       = 0UL;
  sc.bank_idx    = 123UL;

  fd_tower_out_t out;
  memset( &out, 0, sizeof(out) );
  out.vote_slot       = 1UL;
  out.vote_block_id   = (fd_hash_t){ .ul = { 0x33UL } };
  out.vote_bank_hash  = (fd_hash_t){ .ul = { 0x44UL } };
  out.reset_slot      = ULONG_MAX;
  out.root_slot       = ULONG_MAX;

  /* Matching identity produces votes */
  ctx->our_vote_acct_sz = mock_vote_account( ctx->identity_key, ctx->identity_key, ctx->our_vote_acct );
  publish_slot_done( ctx, &sc, &out, 1, 100UL, 0UL, NULL );
  publish_t * pub = publishes_peek_head( ctx->publishes );
  FD_TEST( pub );
  FD_TEST( pub->sig==FD_TOWER_SIG_SLOT_DONE );
  FD_TEST( pub->msg.slot_done.has_vote_txn==1 );
  FD_TEST( pub->msg.slot_done.is_voting==1 );
  FD_TEST( pub->msg.slot_done.authority_idx==ULONG_MAX );
  publishes_pop_head_nocopy( ctx->publishes );

  /* Matching identity but no votable slot: voter with no vote txn */
  fd_tower_out_t out_no_vote = out;
  out_no_vote.vote_slot = ULONG_MAX;
  publish_slot_done( ctx, &sc, &out_no_vote, 1, 100UL, 0UL, NULL );
  pub = publishes_peek_head( ctx->publishes );
  FD_TEST( pub );
  FD_TEST( pub->sig==FD_TOWER_SIG_SLOT_DONE );
  FD_TEST( pub->msg.slot_done.has_vote_txn==0 );
  FD_TEST( pub->msg.slot_done.is_voting==1 );
  publishes_pop_head_nocopy( ctx->publishes );

  /* Other identity prevents vote publishing */
  fd_pubkey_t other_identity = { .ul = { 0x99UL } };
  ctx->our_vote_acct_sz = mock_vote_account( &other_identity, ctx->identity_key, ctx->our_vote_acct );
  publish_slot_done( ctx, &sc, &out, 1, 100UL, 0UL, NULL );
  pub = publishes_peek_head( ctx->publishes );
  FD_TEST( pub );
  FD_TEST( pub->sig==FD_TOWER_SIG_SLOT_DONE );
  FD_TEST( pub->msg.slot_done.has_vote_txn==0 );
  FD_TEST( pub->msg.slot_done.is_voting==0 );

  fd_wksp_delete( fd_wksp_leave( wksp ) );

  FD_LOG_NOTICE(( "pass: test_publish_slot_done_identity_mismatch" ));
}

static void
test_count_vote_txn( void ) {

  /* Set up a minimal fd_tower_tile_t with just what count_vote_txn needs
     before hitting the tower validation checks: scratch_tower, metrics,
     and compact_tower_sync_serde. */

  static uchar tower_mem2[ 65536 ] __attribute__((aligned(128)));
  static uchar scratch_tower_mem[ FD_TOWER_VOTE_FOOTPRINT ] __attribute__((aligned(FD_TOWER_VOTE_ALIGN)));
  static uchar root_vtr_pool_mem[ 65536 ] __attribute__((aligned(128)));
  static uchar root_vtr_map_mem [ 65536 ] __attribute__((aligned(128)));
  static uchar next_vtr_pool_mem[ 65536 ] __attribute__((aligned(128)));
  static uchar next_vtr_map_mem [ 65536 ] __attribute__((aligned(128)));
  static fd_tower_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );
  ctx->tower         = fd_tower_join( fd_tower_new( tower_mem2, 2, 2, 0 ) );
  ctx->scratch_tower = fd_tower_vote_join( fd_tower_vote_new( scratch_tower_mem ) );
  ctx->tower->root   = 0; /* mark as ready */

  ulong vtr_chain_cnt = epoch_vtr_map_chain_cnt_est( 4UL );
  ctx->root_epoch_vtr_pool = epoch_vtr_pool_join( epoch_vtr_pool_new( root_vtr_pool_mem, 4UL ) );
  ctx->root_epoch_vtr_map  = epoch_vtr_map_join ( epoch_vtr_map_new ( root_vtr_map_mem,  vtr_chain_cnt, 0UL ) );
  ctx->next_epoch_vtr_pool = epoch_vtr_pool_join( epoch_vtr_pool_new( next_vtr_pool_mem, 4UL ) );
  ctx->next_epoch_vtr_map  = epoch_vtr_map_join ( epoch_vtr_map_new ( next_vtr_map_mem,  vtr_chain_cnt, 0UL ) );

  FD_TEST( ctx->tower );
  FD_TEST( ctx->scratch_tower );
  FD_TEST( ctx->root_epoch_vtr_pool && ctx->root_epoch_vtr_map );
  FD_TEST( ctx->next_epoch_vtr_pool && ctx->next_epoch_vtr_map );

  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) );
  FD_TEST( ctx->mleaders );

  fd_txn_p_t        txnp[1];
  uchar             txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_txn_t const *  txn;
  fd_hash_t         block_id_null    = {0};
  fd_hash_t         block_id_nonnull = { .ul = { 0xBB } };

  /* 1. Valid tower: 3 lockouts, strictly increasing slots, strictly
        decreasing confirmation counts.  Tower validation passes, then
        exits at null block_id check.  BadTower must stay 0. */

  {
    ulong slots[] = { 52, 57, 60 };
    ulong confs[] = { 31, 20, 1 };
    txn = mock_vote_txn( 42, 3, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX      ]==0 );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_UNKNOWN_BLOCK_ID_IDX ]==1 );
  }

  /* 2. confirmation_count > FD_TOWER_VOTE_MAX. */

  {
    ulong slots[] = { 52 };
    ulong confs[] = { FD_TOWER_VOTE_MAX + 1 };
    txn = mock_vote_txn( 42, 1, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]==1 );
  }

  /* 3. Non-decreasing confirmation counts (equal). */

  {
    ulong slots[] = { 52, 57 };
    ulong confs[] = { 10, 10 };
    txn = mock_vote_txn( 42, 2, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]==1 );
  }

  /* 4. Increasing confirmation counts. */

  {
    ulong slots[] = { 52, 57, 60 };
    ulong confs[] = { 10, 5, 7 };
    txn = mock_vote_txn( 42, 3, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]==1 );
  }

  /* 5. Valid 1-lockout tower. */

  {
    ulong slots[] = { 10 };
    ulong confs[] = { 1 };
    txn = mock_vote_txn( 0, 1, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]==0 );
  }

  /* 6. Single valid lockout — edge case with exactly 1 vote. */

  {
    ulong slots[] = { 1 };
    ulong confs[] = { FD_TOWER_VOTE_MAX };
    txn = mock_vote_txn( 0, 1, slots, confs, &block_id_null, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]==0 );
  }

  /* 7. Empty tower (0 lockouts) — not a bad tower, hits EmptyTower.
        Needs non-null block_id to get past the hash_null check. */

  {
    txn = mock_vote_txn( 42, 0, NULL, NULL, &block_id_nonnull, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX   ]==0 );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_EMPTY_TOWER_IDX ]==1 );
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
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_BAD_TOWER_IDX ]==0 );
  }

  /* 9. Vote epoch > root_epoch+1 — too far ahead.  Tower validation
        passes, block_id is non-null, last_vote_slot > tower root,
        lsched returns epoch=2 against root_epoch=0 → votes_too_new. */

  {
    ulong slots[] = { 10 };
    ulong confs[] = { 1 };
    txn = mock_vote_txn( 0, 1, slots, confs, &block_id_nonnull, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    ctx->root_epoch                    = 0;
    ctx->mleaders->lsched[0]->epoch    = 2;
    ctx->mleaders->lsched[0]->slot0    = 0;
    ctx->mleaders->lsched[0]->slot_cnt = 100;
    ctx->mleaders->init_done[0]        = 1;
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_NOT_STAKED_IDX ]==1 );
  }

  /* 10. Vote epoch == root_epoch+1 — valid case, takes the
         next_epoch_vtr_map branch.  The map is empty so the per-vtr
         lookup returns NULL → NOT_STAKED (not rejected as too new). */

  {
    ulong slots[] = { 10 };
    ulong confs[] = { 1 };
    txn = mock_vote_txn( 0, 1, slots, confs, &block_id_nonnull, txnp, txn_mem );
    memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
    ctx->root_epoch                 = 0;
    ctx->mleaders->lsched[0]->epoch = 1;
    count_vote_txn( ctx, txn, txnp->payload );
    FD_TEST( ctx->metrics.votes[ FD_METRICS_ENUM_VOTE_TXN_RESULT_V_NOT_STAKED_IDX ]==1 );
  }

  FD_LOG_NOTICE(( "pass: test_count_vote_txn_tower_checks" ));
}

static void
test_parent_vote_txn_recent_blockhash( void ) {
  static fd_tower_tile_t ctx[1];
  static uchar tower_mem[ 1UL<<20 ] __attribute__((aligned(128)));
  memset( ctx, 0, sizeof(ctx) );
  ctx->tower = fd_tower_join( fd_tower_new( tower_mem, 32UL, 1UL, 0UL ) );
  FD_TEST( ctx->tower );

  fd_tower_blk_t * parent_blk = fd_tower_blocks_insert( ctx->tower, 103UL, 102UL );
  FD_TEST( parent_blk );
  parent_blk->block_hash = (fd_hash_t){ .ul = { 1103UL } };

  fd_tower_blk_t * root_blk = fd_tower_blocks_insert( ctx->tower, 104UL, 103UL );
  FD_TEST( root_blk );
  root_blk->block_hash = (fd_hash_t){ .ul = { 1104UL } };
  ctx->tower->root = 104UL;
  fd_tower_vote_push_tail( ctx->tower->votes, (fd_tower_vote_t){ .slot = 120UL, .conf = 1UL } );

  fd_replay_slot_completed_t slot_completed = {0};
  slot_completed.parent_slot = 103UL;
  fd_hash_t bank_hash          = { .ul = { 0xAAUL } };
  fd_hash_t block_id           = { .ul = { 0xBBUL } };
  fd_pubkey_t validator_identity = { .ul = { 0x11UL } };
  fd_pubkey_t vote_acc           = { .ul = { 0x22UL } };
  fd_txn_p_t txnp[1];

  fd_tower_blk_t *  recent_blockhash_blk = fd_tower_blocks_query( ctx->tower, slot_completed.parent_slot );
  FD_TEST( recent_blockhash_blk );
  fd_hash_t const * recent_blockhash = fd_type_pun_const( recent_blockhash_blk->block_hash.uc );
  fd_tower_to_vote_txn( ctx->tower, &bank_hash, &block_id, recent_blockhash, &validator_identity, &validator_identity, &vote_acc, txnp );

  uchar txn_mem[ FD_TXN_MAX_SZ ];
  ulong parse_result = fd_txn_parse_core( txnp->payload, txnp->payload_sz, txn_mem, NULL, NULL );
  FD_TEST( parse_result>0UL );
  fd_txn_t const * txn = (fd_txn_t const *)txn_mem;
  FD_TEST( 0==memcmp( fd_txn_get_recent_blockhash( txn, txnp->payload ), &parent_blk->block_hash, sizeof(fd_hash_t) ) );

  FD_LOG_NOTICE(( "pass: test_parent_vote_txn_recent_blockhash" ));
}

/* ---- test_fixture_replay ---- */

#define MOCK_SLOT_MAX (64UL)

/* Fixture record layout: vote_acc(32) + id_key(32) + stake(8) +
   data_sz(8) + vote_data(FD_VOTE_STATE_DATA_MAX).  Each fixture file
   contains FIXTURE_VTR_CNT records for a single slot. */

#define FIXTURE_VTR_CNT    (100UL)
#define FIXTURE_RECORD_SZ  (32UL + 32UL + 8UL + 8UL + FD_VOTE_STATE_DATA_MAX)
#define FIXTURE_FILE_SZ    (FIXTURE_VTR_CNT * FIXTURE_RECORD_SZ)

/* mock_query_towers: loads voter data from a fixture file for the
   current slot and calls count_vote_acc for each record. */

ulong
mock_query_towers( fd_tower_tile_t *            ctx,
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

    ctx->vote_accs[i] = vote_acc;
    fd_vote_account_node_pubkey( data, FD_VOTE_STATE_DATA_MAX, &ctx->id_keys[i] );

    total_stake += stake;
    prev_voter_idx = fd_tower_stakes_insert( ctx->tower, slot_completed->slot, &vote_acc, stake, prev_voter_idx );
  }

  /* No reconciliation in mock — just report not found. */

  *found_our_vote_acct = 0;
  *our_vote_acct_bal   = ULONG_MAX;

  return total_stake;
}

/* mock_topo_with_accdb constructs a minimal fd_topo_t containing one
   accdb shmem object and wires tile->tower.accdb_obj_id to it.  This is
   needed because init_choreo joins fd_accdb against
   tile->tower.accdb_obj_id.  Also dups a memfd onto fd FD_ACCDB_FD_RW so that
   the writer accdb join in init_choreo has a valid backing fd. */

static void
mock_topo_with_accdb( fd_wksp_t *      wksp,
                      fd_topo_t *      topo,
                      fd_topo_tile_t * tile ) {
  static int      accdb_data_fd = -1;
  static int      fd_inited     = 0;
  if( !fd_inited ) {
    accdb_data_fd = memfd_create( "tower_accdb_test_data", 0 );
    FD_TEST( accdb_data_fd>=0 );
    FD_TEST( dup2( accdb_data_fd, FD_ACCDB_FD_RW )==FD_ACCDB_FD_RW );
    fd_inited = 1;
  }

  ulong const max_accounts        = 1024UL;
  ulong const max_writes_per_slot = 64UL;
  ulong const partition_cnt       = 8192UL;
  ulong const partition_sz        = 1UL<<24UL;
  ulong const cache_fp            = 64UL<<20UL;
  ulong const cache_min_reserved  = 1UL;
  ulong const joiner_cnt          = 1UL;

  memset( topo, 0, sizeof(*topo) );
  fd_topob_new( topo, "topo" );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "wksp" );
  topo_wksp->wksp = wksp;

  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, tile->tower.max_live_slots, max_writes_per_slot, partition_cnt, cache_fp, cache_min_reserved, joiner_cnt );
  void * shmem_mem = fd_wksp_alloc_laddr( wksp, fd_accdb_shmem_align(), shmem_fp, 1UL );
  FD_TEST( shmem_mem );
  FD_TEST( fd_accdb_shmem_new( shmem_mem, max_accounts, tile->tower.max_live_slots, max_writes_per_slot, partition_cnt, partition_sz, cache_fp, cache_min_reserved, 0, 42UL, joiner_cnt ) );

  fd_topo_obj_t * shmem_obj = fd_topob_obj( topo, "accdb_shmem", "wksp" );
  shmem_obj->wksp_id = topo_wksp->id;
  shmem_obj->offset  = fd_wksp_gaddr_fast( wksp, shmem_mem );

  tile->tower.accdb_obj_id = shmem_obj->id;
}

static void
test_fixture_replay( fd_wksp_t * wksp ) {

  /* Use scratch_footprint to compute the exact allocation size needed,
     matching the production init path.  We construct a mock
     fd_topo_tile_t with just the fields that scratch_footprint and
     init_choreo access. */

  static fd_topo_tile_t tile[1];
  memset( tile, 0, sizeof(*tile) );
  tile->tower.max_live_slots = MOCK_SLOT_MAX;

  static fd_topo_t topo[1];
  mock_topo_with_accdb( wksp, topo, tile );

  FD_TEST( scratch_align()==128UL );

  ulong footprint = scratch_footprint( tile );
  FD_TEST( footprint );

  void * scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), footprint, 1UL );
  FD_TEST( scratch );

  /* Initialize all choreo structures via the production init path.
     init_choreo handles scratch layout, new/join of all
     choreo structures, and state initialization. */

  ((fd_tower_tile_t *)scratch)->seed = 42UL;
  fd_tower_tile_t * ctx = init_choreo( scratch, topo, tile );
  FD_TEST( ctx );

  /* Set fields normally handled by privileged_init. */

  ctx->checkpt_fd = -1;
  ctx->restore_fd = -1;
  memset( ctx->identity_key, 0x11, sizeof(fd_pubkey_t) );
  memset( ctx->vote_account, 0x22, sizeof(fd_pubkey_t) );

  /* Replay each fixture slot. */

  ulong start_slot = 398915634UL;
  ulong num_slots  = 32UL;

  fd_vote_stake_weight_t fixture_stakes[1] = {{ .vote_key = {{0}}, .id_key = {{0}}, .stake = 1UL }};
  ctx->mleaders->lsched[0] = fd_epoch_leaders_join( fd_epoch_leaders_new( ctx->mleaders->_lsched[0], 0, start_slot - 1, num_slots + MOCK_SLOT_MAX + 100, 1UL, fixture_stakes, 0UL ) );
  ctx->mleaders->init_done[0] = 1;

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

  FD_TEST( fd_ghost_root( ctx->ghost ) );

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

   3! = 6 orderings × 2 sub-cases for C (C=A: confirmed block matches
   replayed; C=B: differs) = 12 total cases.  Six reduce, leaving 6
   minimal that we test below:

           C = A (confirmed = replayed)        C = B (confirmed ≠ replayed)
        +-------+--------+----------------+ +-------+--------+----------------+
        | Order | Status | Reduces to     | | Order | Status | Reduces to     |
        +-------+--------+----------------+ +-------+--------+----------------+
        | RCE   | tested |                | | RCE   | tested |                |
        | REC   | tested |                | | ERC   | tested |                |
        | CRE   | tested |                | | CRE   | tested |                |
        | ERC   |        | REC            | | REC   |        | RCE            |
        | ECR   |        | ERC → REC      | | ECR   |        | CRE            |
        | CER   |        | CRE            | | CER   |        | CRE            |
        +-------+--------+----------------+ +-------+--------+----------------+

   Why the reductions hold:
     C=A:  ECR ≡ ERC: C and R commute after E.
           ERC ≡ REC: ghost A invalid either way; C=A re-validates.
           CER ≡ CRE: E is a no-op once C has forward-confirmed A.
     C=B:  REC ≡ RCE: C=B invalidates A; swapping C/E preserves end state.
           ECR ≡ CRE: R reconciles both — E/C order before R doesn't matter.
           CER ≡ CRE: E redundant once C has forward-confirmed B. */

#define EQVOC_START_SLOT  398915634UL
#define EQVOC_BOOT_CNT   10UL

/* eqvoc_setup bootstraps a fresh choreo context by replaying
   EQVOC_BOOT_CNT slots.  Returns the initialized context. */

static fd_tower_tile_t *
eqvoc_setup( fd_wksp_t * wksp ) {
  static fd_topo_tile_t tile[1];
  memset( tile, 0, sizeof(*tile) );
  tile->tower.max_live_slots = MOCK_SLOT_MAX;

  static fd_topo_t topo[1];
  memset( topo, 0, sizeof(*topo) );
  mock_topo_with_accdb( wksp, topo, tile );

  void * scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( tile ), 1UL );
  FD_TEST( scratch );

  ((fd_tower_tile_t *)scratch)->seed = 42UL;
  fd_tower_tile_t * ctx = init_choreo( scratch, topo, tile );
  FD_TEST( ctx );

  ctx->checkpt_fd = -1;
  ctx->restore_fd = -1;
  memset( ctx->identity_key, 0x11, sizeof(fd_pubkey_t) );
  memset( ctx->vote_account, 0x22, sizeof(fd_pubkey_t) );

  fd_vote_stake_weight_t eqvoc_stakes[1] = {{ .vote_key = {{0}}, .id_key = {{0}}, .stake = 1UL }};
  ulong eqvoc_slot_cnt = EQVOC_BOOT_CNT + MOCK_SLOT_MAX + 100;
  ctx->mleaders->lsched[0] = fd_epoch_leaders_join( fd_epoch_leaders_new( ctx->mleaders->_lsched[0], 0, EQVOC_START_SLOT - 1, eqvoc_slot_cnt, 1UL, eqvoc_stakes, 0UL ) );
  ctx->mleaders->init_done[0] = 1;

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
     already exist, then set stake high enough for DUPLICATE (>52%). */

  if( !fd_votes_query( ctx->votes, slot, block_id ) ) {
    int err = fd_votes_count_vote( ctx->votes, &ctx->vote_accs[0], 1UL, slot, block_id );
    FD_TEST( err==FD_VOTES_SUCCESS );
  }
  fd_votes_blk_t * vblk = fd_votes_query( ctx->votes, slot, block_id );
  FD_TEST( vblk );
  vblk->stake = 53;
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

  /* fd_ghost_confirm re-validates A. */

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

  /* E before R: insert two conflicting shreds into eqvoc so that
     fd_eqvoc_proof_verified returns true when replay checks it. */

  {
    static uchar s1[FD_SHRED_MAX_SZ], s2[FD_SHRED_MAX_SZ];
    memset( s1, 0, sizeof(s1) );
    memset( s2, 0, sizeof(s2) );
    fd_shred_t * shred1 = (fd_shred_t *)s1;
    fd_shred_t * shred2 = (fd_shred_t *)s2;
    shred1->variant     = FD_SHRED_TYPE_MERKLE_DATA;
    shred1->slot        = slot;
    shred1->fec_set_idx = 0;
    shred2->variant     = FD_SHRED_TYPE_MERKLE_DATA;
    shred2->slot        = slot;
    shred2->fec_set_idx = 0;
    fd_gossip_duplicate_shred_t proof_chunks[FD_EQVOC_CHUNK_CNT];
    FD_TEST( fd_eqvoc_shred_insert( ctx->eqvoc, 0, shred1, proof_chunks )==0 );
    FD_TEST( fd_eqvoc_shred_insert( ctx->eqvoc, 1, shred2, proof_chunks )==1 );
    FD_TEST( fd_eqvoc_proof_verified( ctx->eqvoc, slot ) );
  }

  mock_replay( ctx, slot, &A );

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

  /* fd_votes_query(NULL) finds B's fwd entry, sets tower confirmed and
     ghost_eqvoc(A). */

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

  test_publish_slot_done_identity_mismatch();
  test_count_vote_txn();
  test_parent_vote_txn_recent_blockhash();

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"              );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 4UL                     );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
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
