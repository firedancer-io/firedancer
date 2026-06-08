/* test_replay_tile.c — Tests the replay tile's FEC consumption path
   through reasm, verifying that equivocating FEC sets are not delivered.

   Follows the pattern of test_repair_tile.c and test_tower_tile.c:
   mock heavy dependencies via #define before including the tile .c. */

#include "../../disco/topo/fd_topo.h" /* pulls in fd_stem.h */

/* ---- Mock fd_stem_publish ---- */

static ulong mock_stem_publish_cnt;
#undef  fd_stem_publish
#define fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub ) \
  do { (void)(stem); (void)(out_idx); (void)(sig); (void)(chunk); (void)(sz); \
       (void)(ctl); (void)(tsorig); (void)(tspub); mock_stem_publish_cnt++; } while(0)

/* ---- Mock store lock macros ----
   Include fd_store.h first to get the type definitions, then override
   the lock macros to no-ops. */

#include "../../disco/store/fd_store.h"
#undef  FD_STORE_SLOCK_BEGIN
#undef  FD_STORE_SLOCK_END
#define FD_STORE_SLOCK_BEGIN(store) { (void)(store);
#define FD_STORE_SLOCK_END }

/* ---- Pull in type definitions we need for mock function signatures.
   These headers are guarded, so the re-include from fd_replay_tile.c
   will be a no-op. ---- */

#include "../../flamenco/runtime/fd_bank.h"
#include "fd_sched.h"

/* ---- Mock banks ---- */

#define MOCK_BANKS_MAX 16

static fd_bank_t   mock_banks_arr[ MOCK_BANKS_MAX ];
static ulong       mock_banks_next = 1UL; /* 0 is reserved for root */

fd_bank_t *
mock_banks_bank_query_fn( fd_banks_t * banks FD_PARAM_UNUSED,
                          ulong        bank_idx ) {
  if( FD_UNLIKELY( bank_idx>=MOCK_BANKS_MAX ) ) return NULL;
  return &mock_banks_arr[ bank_idx ];
}

fd_bank_t *
mock_banks_new_bank_fn( fd_banks_t * banks FD_PARAM_UNUSED,
                        ulong        parent_bank_idx FD_PARAM_UNUSED,
                        long         now FD_PARAM_UNUSED ) {
  FD_TEST( mock_banks_next < MOCK_BANKS_MAX );
  ulong idx = mock_banks_next++;
  fd_bank_t * bank = &mock_banks_arr[ idx ];
  memset( bank, 0, sizeof(fd_bank_t) );
  bank->idx      = idx;
  bank->bank_seq = idx;
  bank->state    = FD_BANK_STATE_FROZEN;
  return bank;
}

int   mock_banks_is_full_fn   ( fd_banks_t * b FD_PARAM_UNUSED ) { return 0; }
void  mock_banks_mark_dead_fn ( fd_banks_t * b FD_PARAM_UNUSED, ulong i FD_PARAM_UNUSED, ulong * dead_idxs FD_PARAM_UNUSED, ulong * dead_idxs_cnt FD_PARAM_UNUSED ) {}
ulong mock_banks_pool_used_fn ( fd_banks_t * b FD_PARAM_UNUSED ) { return 0; }
int   mock_banks_prune_one_fn ( fd_banks_t * b FD_PARAM_UNUSED, fd_banks_prune_cancel_info_t * ci FD_PARAM_UNUSED ) { return 0; }
void  mock_banks_get_frontier_fn( fd_banks_t * b FD_PARAM_UNUSED, ulong * out FD_PARAM_UNUSED, ulong * cnt FD_PARAM_UNUSED ) { *cnt = 0; }

fd_bank_t *
mock_banks_clone_fn( fd_banks_t * banks FD_PARAM_UNUSED, ulong bank_idx ) {
  return &mock_banks_arr[ bank_idx ];
}

#define fd_banks_bank_query          mock_banks_bank_query_fn
#define fd_banks_new_bank            mock_banks_new_bank_fn
#define fd_banks_is_full             mock_banks_is_full_fn
#define fd_banks_mark_bank_dead      mock_banks_mark_dead_fn
#define fd_banks_pool_used_cnt       mock_banks_pool_used_fn
#define fd_banks_prune_one_dead_bank mock_banks_prune_one_fn
#define fd_banks_get_frontier        mock_banks_get_frontier_fn
#define fd_banks_clone_from_parent   mock_banks_clone_fn

/* ---- Mock store ---- */

static fd_store_fec_t mock_store_fec;
static uchar          mock_store_data[ 4096 ];

fd_store_fec_t *
mock_store_query_fn( fd_store_t *      store FD_PARAM_UNUSED,
                     fd_hash_t const * merkle_root FD_PARAM_UNUSED ) {
  return &mock_store_fec;
}

#define fd_store_query mock_store_query_fn

/* ---- Mock sched ---- */

static fd_sched_fec_t mock_sched_last_fec;
static int            mock_sched_fec_ingest_called;

int mock_sched_fec_ingest_fn( fd_sched_t * s FD_PARAM_UNUSED, fd_sched_fec_t * f ) {
  mock_sched_last_fec = *f;
  mock_sched_fec_ingest_called = 1;
  return 1;
}
ulong mock_sched_can_ingest_fn  ( fd_sched_t * s FD_PARAM_UNUSED ) { return ULONG_MAX; }
int   mock_sched_is_drained_fn  ( fd_sched_t * s FD_PARAM_UNUSED ) { return 1; }
void  mock_sched_abandon_fn     ( fd_sched_t * s FD_PARAM_UNUSED, ulong i FD_PARAM_UNUSED ) {}
ulong mock_sched_pruned_fn      ( fd_sched_t * s FD_PARAM_UNUSED ) { return ULONG_MAX; }
void  mock_sched_metrics_fn     ( fd_sched_t * s FD_PARAM_UNUSED ) {}
void  mock_sched_poh_fn         ( fd_sched_t * s FD_PARAM_UNUSED, ulong a FD_PARAM_UNUSED, ulong b FD_PARAM_UNUSED, ulong c FD_PARAM_UNUSED, ulong d FD_PARAM_UNUSED, fd_hash_t const * e FD_PARAM_UNUSED ) {}

#define fd_sched_fec_ingest        mock_sched_fec_ingest_fn
#define fd_sched_can_ingest_cnt    mock_sched_can_ingest_fn
#define fd_sched_is_drained        mock_sched_is_drained_fn
#define fd_sched_block_abandon     mock_sched_abandon_fn
#define fd_sched_pruned_block_next mock_sched_pruned_fn
#define fd_sched_metrics_write     mock_sched_metrics_fn
#define fd_sched_set_poh_params    mock_sched_poh_fn

/* ---- Include the tile under test ---- */

#include "fd_replay_tile.c"

/* ---- Test setup ---- */

static void
setup_ctx( fd_replay_tile_t * ctx, fd_wksp_t * wksp ) {
  memset( ctx, 0, sizeof(*ctx) );

  /* Reasm */

  ulong fec_max = 32UL;
  void * reasm_mem = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  FD_TEST( reasm_mem );
  ctx->reasm = fd_reasm_join( fd_reasm_new( reasm_mem, fec_max, 0UL ) );
  FD_TEST( ctx->reasm );

  /* Block-id map */

  ulong bid_cnt   = MOCK_BANKS_MAX;
  ulong chain_cnt = fd_block_id_map_chain_cnt_est( bid_cnt );

  ctx->block_id_arr = fd_wksp_alloc_laddr( wksp, alignof(fd_block_id_ele_t), sizeof(fd_block_id_ele_t) * bid_cnt, 1UL );
  FD_TEST( ctx->block_id_arr );
  memset( ctx->block_id_arr, 0, sizeof(fd_block_id_ele_t) * bid_cnt );

  void * bid_map_mem = fd_wksp_alloc_laddr( wksp, fd_block_id_map_align(), fd_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( bid_map_mem );
  ctx->block_id_map_seed = 42UL;
  ctx->block_id_map = fd_block_id_map_join( fd_block_id_map_new( bid_map_mem, chain_cnt, ctx->block_id_map_seed ) );
  FD_TEST( ctx->block_id_map );

  /* Mock store — fd_store_fec_data needs store_gaddr */

  static fd_store_t mock_store;
  memset( &mock_store, 0, sizeof(mock_store) );
  mock_store.store_gaddr   = (ulong)&mock_store;
  mock_store_fec.data_gaddr = (ulong)mock_store_data;
  ctx->store = &mock_store;

  /* Mock banks — initialize root bank at index 0 */

  memset( mock_banks_arr, 0, sizeof(mock_banks_arr) );
  mock_banks_next = 1UL;
  mock_banks_arr[ 0 ].idx      = 0;
  mock_banks_arr[ 0 ].bank_seq = 0;
  mock_banks_arr[ 0 ].state    = FD_BANK_STATE_FROZEN;

  ctx->is_booted    = 1;
  ctx->wfs_complete = 1;
  ctx->is_leader    = 0;
  ctx->consensus_root_slot     = ULONG_MAX;
  ctx->consensus_root_bank_idx = ULONG_MAX;
  ctx->published_root_slot     = ULONG_MAX;
  ctx->published_root_bank_idx = ULONG_MAX;
}

static void
test_eqvoc_last_fec( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_reasm_t * reasm = ctx->reasm;

  /* Merkle roots — arbitrary unique hashes. */

  fd_hash_t mr_root      = { .ul = { 100 } };
  fd_hash_t mr1_0        = { .ul = { 200 } };
  fd_hash_t mr1_32       = { .ul = { 300 } };
  fd_hash_t mr1_32_eqvoc = { .ul = { 999 } };
  fd_hash_t mr2_0        = { .ul = { 400 } };

  fd_reasm_fec_t * ev[ 1 ];

  /* 1. Insert root FEC (slot 0).  chained_merkle_root is NULL for the
     very first FEC in a reasm instance.  The root is automatically
     marked popped=1, confirmed=1 by fd_reasm_insert. */

  fd_reasm_fec_t * f_root = fd_reasm_init( reasm, &mr_root, 0 );
  FD_TEST( f_root );

  /* Assign bank state on the root so child FECs see a valid parent. */

  f_root->bank_idx = 0;
  f_root->bank_seq = 0;

  /* 2. Insert FEC 0 of slot 1 (chained off root). */

  fd_reasm_fec_t * f1_0 = fd_reasm_insert( reasm, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_0 );
  FD_TEST( !*ev );

  /* 3. Insert FEC 32 of slot 1 (slot_complete, chained off FEC 0). */

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f1_32 );
  FD_TEST( !*ev );

  /* 4. Pop FEC 0 and process it through the replay tile path. */

  fd_reasm_fec_t * fec = fd_reasm_pop( reasm );
  FD_TEST( fec );
  FD_TEST( fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );

  /* 5. Pop FEC 32 and process it. */

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec );
  FD_TEST( fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==1 );

  /* 6. Insert equivocating FEC 32 — same (slot, fec_set_idx) but
     different merkle root.  Reasm detects the equivocation. */

  fd_reasm_fec_t * f1_32_eq = fd_reasm_insert( reasm, &mr1_32_eqvoc, &mr1_0,
      1, 32, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f1_32_eq );
  FD_TEST( !*ev );

  /* 7. Verify: the equivocating FEC is NOT delivered.  The eqvoc flag
     is set and confirmed==0, so the gate blocks delivery. */

  FD_TEST( f1_32_eq->eqvoc==1 );
  FD_TEST( f1_32_eq->confirmed==0 );
  FD_TEST( fd_reasm_peek( reasm )==NULL );
  FD_TEST( fd_reasm_pop ( reasm )==NULL );

  fd_reasm_confirm( reasm, &mr1_32_eqvoc );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec );
  FD_TEST( fec->slot==1 && fec->fec_set_idx==32 );

  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==2 );                             /* new bank is allocated */
  FD_TEST( fd_reasm_query( reasm, &mr1_0 )->bank_idx==2 ); /* bank idx is updated for fec 0 */

  /* latest mr is updated */
  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ fec->bank_idx ];
  FD_TEST( memcmp( &block_id_ele->latest_mr, &mr1_32_eqvoc, sizeof(fd_hash_t) ) == 0 ); /* so bad lol */

  fd_block_id_ele_t * block_id_ele_0 = &ctx->block_id_arr[ 1 ];
  FD_TEST( memcmp( &block_id_ele_0->latest_mr, &mr1_32, sizeof(fd_hash_t) ) == 0 );

  fd_reasm_fec_t * f2_0 = fd_reasm_insert( reasm, &mr2_0, &mr1_32_eqvoc,
      2, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f2_0 );
  FD_TEST( !*ev );
  fec = fd_reasm_pop( reasm );
  FD_TEST( fec );
  FD_TEST( fec->slot==2 && fec->fec_set_idx==0 );

  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==3 ); /* used to bank hash mismatch */

  FD_LOG_NOTICE(( "pass: test_eqvoc_fec_gate" ));
}

static void
test_eqvoc_first_fec( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_reasm_t * reasm = ctx->reasm;

  fd_hash_t mr_root = { .ul = { 100 } };
  fd_hash_t mr1_0   = { .ul = { 200 } };
  fd_hash_t mr1_32  = { .ul = { 300 } };

  fd_reasm_fec_t * ev[ 1 ];

  fd_reasm_fec_t * f_root = fd_reasm_init( reasm, &mr_root, 0 );
  FD_TEST( f_root );
  f_root->bank_idx = 0;
  f_root->bank_seq = 0;

  fd_reasm_fec_t * f1_0 = fd_reasm_insert( reasm, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_0 );
  FD_TEST( !*ev );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_32 );

  fd_reasm_fec_t * fec = fd_reasm_pop( reasm );
  FD_TEST( fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==1 );

  /* Insert equivocating version */
  fd_hash_t mr1_32_ = { .ul = { 32, 1 } };
  fd_hash_t mr1_0_  = { .ul = { 0,  1 } };
  fd_reasm_fec_t * f1_32_eq = fd_reasm_insert( reasm, &mr1_32_, &mr1_0_,
      1, 32, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f1_32_eq->eqvoc );

  fd_reasm_fec_t * fd_1_0_eq = fd_reasm_insert( reasm, &mr1_0_, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( fd_1_0_eq->eqvoc );

  /* no delivery of eqvoc */
  FD_TEST( fd_reasm_peek( reasm )==NULL );

  /* confirm equivocating version */
  fd_reasm_confirm( reasm, &mr1_32_ );

  /* delivery of confirmed version */
  fec = fd_reasm_pop( reasm );
  FD_TEST( fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==2 );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==2 );

  FD_TEST( fd_reasm_peek( reasm )==NULL );

  FD_LOG_NOTICE(( "pass: test_eqvoc_first_fec" ));
}

/* Happy path: 4 FECs in slot 1, all popped and processed normally.
   After fd_reasm_confirm, no FECs should be re-delivered. */

static void
test_confirm( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_reasm_t * reasm = ctx->reasm;

  fd_hash_t mr_root = { .ul = { 100 } };
  fd_hash_t mr1_0   = { .ul = { 200 } };
  fd_hash_t mr1_32  = { .ul = { 300 } };
  fd_hash_t mr1_64  = { .ul = { 400 } };
  fd_hash_t mr1_96  = { .ul = { 500 } };

  fd_reasm_fec_t * ev[ 1 ];

  /* Root FEC (slot 0). */

  fd_reasm_fec_t * f_root = fd_reasm_init( reasm, &mr_root, 0 );
  FD_TEST( f_root );
  f_root->bank_idx = 0;
  f_root->bank_seq = 0;

  /* Slot 1: 4 FECs chained sequentially. */

  fd_reasm_fec_t * f1_0 = fd_reasm_insert( reasm, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_0 );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_32 );

  fd_reasm_fec_t * f1_64 = fd_reasm_insert( reasm, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_64 );

  fd_reasm_fec_t * f1_96 = fd_reasm_insert( reasm, &mr1_96, &mr1_64,
      1, 96, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f1_96 );

  /* Pop and process all 4 FECs. */

  fd_reasm_fec_t * fec;

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==64 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==96 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==1 );

  /* Queue should be empty. */

  FD_TEST( fd_reasm_peek( reasm )==NULL );

  /* Confirm the slot.  No equivocation occurred, so no FEC should be
     re-delivered. */

  fd_reasm_confirm( reasm, &mr1_96 );

  FD_TEST( fd_reasm_peek( reasm )==NULL );
  FD_TEST( fd_reasm_pop ( reasm )==NULL );

  FD_LOG_NOTICE(( "pass: test_confirm" ));
}

/* Stale redeliver: insert, pop, process, evict, then reinsert the same
   FEC sets.  Verifies that the system handles re-receipt of evicted
   FECs gracefully — a new bank is allocated and execution is
   scheduled. */

static void
test_stale_redeliver( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_reasm_t * reasm = ctx->reasm;

  fd_hash_t mr_root = { .ul = { 100 } };
  fd_hash_t mr1_0   = { .ul = { 200 } };
  fd_hash_t mr1_32  = { .ul = { 300 } };
  fd_hash_t mr1_64  = { .ul = { 400 } };

  fd_reasm_fec_t * ev[ 1 ];

  /* 1. Insert root FEC (slot 0). */

  fd_reasm_fec_t * f_root = fd_reasm_init( reasm, &mr_root, 0 );
  FD_TEST( f_root );
  f_root->bank_idx = 0;
  f_root->bank_seq = 0;

  /* 2. Insert 3 FEC sets for slot 1. */

  fd_reasm_fec_t * f1_0 = fd_reasm_insert( reasm, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_0 );
  FD_TEST( !*ev );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_32 );
  FD_TEST( !*ev );

  fd_reasm_fec_t * f1_64 = fd_reasm_insert( reasm, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f1_64 );
  FD_TEST( !*ev );

  /* 3. Pop and process all 3. */

  fd_reasm_fec_t * fec;

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==64 );
  process_fec_set( ctx, NULL, fec );

  /* After processing, bank 1 should have been allocated. */
  FD_TEST( fec->bank_idx==1 );
  FD_TEST( mock_banks_next==2UL );

  /* Queue should be empty. */
  FD_TEST( fd_reasm_peek( reasm )==NULL );

  /* 4. Evict the slot 1 chain by removing the leaf (FEC 64) from the
     frontier.  fd_reasm_remove walks up to fec_set_idx==0, so FECs 0,
     32, 64 are all evicted. */

  fd_reasm_fec_t * leaf = fd_reasm_query( reasm, &mr1_64 );
  FD_TEST( leaf );
  fd_reasm_fec_t * evicted_head = fd_reasm_remove( reasm, leaf, NULL );
  FD_TEST( evicted_head );

  /* Walk the evicted chain and release each element back to the pool.
     The chain is linked via child pointers (linear, no branches). */
  fd_reasm_fec_t * curr = evicted_head;
  while( curr ) {
    fd_reasm_fec_t * next = fd_reasm_child( reasm, curr );
    fd_reasm_pool_release( reasm, curr );
    curr = next;
  }

  /* All 3 FECs should be gone from reasm. */
  FD_TEST( !fd_reasm_query( reasm, &mr1_0  ) );
  FD_TEST( !fd_reasm_query( reasm, &mr1_32 ) );
  FD_TEST( !fd_reasm_query( reasm, &mr1_64 ) );

  /* 5. Reinsert the same 3 FECs. */

  f1_0 = fd_reasm_insert( reasm, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_0 );
  FD_TEST( !*ev );

  f1_32 = fd_reasm_insert( reasm, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_32 );
  FD_TEST( !*ev );

  f1_64 = fd_reasm_insert( reasm, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f1_64 );
  FD_TEST( !*ev );

  /* 6. Pop and process all 3 again. */

  mock_sched_fec_ingest_called = 0;

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==64 );
  process_fec_set( ctx, NULL, fec );

  /* 7. A NEW bank should have been allocated (fec_set_idx==0 always
     allocates a new bank in insert_fec_set). */
  FD_TEST( fec->bank_idx==2 );
  FD_TEST( mock_banks_next==3UL );

  /* 8. Execution was scheduled for the reinserted FECs. */
  FD_TEST( mock_sched_fec_ingest_called );

  /* Queue should be drained. */
  FD_TEST( fd_reasm_peek( reasm )==NULL );

  FD_LOG_NOTICE(( "pass: test_stale_redeliver" ));
}

/* Mid-slot equivocation with eviction: slot 1 equivocates mid-slot.
   We deliver the full version A first (FEC 0, 32, 64), then the entire
   slot 1 chain gets evicted from reasm.  We reinsert FEC 0 with the
   same merkle root (it is shared between both versions), which gets a
   fresh bank.  Then we receive version B (FEC 32' and 64' with
   different merkle roots).  Since version A's FECs were evicted, reasm
   does NOT detect equivocation.  The replay tile allocates a new bank
   starting from FEC 0 for version B. */

static void
test_eqvoc_mid_slot_evicted( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_reasm_t * reasm = ctx->reasm;

  /* Merkle roots — arbitrary unique hashes. */

  fd_hash_t mr_root       = { .ul = { 100 } };
  fd_hash_t mr1_0         = { .ul = { 200 } };
  fd_hash_t mr1_32        = { .ul = { 300 } };
  fd_hash_t mr1_64        = { .ul = { 400 } };
  fd_hash_t mr1_32_prime  = { .ul = { 500 } };
  fd_hash_t mr1_64_prime  = { .ul = { 600 } };

  fd_reasm_fec_t * ev[ 1 ];

  /* 1. Insert root FEC (slot 0). */

  fd_reasm_fec_t * f_root = fd_reasm_init( reasm, &mr_root, 0 );
  FD_TEST( f_root );
  f_root->bank_idx = 0;
  f_root->bank_seq = 0;

  /* 2. Insert 3 FEC sets for slot 1 version A. */

  fd_reasm_fec_t * f1_0 = fd_reasm_insert( reasm, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_0 );
  FD_TEST( !*ev );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_32 );
  FD_TEST( !*ev );

  fd_reasm_fec_t * f1_64 = fd_reasm_insert( reasm, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f1_64 );
  FD_TEST( !*ev );

  /* 3. Pop and process all 3 FEC sets.  After this, bank 1 is allocated
     for slot 1. */

  fd_reasm_fec_t * fec;

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==64 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==1 );

  FD_TEST( fd_reasm_peek( reasm )==NULL );

  /* 4. Evict the entire slot 1 chain from reasm.  fd_reasm_remove walks
     UP from the leaf (FEC 64) and stops at fec_set_idx==0, so FEC 0,
     32, and 64 are all evicted.  Walk the evicted chain (linked via
     child pointers) and release each element back to the pool. */

  fd_reasm_fec_t * evicted = fd_reasm_remove( reasm, f1_64, NULL );
  FD_TEST( evicted );
  while( evicted ) {
    fd_reasm_fec_t * next = fd_reasm_child( reasm, evicted );
    fd_reasm_pool_release( reasm, evicted );
    evicted = next;
  }

  /* All 3 FECs should be gone from reasm. */

  FD_TEST( !fd_reasm_query( reasm, &mr1_0  ) );
  FD_TEST( !fd_reasm_query( reasm, &mr1_32 ) );
  FD_TEST( !fd_reasm_query( reasm, &mr1_64 ) );

  /* 5. Reinsert FEC 0 with the SAME merkle root (mr1_0).  Since the
     original was evicted, reasm does not detect equivocation.  Pop and
     process it: allocates a new bank (bank_idx=2). */

  fd_reasm_fec_t * f1_0_new = fd_reasm_insert( reasm, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_0_new );
  FD_TEST( !*ev );
  FD_TEST( !f1_0_new->eqvoc );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==2 );

  /* 6. Insert version B's FEC 32' and 64' (different merkle roots from
     version A) chaining off the reinserted FEC 0.  Reasm does NOT
     detect equivocation because version A was evicted. */

  fd_reasm_fec_t * f1_32p = fd_reasm_insert( reasm, &mr1_32_prime, &mr1_0,
      1, 32, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_32p );
  FD_TEST( !*ev );
  FD_TEST( !f1_32p->eqvoc );

  fd_reasm_fec_t * f1_64p = fd_reasm_insert( reasm, &mr1_64_prime, &mr1_32_prime,
      1, 64, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f1_64p );
  FD_TEST( !*ev );
  FD_TEST( !f1_64p->eqvoc );

  /* 7. Pop and process version B's FEC sets.  They should inherit the
     fresh bank (bank_idx=2) from the reinserted FEC 0. */

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==2 );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==64 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==2 );

  FD_TEST( fd_reasm_peek( reasm )==NULL );

  FD_LOG_NOTICE(( "pass: test_eqvoc_mid_slot_evicted" ));
}

/* Banks eviction across two consecutive slots: slots 1 and 2 each have
   2 FECs.  We pop and process all of slot 1 (bank 1) and the first FEC
   of slot 2 (bank 2).  Then banks evicts both banks (simulated by
   bumping bank_seq so the replay tile sees a seq mismatch).  When we
   continue popping slot 2's second FEC and call process_fec_set, the
   backfill path should walk up, discover both slot 2's and slot 1's
   banks are invalid, and reallocate banks for both slots. */

static void
test_banks_evict_backfill( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_reasm_t * reasm = ctx->reasm;

  fd_hash_t mr_root = { .ul = { 100 } };
  fd_hash_t mr1_0   = { .ul = { 200 } };
  fd_hash_t mr1_32  = { .ul = { 300 } };
  fd_hash_t mr2_0   = { .ul = { 400 } };
  fd_hash_t mr2_32  = { .ul = { 500 } };

  fd_reasm_fec_t * ev[ 1 ];

  /* 1. Root FEC (slot 0). */

  fd_reasm_fec_t * f_root = fd_reasm_init( reasm, &mr_root, 0 );
  FD_TEST( f_root );
  f_root->bank_idx = 0;
  f_root->bank_seq = 0;

  /* 2. Insert slot 1: 2 FECs (0 and 32), slot_complete on FEC 32. */

  fd_reasm_fec_t * f1_0 = fd_reasm_insert( reasm, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_0 && !*ev );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f1_32 && !*ev );

  /* 3. Insert slot 2: 2 FECs (0 and 32), slot_complete on FEC 32. */

  fd_reasm_fec_t * f2_0 = fd_reasm_insert( reasm, &mr2_0, &mr1_32,
      2, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f2_0 && !*ev );

  fd_reasm_fec_t * f2_32 = fd_reasm_insert( reasm, &mr2_32, &mr2_0,
      2, 32, 1, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f2_32 && !*ev );

  /* 4. Pop and process all of slot 1 → bank 1. */

  fd_reasm_fec_t * fec;

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==1 );

  /* 5. Pop and process first FEC of slot 2 → bank 2. */

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==2 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==2 );

  /* 6. Simulate banks evicting both bank 1 and bank 2 by bumping their
     bank_seq.  Now the replay tile will see a seq mismatch and treat
     them as evicted. */

  mock_banks_arr[ 1 ].bank_seq = 999UL;
  mock_banks_arr[ 2 ].bank_seq = 999UL;

  /* 7. Pop the second FEC of slot 2 and process it.  The parent
     (slot 2, FEC 0) has bank_idx=2 whose bank_seq no longer matches,
     so process_fec_set detects has_evicted and calls backfill_fec_sets.
     backfill walks up:
       - slot 2 FEC 0 (not slot_complete) → skip
       - slot 1 FEC 32 (slot_complete, bank evicted) → add to path
       - slot 1 FEC 0 (not slot_complete) → skip
       - root (slot_complete, bank valid) → stop
     Then replays top-down: slot 1 gets new bank 3, slot 2 gets new
     bank 4. */

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==2 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );

  /* 8. Verify: slot 1 was backfilled with a new bank (bank 3). */

  FD_TEST( f1_0->bank_idx==3 );
  FD_TEST( f1_32->bank_idx==3 );

  /* 9. Verify: slot 2 was backfilled with a new bank (bank 4). */

  FD_TEST( f2_0->bank_idx==4 );
  FD_TEST( f2_32->bank_idx==4 );

  /* 10. Verify mock_banks_next advanced past bank 4. */

  FD_TEST( mock_banks_next==5UL );

  FD_LOG_NOTICE(( "pass: test_banks_evict_backfill" ));
}

/* Partial execution eviction: slot 1 has 4 FECs (0, 32, 64, 96) with 96
   NOT slot_complete.  We pop and process only the first 2 (FEC 0 and
   32), which sets bank_idx=1 on those FECs.  FECs 64 and 96 remain
   unprocessed with bank_idx=ULONG_MAX.  Then we evict the frontier leaf
   (FEC 96).  fd_reasm_remove walks UP from the leaf checking that each
   node shares the same bank_idx as the tail.  When it reaches FEC 32
   (bank_idx=1) while tail has bank_idx=ULONG_MAX, make sure fd_reasm.c
   wouldn't crash. */

static void
test_partial_exec_evict( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_reasm_t * reasm = ctx->reasm;

  fd_hash_t mr_root = { .ul = { 100 } };
  fd_hash_t mr1_0   = { .ul = { 200 } };
  fd_hash_t mr1_32  = { .ul = { 300 } };
  fd_hash_t mr1_64  = { .ul = { 400 } };
  fd_hash_t mr1_96  = { .ul = { 500 } };

  fd_reasm_fec_t * ev[ 1 ];

  /* 1. Root FEC (slot 0). */

  fd_reasm_fec_t * f_root = fd_reasm_init( reasm, &mr_root, 0 );
  FD_TEST( f_root );
  f_root->bank_idx = 0;
  f_root->bank_seq = 0;

  /* 2. Insert 4 FECs for slot 1.  Crucially, FEC 96 is NOT
     slot_complete — the slot is still incomplete, making FEC 96 a valid
     eviction candidate via the unconfirmed frontier leaf path. */

  fd_reasm_fec_t * f1_0 = fd_reasm_insert( reasm, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_0 && !*ev );

  fd_reasm_fec_t * f1_32 = fd_reasm_insert( reasm, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_32 && !*ev );

  fd_reasm_fec_t * f1_64 = fd_reasm_insert( reasm, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_64 && !*ev );

  fd_reasm_fec_t * f1_96 = fd_reasm_insert( reasm, &mr1_96, &mr1_64,
      1, 96, 1, 32, 1, 0, 0, NULL, ev );
  FD_TEST( f1_96 && !*ev );

  /* 3. Pop and process only the first 2 FECs.  After this, FEC 0 and
     32 have bank_idx=1.  FECs 64 and 96 remain in the delivery queue
     with bank_idx=ULONG_MAX. */

  fd_reasm_fec_t * fec;

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==0 );
  process_fec_set( ctx, NULL, fec );

  fec = fd_reasm_pop( reasm );
  FD_TEST( fec && fec->slot==1 && fec->fec_set_idx==32 );
  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==1 );

  /* Verify FECs 64 and 96 have NOT been processed. */

  FD_TEST( f1_64->bank_idx==ULONG_MAX );
  FD_TEST( f1_96->bank_idx==ULONG_MAX );

  /* 4. Evict the frontier leaf (FEC 96).  This is the node the eviction
     policy would select: it is an unconfirmed, !slot_complete frontier
     leaf.  fd_reasm_remove walks up from FEC 96 toward fec_set_idx==0.
     The walk hits FEC 32 (bank_idx=1) while tail (FEC 96) has
     bank_idx=ULONG_MAX. */

  fd_reasm_fec_t * evicted = fd_reasm_remove( reasm, f1_96, NULL );
  FD_TEST( evicted );

  /* Release evicted chain back to pool. */

  ulong evict_order[ 4 ] = { 1, 1, ULONG_MAX, ULONG_MAX };
  uint  evict_idx        = 0;

  while( evicted ) {
    FD_LOG_NOTICE(( "evicting FEC slot %lu, fec idx %u, bank idx %lu", evicted->slot, evicted->fec_set_idx, evicted->bank_idx ));
    FD_TEST( evict_order[ evict_idx ] == evicted->bank_idx && evicted->fec_set_idx == 32*evict_idx );
    fd_reasm_fec_t * next = fd_reasm_child( reasm, evicted );
    fd_reasm_pool_release( reasm, evicted );
    evicted = next;
    evict_idx++;
  }
  FD_LOG_NOTICE(( "pass: test_partial_exec_evict" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 2;
  char *      page_sz  = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_banks_evict_backfill( wksp );
  test_partial_exec_evict( wksp );
  test_eqvoc_mid_slot_evicted( wksp );
  test_confirm( wksp );
  test_eqvoc_last_fec( wksp );
  test_eqvoc_first_fec( wksp );
  test_stale_redeliver( wksp );

  fd_halt();
  return 0;
}
