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
void  mock_banks_mark_dead_fn ( fd_banks_t * b FD_PARAM_UNUSED, ulong i FD_PARAM_UNUSED ) {}
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

int   mock_sched_fec_ingest_fn  ( fd_sched_t * s FD_PARAM_UNUSED, fd_sched_fec_t * f FD_PARAM_UNUSED ) { return 1; }
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

/* ---- Mock accdb vtable (defined after include so types are complete) ---- */

static fd_funk_txn_xid_t
mock_accdb_root_get_fn( fd_accdb_admin_t const * admin FD_PARAM_UNUSED ) {
  return (fd_funk_txn_xid_t){ .ul = { 0UL, 0UL } };
}

static void mock_accdb_attach_child_fn( fd_accdb_admin_t * a FD_PARAM_UNUSED,
    fd_funk_txn_xid_t const * b FD_PARAM_UNUSED, fd_funk_txn_xid_t const * c FD_PARAM_UNUSED ) {}
static void mock_accdb_advance_root_fn( fd_accdb_admin_t * a FD_PARAM_UNUSED,
    fd_funk_txn_xid_t const * b FD_PARAM_UNUSED ) {}
static void mock_accdb_cancel_fn( fd_accdb_admin_t * a FD_PARAM_UNUSED,
    fd_funk_txn_xid_t const * b FD_PARAM_UNUSED ) {}
static void mock_accdb_fini_fn( fd_accdb_admin_t * a FD_PARAM_UNUSED ) {}

static fd_accdb_admin_vt_t const mock_accdb_vt = {
  .fini         = mock_accdb_fini_fn,
  .root_get     = mock_accdb_root_get_fn,
  .attach_child = mock_accdb_attach_child_fn,
  .advance_root = mock_accdb_advance_root_fn,
  .cancel       = mock_accdb_cancel_fn,
};

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

  /* Mock accdb admin */

  ctx->accdb_admin->base.vt = &mock_accdb_vt;

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

  fd_reasm_fec_t * f_root = fd_reasm_insert( reasm, &mr_root, NULL,
      0, 0, 0, 32, 1, 1, 0, NULL, ev );
  FD_TEST( f_root );
  FD_TEST( !*ev );
  FD_TEST( f_root->popped==1 );

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
  FD_TEST( fec->slot==1 && fec->fec_set_idx==0 );
  FD_TEST( fec->bank_idx==1 );

  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==2 ); /* used to GET DROPPED. Perhaps unintentionally. but bank_idx would get set to 1. so bad  */
  /* latest mr is still the previous one*/
  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ fec->bank_idx ];
  FD_TEST( memcmp( &block_id_ele->latest_mr, &mr1_0, sizeof(fd_hash_t) ) == 0 ); /* so bad lol */

  FD_TEST( fd_reasm_peek( reasm ) );
  fec = fd_reasm_pop( reasm );
  FD_TEST( fec );
  FD_TEST( fec->slot==1 && fec->fec_set_idx==32 );
  FD_TEST( fec->bank_idx==ULONG_MAX );

  process_fec_set( ctx, NULL, fec );
  FD_TEST( fec->bank_idx==2 );
  FD_TEST( fd_reasm_query( reasm, &mr1_32 )->bank_idx==1 );

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

  fd_reasm_fec_t * f_root = fd_reasm_insert( reasm, &mr_root, NULL,
      0, 0, 0, 32, 1, 1, 0, NULL, ev );
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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 2;
  char *      page_sz  = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_confirm( wksp );
  test_eqvoc_last_fec( wksp );

  fd_halt();
  return 0;
}
