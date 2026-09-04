/* test_replay_tile.c — Tests the replay tile's FEC consumption path
   through reasm, verifying that equivocating FEC sets are not delivered.

   Follows the pattern of test_repair_tile.c and test_tower_tile.c:
   mock heavy dependencies via #define before including the tile .c. */
#define _GNU_SOURCE
#include "../../disco/store/fd_store.h"
#include <fcntl.h>

/* ---- Pull in type definitions we need for mock function signatures.
   These headers are guarded, so the re-include from fd_replay_tile.c
   will be a no-op. ---- */

#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_runtime_helpers.h" /* IWYU pragma: keep */
#include "../../flamenco/runtime/sysvar/fd_sysvar_rent.h" /* IWYU pragma: keep */
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/progcache/fd_progcache_admin.h" /* IWYU pragma: keep */
#include "../../flamenco/rewards/fd_rewards.h" /* IWYU pragma: keep */
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/rewards/fd_stake_rewards.h"
#include "fd_sched.h"

#define TEST_BANKS_MAX 16UL
#define TEST_OUT_CNT   3UL
#define TEST_REPAIR_IN_IDX 0UL
#define TEST_EXECRP_IN_IDX 1UL

/* ---- Mock store ---- */

static fd_store_fec_t mock_store_fec;
static uchar          mock_store_data[ 4096 ];
static ulong          mock_store_view_call_cnt;
static ulong          mock_store_view_success_cnt;
static ulong          mock_store_view_release_cnt;
static int            mock_store_view_fail;

fd_store_fec_t *
mock_store_query_fn( fd_store_map_t *  map FD_PARAM_UNUSED,
                     fd_hash_t const * merkle_root FD_PARAM_UNUSED ) {
  return &mock_store_fec;
}

int
mock_store_fec_data_view_fn( fd_store_t *               store FD_PARAM_UNUSED,
                             int                        disk_fd FD_PARAM_UNUSED,
                             fd_store_fec_t *           fec FD_PARAM_UNUSED,
                             fd_store_fec_data_view_t * view ) {
  mock_store_view_call_cnt++;
  if( FD_UNLIKELY( mock_store_view_fail ) ) {
    view->data  = NULL;
    view->fec   = NULL;
    view->flags = 0U;
    return -1;
  }
  view->data = mock_store_data;
  view->fec = &mock_store_fec;
  view->flags = 0U;
  mock_store_view_success_cnt++;
  return 0;
}

void
mock_store_fec_data_view_release_fn( fd_store_t *                     store FD_PARAM_UNUSED,
                                     fd_store_fec_data_view_t *       view ) {
  FD_TEST( view && view->fec );
  mock_store_view_release_cnt++;
  view->data = NULL;
  view->fec  = NULL;
}

#define fd_store_query mock_store_query_fn
#define fd_store_fec_data_view mock_store_fec_data_view_fn
#define fd_store_fec_data_view_release mock_store_fec_data_view_release_fn

/* ---- Mock sched ---- */

static fd_sched_fec_t mock_sched_last_fec;
static ulong          mock_sched_fec_ingest_cnt;
static ulong          mock_sched_abandon_cnt;
static ulong          mock_sched_abandon_idx;
static ulong          mock_sched_root_notify_cnt;
static ulong          mock_sched_root_notify_idx;
static ulong          mock_sched_capacity;
static fd_sched_txn_info_t mock_sched_txn_info;
static fd_txn_p_t     mock_sched_txn;
static ulong          mock_sched_txn_idx;
static ulong          mock_sched_task_done_cnt;
static ulong          mock_sched_task_done_type;
static ulong          mock_sched_task_done_txn_idx;
static ulong          mock_sched_task_done_exec_idx;
static long           mock_sched_task_done_tick;

int mock_sched_fec_ingest_fn( fd_sched_t * s FD_PARAM_UNUSED, fd_sched_fec_t * f ) {
  mock_sched_last_fec = *f;
  mock_sched_fec_ingest_cnt++;
  return 1;
}
ulong mock_sched_can_ingest_fn  ( fd_sched_t * s FD_PARAM_UNUSED ) { return mock_sched_capacity; }
int   mock_sched_is_drained_fn  ( fd_sched_t * s FD_PARAM_UNUSED ) { return 1; }
void  mock_sched_abandon_fn     ( fd_sched_t * s FD_PARAM_UNUSED, ulong i, int invalid FD_PARAM_UNUSED ) {
  mock_sched_abandon_cnt++;
  mock_sched_abandon_idx = i;
}
void  mock_sched_cancel_fn      ( fd_sched_t * s FD_PARAM_UNUSED, ulong i FD_PARAM_UNUSED ) {}
int   mock_sched_is_discarded_fn( fd_sched_t * s FD_PARAM_UNUSED, ulong i FD_PARAM_UNUSED ) { return 0; }
ulong mock_sched_pruned_fn      ( fd_sched_t * s FD_PARAM_UNUSED ) { return ULONG_MAX; }
void  mock_sched_metrics_fn     ( fd_sched_t * s FD_PARAM_UNUSED ) {}
void  mock_sched_poh_fn         ( fd_sched_t * s FD_PARAM_UNUSED, ulong a FD_PARAM_UNUSED, ulong b FD_PARAM_UNUSED, ulong c FD_PARAM_UNUSED, ulong d FD_PARAM_UNUSED, fd_hash_t const * e FD_PARAM_UNUSED ) {}
ulong mock_sched_task_next_fn   ( fd_sched_t * s FD_PARAM_UNUSED, fd_sched_task_t * t FD_PARAM_UNUSED ) { return 0UL; }
void  mock_sched_root_notify_fn ( fd_sched_t * s FD_PARAM_UNUSED, ulong i ) {
  mock_sched_root_notify_cnt++;
  mock_sched_root_notify_idx = i;
}

int
mock_sched_task_done_fn( fd_sched_t * s FD_PARAM_UNUSED,
                         ulong        task_type,
                         ulong        txn_idx,
                         ulong        exec_idx,
                         void *       data FD_PARAM_UNUSED ) {
  mock_sched_task_done_cnt++;
  mock_sched_task_done_type     = task_type;
  mock_sched_task_done_txn_idx  = txn_idx;
  mock_sched_task_done_exec_idx = exec_idx;
  if( task_type==FD_SCHED_TT_TXN_EXEC ) mock_sched_txn_info.tick_exec_done = mock_sched_task_done_tick;
  return 0;
}

fd_txn_p_t *
mock_sched_get_txn_fn( fd_sched_t * s FD_PARAM_UNUSED,
                       ulong        txn_idx ) {
  FD_TEST( txn_idx==mock_sched_txn_idx );
  return &mock_sched_txn;
}

fd_sched_txn_info_t *
mock_sched_get_txn_info_fn( fd_sched_t * s FD_PARAM_UNUSED,
                            ulong        txn_idx ) {
  FD_TEST( txn_idx==mock_sched_txn_idx );
  return &mock_sched_txn_info;
}

#define fd_sched_fec_ingest        mock_sched_fec_ingest_fn
#define fd_sched_can_ingest_cnt    mock_sched_can_ingest_fn
#define fd_sched_is_drained        mock_sched_is_drained_fn
#define fd_sched_block_abandon     mock_sched_abandon_fn
#define fd_sched_cancel            mock_sched_cancel_fn
#define fd_sched_block_is_discarded mock_sched_is_discarded_fn
#define fd_sched_pruned_block_next mock_sched_pruned_fn
#define fd_sched_metrics_write     mock_sched_metrics_fn
#define fd_sched_set_poh_params    mock_sched_poh_fn
#define fd_sched_task_next_ready   mock_sched_task_next_fn
#define fd_sched_root_notify       mock_sched_root_notify_fn
#define fd_sched_task_done         mock_sched_task_done_fn
#define fd_sched_get_txn           mock_sched_get_txn_fn
#define fd_sched_get_txn_info      mock_sched_get_txn_info_fn

/* ---- Mock leader setup dependencies ---- */

static ulong mock_next_leader_slot = ULONG_MAX;
static ulong mock_txncache_fork_id_next;
static ulong mock_progcache_fork_id_next;
static ushort mock_accdb_fork_id_next;
static int   mock_epoch_boundary_enabled;
static ulong mock_epoch_boundary_fork_cnt;
static ulong mock_epoch_boundary_fork_max;
static int   mock_epoch_boundary_overflow;
static int   mock_snapshot_boot;

ulong
mock_multi_epoch_leaders_next_slot_fn( fd_multi_epoch_leaders_t const * mleaders FD_PARAM_UNUSED,
                                       ulong                            start_slot,
                                       fd_pubkey_t const *              leader_q FD_PARAM_UNUSED ) {
  return mock_next_leader_slot>=start_slot ? mock_next_leader_slot : ULONG_MAX;
}

fd_txncache_fork_id_t
mock_txncache_attach_child_fn( fd_txncache_t *       tc FD_PARAM_UNUSED,
                               fd_txncache_fork_id_t parent_fork_id FD_PARAM_UNUSED ) {
  return (fd_txncache_fork_id_t){ .val=(ushort)++mock_txncache_fork_id_next };
}

fd_progcache_fork_id_t
mock_progcache_attach_child_fn( fd_progcache_join_t *  cache FD_PARAM_UNUSED,
                                fd_progcache_fork_id_t parent_fork_id FD_PARAM_UNUSED ) {
  return ++mock_progcache_fork_id_next;
}

fd_accdb_fork_id_t
mock_accdb_attach_child_fn( fd_accdb_t *       accdb FD_PARAM_UNUSED,
                            fd_accdb_fork_id_t parent_fork_id FD_PARAM_UNUSED ) {
  return (fd_accdb_fork_id_t){ .val=++mock_accdb_fork_id_next };
}

void
mock_runtime_block_execute_prepare_fn( fd_banks_t *         banks FD_PARAM_UNUSED,
                                       fd_bank_t *          bank,
                                       fd_accdb_t *         accdb FD_PARAM_UNUSED,
                                       fd_runtime_stack_t * runtime_stack FD_PARAM_UNUSED,
                                       fd_capture_ctx_t *   capture_ctx FD_PARAM_UNUSED,
                                       int *                is_epoch_boundary ) {
  if( FD_UNLIKELY( !mock_epoch_boundary_enabled ) ) {
    *is_epoch_boundary = 0;
    return;
  }

  *is_epoch_boundary = 1;
  bank->f.epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, bank->f.slot, NULL );

  if( FD_UNLIKELY( mock_epoch_boundary_fork_cnt>=mock_epoch_boundary_fork_max ) ) {
    mock_epoch_boundary_overflow = 1;
    return;
  }

  mock_epoch_boundary_fork_cnt++;
  bank->stake_rewards_fork_id = fd_stake_rewards_init( fd_bank_stake_rewards_modify( bank ),
                                                       bank->f.epoch,
                                                       &bank->f.prev_bank_hash,
                                                       bank->f.block_height,
                                                       1U,
                                                       0UL );
}

#define fd_multi_epoch_leaders_get_next_slot mock_multi_epoch_leaders_next_slot_fn
#define fd_txncache_attach_child             mock_txncache_attach_child_fn
#define fd_progcache_attach_child            mock_progcache_attach_child_fn
#define fd_accdb_attach_child                mock_accdb_attach_child_fn
/* Bypass unrelated boot dependencies while exercising snapshot DONE to completion. */
#define fd_sysvar_cache_restore(bank,accdb)  (mock_snapshot_boot ? 1 : (fd_sysvar_cache_restore)(bank,accdb))
#define fd_sysvar_rent_read(accdb,fork,rent) (mock_snapshot_boot ? (rent) : (fd_sysvar_rent_read)(accdb,fork,rent))
#define fd_sched_block_add_done(s,b,p,slot)   do { if( !mock_snapshot_boot ) (fd_sched_block_add_done)(s,b,p,slot); } while(0)
#define fd_runtime_update_next_leaders(b,s)  do { if( !mock_snapshot_boot ) (fd_runtime_update_next_leaders)(b,s); } while(0)
#define fd_runtime_update_leaders(b,s)       do { if( !mock_snapshot_boot ) (fd_runtime_update_leaders)(b,s); } while(0)
#define fd_multi_epoch_leaders_epoch_msg_init(m,msg) do { if( !mock_snapshot_boot ) (fd_multi_epoch_leaders_epoch_msg_init)(m,msg); } while(0)
#define fd_multi_epoch_leaders_epoch_msg_fini(m)     do { if( !mock_snapshot_boot ) (fd_multi_epoch_leaders_epoch_msg_fini)(m); } while(0)
#define fd_progcache_reset(cache)                    do { if( !mock_snapshot_boot ) (fd_progcache_reset)(cache); } while(0)
#define fd_sysvar_cache_stake_history_view(cache,view) (mock_snapshot_boot ? NULL : (fd_sysvar_cache_stake_history_view)(cache,view))
#define fd_stake_delegations_refresh(d,e,h,w,f,r,a,i) do { if( !mock_snapshot_boot ) (fd_stake_delegations_refresh)(d,e,h,w,f,r,a,i); } while(0)
#define fd_vote_stakes_refresh(v,f,a,i)              do { if( !mock_snapshot_boot ) (fd_vote_stakes_refresh)(v,f,a,i); } while(0)
#define fd_rewards_recalculate_partitioned_rewards(b,k,a,s,c) do { if( !mock_snapshot_boot ) (fd_rewards_recalculate_partitioned_rewards)(b,k,a,s,c); } while(0)
#define fd_accdb_lamports(a,i,p) (mock_snapshot_boot ? 0UL : (fd_accdb_lamports)(a,i,p))
#define fd_runtime_block_execute_prepare     mock_runtime_block_execute_prepare_fn

/* ---- Include the tile under test ---- */

#include "fd_replay_tile.c"

/* ---- Test setup ---- */

static fd_frag_meta_t * test_stem_mcaches[ TEST_OUT_CNT ];
static ulong            test_stem_seqs[ TEST_OUT_CNT ];
static ulong            test_stem_depths[ TEST_OUT_CNT ];
static ulong            test_stem_cr_avail[ TEST_OUT_CNT ];
static ulong            test_stem_min_cr_avail[ 1 ];
static int              test_stem_out_reliable[ TEST_OUT_CNT ];
static fd_stem_context_t test_stem[ 1 ];

static void
setup_repair_input( fd_replay_tile_t * ctx, fd_wksp_t * wksp ) {
  ulong const depth = 128UL;
  ulong const mtu   = sizeof(fd_repair_fec_complete_t);
  ulong dcache_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );

  void * dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
  FD_TEST( dcache_mem );
  void * dcache = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );
  FD_TEST( dcache );

  ctx->in_cnt = 1UL;
  ctx->in_kind[ TEST_REPAIR_IN_IDX ] = IN_KIND_REPAIR;
  ctx->in[ TEST_REPAIR_IN_IDX ].mem    = wksp;
  ctx->in[ TEST_REPAIR_IN_IDX ].chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  ctx->in[ TEST_REPAIR_IN_IDX ].wmark  = fd_dcache_compact_wmark ( wksp, dcache, mtu );
  ctx->in[ TEST_REPAIR_IN_IDX ].mtu    = mtu;
}

static void
setup_stem( fd_replay_tile_t * ctx, fd_wksp_t * wksp ) {
  ulong const depth = 128UL;
  ulong const mtu   = FD_TPU_PARSED_MTU;

  for( ulong i=0UL; i<TEST_OUT_CNT; i++ ) {
    void * mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL );
    FD_TEST( mcache_mem );
    test_stem_mcaches[ i ] = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, 0UL ) );
    FD_TEST( test_stem_mcaches[ i ] );

    ulong dcache_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
    void * dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
    FD_TEST( dcache_mem );
    void * dcache = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );
    FD_TEST( dcache );

    test_stem_seqs[ i ]         = 0UL;
    test_stem_depths[ i ]       = depth;
    test_stem_cr_avail[ i ]    = ULONG_MAX;
    test_stem_out_reliable[ i ] = 1;

    fd_replay_out_link_t out = {
      .idx    = i,
      .mem    = wksp,
      .chunk0 = fd_dcache_compact_chunk0( wksp, dcache ),
      .wmark  = fd_dcache_compact_wmark ( wksp, dcache, mtu ),
      .chunk  = fd_dcache_compact_chunk0( wksp, dcache )
    };

    if( i==0UL )      *ctx->replay_out = out;
    else if( i==1UL ) *ctx->exec_out   = out;
    else              *ctx->epoch_out  = out;
  }

  *test_stem_min_cr_avail = ULONG_MAX;
  *test_stem = (fd_stem_context_t) {
    .mcaches             = test_stem_mcaches,
    .seqs                = test_stem_seqs,
    .depths              = test_stem_depths,
    .cr_avail            = test_stem_cr_avail,
    .min_cr_avail        = test_stem_min_cr_avail,
    .cr_decrement_amount = 0UL,
    .out_reliable        = test_stem_out_reliable
  };
}

static ulong test_timing_of_bank[ TEST_BANKS_MAX ];

static void
setup_timing( fd_replay_tile_t * ctx,
              fd_wksp_t *        wksp ) {
  fd_clock_tile_init( ctx->clock );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_timing_slot_pool_align(), fd_timing_slot_pool_footprint( FD_REPLAY_TXN_TIMING_SLOTS ), 1UL );
  ctx->timing_slot_pool = fd_timing_slot_pool_join( fd_timing_slot_pool_new( mem, FD_REPLAY_TXN_TIMING_SLOTS ) );
  FD_TEST( ctx->timing_slot_pool );
  ctx->timing_slot_of_bank = test_timing_of_bank;
  for( ulong i=0UL; i<TEST_BANKS_MAX; i++ ) ctx->timing_slot_of_bank[ i ] = fd_timing_slot_pool_idx_null( ctx->timing_slot_pool );
}

static void
setup_ctx_with_fork_width( fd_replay_tile_t * ctx,
                           fd_wksp_t *        wksp,
                           ulong              max_fork_width ) {
  FD_TEST( mock_store_view_success_cnt==mock_store_view_release_cnt );
  mock_store_view_call_cnt    = 0UL;
  mock_store_view_success_cnt = 0UL;
  mock_store_view_release_cnt = 0UL;
  mock_store_view_fail        = 0;
  memset( ctx, 0, sizeof(*ctx) );
  setup_timing( ctx, wksp );

  /* Reasm */

  ulong fec_max = 32UL;
  void * reasm_mem = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( fec_max ), 1UL );
  FD_TEST( reasm_mem );
  ctx->reasm = fd_reasm_join( fd_reasm_new( reasm_mem, fec_max, 0UL ) );
  FD_TEST( ctx->reasm );

  /* Block-id map */

  ulong bid_cnt   = TEST_BANKS_MAX;
  ulong chain_cnt = fd_block_id_map_chain_cnt_est( bid_cnt );

  ctx->block_id_arr = fd_wksp_alloc_laddr( wksp, alignof(fd_block_id_ele_t), sizeof(fd_block_id_ele_t) * bid_cnt, 1UL );
  FD_TEST( ctx->block_id_arr );
  memset( ctx->block_id_arr, 0, sizeof(fd_block_id_ele_t) * bid_cnt );

  void * bid_map_mem = fd_wksp_alloc_laddr( wksp, fd_block_id_map_align(), fd_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( bid_map_mem );
  ctx->block_id_map_seed = 42UL;
  ctx->block_id_map = fd_block_id_map_join( fd_block_id_map_new( bid_map_mem, chain_cnt, ctx->block_id_map_seed ) );
  FD_TEST( ctx->block_id_map );

  ctx->reception_stats_cnt = bid_cnt;
  ctx->reception_stats = fd_wksp_alloc_laddr( wksp, alignof(fd_reception_stats_t), sizeof(fd_reception_stats_t)*bid_cnt, 1UL );
  FD_TEST( ctx->reception_stats );
  for( ulong i=0UL; i<ctx->reception_stats_cnt; i++ ) ctx->reception_stats[ i ].slot = ULONG_MAX;

  static fd_store_t mock_store;
  memset( &mock_store, 0, sizeof(mock_store) );
  mock_store.store_gaddr = (ulong)&mock_store;
  ctx->store             = &mock_store;
  ctx->store_disk_fd     = -1;

  /* Real banks — initialize root bank. */

  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( TEST_BANKS_MAX, max_fork_width, 2048UL, 32768UL, 2048UL ), 1UL );
  FD_TEST( banks_mem );
  ctx->banks = fd_banks_join( fd_banks_new( banks_mem, TEST_BANKS_MAX, max_fork_width, 2048UL, 32768UL, 2048UL, 0, 42UL ) );
  FD_TEST( ctx->banks );
  fd_bank_t * root_bank = fd_banks_init_bank( ctx->banks );
  FD_TEST( root_bank );
  root_bank->f.slot                        = 0UL;
  root_bank->f.parent_slot                 = ULONG_MAX;
  root_bank->f.ticks_per_slot              = 64UL;
  root_bank->f.slot_params                 = FD_SLOT_PARAMS_400MS;
  root_bank->f.slot_params.hashes_per_tick = 4UL;
  root_bank->f.slot_params_default         = FD_SLOT_PARAMS_400MS;
  fd_epoch_schedule_derive( &root_bank->f.epoch_schedule, 128UL, 128UL, 0 );
  fd_hash_t genesis_hash = { .ul = { 1UL } };
  fd_blockhashes_init( &root_bank->f.block_hash_queue, 42UL );
  fd_blockhash_info_t * bh_info = fd_blockhashes_push_new( &root_bank->f.block_hash_queue, &genesis_hash );
  FD_TEST( bh_info );
  bh_info->lamports_per_signature = 5000UL;

  ctx->is_booted    = 1;
  ctx->wfs_complete = 1;
  ctx->is_leader    = 0;
  ctx->supports_leader = 1;
  ctx->identity_vote_rooted = 1;
  ctx->highwater_leader_slot = ULONG_MAX;
  ctx->next_leader_slot      = ULONG_MAX;
  ctx->next_leader_tickcount = LONG_MAX;
  ctx->reset_slot            = 0UL;
  ctx->tick_per_ns           = fd_tempo_tick_per_ns( NULL );
  ctx->block_id_len   = bid_cnt;
  ctx->max_live_slots = bid_cnt;
  ctx->consensus_root_slot     = ULONG_MAX;
  ctx->published_root_slot     = ULONG_MAX;
  ctx->published_root_bank_idx = root_bank->idx;

  mock_next_leader_slot       = ULONG_MAX;
  mock_txncache_fork_id_next  = 0UL;
  mock_progcache_fork_id_next = 0UL;
  mock_accdb_fork_id_next     = 0U;
  mock_sched_abandon_cnt      = 0UL;
  mock_sched_abandon_idx      = ULONG_MAX;
  mock_sched_root_notify_cnt  = 0UL;
  mock_sched_root_notify_idx  = ULONG_MAX;
  mock_sched_capacity         = ULONG_MAX;
  mock_epoch_boundary_enabled = 0;
  mock_epoch_boundary_fork_cnt = 0UL;
  mock_epoch_boundary_fork_max = ULONG_MAX;
  mock_epoch_boundary_overflow = 0;

  setup_stem( ctx, wksp );
  setup_repair_input( ctx, wksp );
}

static void
setup_ctx( fd_replay_tile_t * ctx, fd_wksp_t * wksp ) {
  setup_ctx_with_fork_width( ctx, wksp, 8UL );
}

static fd_reasm_fec_t *
init_root_fec( fd_replay_tile_t * ctx,
               fd_hash_t const *  mr_root ) {
  fd_reasm_fec_t * f_root = fd_reasm_init( ctx->reasm, mr_root, 0 );
  FD_TEST( f_root );

  fd_bank_t * root_bank = fd_banks_root( ctx->banks );
  FD_TEST( root_bank );
  f_root->bank_idx = (uint)root_bank->idx;
  f_root->bank_seq = root_bank->bank_seq;

  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ root_bank->idx ];
  block_id_ele->block_id_seen  = 1;
  block_id_ele->slot           = root_bank->f.slot;
  block_id_ele->bank_seq       = root_bank->bank_seq;
  block_id_ele->latest_fec_idx = 0U;
  block_id_ele->latest_mr      = *mr_root;
  block_id_ele->dmr            = *mr_root;
  FD_TEST( fd_block_id_map_ele_insert( ctx->block_id_map, block_id_ele, ctx->block_id_arr ) );

  ctx->reset_cmr = *mr_root;
  return f_root;
}

static fd_reasm_fec_t *
ingest_fec_complete_with_signal( fd_replay_tile_t *               ctx,
                                 ulong                            sig,
                                 fd_hash_t const *                merkle_root,
                                 fd_hash_t const *                chained_merkle_root,
                                 ulong                            slot,
                                 uint                             fec_set_idx,
                                 ushort                           parent_off,
                                 ushort                           data_cnt,
                                 int                              data_complete,
                                 int                              slot_complete,
                                 fd_fec_complete_metrics_t const * metrics ) {
  ulong chunk = ctx->in[ TEST_REPAIR_IN_IDX ].chunk0;
  fd_repair_fec_complete_t * complete_msg = fd_chunk_to_laddr( ctx->in[ TEST_REPAIR_IN_IDX ].mem, chunk );
  memset( complete_msg, 0, sizeof(fd_repair_fec_complete_t) );

  complete_msg->fec.merkle_root         = *merkle_root;
  complete_msg->fec.chained_merkle_root = *chained_merkle_root;
  complete_msg->fec.last_shred_hdr.slot        = slot;
  complete_msg->fec.last_shred_hdr.fec_set_idx = fec_set_idx;
  complete_msg->fec.last_shred_hdr.idx         = fec_set_idx + (uint)data_cnt - 1U;
  complete_msg->fec.last_shred_hdr.data.parent_off = parent_off;
  complete_msg->fec.last_shred_hdr.data.flags =
    (uchar)( fd_uchar_if( data_complete, FD_SHRED_DATA_FLAG_DATA_COMPLETE, 0U ) |
             fd_uchar_if( slot_complete, FD_SHRED_DATA_FLAG_SLOT_COMPLETE, 0U ) );
  if( metrics ) complete_msg->metrics = *metrics;

  FD_TEST( !returnable_frag( ctx, TEST_REPAIR_IN_IDX, 0UL, sig, chunk,
                             sizeof(fd_repair_fec_complete_t), 0UL, 0UL,
                             fd_frag_meta_ts_comp( fd_tickcount() ), test_stem ) );

  fd_reasm_fec_t * fec = fd_reasm_query( ctx->reasm, merkle_root );
  FD_TEST( fec );
  return fec;
}

static fd_reasm_fec_t *
ingest_fec_complete_with_metrics( fd_replay_tile_t *               ctx,
                                  fd_hash_t const *                merkle_root,
                                  fd_hash_t const *                chained_merkle_root,
                                  ulong                            slot,
                                  uint                             fec_set_idx,
                                  ushort                           parent_off,
                                  ushort                           data_cnt,
                                  int                              data_complete,
                                  int                              slot_complete,
                                  fd_fec_complete_metrics_t const * metrics ) {
  return ingest_fec_complete_with_signal( ctx, REPAIR_SIG_FEC, merkle_root, chained_merkle_root,
                                          slot, fec_set_idx, parent_off, data_cnt,
                                          data_complete, slot_complete, metrics );
}

static fd_reasm_fec_t *
ingest_fec_complete( fd_replay_tile_t * ctx,
                     fd_hash_t const *  merkle_root,
                     fd_hash_t const *  chained_merkle_root,
                     ulong              slot,
                     uint               fec_set_idx,
                     ushort             parent_off,
                     ushort             data_cnt,
                     int                data_complete,
                     int                slot_complete ) {
  return ingest_fec_complete_with_metrics( ctx, merkle_root, chained_merkle_root, slot, fec_set_idx,
                                           parent_off, data_cnt, data_complete, slot_complete, NULL );
}

static void
assert_reception_event_matches( fd_event_block_completed_t const * ev,
                                fd_fec_complete_metrics_t const *  metrics,
                                uint                               fec_set_idx ) {
  FD_TEST( ev->last_completed_fec_set_index==fec_set_idx );
  FD_TEST( ev->turbine_shred_count==metrics->blk_turbine_cnt );
  FD_TEST( ev->repair_shred_count==metrics->blk_repair_cnt );
  FD_TEST( ev->recovered_shred_count==metrics->blk_recovered_cnt );
  FD_TEST( ev->data_shred_count==metrics->blk_data_cnt );
  FD_TEST( ev->parity_shred_count==metrics->blk_parity_cnt );
  FD_TEST( ev->chain_confirmed==!!metrics->blk_chain_confirmed );
  FD_TEST( ev->slot_complete_flag==!!metrics->blk_slot_complete );
  FD_TEST( ev->lowest_verified_fec_index==metrics->blk_lowest_verified_fec );
  FD_TEST( ev->repair_request_window_count==metrics->blk_req_window_cnt );
  FD_TEST( ev->repair_request_highest_window_count==metrics->blk_req_highest_cnt );
  FD_TEST( ev->repair_request_orphan_count==metrics->blk_req_orphan_cnt );
  FD_TEST( ev->repair_responses_received==metrics->blk_repair_responses );
  FD_TEST( ev->repair_requests_retransmitted==metrics->blk_req_retransmit_cnt );
  FD_TEST( ev->repair_failed_chain_verify==!!metrics->blk_chain_verify_failed );
  FD_TEST( ev->first_shred_received_time==metrics->blk_first_shred_ts_nanos );
  FD_TEST( ev->last_shred_received_time==metrics->blk_last_shred_ts_nanos );
  FD_TEST( ev->first_repair_request_time==metrics->blk_first_req_ts_nanos );
  FD_TEST( ev->last_repair_received_time==metrics->blk_last_repair_resp_ts_nanos );
}

static void
test_txn_completion_publish( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );

  ulong const depth = 128UL;
  ulong const mtu   = sizeof(fd_execrp_task_done_msg_t);
  ulong dcache_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  void * dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
  FD_TEST( dcache_mem );
  void * dcache = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );
  FD_TEST( dcache );

  ctx->in_cnt = fd_ulong_max( ctx->in_cnt, TEST_EXECRP_IN_IDX+1UL );
  ctx->in_kind[ TEST_EXECRP_IN_IDX ] = IN_KIND_EXECRP;
  ctx->in[ TEST_EXECRP_IN_IDX ].mem    = wksp;
  ctx->in[ TEST_EXECRP_IN_IDX ].chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  ctx->in[ TEST_EXECRP_IN_IDX ].wmark  = fd_dcache_compact_wmark ( wksp, dcache, mtu );
  ctx->in[ TEST_EXECRP_IN_IDX ].mtu    = mtu;

  fd_bank_t * bank = fd_banks_root( ctx->banks );
  FD_TEST( bank );
  FD_TEST( bank->cost_tracker_pool_idx==ULONG_MAX );
  bank->refcnt = 1UL;

  mock_sched_txn_idx = 37UL;
  fd_memset( &mock_sched_txn, 0x5a, sizeof(mock_sched_txn) );
  mock_sched_txn.payload_sz = 321UL;

  mock_sched_txn_info = (fd_sched_txn_info_t) {
    .flags                    = FD_SCHED_TXN_SIGVERIFY_DONE,
    .txn_err                  = FD_RUNTIME_EXECUTE_SUCCESS,
    .received_ns              = 1000L,
    .is_simple_vote           = 0,
    .tick_parsed              = 1001L,
    .tick_sigverify_disp      = 1002L,
    .tick_sigverify_done      = 1003L,
    .tick_exec_disp           = 1004L,
    .tick_exec_done           = LONG_MAX,
    .tick_load_start          = LONG_MAX,
    .tick_check_start         = LONG_MAX,
    .tick_exec_start          = LONG_MAX,
    .tick_commit_start        = LONG_MAX,
    .tick_commit_end          = LONG_MAX,
    .slot                     = 1234UL,
    .bank_seq                 = ULONG_MAX,
    .index_in_slot            = 56UL,
    .exec_tile_idx            = 7UL,
    .sigverify_exec_tile_idx  = 9UL,
    .compute_units_consumed   = 0U,
    .max_compute_units        = ULONG_MAX,
    .transaction_fee          = ULONG_MAX,
    .priority_fee             = ULONG_MAX,
    .tips                     = ULONG_MAX,
  };

  mock_sched_task_done_cnt      = 0UL;
  mock_sched_task_done_type     = ULONG_MAX;
  mock_sched_task_done_txn_idx  = ULONG_MAX;
  mock_sched_task_done_exec_idx = ULONG_MAX;
  mock_sched_task_done_tick     = 1005L;

  ulong in_chunk = ctx->in[ TEST_EXECRP_IN_IDX ].chunk0;
  fd_execrp_task_done_msg_t * msg = fd_chunk_to_laddr( ctx->in[ TEST_EXECRP_IN_IDX ].mem, in_chunk );
  fd_memset( msg, 0, sizeof(*msg) );
  msg->bank_idx                         = bank->idx;
  msg->txn_exec->txn_idx                = mock_sched_txn_idx;
  msg->txn_exec->is_committable         = 1;
  msg->txn_exec->is_fees_only           = 1;
  msg->txn_exec->txn_err                = FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
  msg->txn_exec->is_simple_vote         = 1;
  msg->txn_exec->tick_load_start        = 2001L;
  msg->txn_exec->tick_check_start       = 2002L;
  msg->txn_exec->tick_exec_start        = LONG_MAX;
  msg->txn_exec->tick_commit_start      = 2003L;
  msg->txn_exec->tick_commit_end        = 2004L;
  msg->txn_exec->compute_units_consumed = 3456U;
  msg->txn_exec->transaction_fee        = 5001UL;
  msg->txn_exec->priority_fee           = 5002UL;
  msg->txn_exec->tips                   = 5003UL;
  msg->txn_exec->bank_seq               = 4321UL;

  ulong out_chunk = ctx->replay_out->chunk;
  ulong sig = (FD_EXECRP_TT_TXN_EXEC<<32) | mock_sched_txn_info.exec_tile_idx;
  FD_TEST( !returnable_frag( ctx, TEST_EXECRP_IN_IDX, 0UL, sig, in_chunk,
                             sizeof(*msg), 0UL, 0UL, 0UL, test_stem ) );

  FD_TEST( bank->refcnt==0UL );
  FD_TEST( mock_sched_task_done_cnt==1UL );
  FD_TEST( mock_sched_task_done_type==FD_SCHED_TT_TXN_EXEC );
  FD_TEST( mock_sched_task_done_txn_idx==mock_sched_txn_idx );
  FD_TEST( mock_sched_task_done_exec_idx==mock_sched_txn_info.exec_tile_idx );

  ulong out_idx = ctx->replay_out->idx;
  FD_TEST( test_stem_seqs[ out_idx ]==1UL );
  fd_frag_meta_t const * meta = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( 0UL, test_stem_depths[ out_idx ] );
  FD_TEST( meta->seq==0UL );
  FD_TEST( meta->sig==REPLAY_SIG_TXN_EXECUTED );
  FD_TEST( meta->chunk==out_chunk );
  FD_TEST( meta->sz==sizeof(fd_replay_txn_executed_t) );

  fd_replay_txn_executed_t const * out = fd_chunk_to_laddr_const( ctx->replay_out->mem, meta->chunk );
  FD_TEST( !memcmp( out->txn, &mock_sched_txn, sizeof(mock_sched_txn) ) );
  FD_TEST( out->txn_err==msg->txn_exec->txn_err );
  FD_TEST( out->is_committable==msg->txn_exec->is_committable );
  FD_TEST( out->is_fees_only==msg->txn_exec->is_fees_only );
  FD_TEST( out->is_simple_vote==msg->txn_exec->is_simple_vote );

  FD_TEST( out->tick_parsed==mock_sched_txn_info.tick_parsed );
  FD_TEST( out->tick_sigverify_disp==mock_sched_txn_info.tick_sigverify_disp );
  FD_TEST( out->tick_sigverify_done==mock_sched_txn_info.tick_sigverify_done );
  FD_TEST( out->tick_exec_done==mock_sched_task_done_tick );
  FD_TEST( out->tick_load_start==msg->txn_exec->tick_load_start );
  FD_TEST( out->tick_check_start==msg->txn_exec->tick_check_start );
  FD_TEST( out->tick_exec_start==LONG_MAX );
  FD_TEST( out->tick_commit_start==msg->txn_exec->tick_commit_start );
  FD_TEST( out->tick_commit_end==msg->txn_exec->tick_commit_end );

  FD_TEST( out->slot==mock_sched_txn_info.slot );
  FD_TEST( mock_sched_txn_info.bank_seq==msg->txn_exec->bank_seq );
  FD_TEST( out->bank_seq==msg->txn_exec->bank_seq );
  FD_TEST( out->index_in_slot==mock_sched_txn_info.index_in_slot );
  FD_TEST( out->exec_tile_idx==mock_sched_txn_info.exec_tile_idx );
  FD_TEST( out->sigverify_exec_tile_idx==mock_sched_txn_info.sigverify_exec_tile_idx );
  FD_TEST( out->compute_units_consumed==msg->txn_exec->compute_units_consumed );
  FD_TEST( out->max_compute_units==ULONG_MAX );
  FD_TEST( out->transaction_fee==msg->txn_exec->transaction_fee );
  FD_TEST( out->priority_fee==msg->txn_exec->priority_fee );
  FD_TEST( out->tips==msg->txn_exec->tips );

  FD_LOG_NOTICE(( "pass: test_txn_completion_publish" ));
}

static void
test_reception_metrics_sidecar( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[1];
  setup_ctx( ctx, wksp );

  fd_hash_t mr_root = { .ul = { 100UL } };
  fd_hash_t mr1_0   = { .ul = { 200UL } };
  fd_hash_t mr1_32  = { .ul = { 300UL } };
  fd_hash_t mr1_64  = { .ul = { 400UL } };
  fd_hash_t mr1_0_b = { .ul = { 500UL } };
  init_root_fec( ctx, &mr_root );

  fd_fec_complete_metrics_t metrics_a = {
    .stats_valid                   = 1U,
    .blk_turbine_cnt               = 1U,
    .blk_repair_cnt                = 2U,
    .blk_recovered_cnt             = 3U,
    .blk_data_cnt                  = 4U,
    .blk_parity_cnt                = 5U,
    .blk_lowest_verified_fec       = 6U,
    .blk_chain_confirmed           = 1U,
    .blk_slot_complete             = 0U,
    .blk_req_window_cnt            = 7U,
    .blk_req_highest_cnt           = 8U,
    .blk_req_orphan_cnt            = 9U,
    .blk_req_retransmit_cnt        = 10U,
    .blk_repair_responses          = 11U,
    .blk_chain_verify_failed       = 0U,
    .fec_completed_ts_nanos        = 12UL,
    .blk_first_shred_ts_nanos      = 13UL,
    .blk_last_shred_ts_nanos       = 14UL,
    .blk_first_req_ts_nanos        = 15UL,
    .blk_last_repair_resp_ts_nanos = 16UL,
  };

  fd_reasm_fec_t * f1_0 = ingest_fec_complete_with_metrics( ctx, &mr1_0, &mr_root,
      1UL, 0U, 1U, 32U, 1, 0, &metrics_a );
  FD_TEST( f1_0->fec_completed_ts_nanos==metrics_a.fec_completed_ts_nanos );
  FD_TEST( ctx->reception_stats[ 1UL % ctx->reception_stats_cnt ].slot==1UL );

  fd_fec_complete_metrics_t metrics_invalid = {
    .stats_valid            = 0U,
    .fec_completed_ts_nanos = 22UL,
  };
  fd_reasm_fec_t * f1_32 = ingest_fec_complete_with_metrics( ctx, &mr1_32, &mr1_0,
      1UL, 32U, 1U, 32U, 1, 0, &metrics_invalid );
  FD_TEST( f1_32->fec_completed_ts_nanos==metrics_invalid.fec_completed_ts_nanos );

  fd_event_block_completed_t ev = {0};
  block_completed_event_fill_reception( ctx, &ev, &mr1_32, 1UL );
  FD_TEST( ev.fec_set_count==2UL );
  assert_reception_event_matches( &ev, &metrics_a, 0U );

  fd_fec_complete_metrics_t metrics_b = metrics_a;
  metrics_b.blk_turbine_cnt        = 21U;
  metrics_b.blk_slot_complete      = 1U;
  metrics_b.fec_completed_ts_nanos = 23UL;
  fd_reasm_fec_t * f1_64 = ingest_fec_complete_with_metrics( ctx, &mr1_64, &mr1_32,
      1UL, 64U, 1U, 32U, 1, 1, &metrics_b );
  FD_TEST( f1_64->fec_completed_ts_nanos==metrics_b.fec_completed_ts_nanos );
  FD_TEST( ctx->reception_stats[ 1UL % ctx->reception_stats_cnt ].slot==1UL );

  memset( &ev, 0, sizeof(ev) );
  block_completed_event_fill_reception( ctx, &ev, &mr1_64, 1UL );
  assert_reception_event_matches( &ev, &metrics_b, 64U );

  fd_fec_complete_metrics_t metrics_c = metrics_a;
  metrics_c.blk_turbine_cnt        = 31U;
  metrics_c.fec_completed_ts_nanos = 32UL;
  fd_reasm_fec_t * f1_0_b = ingest_fec_complete_with_metrics( ctx, &mr1_0_b, &mr_root,
      1UL, 0U, 1U, 32U, 1, 1, &metrics_c );
  FD_TEST( f1_0_b->eqvoc );
  FD_TEST( ctx->reception_stats[ 1UL % ctx->reception_stats_cnt ].slot==1UL );

  memset( &ev, 0, sizeof(ev) );
  block_completed_event_fill_reception( ctx, &ev, &mr1_64, 1UL );
  assert_reception_event_matches( &ev, &metrics_c, 0U );

  memset( &ev, 0, sizeof(ev) );
  block_completed_event_fill_reception( ctx, &ev, &mr1_0_b, 1UL );
  assert_reception_event_matches( &ev, &metrics_c, 0U );

  fd_fec_complete_metrics_t capacity_metrics = metrics_a;
  for( ulong slot=1UL; slot<=TEST_BANKS_MAX+1UL; slot++ ) {
    capacity_metrics.blk_turbine_cnt = (uint)slot;
    fd_reception_stats_t * stats = &ctx->reception_stats[ slot % ctx->reception_stats_cnt ];
    stats->slot        = slot;
    stats->fec_set_idx = (uint)slot;
    stats->metrics     = capacity_metrics;
  }
  FD_TEST( ctx->reception_stats[ 1UL % ctx->reception_stats_cnt ].slot!=1UL );
  fd_reception_stats_t * latest = &ctx->reception_stats[ (TEST_BANKS_MAX+1UL) % ctx->reception_stats_cnt ];
  FD_TEST( latest->slot==TEST_BANKS_MAX+1UL );
  FD_TEST( latest->metrics.blk_turbine_cnt==TEST_BANKS_MAX+1UL );

  FD_LOG_NOTICE(( "pass: test_reception_metrics_sidecar" ));
}

static int
drive_after_credit_once( fd_replay_tile_t * ctx ) {
  int opt_poll_in = 1;
  int charge_busy = 0;
  ctx->execrp_idle_cnt = 2UL*ctx->in_cnt;
  after_credit( ctx, test_stem, &opt_poll_in, &charge_busy );
  return charge_busy;
}

static fd_reasm_fec_t *
drive_one_fec( fd_replay_tile_t * ctx,
               ulong              slot,
               uint               fec_set_idx ) {
  fd_reasm_fec_t * fec = fd_reasm_peek( ctx->reasm );
  FD_TEST( fec && fec->slot==slot && fec->fec_set_idx==fec_set_idx );

  FD_TEST( drive_after_credit_once( ctx ) );
  FD_TEST( fec->popped );
  return fec;
}

static fd_bank_t *
drive_become_leader( fd_replay_tile_t * ctx,
                     fd_hash_t const *  reset_cmr,
                     ulong              leader_slot ) {
  fd_bank_t * reset_bank = fd_banks_root( ctx->banks );
  FD_TEST( reset_bank );

  mock_next_leader_slot = leader_slot;
  ctx->reset_slot       = reset_bank->f.slot;
  ctx->reset_cmr        = *reset_cmr;
  ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, leader_slot, ctx->identity_pubkey );
  FD_TEST( ctx->next_leader_slot==leader_slot );
  ctx->next_leader_tickcount = 0L;

  FD_TEST( drive_after_credit_once( ctx ) );

  FD_TEST( ctx->is_leader );
  FD_TEST( ctx->leader_bank );
  FD_TEST( ctx->leader_bank->is_leader );
  FD_TEST( ctx->leader_bank->f.slot==leader_slot );
  FD_TEST( ctx->leader_bank->parent_idx==reset_bank->idx );
  return ctx->leader_bank;
}

static void
test_leader_fec_payload_retained( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );

  fd_hash_t mr_root   = { .ul = { 100UL } };
  fd_hash_t mr_leader = { .ul = { 200UL } };
  init_root_fec( ctx, &mr_root );
  drive_become_leader( ctx, &mr_root, 1UL );

  fd_reasm_fec_t * leader_fec = ingest_fec_complete_with_signal(
      ctx, REPAIR_SIG_FEC_LEADER, &mr_leader, &mr_root, 1UL, 0U, 1U, 32U, 1, 1, NULL );
  FD_TEST( leader_fec );

  ulong sched_cnt = mock_sched_fec_ingest_cnt;
  drive_one_fec( ctx, 1UL, 0U );
  FD_TEST( mock_store_view_call_cnt==0UL );
  FD_TEST( mock_sched_fec_ingest_cnt==sched_cnt );

  fd_reasm_fec_t stale_fec = { .key = { .ul = { 300UL } }, .slot = 2UL, .is_leader = 1U };
  FD_TEST( !insert_fec_set( ctx, test_stem, &stale_fec ) );

  FD_LOG_NOTICE(( "pass: test_leader_fec_payload_retained" ));
}

static void
test_snapshot_intervals_use_block_height( void ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_memset( ctx, 0, sizeof(fd_replay_tile_t) );

  ctx->caught_up                             = 1;
  ctx->snapmk.supported                      = 1;
  ctx->snapmk.scheduled_at_slot              = ULONG_MAX;
  ctx->snapmk.full_interval_blocks           = 100000UL;
  ctx->snapmk.next_full_block_height         = ULONG_MAX;
  ctx->snapmk.next_incremental_block_height  = ULONG_MAX;
  ctx->snapmk.base_slot                      = ULONG_MAX;

  int incremental = -1;
  FD_TEST( !snapshot_due_for_root( ctx, 99998UL, 250000UL, 99999UL, 99999UL, &incremental ) );
  FD_TEST( !incremental );
  FD_TEST( ctx->snapmk.next_full_block_height==100000UL );

  FD_TEST( snapshot_due_for_root( ctx, 99999UL, 250001UL, 100000UL, 100000UL, &incremental ) );
  FD_TEST( !incremental );

  ctx->snapmk.next_full_block_height        = 200000UL;
  ctx->snapmk.incremental_interval_blocks   = 200UL;
  ctx->snapmk.next_incremental_block_height = ULONG_MAX;
  ctx->snapmk.base_slot                     = 100UL;
  FD_TEST( !snapshot_due_for_root( ctx, 398UL, 250002UL, 399UL, 399UL, &incremental ) );
  FD_TEST( !incremental );
  FD_TEST( ctx->snapmk.next_incremental_block_height==400UL );

  FD_TEST( snapshot_due_for_root( ctx, 399UL, 250003UL, 400UL, 400UL, &incremental ) );
  FD_TEST( incremental );

  ctx->snapmk.next_full_block_height        = 200000UL;
  ctx->snapmk.next_incremental_block_height = 200000UL;
  FD_TEST( snapshot_due_for_root( ctx, 199999UL, 400UL, 200000UL, 200000UL, &incremental ) );
  FD_TEST( !incremental );

  FD_LOG_NOTICE(( "pass: test_snapshot_intervals_use_block_height" ));
}

static void
start_fec_with_epoch_boundary_mode( fd_replay_tile_t * ctx,
                                    fd_reasm_fec_t *   fec,
                                    int                freeze_bank,
                                    int                epoch_boundary_enabled ) {
  int prev_epoch_boundary_enabled = mock_epoch_boundary_enabled;
  mock_epoch_boundary_enabled = epoch_boundary_enabled;
  replay_block_start( ctx, fec->bank_idx, fec->parent_bank_idx, fec->slot );
  mock_epoch_boundary_enabled = prev_epoch_boundary_enabled;

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, fec->bank_idx );
  FD_TEST( bank );
  if( freeze_bank ) fd_banks_mark_bank_frozen( bank );
}

static void
start_epoch_boundary_fec( fd_replay_tile_t * ctx,
                          fd_reasm_fec_t *   fec,
                          int                freeze_bank ) {
  start_fec_with_epoch_boundary_mode( ctx, fec, freeze_bank, 1 );
}

static void
start_non_epoch_boundary_fec( fd_replay_tile_t * ctx,
                              fd_reasm_fec_t *   fec,
                              int                freeze_bank ) {
  start_fec_with_epoch_boundary_mode( ctx, fec, freeze_bank, 0 );
}

static void
test_consensus_root_notification_handoff( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  memset( ctx, 0, sizeof(*ctx) );
  setup_timing( ctx, wksp );
  setup_stem( ctx, wksp );

  ulong const bank_cnt = 4UL;
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( bank_cnt, bank_cnt, 8UL, 128UL, 8UL ), 1UL );
  FD_TEST( banks_mem );
  ctx->banks = fd_banks_join( fd_banks_new( banks_mem, bank_cnt, bank_cnt, 8UL, 128UL, 8UL, 0, 43UL ) );
  FD_TEST( ctx->banks );

  fd_bank_t * root = fd_banks_init_bank( ctx->banks );
  FD_TEST( root );
  root->f.slot                        = 0UL;
  root->f.parent_slot                 = 0UL;
  root->f.slot_params                 = FD_SLOT_PARAMS_400MS;
  root->f.slot_params.hashes_per_tick = 4UL;
  root->f.slot_params_default         = FD_SLOT_PARAMS_400MS;
  fd_epoch_schedule_derive( &root->f.epoch_schedule, 128UL, 128UL, 0 );

  fd_hash_t root_id  = { .ul = { 100UL } };
  fd_hash_t child_id = { .ul = { 200UL } };
  root->f.block_id   = root_id;
  fd_blockhashes_init( &root->f.block_hash_queue, 42UL );
  FD_TEST( fd_blockhashes_push_new( &root->f.block_hash_queue, &root_id ) );

  ulong chain_cnt = fd_block_id_map_chain_cnt_est( bank_cnt );
  ctx->block_id_arr = fd_wksp_alloc_laddr( wksp, alignof(fd_block_id_ele_t), sizeof(fd_block_id_ele_t)*bank_cnt, 1UL );
  FD_TEST( ctx->block_id_arr );
  memset( ctx->block_id_arr, 0, sizeof(fd_block_id_ele_t)*bank_cnt );
  void * map_mem = fd_wksp_alloc_laddr( wksp, fd_block_id_map_align(), fd_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( map_mem );
  ctx->block_id_map = fd_block_id_map_join( fd_block_id_map_new( map_mem, chain_cnt, 44UL ) );
  FD_TEST( ctx->block_id_map );
  ctx->block_id_len   = bank_cnt;
  ctx->max_live_slots = bank_cnt;

  void * reasm_mem = fd_wksp_alloc_laddr( wksp, fd_reasm_align(), fd_reasm_footprint( 2UL ), 1UL );
  FD_TEST( reasm_mem );
  ctx->reasm = fd_reasm_join( fd_reasm_new( reasm_mem, 2UL, 0UL ) );
  FD_TEST( ctx->reasm );

  void * store_mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( 2UL, 1UL, 0UL, 0UL, 0UL ), 1UL );
  FD_TEST( store_mem );
  ctx->store = fd_store_join( fd_store_new( store_mem, 2UL, 1UL, 0UL, 0UL, 0UL, 0UL ) );
  FD_TEST( ctx->store );
  FD_TEST( fd_store_map_ljoin( ctx->store, ctx->map_join ) );
  ctx->store_disk_fd = -1;

  static fd_runtime_stack_t runtime_stack[ 1 ];
  fd_memset( runtime_stack, 0, sizeof(fd_runtime_stack_t) );
  ctx->runtime_stack = runtime_stack;
  ctx->initial_block_id = root_id;
  ctx->manifest_block_id = root_id;
  ctx->has_manifest_block_id = 1;

  root->accdb_fork_id        = (fd_accdb_fork_id_t){ .val=37U };
  root->parent_accdb_fork_id = root->accdb_fork_id;
  ctx->has_expected_genesis_timestamp = 1;
  mock_accdb_fork_id_next = 0U;
  static ulong test_metrics[ FD_METRICS_TOTAL_SZ/sizeof(ulong) ];
  volatile ulong * saved_metrics_tl = fd_metrics_tl;
  fd_metrics_tl = test_metrics;
  mock_snapshot_boot = 1;
  on_snapshot_message( ctx, test_stem, 0UL, 0UL, fd_ssmsg_sig( FD_SSMSG_DONE ) );
  mock_snapshot_boot = 0;
  fd_metrics_tl = saved_metrics_tl;
  FD_TEST( root->accdb_fork_id.val==37U );
  FD_TEST( root->parent_accdb_fork_id.val==37U );
  FD_TEST( mock_accdb_fork_id_next==0U );
  root->refcnt = 0UL;

  fd_bank_t * child = fd_banks_new_bank( ctx->banks, root->idx, 0L, 0 );
  child = fd_banks_clone_from_parent( ctx->banks, child->idx );
  FD_TEST( child );
  child->f.slot     = 1UL;
  child->f.block_id = child_id;
  fd_banks_mark_bank_frozen( child );

  fd_block_id_ele_t * child_ele = &ctx->block_id_arr[ child->idx ];
  child_ele->latest_mr    = child_id;
  child_ele->slot         = child->f.slot;
  child_ele->bank_seq     = child->bank_seq;
  child_ele->block_id_seen = 1;
  FD_TEST( fd_block_id_map_ele_insert( ctx->block_id_map, child_ele, ctx->block_id_arr ) );

  ctx->resolv_tile_cnt   = 1UL;
  ctx->consensus_root    = root_id;
  ctx->consensus_root_slot = 0UL;
  ctx->notified_root     = root_id;
  ctx->notified_root_slot = 0UL;
  ctx->notified_root_bank = root;

  publish_root_advanced( ctx, test_stem, root );
  FD_TEST( root->refcnt==1UL );

  ctx->consensus_root      = child_id;
  ctx->consensus_root_slot = child->f.slot;

  ulong advanceable_idx = ULONG_MAX;
  FD_TEST( !fd_banks_advance_root_prepare( ctx->banks, child->idx, &advanceable_idx ) );

  FD_TEST( try_notify_consensus_root( ctx, test_stem ) );
  FD_TEST( mock_sched_root_notify_cnt==1UL );
  FD_TEST( mock_sched_root_notify_idx==child->idx );
  FD_TEST( child->refcnt==1UL );

  FD_TEST( !try_notify_consensus_root( ctx, test_stem ) );
  FD_TEST( mock_sched_root_notify_cnt==1UL );
  FD_TEST( child->refcnt==1UL );

  process_resolv_slot_completed( ctx, root->idx );
  FD_TEST( root->refcnt==0UL );
  FD_TEST( fd_banks_advance_root_prepare( ctx->banks, child->idx, &advanceable_idx ) );
  FD_TEST( advanceable_idx==child->idx );

  child->refcnt = 0UL;
  FD_LOG_NOTICE(( "pass: test_consensus_root_notification_handoff" ));
}

static void
test_eqvoc_last_fec( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx_with_fork_width( ctx, wksp, TEST_BANKS_MAX );
  fd_reasm_t * reasm = ctx->reasm;

  /* Merkle roots — arbitrary unique hashes. */

  fd_hash_t mr_root      = { .ul = { 100 } };
  fd_hash_t mr1_0        = { .ul = { 200 } };
  fd_hash_t mr1_32       = { .ul = { 300 } };
  fd_hash_t mr1_32_eqvoc = { .ul = { 999 } };
  fd_hash_t mr2_0        = { .ul = { 400 } };

  /* 1. Insert root FEC (slot 0).  chained_merkle_root is NULL for the
     very first FEC in a reasm instance.  The root is automatically
     marked popped=1, confirmed=1 by fd_reasm_insert. */

  init_root_fec( ctx, &mr_root );

  /* 2. Insert FEC 0 of slot 1 (chained off root). */

  fd_reasm_fec_t * f1_0 = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0 );

  /* 3. Insert FEC 32 of slot 1 (slot_complete, chained off FEC 0). */

  fd_reasm_fec_t * f1_32 = ingest_fec_complete( ctx, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 1 );
  FD_TEST( f1_32 );

  /* 4. Pop FEC 0 and process it through the replay tile path. */

  fd_reasm_fec_t * fec = drive_one_fec( ctx, 1UL, 0U );

  /* 5. Pop FEC 32 and process it. */

  fec = drive_one_fec( ctx, 1UL, 32U );
  ulong first_bank_idx = fec->bank_idx;
  FD_TEST( first_bank_idx!=fd_banks_root( ctx->banks )->idx );

  /* 6. Insert equivocating FEC 32 — same (slot, fec_set_idx) but
     different merkle root.  Reasm detects the equivocation. */

  fd_reasm_fec_t * f1_32_eq = ingest_fec_complete( ctx, &mr1_32_eqvoc, &mr1_0,
      1, 32, 1, 32, 1, 1 );
  FD_TEST( f1_32_eq );

  /* 7. Verify: the equivocating FEC is NOT delivered.  The eqvoc flag
     is set and confirmed==0, so the gate blocks delivery. */

  FD_TEST( f1_32_eq->eqvoc==1 );
  FD_TEST( f1_32_eq->confirmed==0 );
  FD_TEST( fd_reasm_peek( reasm )==NULL );
  FD_TEST( fd_reasm_pop ( reasm )==NULL );

  fd_reasm_confirm( reasm, &mr1_32_eqvoc );

  fec = drive_one_fec( ctx, 1UL, 32U );
  ulong eqvoc_bank_idx = fec->bank_idx;
  FD_TEST( eqvoc_bank_idx!=first_bank_idx );                         /* new bank is allocated */
  FD_TEST( fd_reasm_query( reasm, &mr1_0 )->bank_idx==eqvoc_bank_idx ); /* bank idx is updated for fec 0 */

  /* latest mr is updated */
  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ fec->bank_idx ];
  FD_TEST( memcmp( &block_id_ele->latest_mr, &mr1_32_eqvoc, sizeof(fd_hash_t) ) == 0 ); /* so bad lol */

  fd_block_id_ele_t * block_id_ele_0 = &ctx->block_id_arr[ first_bank_idx ];
  FD_TEST( memcmp( &block_id_ele_0->latest_mr, &mr1_32, sizeof(fd_hash_t) ) == 0 );

  fd_reasm_fec_t * f2_0 = ingest_fec_complete( ctx, &mr2_0, &mr1_32_eqvoc,
      2, 0, 1, 32, 1, 0 );
  FD_TEST( f2_0 );
  fec = drive_one_fec( ctx, 2UL, 0U );
  FD_TEST( fec->bank_idx!=first_bank_idx && fec->bank_idx!=eqvoc_bank_idx ); /* used to bank hash mismatch */

  FD_LOG_NOTICE(( "pass: test_eqvoc_fec_gate" ));
}

static void
test_eqvoc_first_fec( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx_with_fork_width( ctx, wksp, TEST_BANKS_MAX );
  fd_reasm_t * reasm = ctx->reasm;

  fd_hash_t mr_root = { .ul = { 100 } };
  fd_hash_t mr1_0   = { .ul = { 200 } };
  fd_hash_t mr1_32  = { .ul = { 300 } };

  init_root_fec( ctx, &mr_root );

  fd_reasm_fec_t * f1_0 = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0 );

  fd_reasm_fec_t * f1_32 = ingest_fec_complete( ctx, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0 );
  FD_TEST( f1_32 );

  fd_reasm_fec_t * fec = drive_one_fec( ctx, 1UL, 0U );

  fec = drive_one_fec( ctx, 1UL, 32U );
  ulong first_bank_idx = fec->bank_idx;
  FD_TEST( first_bank_idx!=fd_banks_root( ctx->banks )->idx );

  /* Insert equivocating version */
  fd_hash_t mr1_32_ = { .ul = { 32, 1 } };
  fd_hash_t mr1_0_  = { .ul = { 0,  1 } };
  fd_reasm_fec_t * f1_32_eq = ingest_fec_complete( ctx, &mr1_32_, &mr1_0_,
      1, 32, 1, 32, 1, 1 );
  FD_TEST( f1_32_eq->eqvoc );

  fd_reasm_fec_t * fd_1_0_eq = ingest_fec_complete( ctx, &mr1_0_, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( fd_1_0_eq->eqvoc );

  /* no delivery of eqvoc */
  FD_TEST( fd_reasm_peek( reasm )==NULL );

  /* confirm equivocating version */
  fd_reasm_confirm( reasm, &mr1_32_ );

  /* delivery of confirmed version */
  fec = drive_one_fec( ctx, 1UL, 0U );
  ulong eqvoc_bank_idx = fec->bank_idx;
  FD_TEST( eqvoc_bank_idx!=first_bank_idx );

  fec = drive_one_fec( ctx, 1UL, 32U );
  FD_TEST( fec->bank_idx==eqvoc_bank_idx );

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

  /* Root FEC (slot 0). */

  init_root_fec( ctx, &mr_root );

  /* Slot 1: 4 FECs chained sequentially. */

  fd_reasm_fec_t * f1_0 = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0 );

  fd_reasm_fec_t * f1_32 = ingest_fec_complete( ctx, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0 );
  FD_TEST( f1_32 );

  fd_reasm_fec_t * f1_64 = ingest_fec_complete( ctx, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 0 );
  FD_TEST( f1_64 );

  fd_reasm_fec_t * f1_96 = ingest_fec_complete( ctx, &mr1_96, &mr1_64,
      1, 96, 1, 32, 1, 1 );
  FD_TEST( f1_96 );

  /* Pop and process all 4 FECs. */

  fd_reasm_fec_t * fec = drive_one_fec( ctx, 1UL, 0U );
  ulong bank_idx = fec->bank_idx;

  fec = drive_one_fec( ctx, 1UL, 32U );
  FD_TEST( fec->bank_idx==bank_idx );

  fec = drive_one_fec( ctx, 1UL, 64U );
  FD_TEST( fec->bank_idx==bank_idx );

  fec = drive_one_fec( ctx, 1UL, 96U );
  FD_TEST( fec->bank_idx==bank_idx );

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

  /* 1. Insert root FEC (slot 0). */

  init_root_fec( ctx, &mr_root );

  /* 2. Insert 3 FEC sets for slot 1. */

  fd_reasm_fec_t * f1_0 = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0 );

  fd_reasm_fec_t * f1_32 = ingest_fec_complete( ctx, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0 );
  FD_TEST( f1_32 );

  fd_reasm_fec_t * f1_64 = ingest_fec_complete( ctx, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 1 );
  FD_TEST( f1_64 );

  /* 3. Pop and process all 3. */

  fd_reasm_fec_t * fec = drive_one_fec( ctx, 1UL, 0U );

  fec = drive_one_fec( ctx, 1UL, 32U );

  fec = drive_one_fec( ctx, 1UL, 64U );

  /* After processing, bank 1 should have been allocated. */
  ulong first_bank_idx = fec->bank_idx;
  FD_TEST( first_bank_idx!=fd_banks_root( ctx->banks )->idx );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==2UL );

  /* Queue should be empty. */
  FD_TEST( fd_reasm_peek( reasm )==NULL );

  /* 4. Evict the slot 1 chain by removing the leaf (FEC 64) from the
     frontier.  fd_reasm_remove walks up to fec_set_idx==0, so FECs 0,
     32, 64 are all evicted. */

  fd_reasm_fec_t * leaf = fd_reasm_query( reasm, &mr1_64 );
  FD_TEST( leaf );
  fd_reasm_fec_t * evicted_head = fd_reasm_remove( reasm, leaf, NULL, NULL );
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

  f1_0 = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0 );

  f1_32 = ingest_fec_complete( ctx, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0 );
  FD_TEST( f1_32 );

  f1_64 = ingest_fec_complete( ctx, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 1 );
  FD_TEST( f1_64 );

  /* 6. Pop and process all 3 again. */

  ulong sched_ingest_cnt_before = mock_sched_fec_ingest_cnt;

  fec = drive_one_fec( ctx, 1UL, 0U );

  fec = drive_one_fec( ctx, 1UL, 32U );

  fec = drive_one_fec( ctx, 1UL, 64U );

  /* 7. A NEW bank should have been allocated (fec_set_idx==0 always
     allocates a new bank in insert_fec_set). */
  FD_TEST( fec->bank_idx!=first_bank_idx );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==3UL );

  /* 8. Execution was scheduled for the reinserted FECs. */
  FD_TEST( mock_sched_fec_ingest_cnt>sched_ingest_cnt_before );

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

  /* 1. Insert root FEC (slot 0). */

  init_root_fec( ctx, &mr_root );

  /* 2. Insert 3 FEC sets for slot 1 version A. */

  fd_reasm_fec_t * f1_0 = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0 );

  fd_reasm_fec_t * f1_32 = ingest_fec_complete( ctx, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0 );
  FD_TEST( f1_32 );

  fd_reasm_fec_t * f1_64 = ingest_fec_complete( ctx, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 1 );
  FD_TEST( f1_64 );

  /* 3. Pop and process all 3 FEC sets.  After this, bank 1 is allocated
     for slot 1. */

  fd_reasm_fec_t * fec = drive_one_fec( ctx, 1UL, 0U );

  fec = drive_one_fec( ctx, 1UL, 32U );

  fec = drive_one_fec( ctx, 1UL, 64U );
  ulong version_a_bank_idx = fec->bank_idx;
  FD_TEST( version_a_bank_idx!=fd_banks_root( ctx->banks )->idx );

  FD_TEST( fd_reasm_peek( reasm )==NULL );

  /* 4. Evict the entire slot 1 chain from reasm.  fd_reasm_remove walks
     UP from the leaf (FEC 64) and stops at fec_set_idx==0, so FEC 0,
     32, and 64 are all evicted.  Walk the evicted chain (linked via
     child pointers) and release each element back to the pool. */

  fd_reasm_fec_t * evicted = fd_reasm_remove( reasm, f1_64, NULL, NULL );
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

  fd_reasm_fec_t * f1_0_new = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0_new );
  FD_TEST( !f1_0_new->eqvoc );

  fec = drive_one_fec( ctx, 1UL, 0U );
  ulong version_b_bank_idx = fec->bank_idx;
  FD_TEST( version_b_bank_idx!=version_a_bank_idx );

  /* 6. Insert version B's FEC 32' and 64' (different merkle roots from
     version A) chaining off the reinserted FEC 0.  Reasm does NOT
     detect equivocation because version A was evicted. */

  fd_reasm_fec_t * f1_32p = ingest_fec_complete( ctx, &mr1_32_prime, &mr1_0,
      1, 32, 1, 32, 1, 0 );
  FD_TEST( f1_32p );
  FD_TEST( !f1_32p->eqvoc );

  fd_reasm_fec_t * f1_64p = ingest_fec_complete( ctx, &mr1_64_prime, &mr1_32_prime,
      1, 64, 1, 32, 1, 1 );
  FD_TEST( f1_64p );
  FD_TEST( !f1_64p->eqvoc );

  /* 7. Pop and process version B's FEC sets.  They should inherit the
     fresh bank (bank_idx=2) from the reinserted FEC 0. */

  fec = drive_one_fec( ctx, 1UL, 32U );
  FD_TEST( fec->bank_idx==version_b_bank_idx );

  fec = drive_one_fec( ctx, 1UL, 64U );
  FD_TEST( fec->bank_idx==version_b_bank_idx );

  FD_TEST( fd_reasm_peek( reasm )==NULL );

  FD_LOG_NOTICE(( "pass: test_eqvoc_mid_slot_evicted" ));
}

/* Banks eviction across two consecutive slots: slots 1 and 2 each have
   2 FECs.  We pop and process all of slot 1 (bank 1) and the first FEC
   of slot 2 (bank 2).  Then banks evicts both banks (simulated by
   bumping bank_seq so the replay tile sees a seq mismatch).  Backfill
   reconstructs at most one slot at a time: slot 2's second FEC rebuilds
   slot 1, then a future slot 3 FEC rebuilds slot 2. */

static void
test_banks_evict_backfill( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );

  fd_hash_t mr_root = { .ul = { 100 } };
  fd_hash_t mr1_0   = { .ul = { 200 } };
  fd_hash_t mr1_32  = { .ul = { 300 } };
  fd_hash_t mr2_0   = { .ul = { 400 } };
  fd_hash_t mr2_32  = { .ul = { 500 } };
  fd_hash_t mr3_0   = { .ul = { 600 } };

  /* 1. Root FEC (slot 0). */

  init_root_fec( ctx, &mr_root );

  /* 2. Insert slot 1: 2 FECs (0 and 32), slot_complete on FEC 32. */

  fd_reasm_fec_t * f1_0 = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0 );

  fd_reasm_fec_t * f1_32 = ingest_fec_complete( ctx, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 1 );
  FD_TEST( f1_32 );

  /* 3. Insert slot 2: 2 FECs (0 and 32), slot_complete on FEC 32. */

  fd_reasm_fec_t * f2_0 = ingest_fec_complete( ctx, &mr2_0, &mr1_32,
      2, 0, 1, 32, 1, 0 );
  FD_TEST( f2_0 );

  fd_reasm_fec_t * f2_32 = ingest_fec_complete( ctx, &mr2_32, &mr2_0,
      2, 32, 1, 32, 1, 1 );
  FD_TEST( f2_32 );

  /* 4. Pop and process all of slot 1 → bank 1. */

  fd_reasm_fec_t * fec = drive_one_fec( ctx, 1UL, 0U );

  fec = drive_one_fec( ctx, 1UL, 32U );
  ulong slot1_bank_idx = fec->bank_idx;
  FD_TEST( slot1_bank_idx!=fd_banks_root( ctx->banks )->idx );

  /* 5. Pop and process first FEC of slot 2 → bank 2. */

  fec = drive_one_fec( ctx, 2UL, 0U );
  ulong slot2_bank_idx = fec->bank_idx;
  FD_TEST( slot2_bank_idx!=slot1_bank_idx );

  /* 6. Simulate banks evicting both bank 1 and bank 2 by bumping their
     bank_seq.  Now the replay tile will see a seq mismatch and treat
     them as evicted. */

  fd_banks_bank_query( ctx->banks, slot1_bank_idx )->bank_seq = 999UL;
  fd_banks_bank_query( ctx->banks, slot2_bank_idx )->bank_seq = 999UL;

  /* 7. Pop the second FEC of slot 2 and process it.  Backfill walks
     through invalid slots 2 and 1, but retains and reconstructs only
     the oldest slot nearest the valid root. */

  fec = drive_one_fec( ctx, 2UL, 32U );

  /* 8. Verify: slot 1 was backfilled with a new bank (bank 3). */

  ulong new_slot1_bank_idx = f1_32->bank_idx;
  FD_TEST( new_slot1_bank_idx!=slot1_bank_idx );
  FD_TEST( f1_0->bank_idx==new_slot1_bank_idx );

  /* 9. Verify: slot 2 has not been backfilled yet. */

  FD_TEST( f2_0->bank_idx==slot2_bank_idx );
  FD_TEST( f2_32->bank_idx==UINT_MAX );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==4UL );

  /* 10. A future FEC chaining off slot 2 drives the next round of
     backfill.  Slot 2 should now receive a replacement bank while
     slot 3 remains deferred. */

  fd_reasm_fec_t * f3_0 = ingest_fec_complete( ctx, &mr3_0, &mr2_32,
      3, 0, 1, 32, 1, 1 );
  FD_TEST( f3_0 );

  fec = drive_one_fec( ctx, 3UL, 0U );

  ulong new_slot2_bank_idx = f2_32->bank_idx;
  FD_TEST( new_slot2_bank_idx!=slot2_bank_idx );
  FD_TEST( new_slot2_bank_idx!=new_slot1_bank_idx );
  FD_TEST( f2_0->bank_idx==new_slot2_bank_idx );
  FD_TEST( f3_0->bank_idx==UINT_MAX );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==5UL );

  FD_LOG_NOTICE(( "pass: test_banks_evict_backfill" ));
}

static void
test_backfill_partial_sched_capacity( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );

  fd_hash_t mr_root = { .ul = { 100 } };
  fd_hash_t mr1_0   = { .ul = { 200 } };
  fd_hash_t mr1_32  = { .ul = { 300 } };
  fd_hash_t mr1_64  = { .ul = { 400 } };
  fd_hash_t mr1_96  = { .ul = { 500 } };

  init_root_fec( ctx, &mr_root );

  fd_reasm_fec_t * f1_0 = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0 );

  fd_reasm_fec_t * f1_32 = ingest_fec_complete( ctx, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0 );
  FD_TEST( f1_32 );

  fd_reasm_fec_t * f1_64 = ingest_fec_complete( ctx, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 0 );
  FD_TEST( f1_64 );

  fd_reasm_fec_t * f1_96 = ingest_fec_complete( ctx, &mr1_96, &mr1_64,
      1, 96, 1, 32, 1, 1 );
  FD_TEST( f1_96 );

  mock_sched_capacity = 2UL;
  ulong sched_ingest_cnt = mock_sched_fec_ingest_cnt;
  backfill_fec_sets( ctx, test_stem, f1_96 );

  FD_TEST( mock_sched_fec_ingest_cnt==sched_ingest_cnt+2UL );
  FD_TEST( f1_0->bank_idx!=UINT_MAX );
  FD_TEST( f1_32->bank_idx==f1_0->bank_idx );
  FD_TEST( f1_64->bank_idx==UINT_MAX );
  FD_TEST( f1_96->bank_idx==UINT_MAX );

  FD_LOG_NOTICE(( "pass: test_backfill_partial_sched_capacity" ));
}

/* Partial execution eviction: slot 1 has 4 FECs (0, 32, 64, 96) with 96
   NOT slot_complete.  We pop and process only the first 2 (FEC 0 and
   32), which sets bank_idx=1 on those FECs.  FECs 64 and 96 remain
   unprocessed with bank_idx=UINT_MAX.  Then we evict the frontier leaf
   (FEC 96).  fd_reasm_remove walks UP from the leaf checking that each
   node shares the same bank_idx as the tail.  When it reaches FEC 32
   (bank_idx=1) while tail has bank_idx=UINT_MAX, make sure fd_reasm.c
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

  /* 1. Root FEC (slot 0). */

  init_root_fec( ctx, &mr_root );

  /* 2. Insert 4 FECs for slot 1.  Crucially, FEC 96 is NOT
     slot_complete — the slot is still incomplete, making FEC 96 a valid
     eviction candidate via the unconfirmed evictable leaf path. */

  fd_reasm_fec_t * f1_0 = ingest_fec_complete( ctx, &mr1_0, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0 );

  fd_reasm_fec_t * f1_32 = ingest_fec_complete( ctx, &mr1_32, &mr1_0,
      1, 32, 1, 32, 1, 0 );
  FD_TEST( f1_32 );

  fd_reasm_fec_t * f1_64 = ingest_fec_complete( ctx, &mr1_64, &mr1_32,
      1, 64, 1, 32, 1, 0 );
  FD_TEST( f1_64 );

  fd_reasm_fec_t * f1_96 = ingest_fec_complete( ctx, &mr1_96, &mr1_64,
      1, 96, 1, 32, 1, 0 );
  FD_TEST( f1_96 );

  /* 3. Pop and process only the first 2 FECs.  After this, FEC 0 and
     32 have bank_idx=1.  FECs 64 and 96 remain in the delivery queue
     with bank_idx=UINT_MAX. */

  fd_reasm_fec_t * fec = drive_one_fec( ctx, 1UL, 0U );

  fec = drive_one_fec( ctx, 1UL, 32U );
  ulong partial_bank_idx = fec->bank_idx;
  FD_TEST( partial_bank_idx!=fd_banks_root( ctx->banks )->idx );

  /* Verify FECs 64 and 96 have NOT been processed. */

  FD_TEST( f1_64->bank_idx==UINT_MAX );
  FD_TEST( f1_96->bank_idx==UINT_MAX );

  /* 4. Evict the frontier leaf (FEC 96).  This is the node the eviction
     policy would select: it is an unconfirmed, !slot_complete frontier
     leaf.  fd_reasm_remove walks up from FEC 96 toward fec_set_idx==0.
     The walk hits FEC 32 (bank_idx=1) while tail (FEC 96) has
     bank_idx=UINT_MAX. */

  fd_reasm_fec_t * evicted = fd_reasm_remove( reasm, f1_96, NULL, NULL );
  FD_TEST( evicted );

  /* Release evicted chain back to pool. */

  uint evict_order[ 4 ] = { (uint)partial_bank_idx, (uint)partial_bank_idx, UINT_MAX, UINT_MAX };
  uint evict_idx        = 0;

  while( evicted ) {
    FD_LOG_NOTICE(( "evicting FEC slot %lu, fec idx %u, bank idx %u", evicted->slot, evicted->fec_set_idx, evicted->bank_idx ));
    FD_TEST( evict_order[ evict_idx ] == evicted->bank_idx && evicted->fec_set_idx == 32*evict_idx );
    fd_reasm_fec_t * next = fd_reasm_child( reasm, evicted );
    fd_reasm_pool_release( reasm, evicted );
    evicted = next;
    evict_idx++;
  }
  FD_LOG_NOTICE(( "pass: test_partial_exec_evict" ));
}

/* Epoch-boundary fork-width exhaustion: max_fork_width-backed runtime
   structures can be exhausted while the total bank pool and cost tracker pool
   still have capacity.  Replay should notice that the next epoch-boundary fork
   needs one of those bounded entries and start evicting a drained evictable
   fork instead of replaying past the limit. */

static void
test_epoch_boundary_fork_width_evict( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  ulong const max_fork_width = 4UL;
  ulong const max_boundary_child_forks = max_fork_width - 1UL; /* stake rewards reserves one fork for root */
  setup_ctx_with_fork_width( ctx, wksp, max_fork_width );

  mock_epoch_boundary_enabled = 1;
  mock_epoch_boundary_fork_max = max_boundary_child_forks;

  fd_hash_t mr_root = { .ul = { 100 } };
  init_root_fec( ctx, &mr_root );

  ulong live_leaf_idx = ULONG_MAX;
  ulong child_leaf_cnt = 0UL;

  /* Fill all epoch-boundary fork slots.  Frozen banks release cost trackers,
     so only the epoch-boundary fork state is exhausted.  Keep one replayable
     drained leaf as the eviction victim, and give some epoch-boundary banks
     live descendants so eviction has to reason about a deeper frontier, not
     just sibling leaves. */

  for( ulong i=0UL; i<max_boundary_child_forks; i++ ) {
    ulong slot = 128UL + i;
    fd_hash_t mr = { .ul = { 1000UL + i } };

    ingest_fec_complete( ctx, &mr, &mr_root, slot, 0U, (ushort)slot, 32U, 1, 1 );
    fd_reasm_fec_t * fec = drive_one_fec( ctx, slot, 0U );
    start_epoch_boundary_fec( ctx, fec, i+1UL<max_boundary_child_forks );

    fd_bank_t * bank = fd_banks_bank_query( ctx->banks, fec->bank_idx );
    FD_TEST( bank );
    bank->refcnt = 0UL;
    live_leaf_idx = fec->bank_idx;

    if( i<2UL ) {
      ulong child_slot = slot + 64UL;
      fd_hash_t mr_child = { .ul = { 3000UL + i } };
      fd_reasm_fec_t * child = ingest_fec_complete( ctx, &mr_child, &mr,
          child_slot, 0U, 64U, 32U, 1, 1 );
      FD_TEST( child );

      child = drive_one_fec( ctx, child_slot, 0U );
      FD_TEST( child->parent_bank_idx==fec->bank_idx );
      start_non_epoch_boundary_fec( ctx, child, 0 );

      fd_bank_t * child_bank = fd_banks_bank_query( ctx->banks, child->bank_idx );
      FD_TEST( child_bank );
      FD_TEST( child_bank->parent_idx==fec->bank_idx );
      child_bank->refcnt = 0UL;
      child_leaf_cnt++;
    }
  }

  FD_TEST( !mock_epoch_boundary_overflow );
  FD_TEST( fd_banks_bank_query( ctx->banks, live_leaf_idx ) );
  FD_TEST( child_leaf_cnt==2UL );

  fd_hash_t mr_extra = { .ul = { 4000 } };
  ingest_fec_complete( ctx, &mr_extra, &mr_root, 512UL, 0U, 512U, 32U, 1, 1 );
  fd_reasm_fec_t * extra = drive_one_fec( ctx, 512UL, 0U );
  start_non_epoch_boundary_fec( ctx, extra, 0 );
  fd_bank_t * extra_bank = fd_banks_bank_query( ctx->banks, extra->bank_idx );
  FD_TEST( extra_bank );
  extra_bank->refcnt = 0UL;

  fd_hash_t mr_over = { .ul = { 2000 } };
  fd_reasm_fec_t * over = ingest_fec_complete( ctx, &mr_over, &mr_root,
      128UL + max_boundary_child_forks, 0U, (ushort)(128UL + max_boundary_child_forks), 32U, 1, 1 );
  FD_TEST( over );

  FD_TEST( drive_after_credit_once( ctx ) );

  FD_TEST( !mock_epoch_boundary_overflow );
  FD_TEST( !over->popped );
  FD_TEST( mock_sched_abandon_cnt==1UL );
  FD_TEST( mock_sched_abandon_idx!=ULONG_MAX );

  fd_bank_t * evicted_bank = fd_banks_bank_query( ctx->banks, mock_sched_abandon_idx );
  FD_TEST( evicted_bank );
  FD_TEST( evicted_bank->state==FD_BANK_STATE_PRUNABLE );

  FD_LOG_NOTICE(( "pass: test_epoch_boundary_fork_width_evict" ));
}

/* Banks full eviction: fill the bank pool with sibling leaves, then ingest
   another slot.  Replay should evict one non-leader evictable leaf, prune it
   once scheduler refs are drained, and use the freed bank for the pending
   FEC. */

static void
test_banks_full_prune_leaf( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx_with_fork_width( ctx, wksp, TEST_BANKS_MAX );

  fd_hash_t mr_root = { .ul = { 100 } };
  init_root_fec( ctx, &mr_root );

  ulong leaf_bank_idxs[ TEST_BANKS_MAX ];
  ulong leaf_bank_seqs[ TEST_BANKS_MAX ];
  ulong leaf_cnt = 0UL;

  fd_bank_t * leader_bank = drive_become_leader( ctx, &mr_root, 1UL );
  ulong const leader_leaf_idx = leader_bank->idx;

  /* Fill the rest of the bank pool with sibling child slots. */

  for( ulong slot=2UL; slot<TEST_BANKS_MAX; slot++ ) {
    fd_hash_t mr = { .ul = { 1000UL+slot } };
    ingest_fec_complete( ctx, &mr, &mr_root, slot, 0U, (ushort)slot, 32U, 1, 1 );
    fd_reasm_fec_t * fec = drive_one_fec( ctx, slot, 0U );
    fd_bank_t * leaf_bank = fd_banks_bank_query( ctx->banks, fec->bank_idx );
    FD_TEST( leaf_bank );
    leaf_bank_idxs[ leaf_cnt ] = fec->bank_idx;
    leaf_bank_seqs[ leaf_cnt ] = leaf_bank->bank_seq;
    leaf_cnt++;

    /* Simulate scheduler draining its ref on the block. */
    leaf_bank->refcnt = 0UL;
  }

  FD_TEST( !fd_banks_can_start_bank( ctx->banks ) );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==TEST_BANKS_MAX );
  FD_TEST( leaf_cnt>1UL );

  ulong const used_before     = fd_banks_pool_used_cnt( ctx->banks );

  /* Ingest a new slot that needs a fresh bank. */

  fd_hash_t mr_next = { .ul = { 2000 } };
  ingest_fec_complete( ctx, &mr_next, &mr_root, TEST_BANKS_MAX, 0U, (ushort)TEST_BANKS_MAX, 32U, 1, 0 );

  FD_TEST( drive_after_credit_once( ctx ) );
  FD_TEST( mock_sched_abandon_cnt==1UL );

  ulong evicted_leaf_pos = ULONG_MAX;
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    if( leaf_bank_idxs[ i ]==mock_sched_abandon_idx ) {
      evicted_leaf_pos = i;
      break;
    }
  }
  FD_TEST( evicted_leaf_pos!=ULONG_MAX );

  ulong evicted_leaf_idx = leaf_bank_idxs[ evicted_leaf_pos ];
  ulong evicted_leaf_seq = leaf_bank_seqs[ evicted_leaf_pos ];
  fd_bank_t * evicted_bank = fd_banks_bank_query( ctx->banks, evicted_leaf_idx );
  FD_TEST( evicted_bank );
  FD_TEST( evicted_bank->bank_seq==evicted_leaf_seq );
  FD_TEST( evicted_bank->state==FD_BANK_STATE_PRUNABLE );

  FD_TEST( drive_after_credit_once( ctx ) );
  FD_TEST( !fd_banks_bank_query( ctx->banks, evicted_leaf_idx ) );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used_before-1UL );

  fd_reasm_fec_t * next = drive_one_fec( ctx, TEST_BANKS_MAX, 0U );
  fd_bank_t * next_bank = fd_banks_bank_query( ctx->banks, next->bank_idx );
  FD_TEST( next_bank );
  FD_TEST( next_bank->bank_seq!=evicted_leaf_seq );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used_before );

  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    fd_bank_t * leaf_bank = fd_banks_bank_query( ctx->banks, leaf_bank_idxs[ i ] );
    if( i==evicted_leaf_pos ) {
      FD_TEST( !leaf_bank || leaf_bank->bank_seq!=leaf_bank_seqs[ i ] );
    } else {
      FD_TEST( leaf_bank );
      FD_TEST( leaf_bank->bank_seq==leaf_bank_seqs[ i ] );
    }
  }
  leader_bank = fd_banks_bank_query( ctx->banks, leader_leaf_idx );
  FD_TEST( leader_bank );
  FD_TEST( leader_bank->is_leader );
  FD_TEST( !fd_banks_can_start_bank( ctx->banks ) );

  FD_LOG_NOTICE(( "pass: test_banks_full_prune_leaf" ));
}

/* Out-queue misordering on eqvoc + confirm.

   Version A of slot 1 is fully replayed.  Then version B FEC 0 arrives
   and is marked eqvoc — pushed to the out queue but not deliverable.
   Next, a non-equivocating slot 3 arrives and goes into the queue after
   FEC 0_B.  When we drive_one_fec for slot 3, fd_reasm_pop drains
   FEC 0_B from the head (eqvoc+unconfirmed → rejected, in_out set to 0
   but popped stays 0), then delivers slot 3.

   After that, version B FEC 32 and slot 2's FECs arrive — eqvoc,
   pushed to the out queue tail.  FEC 0_B is dangling: not in the queue,
   not popped.

   When we confirm slot 2, fd_reasm_confirm walks upward.  FEC 32_B and
   slot 2 FECs have in_out=1 so confirm just sets their confirmed flag.
   But FEC 0_B has !popped && !in_out, so confirm re-inserts it at the
   TAIL — after its own children.

   Queue: [FEC 32_B, slot2 FEC 0, slot2 FEC 32, FEC 0_B].

   Pop now delivers FEC 32_B first.  process_fec_set does
   fd_banks_bank_query(parent->bank_idx) where parent is FEC 0_B whose
   bank_idx is UINT_MAX → segfault. */

static void
test_eqvoc_child_confirm( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_reasm_t * reasm = ctx->reasm;

  fd_hash_t mr_root    = { .ul = { 100 } };
  fd_hash_t mr1_0_a    = { .ul = { 200 } };  /* slot 1 version A FEC 0  */
  fd_hash_t mr1_32_a   = { .ul = { 300 } };  /* slot 1 version A FEC 32 */
  fd_hash_t mr1_0_b    = { .ul = { 400 } };  /* slot 1 version B FEC 0  */
  fd_hash_t mr1_32_b   = { .ul = { 500 } };  /* slot 1 version B FEC 32 */
  fd_hash_t mr2_0      = { .ul = { 600 } };  /* slot 2 FEC 0            */
  fd_hash_t mr2_32     = { .ul = { 700 } };  /* slot 2 FEC 32           */
  fd_hash_t mr3_0      = { .ul = { 800 } };  /* slot 3 FEC 0 (non-eqvoc) */

  /* 1. Root FEC (slot 0). */

  init_root_fec( ctx, &mr_root );

  /* 2. Insert and replay version A of slot 1 (FEC 0 and 32). */

  ingest_fec_complete( ctx, &mr1_0_a, &mr_root,
      1, 0, 1, 32, 1, 0 );

  ingest_fec_complete( ctx, &mr1_32_a, &mr1_0_a,
      1, 32, 1, 32, 1, 1 );

  drive_one_fec( ctx, 1UL, 0U );
  fd_reasm_fec_t * fec = drive_one_fec( ctx, 1UL, 32U );
  ulong version_a_bank_idx = fec->bank_idx;
  FD_TEST( version_a_bank_idx!=fd_banks_root( ctx->banks )->idx );

  /* 3. Version B FEC 0 arrives — eqvoc (same slot+fec_set_idx as
     version A).  Pushed to out queue but not deliverable. */

  fd_reasm_fec_t * f1_0_b = ingest_fec_complete( ctx, &mr1_0_b, &mr_root,
      1, 0, 1, 32, 1, 0 );
  FD_TEST( f1_0_b->eqvoc );

  /* 4. Non-equivocating slot 3 arrives (fork off root).  Goes into the
     out queue AFTER FEC 0_B. */

  fd_reasm_fec_t * f3_0 = ingest_fec_complete( ctx, &mr3_0, &mr_root,
      3, 0, 3, 32, 1, 1 );
  FD_TEST( f3_0 );
  FD_TEST( !f3_0->eqvoc );

  /* 5. Pop slot 3.  fd_reasm_pop first pops FEC 0_B from the head —
     eqvoc+unconfirmed so it is rejected (in_out=0 but popped stays 0).
     Then pop delivers slot 3 FEC 0. */

  fec = drive_one_fec( ctx, 3UL, 0U );
  FD_TEST( fec->bank_idx!=UINT_MAX );

  /* FEC 0_B is now dangling: not in the queue, not marked popped. */
  FD_TEST( !f1_0_b->in_out );
  FD_TEST( !f1_0_b->popped );

  /* 6. Version B FEC 32 and slot 2 chain arrive — eqvoc, pushed to
     out queue tail. */

  fd_reasm_fec_t * f1_32_b = ingest_fec_complete( ctx, &mr1_32_b, &mr1_0_b,
      1, 32, 1, 32, 1, 1 );
  FD_TEST( f1_32_b->eqvoc );

  fd_reasm_fec_t * f2_0 = ingest_fec_complete( ctx, &mr2_0, &mr1_32_b,
      2, 0, 1, 32, 1, 0 );
  FD_TEST( f2_0->eqvoc );

  fd_reasm_fec_t * f2_32 = ingest_fec_complete( ctx, &mr2_32, &mr2_0,
      2, 32, 1, 32, 1, 1 );
  FD_TEST( f2_32->eqvoc );

  /* Out queue: [FEC 32_B, slot2 FEC 0, slot2 FEC 32].
     FEC 0_B is NOT in queue (in_out=0). */
  FD_TEST( f1_32_b->in_out );
  FD_TEST( f2_0->in_out );
  FD_TEST( f2_32->in_out );
  FD_TEST( !f1_0_b->in_out );

  /* 7. Confirm slot 2 FEC 32.  fd_reasm_confirm walks upward:
       - slot2 FEC 32:  in_out=1 → just set confirmed
       - slot2 FEC 0:   in_out=1 → just set confirmed
       - FEC 32_B:      in_out=1 → just set confirmed
       - FEC 0_B:       !popped && !in_out → re-inserted at TAIL
       - root:          confirmed → stop
     Out queue: [FEC 32_B, slot2 FEC 0, slot2 FEC 32, FEC 0_B]. */

  fd_reasm_confirm( reasm, &mr2_32 );
  FD_TEST( f2_32->confirmed );
  FD_TEST( f2_0->confirmed );
  FD_TEST( f1_32_b->confirmed );
  FD_TEST( f1_0_b->confirmed );

  /* 8. Verify the misordering: peek should return FEC 32_B (the child),
     not FEC 0_B (the parent that should come first). */

  fec = fd_reasm_peek( reasm );
  FD_TEST( fec );
  FD_TEST( fec->slot==1 && fec->fec_set_idx==32 );

  /* 9. FEC 32_B requires backfill because its parent FEC 0_B has no
     bank.  If banks cannot allocate, can_process_fec must leave FEC
     32_B queued instead of popping it and failing partway through
     backfill. */

  FD_TEST( f1_0_b->bank_idx==UINT_MAX );

  ulong saved_fork_width = ctx->banks->curr_fork_width;
  ctx->banks->curr_fork_width = ctx->banks->max_fork_width;

  int evict_banks = 0;
  FD_TEST( !can_process_fec( ctx, &evict_banks ) );
  FD_TEST( evict_banks );
  FD_TEST( !f1_32_b->popped );
  FD_TEST( fd_reasm_peek( reasm )==f1_32_b );

  ctx->banks->curr_fork_width = saved_fork_width;
  fec = drive_one_fec( ctx, 1UL, 32U );

  FD_LOG_NOTICE(( "pass: test_eqvoc_child_confirm" ));
}

/* Avoid double scheduling on re-confirm of an already-backfilled FEC.

   When a descendant is confirmed before its ancestor, staged backfill
   replays the oldest invalid slot.  The ancestor FEC ends up with a
   valid bank_idx but still has popped=0 and in_out=0 (only fd_reasm_pop
   sets popped, and backfill doesn't touch the out queue).

   If the ancestor is later confirmed separately, fd_reasm_confirm must
   not reinsert it into the out queue and schedule it a second time.

   The scenario:
     root ← slot 1 version A (fully replayed)
            slot 1 version B (eqvoc) ← slot 2 (eqvoc, inherited)
     1. Drain all eqvoc FECs from out queue (rejected: eqvoc+!confirmed)
     2. Confirm slot 2 (descendant) — backfill replays version B
     3. Confirm slot 1 version B (ancestor) — no redelivery */

static void
test_double_confirm_backfill( fd_wksp_t * wksp ) {

  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_reasm_t * reasm = ctx->reasm;

  fd_hash_t mr_root    = { .ul = { 100 } };
  fd_hash_t mr1_0_a    = { .ul = { 200 } };  /* slot 1 version A FEC 0  */
  fd_hash_t mr1_0_b    = { .ul = { 400 } };  /* slot 1 version B FEC 0  */
  fd_hash_t mr2_0      = { .ul = { 600 } };  /* slot 2 FEC 0            */
  fd_hash_t mr2_32     = { .ul = { 700 } };  /* slot 2 FEC 32           */

  /* 1. Root FEC (slot 0). */

  init_root_fec( ctx, &mr_root );

  /* 2. Fully replay version A of slot 1 (FEC 0). */

  ingest_fec_complete( ctx, &mr1_0_a, &mr_root,
      1, 0, 1, 32, 1, 1 );

  drive_one_fec( ctx, 1UL, 0U );

  /* 3. Version B of slot 1 arrives — eqvoc.  It is pushed to the out
     queue but gated by eqvoc+!confirmed. */

  fd_reasm_fec_t * f1_0_b = ingest_fec_complete( ctx, &mr1_0_b, &mr_root,
      1, 0, 1, 32, 1, 1 );
  FD_TEST( f1_0_b->eqvoc );

  /* 4. Slot 2 chains off version B — eqvoc inherited. */

  fd_reasm_fec_t * f2_0 = ingest_fec_complete( ctx, &mr2_0, &mr1_0_b,
      2, 0, 1, 32, 1, 0 );
  FD_TEST( f2_0->eqvoc );

  fd_reasm_fec_t * f2_32 = ingest_fec_complete( ctx, &mr2_32, &mr2_0,
      2, 32, 1, 32, 1, 1 );
  FD_TEST( f2_32->eqvoc );

  /* 5. Drain the out queue.  All 3 eqvoc FECs are rejected (eqvoc &&
     !confirmed).  After draining, each has popped=0, in_out=0. */

  FD_TEST( !fd_reasm_pop( reasm ) );
  FD_TEST( !f1_0_b->popped  && !f1_0_b->in_out  );
  FD_TEST( !f2_0->popped    && !f2_0->in_out    );
  FD_TEST( !f2_32->popped   && !f2_32->in_out   );

  /* 6. Confirm the descendant (slot 2 FEC 32) first.

     fd_reasm_confirm walks upward setting confirmed=1.  The confirmed
     FEC (slot 2 FEC 32) has !popped && !in_out, so it gets pushed to
     the out queue. */

  fd_reasm_confirm( reasm, &mr2_32 );
  FD_TEST( f2_32->confirmed );
  FD_TEST( f2_0->confirmed  );
  FD_TEST( f1_0_b->confirmed  );

  /* 7. Pop and process the confirmed FEC.  Staged backfill replays
     slot 1 version B and leaves slot 2 deferred. */

  ulong sched_cnt_before = mock_sched_fec_ingest_cnt;
  ulong banks_used_before = fd_banks_pool_used_cnt( ctx->banks );

  fd_reasm_fec_t * fec = drive_one_fec( ctx, 2UL, 32U );
  FD_TEST( fec->bank_idx==UINT_MAX );

  /* After backfill: version B FEC 0 has a valid bank but still
     popped=0, in_out=0 — backfill doesn't touch those flags. */

  FD_TEST( f1_0_b->bank_idx!=UINT_MAX );
  FD_TEST( !f1_0_b->popped );
  FD_TEST( !f1_0_b->in_out );
  FD_TEST( f2_0->bank_idx==UINT_MAX );
  FD_TEST( f2_32->bank_idx==UINT_MAX );

  ulong sched_cnt_after_backfill = mock_sched_fec_ingest_cnt;
  ulong banks_used_after_backfill = fd_banks_pool_used_cnt( ctx->banks );

  /* Backfill should have ingested one slot and allocated one bank. */

  FD_TEST( sched_cnt_after_backfill==sched_cnt_before+1UL );
  FD_TEST( banks_used_after_backfill==banks_used_before+1UL );

  /* 8. Confirm the already-confirmed ancestor.  It must not be
     reinserted into the out queue. */

  fd_reasm_confirm( reasm, &mr1_0_b );

  FD_TEST( !fd_reasm_peek( reasm ) );
  FD_TEST( mock_sched_fec_ingest_cnt==sched_cnt_after_backfill );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==banks_used_after_backfill );

  FD_LOG_NOTICE(( "pass: test_double_confirm_backfill" ));
}

/* Deliver one fd_rotor_replay_fec_t through the ROTOR_SIG_FEC_REPLAY
   handler (it lives under IN_KIND_REPAIR, dispatched by sig).  Returns
   returnable_frag's value: 0 = frag consumed, 1 = kept for retry. */
static int
deliver_rotor_fec( fd_replay_tile_t * ctx,
                   ulong              slot,
                   uint               fec_set_idx,
                   ulong              parent_slot,
                   fd_hash_t const *  parent_block_id,
                   fd_hash_t const *  mr,
                   int                slot_complete,
                   int                verified ) {
  ulong chunk = ctx->in[ TEST_REPAIR_IN_IDX ].chunk0;
  fd_rotor_replay_fec_t * fec = fd_chunk_to_laddr( ctx->in[ TEST_REPAIR_IN_IDX ].mem, chunk );
  memset( fec, 0, sizeof(*fec) );
  fec->slot            = slot;
  fec->fec_set_idx     = fec_set_idx;
  fec->mr              = *mr;
  fec->parent_slot     = parent_slot;
  fec->parent_block_id = *parent_block_id;
  fec->slot_complete   = slot_complete;
  fec->known_id        = verified;

  /* Clear the pacing gate at the top of the handler
     (execrp_idle_cnt >= 2*in_cnt || is_leader) so the FEC reaches the
     drain gate rather than being kept for retry. */
  ctx->execrp_idle_cnt = 2UL*ctx->in_cnt + 4UL;

  return returnable_frag( ctx, TEST_REPAIR_IN_IDX, 0UL, ROTOR_SIG_FEC_REPLAY, chunk,
                          sizeof(fd_rotor_replay_fec_t), 0UL, 0UL,
                          fd_frag_meta_ts_comp( fd_tickcount() ), test_stem );
}

/* Like deliver_rotor_fec, but also sets fec->block_id -- the field the
   deliver_from_root recovery path always populates (non-zero), and that
   replay dedups on to skip already-replayed blocks. */
static int
deliver_rotor_fec_bid( fd_replay_tile_t * ctx,
                       ulong              slot,
                       uint               fec_set_idx,
                       ulong              parent_slot,
                       fd_hash_t const *  parent_block_id,
                       fd_hash_t const *  block_id,
                       fd_hash_t const *  mr,
                       int                slot_complete,
                       int                verified ) {
  ulong chunk = ctx->in[ TEST_REPAIR_IN_IDX ].chunk0;
  fd_rotor_replay_fec_t * fec = fd_chunk_to_laddr( ctx->in[ TEST_REPAIR_IN_IDX ].mem, chunk );
  memset( fec, 0, sizeof(*fec) );
  fec->slot            = slot;
  fec->fec_set_idx     = fec_set_idx;
  fec->mr              = *mr;
  fec->parent_slot     = parent_slot;
  fec->parent_block_id = *parent_block_id;
  fec->block_id        = *block_id;
  fec->slot_complete   = slot_complete;
  fec->known_id        = verified;
  ctx->execrp_idle_cnt = 2UL*ctx->in_cnt + 4UL;
  return returnable_frag( ctx, TEST_REPAIR_IN_IDX, 0UL, ROTOR_SIG_FEC_REPLAY, chunk,
                          sizeof(fd_rotor_replay_fec_t), 0UL, 0UL,
                          fd_frag_meta_ts_comp( fd_tickcount() ), test_stem );
}

/* test_process_rotor_fec_skip_replayed: on recovery rotor re-delivers
   the entire ancestry path from the chainer root, but most of those
   blocks are already replayed.  Replay must SKIP a redelivered FEC
   whose (slot, block_id) names an already-replayed block -- returning
   before it touches the store or creates a duplicate bank -- while
   still processing a FEC for a block it has NOT yet replayed.

   Observability: the skip returns at the top of process_rotor_fec,
   before the store lock, so store_query_cnt does NOT advance for a
   skipped FEC.  The control FEC forces payload pinning to fail after a
   successful lookup and verifies replay abandons it before creating a
   bank or changing the block-id map. */
static void
test_process_rotor_fec_skip_replayed( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );

  ulong  chain_cnt  = fd_ag_block_id_map_chain_cnt_est( TEST_BANKS_MAX );
  void * ag_map_mem = fd_wksp_alloc_laddr( wksp, fd_ag_block_id_map_align(), fd_ag_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( ag_map_mem );
  ctx->ag_block_id_map_seed = 7UL;
  ctx->ag_block_id_map      = fd_ag_block_id_map_join( fd_ag_block_id_map_new( ag_map_mem, chain_cnt, ctx->ag_block_id_map_seed ) );
  FD_TEST( ctx->ag_block_id_map );

  fd_hash_t mr_root = { .ul = { 100 } };
  init_root_fec( ctx, &mr_root );

  fd_bank_t * root_bank = fd_banks_root( ctx->banks );
  FD_TEST( root_bank );
  root_bank->state = FD_BANK_STATE_FROZEN;

  /* Register the root as a resolvable parent (keyed {0, parent_bid}) so
     a NOT-yet-replayed FEC 0 can resolve its parent and reach the store
     query -- i.e. the control FEC is not dropped earlier for a missing
     parent. */
  fd_hash_t parent_bid = { .ul = { 0xBEEFUL } };
  fd_block_id_ele_t * root_ele = &ctx->block_id_arr[ root_bank->idx ];
  root_ele->block_info    = ag_block_id( 0UL, parent_bid.uc );
  root_ele->block_id_seen = 1;
  FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, root_ele, ctx->block_id_arr ) );

  /* An ALREADY-REPLAYED complete block at slot 5 with block_id B: a live
     bank plus an ele keyed by {5, B} with block_id_seen=1. */
  fd_hash_t B = { .ul = { 0x5150UL } };
  fd_bank_t * bank5 = fd_banks_new_bank( ctx->banks, root_bank->idx, 0L, 0 );
  FD_TEST( bank5 );
  bank5->state = FD_BANK_STATE_FROZEN;
  fd_block_id_ele_t * ele5 = &ctx->block_id_arr[ bank5->idx ];
  ele5->slot           = 5UL;
  ele5->bank_seq       = bank5->bank_seq;
  ele5->latest_mr      = B;
  ele5->latest_fec_idx = 0U;
  ele5->block_id_seen  = 1;
  ele5->block_info     = ag_block_id( 5UL, B.uc );
  FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, ele5, ctx->block_id_arr ) );

  mock_sched_capacity = ULONG_MAX;
  ulong used0 = fd_banks_pool_used_cnt( ctx->banks );
  ulong q0    = ctx->metrics.store_query_cnt;

  /* (1) Redelivered FEC for the already-replayed block {5, B}: SKIP.
     No store query, no duplicate bank, existing ele untouched. */
  fd_hash_t mrX = { .ul = { 501 } };
  int r = deliver_rotor_fec_bid( ctx, 5UL, 0U, 0UL, &parent_bid, &B, &mrX, 1 /*slot_complete*/, 1 /*verified*/ );
  FD_TEST( r==0 );                                          /* frag consumed */
  FD_TEST( ctx->metrics.store_query_cnt==q0 );              /* skipped before the store */
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used0 );   /* no duplicate bank */
  FD_TEST( ele5->block_id_seen==1 );                        /* existing ele untouched */

  /* (2) Redelivered FEC for a NOT-yet-replayed block {6, C}: processed
     past the skip check.  Model rotor removing the FEC between delivery
     and replay's payload acquisition.  This must be treated as a pruned
     slice, not an assertion failure, and must not leave a bank behind. */
  fd_hash_t C   = { .ul = { 0x6160UL } };
  fd_hash_t mrY = { .ul = { 601 } };
  ag_block_id_t C_key = ag_block_id( 6UL, C.uc );
  ulong view0    = mock_store_view_call_cnt;
  ulong missing0 = ctx->metrics.store_query_missing_cnt;
  mock_store_view_fail = 1;
  r = deliver_rotor_fec_bid( ctx, 6UL, 0U, 0UL, &parent_bid, &C, &mrY, 1, 1 );
  mock_store_view_fail = 0;
  FD_TEST( r==0 );
  FD_TEST( ctx->metrics.store_query_cnt==q0+1UL );
  FD_TEST( ctx->metrics.store_query_missing_cnt==missing0+1UL );
  FD_TEST( mock_store_view_call_cnt==view0+1UL );
  FD_TEST( mock_store_view_success_cnt==mock_store_view_release_cnt );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used0 );
  FD_TEST( !fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &C_key, NULL, ctx->block_id_arr ) );

  FD_LOG_NOTICE(( "pass: test_process_rotor_fec_skip_replayed" ));
}

/* Exercises the drain_rotor_fecs gate in the ROTOR_SIG_FEC_REPLAY
   handler: a bank eviction breaks the replayable FEC chain, so on the
   first un-replayable FEC (parent absent from ag_block_id_map ->
   PROCESS_FEC_DROP) replay enters drain, ignores subsequent FECs, and
   resumes on the first replayable one (PROCESS_FEC_OK). */
static void
test_drain_rotor_fecs( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );

  /* setup_ctx builds block_id_map but not ag_block_id_map, which the
     rotor-FEC path uses; stand it up here. */
  ulong  chain_cnt  = fd_ag_block_id_map_chain_cnt_est( TEST_BANKS_MAX );
  void * ag_map_mem = fd_wksp_alloc_laddr( wksp, fd_ag_block_id_map_align(), fd_ag_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( ag_map_mem );
  ctx->ag_block_id_map_seed = 7UL;
  ctx->ag_block_id_map      = fd_ag_block_id_map_join( fd_ag_block_id_map_new( ag_map_mem, chain_cnt, ctx->ag_block_id_map_seed ) );
  FD_TEST( ctx->ag_block_id_map );

  fd_hash_t mr_root = { .ul = { 100 } };
  init_root_fec( ctx, &mr_root ); /* root bank + block_id_map entry */

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];

  FD_TEST( ctx->drain_rotor_fecs==0 );

  /* Step 1: FEC 0 whose parent is not in ag_block_id_map -> DROP ->
     enter drain, notify rotor once, consume the frag. */
  fd_hash_t parent_bid = { .ul = { 0xBEEFUL } };
  fd_hash_t mr1        = { .ul = { 201 } };
  int r = deliver_rotor_fec( ctx, 1UL, 0U, 0UL, &parent_bid, &mr1, 0, 0 );
  FD_TEST( r==0 );                                  /* consumed */
  FD_TEST( ctx->drain_rotor_fecs==1 );              /* entered drain */
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );   /* one publish */
  fd_frag_meta_t const * m = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( seq0, test_stem_depths[ out_idx ] );
  FD_TEST( m->sig==REPLAY_SIG_MISSING_FEC );

  /* Step 2: another un-replayable FEC while draining -> ignored, no
     re-notify, still draining. */
  fd_hash_t mr2 = { .ul = { 202 } };
  r = deliver_rotor_fec( ctx, 2UL, 0U, 0UL, &parent_bid, &mr2, 0, 0 );
  FD_TEST( r==0 );
  FD_TEST( ctx->drain_rotor_fecs==1 );              /* still draining */
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );   /* no new publish */

  /* Step 3: make a FEC replayable.  Insert the (non-prunable) root ele
     into ag_block_id_map keyed by {parent_slot, parent_bid}; a FEC 0
     whose parent is that entry returns PROCESS_FEC_OK, so the drain gate
     clears the flag before process_rotor_fec runs.  (process_rotor_fec
     itself may then drop for lack of a store FEC -- the exit is the
     flag clear, which happens first.) */
  fd_bank_t * root_bank = fd_banks_root( ctx->banks );
  root_bank->state = FD_BANK_STATE_FROZEN;          /* valid, non-prunable parent */
  fd_block_id_ele_t * root_ele = &ctx->block_id_arr[ root_bank->idx ];
  root_ele->block_info = ag_block_id( 3UL, parent_bid.uc );
  FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, root_ele, ctx->block_id_arr ) );
  mock_sched_capacity = ULONG_MAX;                  /* sched has room */

  fd_hash_t mr3 = { .ul = { 203 } };
  deliver_rotor_fec( ctx, 4UL, 0U, 3UL, &parent_bid, &mr3, 0, 0 );
  FD_TEST( ctx->drain_rotor_fecs==0 );              /* exited drain */
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );   /* exit does not notify */

  FD_LOG_NOTICE(( "pass: test_drain_rotor_fecs" ));
}

/* Complements test_drain_rotor_fecs by exercising the SKIP and WAIT
   gate results while already draining (neither must exit drain nor
   crash), the OK exit + process, and re-entry into drain after a clean
   exit (a second eviction must publish a fresh MISSING_FEC).  Together
   with test_drain_rotor_fecs this pins down the full drain gate:

     enter (DROP, notify once) -> ignore (SKIP/DROP, consumed, no
       re-notify) -> retry (WAIT, frag kept, no re-notify) -> exit (OK,
       process) -> re-enter (DROP, notify again).

   Liveness note: while draining, SKIP and DROP return 0 (frag consumed,
   no re-notify) but WAIT keeps its keep-and-retry contract.  Recovery
   therefore hinges on the re-delivered path eventually presenting a FEC
   whose parent is live, i.e. PROCESS_FEC_OK.  Rotor guarantees this by
   re-delivering from the chainer root down; the root bank is the
   (non-evictable) published root, so its direct child's FEC 0 is always
   OK -- which is what the OK step below demonstrates. */
static void
test_drain_rotor_fecs_skip_wait_reentry( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );

  ulong  chain_cnt  = fd_ag_block_id_map_chain_cnt_est( TEST_BANKS_MAX );
  void * ag_map_mem = fd_wksp_alloc_laddr( wksp, fd_ag_block_id_map_align(), fd_ag_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( ag_map_mem );
  ctx->ag_block_id_map_seed = 7UL;
  ctx->ag_block_id_map      = fd_ag_block_id_map_join( fd_ag_block_id_map_new( ag_map_mem, chain_cnt, ctx->ag_block_id_map_seed ) );
  FD_TEST( ctx->ag_block_id_map );

  fd_hash_t mr_root = { .ul = { 100 } };
  init_root_fec( ctx, &mr_root );

  fd_bank_t * root_bank = fd_banks_root( ctx->banks );
  FD_TEST( root_bank );

  /* Synthetic parent for the SKIP step: an ele keyed by {slot 5, 0}
     (unverified/turbine style) with latest_fec_idx 0, so a mid-slot FEC
     for slot 5 at fec_set_idx 64 has a present-but-mismatched parent ->
     PROCESS_FEC_SKIP.  It lives at a block_id_arr slot no bank occupies;
     SKIP returns before any bank is touched, so a synthetic ele is safe. */
  ulong skip_idx = 12UL;
  FD_TEST( root_bank->idx!=skip_idx );
  fd_hash_t zero = {0};
  fd_block_id_ele_t * skip_ele = &ctx->block_id_arr[ skip_idx ];
  skip_ele->slot           = 5UL;
  skip_ele->bank_seq       = 0UL;
  skip_ele->latest_fec_idx = 0U;
  skip_ele->block_info     = ag_block_id( 5UL, zero.uc );
  FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, skip_ele, ctx->block_id_arr ) );

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];
  FD_TEST( ctx->drain_rotor_fecs==0 );

  /* Step 1: enter drain via DROP (fec 0 whose parent {0, parent_bid} is
     absent from ag_block_id_map).  One MISSING_FEC publish. */
  fd_hash_t parent_bid = { .ul = { 0xBEEFUL } };
  fd_hash_t mr1        = { .ul = { 201 } };
  FD_TEST( deliver_rotor_fec( ctx, 1UL, 0U, 0UL, &parent_bid, &mr1, 0, 0 )==0 );
  FD_TEST( ctx->drain_rotor_fecs==1 );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );
  fd_frag_meta_t const * m = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( seq0, test_stem_depths[ out_idx ] );
  FD_TEST( m->sig==REPLAY_SIG_MISSING_FEC );

  /* Step 2: a SKIP while draining (mid-slot fec, parent present but
     latest_fec_idx mismatched) must NOT exit drain and must NOT crash. */
  fd_hash_t mr2 = { .ul = { 202 } };
  FD_TEST( deliver_rotor_fec( ctx, 5UL, 64U, 4UL, &parent_bid, &mr2, 0, 0 )==0 );
  FD_TEST( ctx->drain_rotor_fecs==1 );              /* still draining */
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );   /* no re-notify */

  /* Step 3: a WAIT while draining (parent bank present but PRUNABLE)
     must NOT exit drain and must NOT crash.  Unlike SKIP/DROP it is
     not swallowed. */
  fd_block_id_ele_t * root_ele = &ctx->block_id_arr[ root_bank->idx ];
  root_ele->block_info = ag_block_id( 0UL, parent_bid.uc );
  FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, root_ele, ctx->block_id_arr ) );
  root_bank->state = FD_BANK_STATE_PRUNABLE;
  fd_hash_t mr3 = { .ul = { 203 } };
  FD_TEST( deliver_rotor_fec( ctx, 8UL, 0U, 0UL, &parent_bid, &mr3, 0, 0 )==1 ); /* kept for retry */
  FD_TEST( ctx->drain_rotor_fecs==1 );              /* still draining */
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );   /* no re-notify */
  root_bank->state = FD_BANK_STATE_FROZEN;          /* parent now replayable */

  /* Step 4: the first OK clears drain and process_rotor_fec runs.  Exit
     itself must NOT re-notify. */
  mock_sched_capacity = ULONG_MAX;
  fd_hash_t mr4 = { .ul = { 204 } };
  deliver_rotor_fec( ctx, 7UL, 0U, 0UL, &parent_bid, &mr4, 0, 0 );
  FD_TEST( ctx->drain_rotor_fecs==0 );              /* exited drain */
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );   /* exit does not notify */

  /* Step 5: a second eviction (fresh DROP after a clean exit) must
     re-enter drain and publish a fresh MISSING_FEC. */
  fd_hash_t parent_bid2 = { .ul = { 0xF00DUL } };
  fd_hash_t mr5         = { .ul = { 205 } };
  FD_TEST( deliver_rotor_fec( ctx, 9UL, 0U, 999UL, &parent_bid2, &mr5, 0, 0 )==0 );
  FD_TEST( ctx->drain_rotor_fecs==1 );              /* re-entered drain */
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+2UL );   /* exactly one more MISSING_FEC */
  m = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( seq0+1UL, test_stem_depths[ out_idx ] );
  FD_TEST( m->sig==REPLAY_SIG_MISSING_FEC );

  FD_LOG_NOTICE(( "pass: test_drain_rotor_fecs_skip_wait_reentry" ));
}

/* setup_ag_block_id_map stands up the alpenglow compound block-id map
   the rotor-FEC path uses (setup_ctx only builds block_id_map), and
   registers the root bank as a resolvable parent keyed
   {0, parent_bid}, frozen, so a FEC 0 naming that parent passes the
   parent checks. */

static void
setup_ag_block_id_map( fd_replay_tile_t * ctx,
                       fd_wksp_t *        wksp,
                       fd_hash_t const *  parent_bid ) {
  ulong  chain_cnt  = fd_ag_block_id_map_chain_cnt_est( TEST_BANKS_MAX );
  void * ag_map_mem = fd_wksp_alloc_laddr( wksp, fd_ag_block_id_map_align(), fd_ag_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( ag_map_mem );
  ctx->ag_block_id_map_seed = 7UL;
  ctx->ag_block_id_map      = fd_ag_block_id_map_join( fd_ag_block_id_map_new( ag_map_mem, chain_cnt, ctx->ag_block_id_map_seed ) );
  FD_TEST( ctx->ag_block_id_map );

  fd_hash_t mr_root = { .ul = { 100 } };
  init_root_fec( ctx, &mr_root );

  fd_bank_t * root_bank = fd_banks_root( ctx->banks );
  FD_TEST( root_bank );
  root_bank->state = FD_BANK_STATE_FROZEN;
  fd_block_id_ele_t * root_ele = &ctx->block_id_arr[ root_bank->idx ];
  root_ele->block_info    = ag_block_id( 0UL, parent_bid->uc );
  root_ele->block_id_seen = 1;
  FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, root_ele, ctx->block_id_arr ) );
  mock_sched_capacity = ULONG_MAX;
}

static ulong
replay_out_sig( fd_replay_tile_t * ctx, ulong seq ) {
  ulong out_idx = ctx->replay_out->idx;
  fd_frag_meta_t const * m = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( seq, test_stem_depths[ out_idx ] );
  return m->sig;
}

/* test_rotor_fec_turbine_keying: the replay side of the known_id
   contract.  A turbine block (known_id clear) is keyed {slot, 0} until
   replay processes its slot-complete FEC, then re-keyed {slot, dmr};
   this holds even when rotor filled in block_id on a redelivered copy
   of an incomplete block.  Consequences pinned here:
     (a) a redelivered FEC 0 with a nonzero block_id but known_id clear
         creates the {slot, 0} element, and the live turbine FEC 32
         (no block_id) finds it;
     (b) a duplicate FEC 32 is SKIPped by the {slot, 0} dedup;
     (c) a child's FEC 0 names its parent by id and cannot attach while
         the parent is still keyed {slot, 0} (DROP, one MISSING_FEC), so
         a child can never enter sched before its parent finished
         delivering;
     (d) the slot-complete FEC re-keys the parent by id and the child
         then attaches.
   The live failure this guards against keyed the redelivered FEC 0 by
   id, stranded the turbine FECs 32/64 and let the child attach early,
   tripping fd_sched_fec_ingest's child_idx invariant. */

static void
test_rotor_fec_turbine_keying( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_hash_t parent_bid = { .ul = { 0xBEEFUL } };
  setup_ag_block_id_map( ctx, wksp, &parent_bid );

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];
  ulong used0   = fd_banks_pool_used_cnt( ctx->banks );
  ulong ing0    = mock_sched_fec_ingest_cnt;

  fd_hash_t B    = { .ul = { 0x5150UL } };
  fd_hash_t mr0  = { .ul = { 501 } };
  fd_hash_t mr32 = { .ul = { 502 } };
  fd_hash_t mr64 = { .ul = { 503 } };
  ag_block_id_t key_slot = { .slot = 5UL };
  ag_block_id_t key_id   = ag_block_id( 5UL, B.uc );

  /* (a) Redelivered FEC 0 of an incomplete turbine block: block_id
     filled in, known_id clear.  Keyed {5, 0}, not {5, B}. */
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, 0U, 0UL, &parent_bid, &B, &mr0, 0, 0 )==0 );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used0+1UL );
  FD_TEST( mock_sched_fec_ingest_cnt==ing0+1UL );
  fd_block_id_ele_t * ele5 = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key_slot, NULL, ctx->block_id_arr );
  FD_TEST( ele5 );
  FD_TEST( !fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key_id, NULL, ctx->block_id_arr ) );
  FD_TEST( ele5->latest_fec_idx==0U && !ele5->block_id_seen );
  FD_TEST( ctx->drain_rotor_fecs==0 && test_stem_seqs[ out_idx ]==seq0 );

  /* The live turbine FEC 32 (no block_id) finds the block. */
  FD_TEST( deliver_rotor_fec( ctx, 5UL, FD_FEC_SHRED_CNT, 0UL, &parent_bid, &mr32, 0, 0 )==0 );
  FD_TEST( ele5->latest_fec_idx==FD_FEC_SHRED_CNT );
  FD_TEST( mock_sched_fec_ingest_cnt==ing0+2UL );
  FD_TEST( ctx->drain_rotor_fecs==0 && test_stem_seqs[ out_idx ]==seq0 );

  /* (b) A redelivered duplicate of FEC 32 is SKIPped on {5, 0}: no store
     query, nothing ingested. */
  ulong q0 = ctx->metrics.store_query_cnt;
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, FD_FEC_SHRED_CNT, 0UL, &parent_bid, &B, &mr32, 0, 0 )==0 );
  FD_TEST( ctx->metrics.store_query_cnt==q0 );
  FD_TEST( mock_sched_fec_ingest_cnt==ing0+2UL );
  FD_TEST( ele5->latest_fec_idx==FD_FEC_SHRED_CNT );

  /* (c) The child's FEC 0 names parent {5, B}; while 5 is still keyed
     {5, 0} it cannot attach: DROP, drain, exactly one MISSING_FEC. */
  fd_hash_t mr6 = { .ul = { 601 } };
  FD_TEST( deliver_rotor_fec( ctx, 6UL, 0U, 5UL, &B, &mr6, 0, 0 )==0 );
  FD_TEST( ctx->drain_rotor_fecs==1 );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );
  FD_TEST( replay_out_sig( ctx, seq0 )==REPLAY_SIG_MISSING_FEC );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used0+1UL );      /* no bank for the child */

  /* (d) The slot-complete FEC re-keys 5 to {5, B} (and, being OK, exits
     drain); the child now attaches on a fresh bank with no re-notify. */
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, 2U*FD_FEC_SHRED_CNT, 0UL, &parent_bid, &B, &mr64, 1, 0 )==0 );
  FD_TEST( ctx->drain_rotor_fecs==0 );
  FD_TEST( ele5->block_id_seen );
  FD_TEST( fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key_id,   NULL, ctx->block_id_arr )==ele5 );
  FD_TEST( !fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key_slot, NULL, ctx->block_id_arr ) );
  FD_TEST( mock_sched_fec_ingest_cnt==ing0+3UL );

  FD_TEST( deliver_rotor_fec( ctx, 6UL, 0U, 5UL, &B, &mr6, 0, 0 )==0 );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used0+2UL );
  FD_TEST( mock_sched_fec_ingest_cnt==ing0+4UL );
  FD_TEST( ctx->drain_rotor_fecs==0 );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );                  /* no further notify */

  FD_LOG_NOTICE(( "pass: test_rotor_fec_turbine_keying" ));
}

/* test_dead_block_children_drop: what replay does around a block it
   ruled dead, as observed live with a block whose footer cert failed
   verification.  mark_bank_dead publishes SLOT_DEAD; the dead bank is
   then eagerly pruned (fd_banks_prune_one_bank drains the dead deque),
   after which its idx reads as no bank at all.  A child FEC 0 chained
   off it therefore DROPs ("parent bank evicted"): frag consumed, drain
   entered, exactly one MISSING_FEC.  Further FECs of the dead block or
   its descendants are consumed silently while draining.  Finally the
   CURRENT behavior: rotor's redelivery brings the dead block's FEC 0
   back and replay, having no memory of the verdict, replays it again
   on a fresh bank.  TODO that last step goes away once rotor consumes
   SLOT_DEAD and stops delivering the dead lineage. */

static void
test_dead_block_children_drop( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_hash_t parent_bid = { .ul = { 0xBEEFUL } };
  setup_ag_block_id_map( ctx, wksp, &parent_bid );

  ulong out_idx = ctx->replay_out->idx;

  /* Replay block 5 in full: FEC 0 and the slot-complete FEC 32 with id B. */
  fd_hash_t B    = { .ul = { 0x5150UL } };
  fd_hash_t mr0  = { .ul = { 501 } };
  fd_hash_t mr32 = { .ul = { 502 } };
  FD_TEST( deliver_rotor_fec    ( ctx, 5UL, 0U,               0UL, &parent_bid,     &mr0,  0, 0 )==0 );
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, FD_FEC_SHRED_CNT, 0UL, &parent_bid, &B, &mr32, 1, 0 )==0 );
  ag_block_id_t       key5 = ag_block_id( 5UL, B.uc );
  fd_block_id_ele_t * ele5 = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key5, NULL, ctx->block_id_arr );
  FD_TEST( ele5 && ele5->block_id_seen );
  ulong       idx5  = fd_block_id_ele_get_idx( ctx->block_id_arr, ele5 );
  fd_bank_t * bank5 = fd_banks_bank_query( ctx->banks, idx5 );
  FD_TEST( bank5 );
  bank5->state = FD_BANK_STATE_REPLAYABLE;                          /* as at finalize */

  /* Rule it dead, as replay_block_finalize does on a bad footer. */
  ulong seq_dead = test_stem_seqs[ out_idx ];
  mark_bank_dead( ctx, test_stem, idx5, FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_BAD_FOOTER, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED );
  FD_TEST( bank5->state==FD_BANK_STATE_DEAD );
  FD_TEST( test_stem_seqs[ out_idx ]==seq_dead+1UL );
  FD_TEST( replay_out_sig( ctx, seq_dead )==REPLAY_SIG_SLOT_DEAD );

  /* Eager prune of the dead leaf, as try_prune_bank does on the next
     credit.  Ingest took one refcnt for sched; live, sched's abandon
     drains its tasks and fd_sched_pruned_block_next hands that refcnt
     back before the prune can run.  The mock sched never does, so
     return it here.  The bank is then released and its idx no longer
     resolves. */
  FD_TEST( bank5->refcnt==1UL );
  bank5->refcnt = 0UL;
  fd_banks_prune_cancel_info_t cancel[ 1 ];
  FD_TEST( fd_banks_prune_one_bank( ctx->banks, cancel ) );
  FD_TEST( !fd_banks_bank_query( ctx->banks, idx5 ) );
  ulong used_dead = fd_banks_pool_used_cnt( ctx->banks );
  ulong ing_dead  = mock_sched_fec_ingest_cnt;

  /* The child's FEC 0 finds the stale {5, B} element but no live bank:
     DROP, drain, one MISSING_FEC, no bank. */
  fd_hash_t mr6 = { .ul = { 601 } };
  ulong seq1 = test_stem_seqs[ out_idx ];
  FD_TEST( ctx->drain_rotor_fecs==0 );
  FD_TEST( deliver_rotor_fec( ctx, 6UL, 0U, 5UL, &B, &mr6, 0, 0 )==0 );
  FD_TEST( ctx->drain_rotor_fecs==1 );
  FD_TEST( test_stem_seqs[ out_idx ]==seq1+1UL );
  FD_TEST( replay_out_sig( ctx, seq1 )==REPLAY_SIG_MISSING_FEC );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used_dead );
  FD_TEST( mock_sched_fec_ingest_cnt==ing_dead );

  /* While draining: a late FEC of the dead block itself and the child's
     next FEC are consumed silently, no re-notify, nothing ingested. */
  fd_hash_t mr6b = { .ul = { 602 } };
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, FD_FEC_SHRED_CNT, 0UL, &parent_bid, &B, &mr32, 1, 0 )==0 );
  FD_TEST( deliver_rotor_fec    ( ctx, 6UL, FD_FEC_SHRED_CNT, 5UL, &B,              &mr6b, 0, 0 )==0 );
  FD_TEST( ctx->drain_rotor_fecs==1 );
  FD_TEST( test_stem_seqs[ out_idx ]==seq1+1UL );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used_dead );
  FD_TEST( mock_sched_fec_ingest_cnt==ing_dead );

  /* CURRENT behavior: the redelivered FEC 0 of the dead block is not
     recognized as dead (the {5, B} element has no live bank, so the
     dedup does not SKIP it) and is replayed again on a fresh bank,
     exiting drain without a re-notify. */
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, 0U, 0UL, &parent_bid, &B, &mr0, 0, 0 )==0 );
  FD_TEST( ctx->drain_rotor_fecs==0 );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used_dead+1UL );
  FD_TEST( mock_sched_fec_ingest_cnt==ing_dead+1UL );
  FD_TEST( test_stem_seqs[ out_idx ]==seq1+1UL );

  FD_LOG_NOTICE(( "pass: test_dead_block_children_drop" ));
}

/* A stale {slot, id} map entry (left behind when the block's bank was
   evicted or pruned) must not shadow the {slot, 0} key of a rebuild in
   flight: a second redelivered FEC 0 has to SKIP against the live
   zero-key element instead of allocating a duplicate bank and stealing
   the mapping.  The stale entry only survives if the rebuild lands on a
   different bank idx, so a second bank is freed after the block's. */
static void
test_stale_id_key_does_not_shadow_rebuild( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_hash_t parent_bid = { .ul = { 0xBEEFUL } };
  setup_ag_block_id_map( ctx, wksp, &parent_bid );
  ulong out_idx = ctx->replay_out->idx;

  /* Replay blocks 5 and 6 (siblings off the root) in full, then rule
     both dead and prune them in that order, so 6's idx is the next one
     handed out.  Both map entries outlive their banks. */
  fd_hash_t B5 = { .ul = { 0x5150UL } }, B6 = { .ul = { 0x6160UL } };
  fd_hash_t mr5_0 = { .ul = { 501 } }, mr5_32 = { .ul = { 502 } }, mr6_0 = { .ul = { 601 } }, mr6_32 = { .ul = { 602 } };
  FD_TEST( deliver_rotor_fec    ( ctx, 5UL, 0U,               0UL, &parent_bid,      &mr5_0,  0, 0 )==0 );
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, FD_FEC_SHRED_CNT, 0UL, &parent_bid, &B5, &mr5_32, 1, 0 )==0 );
  FD_TEST( deliver_rotor_fec    ( ctx, 6UL, 0U,               0UL, &parent_bid,      &mr6_0,  0, 0 )==0 );
  FD_TEST( deliver_rotor_fec_bid( ctx, 6UL, FD_FEC_SHRED_CNT, 0UL, &parent_bid, &B6, &mr6_32, 1, 0 )==0 );
  ag_block_id_t       key5_id   = ag_block_id( 5UL, B5.uc );
  ag_block_id_t       key5_slot = { .slot = 5UL };
  fd_block_id_ele_t * stale     = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key5_id, NULL, ctx->block_id_arr );
  FD_TEST( stale && stale->block_id_seen );
  ulong idx5 = fd_block_id_ele_get_idx( ctx->block_id_arr, stale );
  for( ulong slot=5UL; slot<=6UL; slot++ ) {
    ag_block_id_t       key = ag_block_id( slot, slot==5UL ? B5.uc : B6.uc );
    fd_block_id_ele_t * ele = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key, NULL, ctx->block_id_arr );
    ulong               idx = fd_block_id_ele_get_idx( ctx->block_id_arr, ele );
    fd_bank_t *         b   = fd_banks_bank_query( ctx->banks, idx );
    b->state = FD_BANK_STATE_REPLAYABLE;
    mark_bank_dead( ctx, test_stem, idx, FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_BAD_FOOTER, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED );
    b->refcnt = 0UL;
    fd_banks_prune_cancel_info_t cancel[ 1 ];
    FD_TEST( fd_banks_prune_one_bank( ctx->banks, cancel ) );
    FD_TEST( !fd_banks_bank_query( ctx->banks, idx ) );
  }
  FD_TEST( fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key5_id, NULL, ctx->block_id_arr )==stale );
  ulong used0 = fd_banks_pool_used_cnt( ctx->banks );
  ulong ing0  = mock_sched_fec_ingest_cnt;
  ulong seq0  = test_stem_seqs[ out_idx ];

  /* Redelivered FEC 0 of block 5 (unknown id, block_id filled in) starts
     a rebuild keyed {5, 0} on a fresh bank at a different idx; the stale
     {5, B5} entry stays. */
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, 0U, 0UL, &parent_bid, &B5, &mr5_0, 0, 0 )==0 );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used0+1UL );
  FD_TEST( mock_sched_fec_ingest_cnt==ing0+1UL );
  fd_block_id_ele_t * live = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key5_slot, NULL, ctx->block_id_arr );
  FD_TEST( live && live!=stale && !live->block_id_seen && live->latest_fec_idx==0U );
  FD_TEST( fd_block_id_ele_get_idx( ctx->block_id_arr, live )!=idx5 );
  FD_TEST( fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key5_id, NULL, ctx->block_id_arr )==stale );
  ulong idx_live = fd_block_id_ele_get_idx( ctx->block_id_arr, live );

  /* The same FEC 0 again: the stale id hit has no live bank, so the slot
     key is consulted and the FEC SKIPs.  No new bank, mapping intact. */
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, 0U, 0UL, &parent_bid, &B5, &mr5_0, 0, 0 )==0 );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used0+1UL );
  FD_TEST( mock_sched_fec_ingest_cnt==ing0+1UL );
  FD_TEST( fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key5_slot, NULL, ctx->block_id_arr )==live );
  FD_TEST( fd_banks_bank_query( ctx->banks, idx_live ) );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0 );

  /* The rebuild completes: the slot-complete FEC re-keys {5, 0} to
     {5, B5}, displacing the stale entry. */
  FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, FD_FEC_SHRED_CNT, 0UL, &parent_bid, &B5, &mr5_32, 1, 0 )==0 );
  FD_TEST( mock_sched_fec_ingest_cnt==ing0+2UL );
  FD_TEST( fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key5_id, NULL, ctx->block_id_arr )==live );
  FD_TEST( live->block_id_seen );
  FD_TEST( !fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key5_slot, NULL, ctx->block_id_arr ) );

  FD_LOG_NOTICE(( "pass: test_stale_id_key_does_not_shadow_rebuild" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 2UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_txn_completion_publish( wksp );              fd_wksp_reset( wksp, 42U );
  test_leader_fec_payload_retained( wksp );          fd_wksp_reset( wksp, 42U );
  test_reception_metrics_sidecar( wksp );           fd_wksp_reset( wksp, 42U );
  test_snapshot_intervals_use_block_height();
  test_consensus_root_notification_handoff( wksp ); fd_wksp_reset( wksp, 42U );
  test_epoch_boundary_fork_width_evict( wksp );     fd_wksp_reset( wksp, 42U );
  test_banks_full_prune_leaf( wksp );               fd_wksp_reset( wksp, 42U );
  test_banks_evict_backfill( wksp );                fd_wksp_reset( wksp, 42U );
  test_backfill_partial_sched_capacity( wksp );     fd_wksp_reset( wksp, 42U );
  test_double_confirm_backfill( wksp );             fd_wksp_reset( wksp, 42U );
  test_partial_exec_evict( wksp );                  fd_wksp_reset( wksp, 42U );
  test_eqvoc_mid_slot_evicted( wksp );              fd_wksp_reset( wksp, 42U );
  test_confirm( wksp );                             fd_wksp_reset( wksp, 42U );
  test_eqvoc_last_fec( wksp );                      fd_wksp_reset( wksp, 42U );
  test_eqvoc_first_fec( wksp );                     fd_wksp_reset( wksp, 42U );
  test_stale_redeliver( wksp );                     fd_wksp_reset( wksp, 42U );
  test_eqvoc_child_confirm( wksp );                 fd_wksp_reset( wksp, 42U );
  test_drain_rotor_fecs( wksp );                    fd_wksp_reset( wksp, 42U );
  test_drain_rotor_fecs_skip_wait_reentry( wksp );  fd_wksp_reset( wksp, 42U );
  test_process_rotor_fec_skip_replayed( wksp );     fd_wksp_reset( wksp, 42U );
  test_rotor_fec_turbine_keying( wksp );            fd_wksp_reset( wksp, 42U );
  test_dead_block_children_drop( wksp );
  test_stale_id_key_does_not_shadow_rebuild( wksp );

  FD_TEST( mock_store_view_success_cnt==mock_store_view_release_cnt );

  fd_halt();
  return 0;
}
