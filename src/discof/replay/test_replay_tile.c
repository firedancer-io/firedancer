/* test_replay_tile.c — Tests the replay tile's Alpenglow paths: rotor
   FEC consumption, votor rooting and leader slots.

   Mocks heavy dependencies via #define before including the tile .c. */
#define _GNU_SOURCE
#include "../../disco/store/fd_store.h"
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- Pull in type definitions we need for mock function signatures.
   These headers are guarded, so the re-include from fd_replay_tile.c
   will be a no-op. ---- */

#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_runtime.h"
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
#define TEST_OUT_CNT   5UL
#define TEST_REPAIR_IN_IDX 0UL
#define TEST_EXECRP_IN_IDX 1UL

static fd_validator_location_t const no_loc = {0};

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

static ulong          mock_sched_fec_ingest_cnt;
static ulong          mock_sched_abandon_cnt;
static ulong          mock_sched_abandon_idx;
static ulong          mock_sched_root_notify_cnt;
static ulong          mock_sched_root_notify_idx;
static ulong          mock_sched_cancel_idx;
static ulong          mock_sched_add_done_idx;
static ulong          mock_sched_capacity;
static int            mock_sched_drained;
static fd_sched_txn_info_t mock_sched_txn_info;
static fd_txn_p_t     mock_sched_txn;
static ulong          mock_sched_txn_idx;
static ulong          mock_sched_task_done_cnt;
static ulong          mock_sched_task_done_type;
static ulong          mock_sched_task_done_txn_idx;
static ulong          mock_sched_task_done_exec_idx;
static long           mock_sched_task_done_tick;

int mock_sched_fec_ingest_fn( fd_sched_t * s, fd_sched_fec_t * f ) {
  (void)s; (void)f;
  mock_sched_fec_ingest_cnt++;
  return 1;
}
ulong mock_sched_can_ingest_fn  ( fd_sched_t * s FD_PARAM_UNUSED ) { return mock_sched_capacity; }
int   mock_sched_is_drained_fn  ( fd_sched_t * s FD_PARAM_UNUSED ) { return mock_sched_drained; }
void  mock_sched_abandon_fn     ( fd_sched_t * s FD_PARAM_UNUSED, ulong i, int invalid FD_PARAM_UNUSED ) {
  mock_sched_abandon_cnt++;
  mock_sched_abandon_idx = i;
}
void  mock_sched_cancel_fn      ( fd_sched_t * s FD_PARAM_UNUSED, ulong i ) { mock_sched_cancel_idx = i; }
int   mock_sched_is_discarded_fn( fd_sched_t * s FD_PARAM_UNUSED, ulong i FD_PARAM_UNUSED ) { return 0; }
ulong mock_sched_pruned_fn      ( fd_sched_t * s FD_PARAM_UNUSED ) { return ULONG_MAX; }
void  mock_sched_metrics_fn     ( fd_sched_t * s FD_PARAM_UNUSED, fd_clock_tile_t const * c FD_PARAM_UNUSED ) {}
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
static ulong mock_next_leader_slot_calls;
static ulong mock_txncache_fork_id_next;
static ulong mock_progcache_fork_id_next;
static ushort mock_accdb_fork_id_next;
static fd_accdb_metrics_t mock_accdb_metrics; /* metrics_write without an accdb */
static int   mock_epoch_boundary_enabled;
static int   mock_snapshot_boot;

ulong
mock_multi_epoch_leaders_next_slot_fn( fd_multi_epoch_leaders_t const * mleaders FD_PARAM_UNUSED,
                                       ulong                            start_slot,
                                       fd_pubkey_t const *              leader_q FD_PARAM_UNUSED ) {
  mock_next_leader_slot_calls++;
  return mock_next_leader_slot>=start_slot ? mock_next_leader_slot : ULONG_MAX;
}

/* Off by default so the real leader schedule is used; tests that need
   to control whether a schedule is loaded set the override.
   mock_slot_leader is the pubkey returned when one is loaded. */

static int         mock_leader_for_slot_override;
static int         mock_leader_schedule_loaded;
static fd_pubkey_t mock_slot_leader;

fd_pubkey_t const *
mock_multi_epoch_leaders_leader_for_slot_fn( fd_multi_epoch_leaders_t const * mleaders FD_PARAM_UNUSED,
                                             ulong                            slot     FD_PARAM_UNUSED ) {
  return mock_leader_schedule_loaded ? &mock_slot_leader : NULL;
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

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  bank->stake_rewards_fork_id = fd_stake_rewards_init( stake_rewards,
                                                       &bank->f.prev_bank_hash,
                                                       bank->f.block_height,
                                                       1U,
                                                       0U,
                                                       0UL );
  fd_stake_rewards_fini( stake_rewards, bank->stake_rewards_fork_id );
}

#define fd_multi_epoch_leaders_get_next_slot mock_multi_epoch_leaders_next_slot_fn
#define fd_multi_epoch_leaders_get_leader_for_slot(m,s) \
  ( mock_leader_for_slot_override ? mock_multi_epoch_leaders_leader_for_slot_fn( (m), (s) ) \
                                  : (fd_multi_epoch_leaders_get_leader_for_slot)( (m), (s) ) )
#define fd_txncache_attach_child             mock_txncache_attach_child_fn
#define fd_progcache_attach_child            mock_progcache_attach_child_fn
#define fd_accdb_attach_child                mock_accdb_attach_child_fn
#define fd_accdb_cmd_pending(a)              ( (a) ? (fd_accdb_cmd_pending)(a) : 0 )
#define fd_txncache_cancel_fork(tc,f)        ((void)(tc),(void)(f))
#define fd_progcache_cancel_fork(c,f)        ((void)(c),(void)(f))
#define fd_accdb_purge(a,f)                  ((void)(a),(void)(f))
#define fd_accdb_flush_metrics(a)            do { if( a ) (fd_accdb_flush_metrics)(a); } while(0)
#define fd_accdb_metrics(a)                  ( (a) ? (fd_accdb_metrics)(a) : &mock_accdb_metrics )
#define fd_progcache_cache_class_occupancy(c,u,m) do { if( (c)->shmem ) (fd_progcache_cache_class_occupancy)(c,u,m); else { memset( u, 0, FD_PROGCACHE_CACHE_CLASS_CNT*sizeof(ulong) ); memset( m, 0, FD_PROGCACHE_CACHE_CLASS_CNT*sizeof(ulong) ); } } while(0)
#define fd_sched_block_start_pending(s)      ( (s) ? (fd_sched_block_start_pending)(s) : 0 )
/* Bypass unrelated boot dependencies while exercising snapshot DONE to completion. */
#define fd_sysvar_cache_restore(bank,accdb)  (mock_snapshot_boot ? 1 : (fd_sysvar_cache_restore)(bank,accdb))
#define fd_sysvar_rent_read(accdb,fork,rent) (mock_snapshot_boot ? (rent) : (fd_sysvar_rent_read)(accdb,fork,rent))
#define fd_sched_block_add_done(s,b,p,slot)   do { if( !mock_snapshot_boot ) mock_sched_add_done_idx = (b); } while(0)
#define fd_runtime_update_next_leaders(b,s)  do { if( !mock_snapshot_boot ) (fd_runtime_update_next_leaders)(b,s); } while(0)
#define fd_runtime_update_leaders(b,s)       do { if( !mock_snapshot_boot ) (fd_runtime_update_leaders)(b,s); } while(0)
#define fd_multi_epoch_leaders_epoch_msg_init(m,msg) do { if( !mock_snapshot_boot ) (fd_multi_epoch_leaders_epoch_msg_init)(m,msg); } while(0)
#define fd_multi_epoch_leaders_epoch_msg_fini(m)     do { if( !mock_snapshot_boot ) (fd_multi_epoch_leaders_epoch_msg_fini)(m); } while(0)
#define fd_progcache_reset(cache)                    do { if( !mock_snapshot_boot ) (fd_progcache_reset)(cache); } while(0)
#define fd_sysvar_cache_stake_history_view(cache,view) (mock_snapshot_boot ? NULL : (fd_sysvar_cache_stake_history_view)(cache,view))
#define fd_stake_delegations_refresh(d,e,h,w,f,r)     do { if( !mock_snapshot_boot ) (fd_stake_delegations_refresh)(d,e,h,w,f,r); } while(0)
#define fd_vote_stakes_refresh(v,f,a,i)              do { if( !mock_snapshot_boot ) (fd_vote_stakes_refresh)(v,f,a,i); } while(0)
#define fd_rewards_recalculate_partitioned_rewards(k,a,s,c) do { if( !mock_snapshot_boot ) (fd_rewards_recalculate_partitioned_rewards)(k,a,s,c); } while(0)
#define fd_accdb_lamports(a,i,p) (mock_snapshot_boot ? 0UL : (fd_accdb_lamports)(a,i,p))
static ulong mock_migration_slot = ULONG_MAX;
#define fd_alpenglow_migration_slot(b,a) (mock_snapshot_boot || mock_footer_finalize ? mock_migration_slot : (fd_alpenglow_migration_slot)(b,a))
#define fd_runtime_block_execute_prepare     mock_runtime_block_execute_prepare_fn

/* Isolate footer rooting from scheduler storage and runtime settlement. */
static int               mock_footer_finalize;
static fd_block_footer_t mock_footer_storage[ 1 ];
static fd_block_footer_t * mock_footer = mock_footer_storage;
static fd_hash_t         mock_footer_poh;

#define fd_sched_get_poh(s,b)        (mock_footer_finalize ? &mock_footer_poh : (fd_sched_get_poh)(s,b))
#define fd_sched_get_shred_cnt(s,b)  (mock_footer_finalize ? 0U : (fd_sched_get_shred_cnt)(s,b))
#define fd_sched_get_footer(s,b)     (mock_footer_finalize ? mock_footer : mock_snapshot_boot ? NULL : (fd_sched_get_footer)(s,b))
static int mock_footer_verify; /* mocked finalize still verifies certs */
#define fd_alpenglow_producer_time_bounds(b,a,l,h) do { if( mock_footer_finalize ) { *(l) = 0L; *(h) = LONG_MAX; } else (fd_alpenglow_producer_time_bounds)(b,a,l,h); } while(0)
#define fd_runtime_block_execute_finalize(b,a,c,f,s,g) (mock_footer_finalize ? ( mock_footer_verify && (f) ? fd_alpenglow_footer_verify(b,f,s,g) : 0 ) : (fd_runtime_block_execute_finalize)(b,a,c,f,s,g))
#define fd_runtime_block_execute_finalize_unverified(b,a,f,g) (mock_footer_finalize ? 0 : (fd_runtime_block_execute_finalize_unverified)(b,a,f,g))
#define fd_txncache_finalize_fork(t,f,o,h) do { if( !mock_footer_finalize ) (fd_txncache_finalize_fork)(t,f,o,h); } while(0)
static ulong mock_cert_tiles; /* idle exec tiles fd_sched_cert_dispatch claims from */
static ulong
mock_sched_cert_dispatch_fn( fd_sched_t * s FD_PARAM_UNUSED,
                             ulong        b FD_PARAM_UNUSED,
                             ulong        cnt ) {
  ulong tiles = 0UL;
  for( ulong idle=mock_cert_tiles; idle && cnt; cnt--, idle=fd_ulong_pop_lsb( idle ) ) tiles |= fd_ulong_mask_bit( fd_ulong_find_lsb( idle ) );
  return tiles;
}
#define fd_sched_cert_dispatch mock_sched_cert_dispatch_fn

/* ---- Include the tile under test ---- */

#include "fd_replay_tile.c"
#include "../../choreo/votor/ag_vote_serde.h"

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
  ulong const mtu   = sizeof(fd_rotor_replay_fec_t);
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
    else if( i==1UL ) { ctx->exec_out[ 0 ] = out; ctx->exec_cnt = 1UL; }
    else if( i==2UL ) *ctx->epoch_out  = out;
    else if( i==3UL ) *ctx->slot_out   = out;
    else              *ctx->rotor_out  = out;
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
  ctx->max_txn_per_slot     = FD_MAX_TXN_PER_SLOT;
  ctx->max_shreds_per_block = FD_SHRED_BLK_MAX;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_timing_slot_pool_align(), fd_timing_slot_pool_footprint( FD_REPLAY_TXN_TIMING_SLOTS ), 1UL );
  ctx->timing_slot_pool = fd_timing_slot_pool_join( fd_timing_slot_pool_new( mem, FD_REPLAY_TXN_TIMING_SLOTS ) );
  FD_TEST( ctx->timing_slot_pool );
  ctx->timing_rec = fd_wksp_alloc_laddr( wksp, alignof(fd_replay_txn_timing_t), FD_REPLAY_TXN_TIMING_SLOTS*ctx->max_txn_per_slot*sizeof(fd_replay_txn_timing_t), 1UL );
  FD_TEST( ctx->timing_rec );
  ctx->timing_slot_of_bank = test_timing_of_bank;
  for( ulong i=0UL; i<TEST_BANKS_MAX; i++ ) ctx->timing_slot_of_bank[ i ] = fd_timing_slot_pool_idx_null( ctx->timing_slot_pool );
}

/* node_info is a shared topology object present in every topology that
   runs replay, so unprivileged_init joins it unconditionally and the
   tile reads it without a NULL check.  Any test reaching that code has
   to stand it up. */

static void
setup_node_info( fd_replay_tile_t * ctx ) {
  static fd_node_info_box_t node_info_box[ 1 ];
  ctx->node_info = fd_node_info_box_join( fd_node_info_box_new( node_info_box ) );
  FD_TEST( ctx->node_info );
}

/* setup_mleaders fills the leader cache for epochs 0 and 1 (128-slot
   epochs, one staked node), as production does at boot. */

static void
setup_mleaders( fd_replay_tile_t * ctx ) {
  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) );
  FD_TEST( ctx->mleaders );
  static uchar buf[ 4096 ] __attribute__((aligned(64)));
  for( ulong epoch=0UL; epoch<2UL; epoch++ ) {
    memset( buf, 0, sizeof(buf) );
    fd_epoch_info_msg_t * msg = (fd_epoch_info_msg_t *)buf;
    msg->features.geo_aware_leader_schedule = FD_FEATURE_DISABLED;
    msg->epoch           = epoch;
    msg->staked_vote_cnt = 1UL;
    msg->staked_id_cnt   = 1UL;
    msg->start_slot      = epoch*128UL;
    msg->slot_cnt        = 128UL;
    msg->ns_per_slot     = 400000000UL;
    fd_epoch_schedule_derive( &msg->epoch_schedule, 128UL, 128UL, 0 );
    fd_vote_stake_weight_t * vw = fd_epoch_info_msg_stake_weights( msg );
    memset( vw[ 0 ].vote_key.uc, 0x33, 32UL );
    memset( vw[ 0 ].id_key.uc,   0x33, 32UL );
    vw[ 0 ].stake = 1UL;
    fd_stake_weight_t * iw = fd_epoch_info_msg_id_weights( msg );
    memset( iw[ 0 ].key.uc, 0x33, 32UL );
    iw[ 0 ].stake = 1UL;
    (fd_multi_epoch_leaders_epoch_msg_init)( ctx->mleaders, msg );
    (fd_multi_epoch_leaders_epoch_msg_fini)( ctx->mleaders );
  }
}

static void
setup_ctx( fd_replay_tile_t * ctx,
           fd_wksp_t *        wksp ) {
  FD_TEST( mock_store_view_success_cnt==mock_store_view_release_cnt );
  mock_store_view_call_cnt    = 0UL;
  mock_store_view_success_cnt = 0UL;
  mock_store_view_release_cnt = 0UL;
  mock_store_view_fail        = 0;
  memset( ctx, 0, sizeof(*ctx) );
  setup_timing( ctx, wksp );

  /* Block-id map */

  ulong bid_cnt   = TEST_BANKS_MAX;
  ulong chain_cnt = fd_ag_block_id_map_chain_cnt_est( bid_cnt );

  ctx->block_id_arr = fd_wksp_alloc_laddr( wksp, alignof(fd_block_id_ele_t), sizeof(fd_block_id_ele_t) * bid_cnt, 1UL );
  FD_TEST( ctx->block_id_arr );
  memset( ctx->block_id_arr, 0, sizeof(fd_block_id_ele_t) * bid_cnt );
  ctx->dead_idxs = fd_wksp_alloc_laddr( wksp, alignof(ulong), sizeof(ulong)*bid_cnt, 1UL );
  FD_TEST( ctx->dead_idxs );

  void * bid_map_mem = fd_wksp_alloc_laddr( wksp, fd_ag_block_id_map_align(), fd_ag_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( bid_map_mem );
  ctx->ag_block_id_map_seed = 7UL;
  ctx->ag_block_id_map = fd_ag_block_id_map_join( fd_ag_block_id_map_new( bid_map_mem, chain_cnt, ctx->ag_block_id_map_seed ) );
  FD_TEST( ctx->ag_block_id_map );
  ctx->bhm_map   = fd_bhm_map_join  ( fd_bhm_map_new  ( fd_wksp_alloc_laddr( wksp, fd_bhm_map_align(),   fd_bhm_map_footprint( chain_cnt ), 1UL ), chain_cnt, 7UL ) );
  ctx->bhm_pool  = fd_bhm_pool_join ( fd_bhm_pool_new ( fd_wksp_alloc_laddr( wksp, fd_bhm_pool_align(),  fd_bhm_pool_footprint( bid_cnt ),   1UL ), bid_cnt ) );
  ctx->bhm_dlist = fd_bhm_dlist_join( fd_bhm_dlist_new( fd_wksp_alloc_laddr( wksp, fd_bhm_dlist_align(), fd_bhm_dlist_footprint(),          1UL ) ) );
  FD_TEST( ctx->bhm_map && ctx->bhm_pool && ctx->bhm_dlist );

  ctx->reception_stats_cnt = bid_cnt;
  ctx->reception_stats = fd_wksp_alloc_laddr( wksp, alignof(fd_reception_stats_t), sizeof(fd_reception_stats_t)*bid_cnt, 1UL );
  FD_TEST( ctx->reception_stats );

  static fd_store_t mock_store;
  memset( &mock_store, 0, sizeof(mock_store) );
  mock_store.store_gaddr = (ulong)&mock_store;
  ctx->store             = &mock_store;
  ctx->store_disk_fd     = -1;

  /* Real banks — initialize root bank. */

  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( TEST_BANKS_MAX, 8UL, 2048UL, 2048UL ), 1UL );
  FD_TEST( banks_mem );
  ctx->banks = fd_banks_join( fd_banks_new( banks_mem, FD_STAKE_DELEGATIONS_FD, TEST_BANKS_MAX, 8UL, 2048UL, 32768UL, 2048UL, 0, 42UL ) );
  FD_TEST( ctx->banks );
  fd_bank_t * root_bank = fd_banks_init_bank( ctx->banks );
  FD_TEST( root_bank );
  root_bank->f.slot                        = 0UL;
  root_bank->f.parent_slot                 = ULONG_MAX;
  root_bank->f.ticks_per_slot              = 64UL;
  root_bank->f.slot_params                 = FD_SLOT_PARAMS_400MS;
  root_bank->f.slot_params.hashes_per_tick = 4UL;
  root_bank->f.slot_params_default         = FD_SLOT_PARAMS_400MS;
  root_bank->f.features.alpenglow          = FD_FEATURE_DISABLED;
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
  memset( &mock_slot_leader, 0, sizeof(fd_pubkey_t) );
  mock_txncache_fork_id_next  = 0UL;
  mock_progcache_fork_id_next = 0UL;
  mock_accdb_fork_id_next     = 0U;
  mock_sched_abandon_cnt      = 0UL;
  mock_sched_abandon_idx      = ULONG_MAX;
  mock_sched_root_notify_cnt  = 0UL;
  mock_sched_root_notify_idx  = ULONG_MAX;
  mock_sched_capacity         = ULONG_MAX;
  mock_sched_drained          = 1;
  mock_epoch_boundary_enabled = 0;
  mock_leader_for_slot_override = 0;
  mock_leader_schedule_loaded   = 0;

  setup_mleaders( ctx );

  setup_node_info( ctx );
  setup_stem( ctx, wksp );
  setup_repair_input( ctx, wksp );
}

/* init_root fills the root bank's block id element.  Callers key it in
   ag_block_id_map themselves. */

static void
init_root( fd_replay_tile_t * ctx,
           fd_hash_t const *  mr_root ) {
  fd_bank_t * root_bank = fd_banks_root( ctx->banks );
  FD_TEST( root_bank );

  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ root_bank->idx ];
  block_id_ele->block_id_seen  = 1;
  block_id_ele->slot           = root_bank->f.slot;
  block_id_ele->bank_seq       = root_bank->bank_seq;
  block_id_ele->latest_fec_idx = 0U;
  block_id_ele->latest_mr      = *mr_root;
  block_id_ele->dmr            = *mr_root;
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
  FD_TEST( bank->cost_tracker_fork_id==USHORT_MAX );
  bank->refcnt = 1UL;

  /* Dispatch pins the bank's cost tracker until the task is done. */
  fd_cost_tracker_store_t * cost_tracker_store = fd_bank_cost_tracker( bank );
  bank->cost_tracker_fork_id = fd_cost_tracker_store_new_fork( cost_tracker_store, USHORT_MAX );
  fd_cost_tracker_store_pin( cost_tracker_store, bank->cost_tracker_fork_id )->block_cost_limit = 48000000UL;

  mock_sched_txn_idx = 37UL;
  fd_memset( &mock_sched_txn, 0x5a, sizeof(mock_sched_txn) );
  mock_sched_txn.payload_sz = 321UL;

  mock_sched_txn_info = (fd_sched_txn_info_t) {
    .flags                    = FD_SCHED_TXN_SIGVERIFY_DONE,
    .txn_err                  = FD_RUNTIME_EXECUTE_SUCCESS,
    .received_ns              = 1000L,
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
  FD_TEST( test_stem_seqs[ ctx->slot_out->idx ]==0UL ); /* TXN_EXECUTED is not mirrored to replay_slot */
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
  FD_TEST( out->max_compute_units==48000000UL );
  FD_TEST( out->transaction_fee==msg->txn_exec->transaction_fee );
  FD_TEST( out->priority_fee==msg->txn_exec->priority_fee );
  FD_TEST( out->tips==msg->txn_exec->tips );

  fd_cost_tracker_store_release( cost_tracker_store, bank->cost_tracker_fork_id );
  bank->cost_tracker_fork_id = USHORT_MAX;

  FD_LOG_NOTICE(( "pass: test_txn_completion_publish" ));
}

static void
test_reward_cert_signer_count( void ) {
  static fd_replay_tile_t ctx[ 1 ];
  static fd_bank_t bank[ 1 ];
  bank->f.slot = FD_NUM_SLOTS_FOR_REWARD;
  fd_epoch_schedule_derive( &bank->f.epoch_schedule, 128UL, 128UL, 0 );
  /* Count signers even when our voter rank is unavailable. */
  bank->vote_stakes_fork_id = ULONG_MAX;
  mock_footer_finalize = 1;
  memset( mock_footer, 0, sizeof(fd_block_footer_t) );

  mock_footer->has_skip_reward_cert = mock_footer->has_notar_reward_cert = 1;
  fd_bls_set_insert( mock_footer->skip_reward_cert.signer_set, 1UL );
  fd_bls_set_insert( mock_footer->skip_reward_cert.signer_set, 2UL );
  fd_bls_set_insert( mock_footer->notar_reward_cert.signer_set, 2UL );
  fd_bls_set_insert( mock_footer->notar_reward_cert.signer_set, 3UL );
  ushort rank = 0, count = 0;
  FD_TEST( !replay_reward_cert_voted( ctx, bank, &rank, &count ) );
  FD_TEST( rank==USHORT_MAX && count==3 );

  mock_footer = NULL;
  FD_TEST( !replay_reward_cert_voted( ctx, bank, &rank, &count ) );
  FD_TEST( count==USHORT_MAX );

  mock_footer = mock_footer_storage;
  fd_bls_set_null( mock_footer->skip_reward_cert.signer_set );
  fd_bls_set_null( mock_footer->notar_reward_cert.signer_set );
  FD_TEST( !replay_reward_cert_voted( ctx, bank, &rank, &count ) );
  FD_TEST( count==0 );
  mock_footer_finalize = 0;

  FD_LOG_NOTICE(( "pass: test_reward_cert_signer_count" ));
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

/* A snapshot can come due on a published-root bank that is still in
   epoch E after the consensus root entered E+1.  By then replay has
   computed E+2's leader schedule into E's parity slot, so looking the
   leader up by the bank's epoch fails.  snapmk_start must use the
   leader recorded on the bank when the block was executed. */

static void
test_snapmk_start_leader_after_epoch_rollover( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );

  fd_bank_t * bank = fd_banks_root( ctx->banks );
  FD_TEST( bank );
  bank->f.slot  = 127UL;                 /* last slot of epoch 0 (128-slot epochs) */
  bank->f.epoch = 0UL;
  ctx->published_root_bank_idx = bank->idx;
  ctx->snapmk.supported        = 1;
  ctx->snapmk.active           = 0;
  ctx->snapmk.base_slot        = ULONG_MAX;
  *ctx->snapmk_out = *ctx->slot_out;

  /* The consensus root is in epoch 1: epoch 2's schedule now lives in
     epoch 0's parity slot, so a lookup by the bank's epoch finds no
     leader for slot 127. */
  fd_vote_stake_weight_t w2[ 1 ] = { { .stake = 1UL } };
  memset( w2[ 0 ].vote_key.uc, 0x22, 32UL );
  memset( w2[ 0 ].id_key.uc,   0x22, 32UL );
  FD_TEST( fd_epoch_leaders_join( fd_epoch_leaders_new( fd_bank_epoch_leaders_modify( bank, 0UL ), 2UL, 256UL, 128UL, 1UL, w2, 0 ) ) );
  FD_TEST( !fd_epoch_leaders_get( fd_bank_epoch_leaders_query( bank, 0UL ), 127UL ) );

  fd_pubkey_t expected; memset( expected.uc, 0x11, 32UL );
  bank->leader = expected;

  ulong chunk = ctx->snapmk_out->chunk;
  snapmk_start( ctx, test_stem, 0 );
  fd_replay_snap_start_t const * msg = fd_chunk_to_laddr_const( ctx->snapmk_out->mem, chunk );
  FD_TEST( msg->slot==127UL );
  FD_TEST( !memcmp( msg->leader.uc, expected.uc, 32UL ) );
  FD_TEST( ctx->snapmk.active );

  FD_LOG_NOTICE(( "pass: test_snapmk_start_leader_after_epoch_rollover" ));
}

static void
test_snapshot_found_deleted_state( fd_wksp_t * wksp ) {
  ulong  data_sz = fd_dcache_req_data_sz( sizeof(fd_snapmk_msg_t), 4UL, 1UL, 1 );
  void * dcache  = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp,
                     fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL ), data_sz, 0UL ) );
  FD_TEST( dcache );

  static fd_replay_tile_t ctx[ 1 ];
  fd_memset( ctx, 0, sizeof(fd_replay_tile_t) );

  ulong in_idx = 0UL;
  ctx->in[ in_idx ].mem = fd_wksp_containing( dcache );

  ulong chunk0 = fd_dcache_compact_chunk0( ctx->in[ in_idx ].mem, dcache );

  /* FOUND messages: keep max. */

  fd_snapmk_msg_t * msg = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk0 );
  msg->found.slot      = 100UL;
  msg->found.base_slot = ULONG_MAX; /* full */
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_FOUND, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_full==100UL );
  FD_TEST( ctx->snapmk.snap_finished_incr==0UL );

  msg->found.slot = 200UL;
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_FOUND, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_full==200UL );

  msg->found.slot = 150UL;
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_FOUND, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_full==200UL );

  msg->found.slot      = 250UL;
  msg->found.base_slot = 200UL; /* incremental */
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_FOUND, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_incr==250UL );
  FD_TEST( ctx->snapmk.snap_finished_full==200UL );

  msg->found.slot      = 210UL;
  msg->found.base_slot = 200UL;
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_FOUND, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_incr==250UL );

  /* DELETED messages: reset-if-match. */

  fd_snapmk_msg_deleted_t * del = &msg->deleted;
  del->slot      = 100UL;
  del->base_slot = ULONG_MAX; /* full */
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_DELETED, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_full==200UL );

  del->slot = 200UL;
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_DELETED, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_full==0UL );

  del->slot      = 250UL;
  del->base_slot = 200UL; /* incremental */
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_DELETED, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_incr==0UL );

  del->slot      = 999UL;
  del->base_slot = 200UL;
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_DELETED, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_incr==0UL );

  FD_LOG_NOTICE(( "pass: test_snapshot_found_deleted_state" ));
}

/* Test wait_info_healthy (the production health classifier used by
   metrics_write). */

static void
test_wait_info_health_signal( void ) {
  /* Not caught up: always unhealthy regardless of slots. */
  FD_TEST( !wait_info_healthy( 0, 100UL, 100UL ) );
  FD_TEST( !wait_info_healthy( 0, 100UL,  50UL ) );
  FD_TEST( !wait_info_healthy( 0, ULONG_MAX, ULONG_MAX ) );

  /* Caught up and close (distance <= 12): healthy. */
  FD_TEST(  wait_info_healthy( 1, 100UL, 100UL ) );  /* distance 0 */
  FD_TEST(  wait_info_healthy( 1, 112UL, 100UL ) );  /* distance 12 */
  FD_TEST(  wait_info_healthy( 1,  50UL, 100UL ) );  /* turbine behind reset */

  /* Caught up but fallen behind (distance > 12): unhealthy. */
  FD_TEST( !wait_info_healthy( 1, 113UL, 100UL ) );  /* distance 13 */
  FD_TEST( !wait_info_healthy( 1, 200UL, 100UL ) );  /* distance 100 */

  /* ULONG_MAX maps to 0 for both fields. */
  FD_TEST(  wait_info_healthy( 1, ULONG_MAX, ULONG_MAX ) );  /* both 0, distance 0 */
  FD_TEST(  wait_info_healthy( 1, ULONG_MAX, 100UL ) );      /* turbine 0 <= reset */
  FD_TEST( !wait_info_healthy( 1, 100UL, ULONG_MAX ) );      /* turbine 100, reset 0, distance 100 > 12 */

  FD_LOG_NOTICE(( "pass: test_wait_info_health_signal" ));
}

static void
publish( fd_replay_tile_t * ctx,
         fd_wait_info_t *   info ) {
  wait_info_publish( ctx );
  FD_TEST( fd_wait_info_try_read( info, ctx->wait_info ) );
}

static void
test_wait_info_leader_gap( void ) {
  static fd_replay_tile_t   ctx[ 1 ];
  static fd_wait_info_box_t box[ 1 ];
  fd_wait_info_t info;

  fd_memset( ctx, 0, sizeof(fd_replay_tile_t) );
  ctx->wait_info = fd_wait_info_box_join( fd_wait_info_box_new( box ) );
  FD_TEST( ctx->wait_info );
  ctx->next_leader_query_start = ULONG_MAX;
  ctx->highwater_leader_slot   = ULONG_MAX;
  ctx->reset_slot              = 1000UL;
  ctx->caught_up               = 1;
  ctx->catch_up_max_fec_slot   = 1000UL;

  mock_leader_for_slot_override = 1;
  mock_leader_schedule_loaded   = 1;

  /* Steady state: a leader slot is coming up. */
  mock_next_leader_slot        = 5000UL;
  ctx->next_leader_slot        = 5000UL;
  ctx->next_leader_query_start = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST(  info.next_leader_known        );
  FD_TEST(  info.next_leader_slot==5000UL );
  FD_TEST( !info.leader_slot              );
  FD_TEST(  info.tip_slot==1000UL         );
  FD_TEST( !info.leader_highwater_slot    ); /* never led: ULONG_MAX reads 0 */

  /* The tip is what wait measures the gap from, so it must survive
     replay trailing it, and read 0 rather than ULONG_MAX when unset. */
  ctx->catch_up_max_fec_slot   = 1012UL;
  ctx->next_leader_query_start = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST( info.tip_slot==1012UL );
  FD_TEST( info.reset_slot==1000UL );

  ctx->catch_up_max_fec_slot   = ULONG_MAX;
  ctx->next_leader_query_start = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST( !info.tip_slot );
  ctx->catch_up_max_fec_slot   = 1000UL;

  /* Just finished leading slot 1001, reset_slot still lagging behind
     it: the tile's own next_leader_slot is parked at the sentinel
     until the consensus tile answers.  That must not read as "nothing
     upcoming", and the slot just led must not read as upcoming. */
  ctx->next_leader_slot        = ULONG_MAX;
  ctx->highwater_leader_slot   = 1001UL;
  ctx->leader_bank             = NULL;
  ctx->next_leader_query_start = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST( !( info.next_leader_known && !info.next_leader_slot ) ); /* not "nothing upcoming" */
  FD_TEST( info.next_leader_slot==5000UL );
  FD_TEST( !info.leader_slot             );
  FD_TEST( info.leader_highwater_slot==1001UL );
  FD_TEST( info.reset_slot            ==1000UL );

  /* The only upcoming leader slot is the one just led: the highwater
     term must exclude it. */
  mock_next_leader_slot        = 1001UL;
  ctx->next_leader_query_start = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST(  info.next_leader_known );
  FD_TEST( !info.next_leader_slot  );

  ctx->highwater_leader_slot   = ULONG_MAX;

  /* Genuinely nothing upcoming (unstaked, or past the last leader slot
     of the tracked schedules): wait is allowed to pass. */
  mock_next_leader_slot        = 0UL; /* mock yields ULONG_MAX for start_slot>0 */
  ctx->next_leader_slot        = ULONG_MAX;
  ctx->next_leader_query_start = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST(  info.next_leader_known  );
  FD_TEST( !info.next_leader_slot   );

  /* Schedule not loaded: wait must block rather than read silence as
     "nothing upcoming". */
  mock_leader_schedule_loaded  = 0;
  ctx->next_leader_query_start = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST( !info.next_leader_known );

  /* Actively leading outranks everything else. */
  mock_leader_schedule_loaded  = 1;
  mock_next_leader_slot        = 5000UL;
  static fd_bank_t leader_bank[ 1 ];
  fd_memset( leader_bank, 0, sizeof(fd_bank_t) );
  leader_bank->f.slot          = 1001UL;
  ctx->leader_bank             = leader_bank;
  ctx->next_leader_query_start = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST( info.leader_slot     ==1001UL );
  FD_TEST( info.next_leader_slot==1001UL );

  ctx->leader_bank              = NULL;
  mock_leader_for_slot_override = 0;
  mock_leader_schedule_loaded   = 0;
  mock_next_leader_slot         = ULONG_MAX;
  FD_LOG_NOTICE(( "pass: test_wait_info_leader_gap" ));
}

static void
test_wait_info_produced_incr_cnt( fd_wksp_t * wksp ) {
  ulong  data_sz = fd_dcache_req_data_sz( sizeof(fd_snapmk_msg_t), 4UL, 1UL, 1 );
  void * dcache  = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp,
                     fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL ), data_sz, 0UL ) );
  FD_TEST( dcache );

  static fd_replay_tile_t ctx[ 1 ];
  fd_memset( ctx, 0, sizeof(fd_replay_tile_t) );

  ulong in_idx = 0UL;
  ctx->in[ in_idx ].mem = fd_wksp_containing( dcache );
  ulong chunk0 = fd_dcache_compact_chunk0( ctx->in[ in_idx ].mem, dcache );

  ulong const bank_cnt = 4UL;
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( bank_cnt, 8UL, 8UL, 8UL ), 1UL );
  FD_TEST( banks_mem );
  ctx->banks = fd_banks_join( fd_banks_new( banks_mem, FD_STAKE_DELEGATIONS_FD, bank_cnt, 8UL, 8UL, 128UL, 8UL, 0, 43UL ) );
  FD_TEST( ctx->banks );

  fd_bank_t * root = fd_banks_init_bank( ctx->banks );
  FD_TEST( root );
  root->f.slot = 700UL;
  ctx->snapmk.bank_idx = root->idx;

  /* Found on disk: watermarks move, count does not. */

  fd_snapmk_msg_t * msg = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk0 );
  msg->found.slot      = 500UL;
  msg->found.base_slot = ULONG_MAX; /* full */
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_FOUND, in_idx, chunk0 );
  msg->found.slot      = 600UL;
  msg->found.base_slot = 500UL;     /* incremental */
  msg_snapmk( ctx, NULL, FD_SNAPMK_MSG_FOUND, in_idx, chunk0 );
  FD_TEST( ctx->snapmk.snap_finished_full==500UL );
  FD_TEST( ctx->snapmk.snap_finished_incr==600UL );
  FD_TEST( ctx->snapmk.snap_produced_incr_cnt==0UL );

  /* Produced incremental: count advances. */

  root->refcnt++;
  FD_TEST( fd_epoch_credits_view_init( ctx->snapmk.epoch_credits_view, fd_bank_epoch_credits( root ), root->epoch_credits_fork_id ) );
  ctx->snapmk.active      = 1;
  ctx->snapmk.incremental = 1;
  snapmk_done( ctx, NULL, 1 );
  FD_TEST( !ctx->snapmk.epoch_credits_view->credits );
  FD_TEST( ctx->snapmk.snap_finished_incr==700UL );
  FD_TEST( ctx->snapmk.snap_produced_incr_cnt==1UL );

  /* Produced full: it does not. */

  root->refcnt++;
  FD_TEST( fd_epoch_credits_view_init( ctx->snapmk.epoch_credits_view, fd_bank_epoch_credits( root ), root->epoch_credits_fork_id ) );
  ctx->snapmk.active      = 1;
  ctx->snapmk.incremental = 0;
  snapmk_done( ctx, NULL, 1 );
  FD_TEST( !ctx->snapmk.epoch_credits_view->credits );
  FD_TEST( ctx->snapmk.snap_finished_full==700UL );
  FD_TEST( ctx->snapmk.snap_produced_incr_cnt==1UL );

  /* Failed incremental: it does not. */

  root->refcnt++;
  FD_TEST( fd_epoch_credits_view_init( ctx->snapmk.epoch_credits_view, fd_bank_epoch_credits( root ), root->epoch_credits_fork_id ) );
  ctx->snapmk.active      = 1;
  ctx->snapmk.incremental = 1;
  snapmk_done( ctx, NULL, 0 );
  FD_TEST( !ctx->snapmk.epoch_credits_view->credits );
  FD_TEST( ctx->snapmk.snap_produced_incr_cnt==1UL );

  FD_LOG_NOTICE(( "pass: test_wait_info_produced_incr_cnt" ));
}

static void
test_wait_info_snapshot_intervals( void ) {
  static fd_replay_tile_t   ctx[ 1 ];
  static fd_wait_info_box_t box[ 1 ];
  fd_wait_info_t info;

  fd_memset( ctx, 0, sizeof(fd_replay_tile_t) );
  ctx->wait_info = fd_wait_info_box_join( fd_wait_info_box_new( box ) );
  FD_TEST( ctx->wait_info );
  ctx->next_leader_query_start = ULONG_MAX;
  ctx->highwater_leader_slot   = ULONG_MAX;

  mock_leader_for_slot_override = 1;
  mock_leader_schedule_loaded   = 1;

  /* Both intervals reach the box verbatim. */
  ctx->snapmk.full_interval_blocks        = 25000UL;
  ctx->snapmk.incremental_interval_blocks = 500UL;
  publish( ctx, &info );
  FD_TEST( info.snap_full_interval_blocks==25000UL );
  FD_TEST( info.snap_incr_interval_blocks==500UL   );

  /* unprivileged_init zeroes both when snapmk is unsupported; wait
     reads that as no periodic schedule and stops requiring freshness. */
  ctx->snapmk.full_interval_blocks        = 0UL;
  ctx->snapmk.incremental_interval_blocks = 0UL;
  ctx->next_leader_query_start            = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST( !info.snap_full_interval_blocks );
  FD_TEST( !info.snap_incr_interval_blocks );

  /* Incrementals on with fulls off: wait must still require a fresh
     incremental, so the two intervals cannot collapse into one flag. */
  ctx->snapmk.incremental_interval_blocks = 500UL;
  ctx->next_leader_query_start            = ULONG_MAX;
  publish( ctx, &info );
  FD_TEST( !info.snap_full_interval_blocks         );
  FD_TEST(  info.snap_incr_interval_blocks==500UL  );

  ctx->wait_info                = NULL;
  mock_leader_for_slot_override = 0;
  mock_leader_schedule_loaded   = 0;
  FD_LOG_NOTICE(( "pass: test_wait_info_snapshot_intervals" ));
}

static void
test_next_leader_slot_cache( void ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_memset( ctx, 0, sizeof(fd_replay_tile_t) );
  ctx->next_leader_query_start = ULONG_MAX;

  mock_next_leader_slot       = 100UL;
  mock_next_leader_slot_calls = 0UL;

  /* Cold cache: one scan. */
  FD_TEST( query_next_leader_slot( ctx, 10UL )==100UL );
  FD_TEST( mock_next_leader_slot_calls==1UL );

  /* from advancing up to the cached slot: no rescan. */
  for( ulong from=11UL; from<=100UL; from++ ) FD_TEST( query_next_leader_slot( ctx, from )==100UL );
  FD_TEST( mock_next_leader_slot_calls==1UL );

  /* Passing the cached slot forces exactly one rescan. */
  mock_next_leader_slot = 250UL;
  FD_TEST( query_next_leader_slot( ctx, 101UL )==250UL );
  FD_TEST( mock_next_leader_slot_calls==2UL );
  FD_TEST( query_next_leader_slot( ctx, 200UL )==250UL );
  FD_TEST( mock_next_leader_slot_calls==2UL );

  /* A cached ULONG_MAX is held until something invalidates it, so an
     advancing from does not rescan. */
  mock_next_leader_slot = 0UL; /* mock yields ULONG_MAX for start_slot>0 */
  FD_TEST( query_next_leader_slot( ctx, 251UL )==ULONG_MAX );
  FD_TEST( mock_next_leader_slot_calls==3UL );
  for( ulong from=252UL; from<400UL; from++ ) FD_TEST( query_next_leader_slot( ctx, from )==ULONG_MAX );
  FD_TEST( mock_next_leader_slot_calls==3UL );

  /* Invalidation (mleaders or identity changed) forces a rescan. */
  mock_next_leader_slot        = 500UL;
  ctx->next_leader_query_start = ULONG_MAX;
  FD_TEST( query_next_leader_slot( ctx, 400UL )==500UL );
  FD_TEST( mock_next_leader_slot_calls==4UL );

  /* A regressing from rescans; get_next_slot is not monotone in it. */
  FD_TEST( query_next_leader_slot( ctx, 399UL )==500UL );
  FD_TEST( mock_next_leader_slot_calls==5UL );
  FD_TEST( query_next_leader_slot( ctx, 450UL )==500UL );  /* back inside the window */
  FD_TEST( mock_next_leader_slot_calls==5UL );

  mock_next_leader_slot       = ULONG_MAX;
  mock_next_leader_slot_calls = 0UL;
  FD_LOG_NOTICE(( "pass: test_next_leader_slot_cache" ));
}

static void
test_consensus_root_notification_handoff( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  memset( ctx, 0, sizeof(*ctx) );
  setup_mleaders( ctx );
  setup_timing( ctx, wksp );
  setup_stem( ctx, wksp );
  setup_node_info( ctx );

  ulong const bank_cnt = 4UL;
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( bank_cnt, 8UL, 8UL, 8UL ), 1UL );
  FD_TEST( banks_mem );
  ctx->banks = fd_banks_join( fd_banks_new( banks_mem, FD_STAKE_DELEGATIONS_FD, bank_cnt, 8UL, 8UL, 128UL, 8UL, 0, 43UL ) );
  FD_TEST( ctx->banks );

  fd_bank_t * root = fd_banks_init_bank( ctx->banks );
  FD_TEST( root );
  root->f.slot                        = 0UL;
  root->f.parent_slot                 = 0UL;
  root->f.ticks_per_slot              = 64UL;
  root->f.slot_params                 = FD_SLOT_PARAMS_400MS;
  root->f.slot_params.hashes_per_tick = 4UL;
  root->f.slot_params_default         = FD_SLOT_PARAMS_400MS;
  root->f.features.alpenglow          = 0UL;
  fd_epoch_schedule_derive( &root->f.epoch_schedule, 128UL, 128UL, 0 );

  fd_hash_t root_id  = { .ul = { 100UL } };
  fd_hash_t child_id = { .ul = { 200UL } };
  root->f.block_id   = root_id;
  fd_blockhashes_init( &root->f.block_hash_queue, 42UL );
  FD_TEST( fd_blockhashes_push_new( &root->f.block_hash_queue, &root_id ) );

  ulong chain_cnt = fd_ag_block_id_map_chain_cnt_est( bank_cnt );
  ctx->block_id_arr = fd_wksp_alloc_laddr( wksp, alignof(fd_block_id_ele_t), sizeof(fd_block_id_ele_t)*bank_cnt, 1UL );
  FD_TEST( ctx->block_id_arr );
  memset( ctx->block_id_arr, 0, sizeof(fd_block_id_ele_t)*bank_cnt );
  ctx->dead_idxs = fd_wksp_alloc_laddr( wksp, alignof(ulong), sizeof(ulong)*bank_cnt, 1UL );
  FD_TEST( ctx->dead_idxs );
  void * map_mem = fd_wksp_alloc_laddr( wksp, fd_ag_block_id_map_align(), fd_ag_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( map_mem );
  ctx->ag_block_id_map = fd_ag_block_id_map_join( fd_ag_block_id_map_new( map_mem, chain_cnt, 44UL ) );
  FD_TEST( ctx->ag_block_id_map );
  ctx->block_id_len   = bank_cnt;
  ctx->max_live_slots = bank_cnt;

  void * store_mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( 2UL, 1UL, 0UL, 0UL, 0UL, 1, 1UL ), 1UL );
  FD_TEST( store_mem );
  ctx->store = fd_store_join( fd_store_new( store_mem, 2UL, 1UL, 0UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 0UL, 1, 1UL ) );
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
  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];
  ulong slot_seq0 = test_stem_seqs[ ctx->slot_out->idx ];
  mock_snapshot_boot = 1;
  on_snapshot_message( ctx, test_stem, 0UL, 0UL, fd_ssmsg_sig( FD_SSMSG_REPLAY_READY ) );
  on_snapshot_message( ctx, test_stem, 0UL, 0UL, fd_ssmsg_sig( FD_SSMSG_DONE ) );
  mock_snapshot_boot = 0;
  fd_metrics_tl = saved_metrics_tl;
  FD_TEST( root->accdb_fork_id.val==37U );
  FD_TEST( root->parent_accdb_fork_id.val==37U );
  FD_TEST( mock_accdb_fork_id_next==0U );

  /* Verify REPLAY_SIG_RESET was published (4th message after
     SLOT_COMPLETED, NEXT_LEADER and ROOT_ADVANCED). */
  FD_TEST( test_stem_seqs[ out_idx ]>=seq0+4UL );
  fd_frag_meta_t const * reset_meta = test_stem_mcaches[ out_idx ]
      + fd_mcache_line_idx( seq0+3UL, test_stem_depths[ out_idx ] );
  FD_TEST( reset_meta->sig==REPLAY_SIG_RESET );
  FD_TEST( reset_meta->sz ==sizeof(fd_poh_reset_t) );
  fd_poh_reset_t const * reset = fd_chunk_to_laddr_const( ctx->replay_out->mem, reset_meta->chunk );
  FD_TEST( reset->completed_slot==0UL );
  FD_TEST( reset->ticks_per_slot==64UL );

  /* replay_slot carries the same slot events, in order, byte for byte. */
  FD_TEST( test_stem_seqs[ ctx->slot_out->idx ]-slot_seq0==test_stem_seqs[ out_idx ]-seq0 );
  for( ulong i=0UL; i<test_stem_seqs[ out_idx ]-seq0; i++ ) {
    fd_frag_meta_t const * a = test_stem_mcaches[ out_idx ]            + fd_mcache_line_idx( seq0+i,      test_stem_depths[ out_idx ] );
    fd_frag_meta_t const * b = test_stem_mcaches[ ctx->slot_out->idx ] + fd_mcache_line_idx( slot_seq0+i, test_stem_depths[ ctx->slot_out->idx ] );
    FD_TEST( a->sig==b->sig && a->sz==b->sz );
    FD_TEST( !memcmp( fd_chunk_to_laddr_const( ctx->replay_out->mem, a->chunk ), fd_chunk_to_laddr_const( ctx->slot_out->mem, b->chunk ), a->sz ) );
  }

  root->refcnt = 0UL;

  fd_bank_t * child = fd_banks_new_bank( ctx->banks, root->idx, 0L, 0 );
  child = fd_banks_clone_from_parent( ctx->banks, child->idx );
  FD_TEST( child );
  child->f.slot     = 1UL;
  child->f.block_id = child_id;
  fd_banks_mark_bank_frozen( child );

  fd_block_id_ele_t * child_ele = &ctx->block_id_arr[ child->idx ];
  child_ele->latest_mr     = child_id;
  child_ele->dmr           = child_id;
  child_ele->block_info    = ag_block_id( child->f.slot, child_id.uc );
  child_ele->slot          = child->f.slot;
  child_ele->bank_seq      = child->bank_seq;
  child_ele->block_id_seen = 1;
  FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, child_ele, ctx->block_id_arr ) );

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

/* ---- Alpenglow rooting: a block is rooted once finalized AND replayed ---- */

#define TEST_VOTOR_IN_IDX 2UL

static void
setup_votor_input( fd_replay_tile_t * ctx, fd_wksp_t * wksp ) {
  ulong const depth = 128UL;
  ulong const mtu   = sizeof(fd_votor_msg_t);
  ulong dcache_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );

  void * dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
  FD_TEST( dcache_mem );
  void * dcache = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );
  FD_TEST( dcache );

  ctx->in_kind[ TEST_VOTOR_IN_IDX ] = IN_KIND_VOTOR;
  ctx->in[ TEST_VOTOR_IN_IDX ].mem    = wksp;
  ctx->in[ TEST_VOTOR_IN_IDX ].chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  ctx->in[ TEST_VOTOR_IN_IDX ].wmark  = fd_dcache_compact_wmark ( wksp, dcache, mtu );
  ctx->in[ TEST_VOTOR_IN_IDX ].mtu    = mtu;
}

/* deliver_certed drives a finalization cert through the votor input,
   as votor's CERTED frag would. */

static void
deliver_certed( fd_replay_tile_t * ctx,
                uint               kind,
                ulong              slot,
                fd_hash_t const *  block_id ) {
  ulong chunk = ctx->in[ TEST_VOTOR_IN_IDX ].chunk0;
  fd_votor_certed_t * certed = fd_chunk_to_laddr( ctx->in[ TEST_VOTOR_IN_IDX ].mem, chunk );
  memset( certed, 0, sizeof(fd_votor_certed_t) );
  certed->kind     = kind;
  certed->slot     = slot;
  certed->block_id = *block_id;
  FD_TEST( !returnable_frag( ctx, TEST_VOTOR_IN_IDX, 0UL, FD_VOTOR_SIG_CERTED, chunk, sizeof(fd_votor_msg_t), 0UL, 0UL, 0UL, test_stem ) );
}

/* setup_rooting_ctx boots an Alpenglow ctx rooted at a frozen slot 0
   bank, with the block id map and rooting state replay would have. */

static fd_bank_t *
setup_rooting_ctx( fd_replay_tile_t * ctx,
                   fd_wksp_t *        wksp,
                   fd_hash_t const *  root_id ) {
  memset( ctx, 0, sizeof(*ctx) );
  setup_timing( ctx, wksp );
  setup_node_info( ctx );
  setup_stem( ctx, wksp );
  setup_votor_input( ctx, wksp );

  void * store_mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( 2UL, 1UL, 0UL, 0UL, 0UL, 1, 1UL ), 1UL );
  FD_TEST( store_mem );
  ctx->store = fd_store_join( fd_store_new( store_mem, 2UL, 1UL, 0UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 0UL, 1, 1UL ) );
  FD_TEST( ctx->store );
  FD_TEST( fd_store_map_ljoin( ctx->store, ctx->map_join ) );

  ulong const bank_cnt = 8UL;
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( bank_cnt, 8UL, 8UL, 8UL ), 1UL );
  FD_TEST( banks_mem );
  ctx->banks = fd_banks_join( fd_banks_new( banks_mem, FD_STAKE_DELEGATIONS_FD, bank_cnt, 8UL, 8UL, 128UL, 8UL, 0, 43UL ) );
  FD_TEST( ctx->banks );

  fd_bank_t * root = fd_banks_init_bank( ctx->banks );
  FD_TEST( root );
  root->f.slot     = 0UL;
  root->f.block_id = *root_id;
  fd_epoch_schedule_derive( &root->f.epoch_schedule, 128UL, 128UL, 0 );

  ctx->block_id_arr = fd_wksp_alloc_laddr( wksp, alignof(fd_block_id_ele_t), sizeof(fd_block_id_ele_t)*bank_cnt, 1UL );
  FD_TEST( ctx->block_id_arr );
  memset( ctx->block_id_arr, 0, sizeof(fd_block_id_ele_t)*bank_cnt );
  ctx->dead_idxs = fd_wksp_alloc_laddr( wksp, alignof(ulong), sizeof(ulong)*bank_cnt, 1UL );
  FD_TEST( ctx->dead_idxs );
  ulong  chain_cnt  = fd_ag_block_id_map_chain_cnt_est( bank_cnt );
  void * ag_map_mem = fd_wksp_alloc_laddr( wksp, fd_ag_block_id_map_align(), fd_ag_block_id_map_footprint( chain_cnt ), 1UL );
  FD_TEST( ag_map_mem );
  ctx->ag_block_id_map_seed = 7UL;
  ctx->ag_block_id_map      = fd_ag_block_id_map_join( fd_ag_block_id_map_new( ag_map_mem, chain_cnt, ctx->ag_block_id_map_seed ) );
  FD_TEST( ctx->ag_block_id_map );
  ctx->bhm_map   = fd_bhm_map_join  ( fd_bhm_map_new  ( fd_wksp_alloc_laddr( wksp, fd_bhm_map_align(),   fd_bhm_map_footprint( chain_cnt ), 1UL ), chain_cnt, 7UL ) );
  ctx->bhm_pool  = fd_bhm_pool_join ( fd_bhm_pool_new ( fd_wksp_alloc_laddr( wksp, fd_bhm_pool_align(),  fd_bhm_pool_footprint( bank_cnt ), 1UL ), bank_cnt ) );
  ctx->bhm_dlist = fd_bhm_dlist_join( fd_bhm_dlist_new( fd_wksp_alloc_laddr( wksp, fd_bhm_dlist_align(), fd_bhm_dlist_footprint(),          1UL ) ) );
  FD_TEST( ctx->bhm_map && ctx->bhm_pool && ctx->bhm_dlist );
  ctx->block_id_len   = bank_cnt;
  ctx->max_live_slots = bank_cnt;

  ctx->block_id_arr[ root->idx ].block_info = ag_block_id( 0UL, root_id->uc );
  ctx->block_id_arr[ root->idx ].bank_seq   = root->bank_seq;

  ctx->consensus_root          = *root_id;
  ctx->consensus_root_slot     = 0UL;
  ctx->notified_root           = *root_id;
  ctx->notified_root_slot      = 0UL;
  ctx->notified_root_bank      = root;
  ctx->published_root_slot     = 0UL;
  ctx->published_root_bank_idx = root->idx;
  ctx->finalized_block_id_lo.slot = 0UL;
  ctx->finalized_block_id_hi.slot = 0UL;
  ctx->votor_final->slot       = ULONG_MAX;

  mock_sched_root_notify_cnt = 0UL;
  mock_sched_root_notify_idx = ULONG_MAX;
  return root;
}

/* Give slot a replayable bank chained off parent, with its block id
   already known.  The footer test freezes it through replay. */

static fd_bank_t *
add_replayable_block( fd_replay_tile_t * ctx,
                      fd_bank_t *        parent,
                      ulong              slot,
                      fd_hash_t const *  block_id ) {
  fd_bank_t * bank = fd_banks_new_bank( ctx->banks, parent->idx, 0L, 0 );
  FD_TEST( bank );
  bank = fd_banks_clone_from_parent( ctx->banks, bank->idx );
  FD_TEST( bank );
  bank->f.slot        = slot;
  bank->f.parent_slot = parent->f.slot;
  bank->f.block_id    = *block_id;

  fd_block_id_ele_t * ele = &ctx->block_id_arr[ bank->idx ];
  ele->dmr           = *block_id;
  ele->block_info    = ag_block_id( slot, block_id->uc );
  ele->slot          = slot;
  ele->bank_seq      = bank->bank_seq;
  ele->block_id_seen = 1;
  FD_TEST( fd_ag_block_id_map_ele_insert( ctx->ag_block_id_map, ele, ctx->block_id_arr ) );
  return bank;
}

/* add_block gives the root walk an already replayed block. */

static fd_bank_t *
add_block( fd_replay_tile_t * ctx,
           fd_bank_t *        parent,
           ulong              slot,
           fd_hash_t const *  block_id ) {
  fd_bank_t * bank = add_replayable_block( ctx, parent, slot, block_id );
  fd_banks_mark_bank_frozen( bank );
  return bank;
}

/* expect_rooted checks the root try_advance_root_ag left behind, unsent,
   and that after_credit hands it off as one REPLAY_SIG_ROOT_ADVANCED. */

static void
expect_rooted( fd_replay_tile_t * ctx,
               fd_wksp_t *        wksp,
               ulong              seq,
               fd_bank_t const *  bank ) {
  ulong out_idx = ctx->replay_out->idx;
  FD_TEST( ctx->consensus_root_slot==bank->f.slot && fd_hash_eq( &ctx->consensus_root, &bank->f.block_id ) );
  FD_TEST( test_stem_seqs[ out_idx ]==seq );
  FD_TEST( try_notify_consensus_root( ctx, test_stem ) );
  FD_TEST( mock_sched_root_notify_idx==bank->idx );
  FD_TEST( test_stem_seqs[ out_idx ]==seq+1UL );
  fd_frag_meta_t const * m = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( seq, test_stem_depths[ out_idx ] );
  FD_TEST( m->sig==REPLAY_SIG_ROOT_ADVANCED && m->sz==sizeof(fd_replay_root_advanced_t) );
  fd_replay_root_advanced_t const * rooted = fd_chunk_to_laddr_const( wksp, m->chunk );
  FD_TEST( rooted->slot==bank->f.slot && fd_hash_eq( &rooted->block_id, &bank->f.block_id ) && rooted->bank_idx==bank->idx );
  FD_TEST( !try_notify_consensus_root( ctx, test_stem ) );
}

static void
test_root_from_votor_cert( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 100UL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_hash_t id2     = { .ul = { 202UL } };
  fd_bank_t * root = setup_rooting_ctx( ctx, wksp, &root_id );
  fd_bank_t * b1   = add_block( ctx, root, 1UL, &id1 );
  fd_bank_t * b2   = add_block( ctx, b1,   2UL, &id2 );

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];

  /* A fast final cert for the replayed tip roots it and its unrooted
     ancestor in one step, and the root hands off exactly as a tower
     root does. */
  deliver_certed( ctx, AG_CERT_KIND_FAST_FINAL, 2UL, &id2 );
  FD_TEST( ctx->votor_final->slot==2UL && ctx->votor_final->kind==AG_CERT_KIND_FAST_FINAL );
  expect_rooted( ctx, wksp, seq0, b2 );
  FD_TEST( mock_sched_root_notify_cnt==1UL );

  /* A cert for an already rooted block roots nothing. */
  deliver_certed( ctx, AG_CERT_KIND_FINAL, 1UL, &id1 );
  FD_TEST( ctx->consensus_root_slot==2UL );
  FD_TEST( ctx->finalized_block_id_lo.slot<=ctx->consensus_root_slot );
  FD_TEST( !try_notify_consensus_root( ctx, test_stem ) );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );

  FD_LOG_NOTICE(( "pass: test_root_from_votor_cert" ));
}

static void
test_ag_rank_is_current( void ) {
  /* Never observed (stamp 0) is delinquent once the watermark passes. */
  FD_TEST(  ag_rank_is_current(   0UL, 0UL ) );
  FD_TEST(  ag_rank_is_current( 127UL, 0UL ) );
  FD_TEST( !ag_rank_is_current( 128UL, 0UL ) );

  /* Agave's boundary: >=128 behind is delinquent. */
  FD_TEST(  ag_rank_is_current( 1000UL, 1000UL ) );  /* distance 0   */
  FD_TEST(  ag_rank_is_current( 1000UL,  873UL ) );  /* distance 127 */
  FD_TEST( !ag_rank_is_current( 1000UL,  872UL ) );  /* distance 128 */

  /* A stamp ahead of the watermark saturates rather than wrapping. */
  FD_TEST( ag_rank_is_current( 100UL, 200UL ) );

  FD_LOG_NOTICE(( "pass: test_ag_rank_is_current" ));
}

static void
test_ag_delinquent_epoch_roll( void ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_memset( ctx, 0, sizeof(fd_replay_tile_t) );
  ctx->ag_last_voted_epoch = ULONG_MAX;

  /* First cert seeds the epoch and watermark. */
  ag_delinquent_epoch_roll( ctx, 1000UL, 5UL );
  FD_TEST( ctx->ag_last_voted_epoch==5UL );
  FD_TEST( ctx->ag_last_settled    ==1000UL );

  /* Same epoch: table and standing figure are left alone, watermark
     rises.  An empty cert must not blank a figure that still holds. */
  ctx->ag_last_voted[ 7 ] = 1000UL;
  ctx->delinquent_known   = 1;
  ag_delinquent_epoch_roll( ctx, 1128UL, 5UL );
  FD_TEST( ctx->ag_last_voted[ 7 ]==1000UL );
  FD_TEST( ctx->ag_last_settled   ==1128UL );
  FD_TEST( ctx->delinquent_known );

  /* Out-of-order replay must not walk the watermark backwards. */
  ag_delinquent_epoch_roll( ctx, 1100UL, 5UL );
  FD_TEST( ctx->ag_last_settled==1128UL );

  /* Epoch rollover clears the table and the known flag: ranks are
     epoch-scoped and would otherwise name different validators. */
  ag_delinquent_epoch_roll( ctx, 2000UL, 6UL );
  FD_TEST( ctx->ag_last_voted[ 7 ]==0UL );
  FD_TEST( ctx->ag_last_settled   ==2000UL );
  FD_TEST( !ctx->delinquent_known );

  /* An older epoch must never drag the watermark back or wipe the
     table, independently of the caller's own guard. */
  ctx->ag_last_voted[ 9 ] = 2100UL;
  ctx->delinquent_known   = 1;
  ag_delinquent_epoch_roll( ctx, 1500UL, 5UL );
  FD_TEST( ctx->ag_last_settled   ==2000UL );
  FD_TEST( ctx->ag_last_voted[ 9 ]==2100UL );
  FD_TEST( ctx->delinquent_known );

  FD_LOG_NOTICE(( "pass: test_ag_delinquent_epoch_roll" ));
}

/* fd_vote_stakes_finalize only ranks accounts whose BLS key
   decompresses, so the fixture needs real G1 points. */

#define TEST_AG_VOTERS (4UL)

static void
test_bls_pubkey( uchar out[ static FD_BLS_PUBKEY_COMPRESSED_SZ ],
                 ulong seed ) {
  uchar ikm[ 32 ] = { 0 };
  FD_STORE( ulong, ikm, seed+1UL );
  fd_bls_sec_t sec;
  fd_bls_sec_derive( &sec, ikm, sizeof(ikm) );
  fd_bls_pub_t pub;
  fd_bls_sec_to_pub( &sec, &pub );
  blst_p1_affine_compress( out, &pub );
}

static ushort
test_vote_rank( fd_vote_stakes_t *  vote_stakes,
                ulong               fork_id,
                fd_pubkey_t const * vote_key ) {
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2, iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2, iter );
       fd_vote_stakes_iter_next( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2, iter ) ) {
    fd_vote_stakes_ele_t ele[1];
    fd_vote_stakes_iter_ele( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2, iter, ele );
    if( fd_pubkey_eq( &ele->pubkey, vote_key ) ) return ele->rank;
  }
  FD_LOG_ERR(( "vote account not found" ));
}

static void
test_ag_update_delinquent( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t   root_id = { .ul = { 100UL } };
  fd_bank_t * bank    = setup_rooting_ctx( ctx, wksp, &root_id );
  ctx->ag_last_voted_epoch = ULONG_MAX;

  static fd_wait_info_box_t box[ 1 ];
  ctx->wait_info = fd_wait_info_box_join( fd_wait_info_box_new( box ) );
  FD_TEST( ctx->wait_info );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ulong              fork_id     = bank->vote_stakes_fork_id;
  ulong              epoch       = fd_vote_stakes_fork_epoch( fork_id );

  /* 100+200+300+400 == 1000 lamports of ranked, valid stake. */
  ulong const stake[ TEST_AG_VOTERS ] = { 100UL, 200UL, 300UL, 400UL };
  fd_pubkey_t vote[ TEST_AG_VOTERS ];
  ushort      rank[ TEST_AG_VOTERS ];
  for( ulong i=0UL; i<TEST_AG_VOTERS; i++ ) {
    vote[ i ]        = (fd_pubkey_t){ .ul = { 1000UL+i } };
    fd_pubkey_t node = (fd_pubkey_t){ .ul = { 2000UL+i } };
    uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
    test_bls_pubkey( bls, i );
    fd_vote_stakes_snap_insert_t_2( vote_stakes, fork_id, &vote[ i ], &node, stake[ i ], 0U, bls, FD_VOTE_DEFAULT_BLOCK_REVENUE_COMMISSION_BPS, 0UL, NULL, NULL, &no_loc );
    fd_vote_stakes_update_state( vote_stakes, fork_id, &vote[ i ], 0UL, 0L, 1 );
  }
  fd_vote_stakes_finalize( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2 );
  for( ulong i=0UL; i<TEST_AG_VOTERS; i++ ) {
    rank[ i ] = test_vote_rank( vote_stakes, fork_id, &vote[ i ] );
    FD_TEST( rank[ i ]!=FD_VOTE_STAKES_ALPENGLOW_RANK_NULL );
  }

  fd_bls_set_t reward_set[ fd_bls_set_word_cnt ];
#define CERT_WITHOUT_VOTER_1() do {                  \
    fd_bls_set_null( reward_set );                   \
    fd_bls_set_insert( reward_set, rank[ 0 ] );      \
    fd_bls_set_insert( reward_set, rank[ 2 ] );      \
    fd_bls_set_insert( reward_set, rank[ 3 ] );      \
  } while(0)

  /* Warmup: a table the roll just cleared names only the signers seen
     since, so a walk would count every other rank delinquent.  Nothing
     is published until a sample window has stamped into it. */
  CERT_WITHOUT_VOTER_1();
  ag_update_delinquent( ctx, bank, 500UL-DELINQUENT_SAMPLE_SLOTS, epoch, reward_set );
  FD_TEST( !ctx->delinquent_known );

  /* First sample: signers are stamped before being tested, so they read
     current immediately and only the absent voter 1 is delinquent. */
  CERT_WITHOUT_VOTER_1();
  ag_update_delinquent( ctx, bank, 500UL, epoch, reward_set );
  FD_TEST( ctx->delinquent_known );
  FD_TEST( ctx->cluster_active_stake_lamports==1000UL );
  FD_TEST( ctx->delinquent_stake_lamports    == 200UL );

  /* Voter 1 shows up and clears on the next sample.  Stamping is per
     block, only the sum below samples. */
  fd_bls_set_insert( reward_set, rank[ 1 ] );
  ag_update_delinquent( ctx, bank, 500UL+DELINQUENT_SAMPLE_SLOTS, epoch, reward_set );
  FD_TEST( !ctx->delinquent_stake_lamports );

  /* Still current 127 behind its stamp... */
  ulong voter_1_stamp = 500UL+DELINQUENT_SAMPLE_SLOTS;
  CERT_WITHOUT_VOTER_1();
  ag_update_delinquent( ctx, bank, voter_1_stamp+DELINQUENT_VALIDATOR_SLOT_DISTANCE-1UL, epoch, reward_set );
  FD_TEST( !ctx->delinquent_stake_lamports );

  /* ...and ages out once the watermark passes it.  The exact boundary
     is test_ag_rank_is_current's; sampling cannot resolve it here. */
  ulong aged_out = voter_1_stamp+DELINQUENT_VALIDATOR_SLOT_DISTANCE-1UL+DELINQUENT_SAMPLE_SLOTS;
  ag_update_delinquent( ctx, bank, aged_out, epoch, reward_set );
  FD_TEST( ctx->delinquent_stake_lamports==200UL );

  /* A vote landing between samples is still recorded: stamping is per
     block.  Were it sampled too, voter 1 would read delinquent below. */
  fd_bls_set_insert( reward_set, rank[ 1 ] );
  ag_update_delinquent( ctx, bank, aged_out+1UL, epoch, reward_set );
  FD_TEST( ctx->delinquent_stake_lamports==200UL ); /* no sample yet */
  CERT_WITHOUT_VOTER_1();
  ag_update_delinquent( ctx, bank, aged_out+DELINQUENT_SAMPLE_SLOTS, epoch, reward_set );
  FD_TEST( !ctx->delinquent_stake_lamports );

  /* Age it out again, so the cases below see a standing figure. */
  ulong all_stamped = aged_out+1UL+DELINQUENT_VALIDATOR_SLOT_DISTANCE;
  ag_update_delinquent( ctx, bank, all_stamped, epoch, reward_set );
  FD_TEST( ctx->delinquent_stake_lamports==200UL );

  /* An empty cert stamps nothing, so while the others are still current
     the figure is unchanged. */
  fd_bls_set_null( reward_set );
  ag_update_delinquent( ctx, bank, 900UL, epoch, reward_set );
  FD_TEST( ctx->delinquent_known );
  FD_TEST( ctx->delinquent_stake_lamports==200UL );

  /* A cert whose epoch the t-2 set does not address is ignored. */
  fd_bls_set_null( reward_set );
  fd_bls_set_insert( reward_set, rank[ 1 ] );
  ag_update_delinquent( ctx, bank, 901UL, epoch+1UL, reward_set );
  FD_TEST( ctx->delinquent_stake_lamports==200UL );

  /* But a run of empty certs must not freeze the figure: the watermark
     keeps advancing, so the stamps age out and everyone reads
     delinquent. */
  fd_bls_set_null( reward_set );
  ag_update_delinquent( ctx, bank, all_stamped+DELINQUENT_VALIDATOR_SLOT_DISTANCE, epoch, reward_set );
  FD_TEST( ctx->delinquent_stake_lamports==1000UL );

  /* The bank rolls into the next epoch FD_NUM_SLOTS_FOR_REWARD slots
     before the certs do: the previous epoch's figure must go unknown
     right away, not stay published against the new stake set. */
  bank->vote_stakes_fork_id       = fd_vote_stakes_new_fork( vote_stakes, fork_id, epoch+1UL );
  ctx->ag_last_voted[ rank[ 0 ] ] = 900UL;
  ctx->delinquent_known           = 1;
  CERT_WITHOUT_VOTER_1();
  ag_update_delinquent( ctx, bank, 903UL, epoch, reward_set );
  FD_TEST( !ctx->delinquent_known             );
  FD_TEST( !ctx->ag_last_voted[ rank[ 0 ] ]   );
  FD_TEST( ctx->ag_last_voted_epoch==epoch+1UL );

  /* No wait_info consumer (backtest): the walk is skipped
     rather than run for nothing. */
  ctx->wait_info                         = NULL;
  ctx->delinquent_stake_lamports = 0UL;
  CERT_WITHOUT_VOTER_1();
  ag_update_delinquent( ctx, bank, 902UL, epoch, reward_set );
  FD_TEST( !ctx->delinquent_stake_lamports );

#undef CERT_WITHOUT_VOTER_1
  FD_LOG_NOTICE(( "pass: test_ag_update_delinquent" ));
}

#undef TEST_AG_VOTERS

static void
test_root_waits_for_replay( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 100UL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_hash_t id2     = { .ul = { 202UL } };
  fd_hash_t id3     = { .ul = { 203UL } };
  fd_bank_t * root = setup_rooting_ctx( ctx, wksp, &root_id );
  fd_bank_t * b1   = add_block( ctx, root, 1UL, &id1 );

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];

  /* Finalized ahead of replay: cached, nothing rooted. */
  deliver_certed( ctx, AG_CERT_KIND_FINAL, 2UL, &id2 );
  FD_TEST( ctx->finalized_block_id_lo.slot==2UL && !memcmp( ctx->finalized_block_id_lo.hash, id2.uc, sizeof(fd_hash_t) ) );
  FD_TEST( ctx->finalized_block_id_hi.slot<=ctx->consensus_root_slot );
  FD_TEST( ctx->consensus_root_slot==0UL );
  FD_TEST( !try_notify_consensus_root( ctx, test_stem ) );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0 );

  /* Its slot completing roots it, and the ancestor replay got to first.
     Balance metrics follow the deferred root. */
  fd_bank_t * b2 = add_block( ctx, b1, 2UL, &id2 );
  b2->f.total_epoch_stake = 4242UL;
  FD_MGAUGE_SET( REPLAY, CLUSTER_ACTIVE_STAKE_LAMPORTS, 0UL );
  try_advance_root_ag( ctx, ctx->finalized_block_id_lo );
  expect_rooted( ctx, wksp, seq0, b2 );
  FD_TEST( FD_MGAUGE_GET( REPLAY, CLUSTER_ACTIVE_STAKE_LAMPORTS )==4242UL );

  /* A finalization of a block replay already completed roots at once. */
  fd_bank_t * b3 = add_block( ctx, b2, 3UL, &id3 );
  deliver_certed( ctx, AG_CERT_KIND_FAST_FINAL, 3UL, &id3 );
  expect_rooted( ctx, wksp, seq0+1UL, b3 );

  FD_LOG_NOTICE(( "pass: test_root_waits_for_replay" ));
}

static void
test_root_out_of_order_certs( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 100UL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_hash_t id2     = { .ul = { 202UL } };
  fd_hash_t id3     = { .ul = { 203UL } };
  fd_bank_t * root = setup_rooting_ctx( ctx, wksp, &root_id );
  fd_bank_t * b1   = add_block( ctx, root, 1UL, &id1 );

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];

  /* Newer finality replaces the pending block, but an older cert
     arriving afterwards must not discard it.  Both await replay. */
  deliver_certed( ctx, AG_CERT_KIND_FINAL, 2UL, &id2 );
  deliver_certed( ctx, AG_CERT_KIND_FAST_FINAL, 3UL, &id3 );
  FD_TEST( ctx->finalized_block_id_lo.slot==2UL && !memcmp( ctx->finalized_block_id_lo.hash, id2.uc, sizeof(fd_hash_t) ) );
  FD_TEST( ctx->finalized_block_id_hi.slot==3UL && !memcmp( ctx->finalized_block_id_hi.hash, id3.uc, sizeof(fd_hash_t) ) );
  deliver_certed( ctx, AG_CERT_KIND_FAST_FINAL, 2UL, &id2 );
  FD_TEST( ctx->finalized_block_id_lo.slot==2UL && !memcmp( ctx->finalized_block_id_lo.hash, id2.uc, sizeof(fd_hash_t) ) );
  FD_TEST( ctx->finalized_block_id_hi.slot==3UL && !memcmp( ctx->finalized_block_id_hi.hash, id3.uc, sizeof(fd_hash_t) ) );
  FD_TEST( ctx->consensus_root_slot==0UL );
  FD_TEST( !try_notify_consensus_root( ctx, test_stem ) );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0 );

  /* An older cert can still advance root once its block is replayed;
     the newer block waiting for replay becomes the next target. */
  fd_bank_t * b2 = add_block( ctx, b1, 2UL, &id2 );
  deliver_certed( ctx, AG_CERT_KIND_FINAL, 2UL, &id2 );
  expect_rooted( ctx, wksp, seq0, b2 );
  FD_TEST( ctx->finalized_block_id_hi.slot==3UL && !memcmp( ctx->finalized_block_id_hi.hash, id3.uc, sizeof(fd_hash_t) ) );

  /* Certs below and at the current root must leave the pending block
     intact and publish no additional root notification. */
  deliver_certed( ctx, AG_CERT_KIND_FINAL, 1UL, &id1 );
  FD_TEST( ctx->finalized_block_id_hi.slot==3UL && !memcmp( ctx->finalized_block_id_hi.hash, id3.uc, sizeof(fd_hash_t) ) );
  deliver_certed( ctx, AG_CERT_KIND_FAST_FINAL, 2UL, &id2 );
  FD_TEST( ctx->finalized_block_id_hi.slot==3UL && !memcmp( ctx->finalized_block_id_hi.hash, id3.uc, sizeof(fd_hash_t) ) );
  FD_TEST( ctx->consensus_root_slot==2UL && fd_hash_eq( &ctx->consensus_root, &id2 ) );
  FD_TEST( !try_notify_consensus_root( ctx, test_stem ) );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+1UL );

  /* Replay catches up using the retained finality, without another cert. */
  fd_bank_t * b3 = add_block( ctx, b2, 3UL, &id3 );
  try_advance_root_ag( ctx, ctx->finalized_block_id_hi );
  expect_rooted( ctx, wksp, seq0+1UL, b3 );
  FD_TEST( mock_sched_root_notify_cnt==2UL );

  FD_LOG_NOTICE(( "pass: test_root_out_of_order_certs" ));
}

static void
test_root_lagging_replay( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 100UL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_hash_t id2     = { .ul = { 202UL } };
  fd_hash_t id3     = { .ul = { 203UL } };
  fd_bank_t * root = setup_rooting_ctx( ctx, wksp, &root_id );
  fd_bank_t * b1   = add_block( ctx, root, 1UL, &id1 );

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];

  /* Finality runs ahead of replay: the oldest pending finalization is
     held in lo, so reaching it roots without catching the newest. */
  deliver_certed( ctx, AG_CERT_KIND_FINAL,      2UL, &id2 );
  deliver_certed( ctx, AG_CERT_KIND_FAST_FINAL, 3UL, &id3 );
  FD_TEST( ctx->finalized_block_id_lo.slot==2UL && ctx->finalized_block_id_hi.slot==3UL );

  fd_bank_t * b2 = add_block( ctx, b1, 2UL, &id2 );
  try_advance_root_ag( ctx, ctx->finalized_block_id_lo );
  expect_rooted( ctx, wksp, seq0, b2 );

  fd_bank_t * b3 = add_block( ctx, b2, 3UL, &id3 );
  try_advance_root_ag( ctx, ctx->finalized_block_id_hi );
  expect_rooted( ctx, wksp, seq0+1UL, b3 );
  FD_TEST( mock_sched_root_notify_cnt==2UL );

  FD_LOG_NOTICE(( "pass: test_root_lagging_replay" ));
}

static void
test_root_newer_first( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 100UL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_hash_t id2     = { .ul = { 202UL } };
  fd_hash_t id3     = { .ul = { 203UL } };
  fd_bank_t * root = setup_rooting_ctx( ctx, wksp, &root_id );
  fd_bank_t * b1   = add_block( ctx, root, 1UL, &id1 );

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];

  /* The newer finalization arrives first: the older one still becomes
     lo, the newer moves to hi, and replay roots them in slot order. */
  deliver_certed( ctx, AG_CERT_KIND_FAST_FINAL, 3UL, &id3 );
  deliver_certed( ctx, AG_CERT_KIND_FINAL,      2UL, &id2 );
  FD_TEST( ctx->finalized_block_id_lo.slot==2UL && !memcmp( ctx->finalized_block_id_lo.hash, id2.uc, sizeof(fd_hash_t) ) );
  FD_TEST( ctx->finalized_block_id_hi.slot==3UL && !memcmp( ctx->finalized_block_id_hi.hash, id3.uc, sizeof(fd_hash_t) ) );

  fd_bank_t * b2 = add_block( ctx, b1, 2UL, &id2 );
  try_advance_root_ag( ctx, ctx->finalized_block_id_lo );
  expect_rooted( ctx, wksp, seq0, b2 );

  fd_bank_t * b3 = add_block( ctx, b2, 3UL, &id3 );
  try_advance_root_ag( ctx, ctx->finalized_block_id_hi );
  expect_rooted( ctx, wksp, seq0+1UL, b3 );
  FD_TEST( mock_sched_root_notify_cnt==2UL );

  FD_LOG_NOTICE(( "pass: test_root_newer_first" ));
}

static void
test_root_from_footer( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 100UL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_hash_t id2     = { .ul = { 202UL } };
  fd_hash_t id3     = { .ul = { 203UL } };
  fd_bank_t * root = setup_rooting_ctx( ctx, wksp, &root_id );
  fd_blockhashes_init( &root->f.block_hash_queue, 42UL );
  FD_TEST( fd_blockhashes_push_new( &root->f.block_hash_queue, &root_id ) );

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];

  mock_footer_finalize = 1;
  memset( mock_footer, 0, sizeof(fd_block_footer_t) );

  /* A footer without a finalization cert completes replay but roots nothing. */
  fd_bank_t * b1 = add_replayable_block( ctx, root, 1UL, &id1 );
  FD_TEST( !replay_block_finalize( ctx, test_stem, b1 ) );
  FD_TEST( b1->state==FD_BANK_STATE_FROZEN );
  FD_TEST( ctx->consensus_root_slot==0UL && ctx->finalized_block_id_lo.slot<=ctx->consensus_root_slot );
  FD_TEST( !try_notify_consensus_root( ctx, test_stem ) );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+2UL );

  /* A slow final cert names its slot; the notar cert beside it names
     the block.  Completing slot 2 roots slot 1 without a votor frag. */
  mock_footer->has_final_cert      = 1;
  mock_footer->final_cert.slot     = 1UL;
  mock_footer->notar_cert.slot     = 1UL;
  mock_footer->notar_cert.block_id = id1;
  fd_bank_t * b2 = add_replayable_block( ctx, b1, 2UL, &id2 );
  FD_TEST( !replay_block_finalize( ctx, test_stem, b2 ) );
  fd_frag_meta_t const * m = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( seq0+2UL, test_stem_depths[ out_idx ] );
  FD_TEST( m->sig==REPLAY_SIG_SLOT_COMPLETED );
  fd_replay_slot_completed_t const * completed = fd_chunk_to_laddr_const( wksp, m->chunk );
  FD_TEST( completed->footer.has_final_cert && completed->footer.final_cert.slot==1UL && fd_hash_eq( &completed->footer.notar_cert.block_id, &id1 ) );
  expect_rooted( ctx, wksp, seq0+4UL, b1 );

  /* A fast final cert names its block, and wins over a slow cert beside it. */
  mock_footer->has_fast_final_cert      = 1;
  mock_footer->fast_final_cert.slot     = 2UL;
  mock_footer->fast_final_cert.block_id = id2;
  fd_bank_t * b3 = add_replayable_block( ctx, b2, 3UL, &id3 );
  FD_TEST( !replay_block_finalize( ctx, test_stem, b3 ) );
  expect_rooted( ctx, wksp, seq0+7UL, b2 );
  FD_TEST( ctx->votor_final->slot==ULONG_MAX );
  mock_footer_finalize = 0;

  FD_LOG_NOTICE(( "pass: test_root_from_footer" ));
}

/* test_footer_cert_tasks drives replay_block_finalize with real signed
   footer certs and mocked idle exec tiles.  Claimed tiles get one
   CERT_VERIFY frag each and the bank stays REPLAYABLE until every done
   frag is in, then try_replay freezes and publishes it.  A failed cert
   (on a tile or inline) marks it dead BAD_FOOTER and later done frags
   only drain.  No idle tile or capture on: inline, frozen at once. */

#define CERT_TEST_VAL_CNT (4UL)
#define CERT_TEST_SV      ((ushort)4242)

static fd_bls_sec_t cert_test_sk[ CERT_TEST_VAL_CNT ]; /* by rank */

static void
cert_test_sign( fd_block_footer_cert_t * cert,
                ulong                    slot,
                fd_hash_t const *        bid ) {
  blst_scalar sum = { 0 };
  for( ulong r=0UL; r<CERT_TEST_VAL_CNT; r++ ) blst_sk_add_n_check( &sum, &sum, cert_test_sk+r );
  uchar msg[ AG_VOTE_SIGNING_SER_MAX ];
  ulong sz = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR, slot, bid->uc, CERT_TEST_SV, msg );
  fd_bls_agg_t agg[1]; fd_bls_agg_null( agg );
  fd_bls_sig_t sig[1]; fd_bls_sec_sign( &sum, msg, sz, sig );
  blst_p2_from_affine( &agg->sig, sig );
  for( ulong r=0UL; r<CERT_TEST_VAL_CNT; r++ ) fd_bls_set_insert( agg->set, r );
  FD_TEST( fd_block_footer_cert_from_agg( cert, slot, bid->uc, agg ) );
}

static void
test_footer_cert_tasks( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 100UL } };
  fd_bank_t * root = setup_rooting_ctx( ctx, wksp, &root_id );
  fd_blockhashes_init( &root->f.block_hash_queue, 42UL );
  FD_TEST( fd_blockhashes_push_new( &root->f.block_hash_queue, &root_id ) );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( root );
  ulong              fork_id     = root->vote_stakes_fork_id;
  fd_pubkey_t        vote[ CERT_TEST_VAL_CNT ];
  for( ulong i=0UL; i<CERT_TEST_VAL_CNT; i++ ) {
    vote[ i ]        = (fd_pubkey_t){ .ul = { 3000UL+i } };
    fd_pubkey_t node = (fd_pubkey_t){ .ul = { 4000UL+i } };
    uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
    test_bls_pubkey( bls, 10UL+i );
    fd_vote_stakes_snap_insert_t_2( vote_stakes, fork_id, &vote[ i ], &node, 100UL*(i+1UL), 0U, bls, FD_VOTE_DEFAULT_BLOCK_REVENUE_COMMISSION_BPS, 0UL, NULL, NULL, &no_loc );
  }
  fd_vote_stakes_finalize( vote_stakes, fork_id, FD_VOTE_STAKES_ITER_T_2 );
  for( ulong i=0UL; i<CERT_TEST_VAL_CNT; i++ ) {
    ushort rank = test_vote_rank( vote_stakes, fork_id, &vote[ i ] );
    FD_TEST( rank<CERT_TEST_VAL_CNT );
    uchar ikm[ 32 ] = { 0 };
    FD_STORE( ulong, ikm, 10UL+i+1UL );
    fd_bls_sec_derive( cert_test_sk+rank, ikm, sizeof(ikm) );
  }

  ctx->exec_out[ 1 ] = *ctx->rotor_out; /* spare test link */
  ctx->exec_cnt      = 2UL;
  ctx->is_booted     = 1;
  ctx->shred_version = CERT_TEST_SV;
  void * cache_mem = fd_wksp_alloc_laddr( wksp, FD_FOOTER_CACHE_ALIGN, fd_footer_cache_footprint(), 1UL );
  FD_TEST( cache_mem );
  ctx->footer_cache = fd_footer_cache_join( fd_footer_cache_new( cache_mem ) );

  mock_footer_finalize = 1;
  mock_footer_verify   = 1;
  fd_hash_t ids[ 16 ];
  for( ulong i=0UL; i<16UL; i++ ) ids[ i ] = (fd_hash_t){ .ul = { 300UL+i } };

  fd_bank_t * parent  = root;
  ulong       slot    = 1UL;
  ulong       hm_cnt  = 0UL;
  ulong       out_idx = ctx->replay_out->idx;
  /* mode 0 two tiles, 1 one tile (one cert inline), 2 no idle tile,
     3 capture on, 4 two tiles and a footer bank hash mismatch */
  for( ulong mode=0UL; mode<5UL; mode++ ) {
    for( ulong bad=0UL; bad<2UL; bad++ ) {
      memset( mock_footer, 0, sizeof(fd_block_footer_t) );
      mock_footer->has_fast_final_cert   = 1;
      mock_footer->has_notar_reward_cert = 1;
      cert_test_sign( &mock_footer->fast_final_cert,   parent->f.slot, &parent->f.block_id );
      cert_test_sign( &mock_footer->notar_reward_cert, parent->f.slot, &parent->f.block_id );
      if( bad ) mock_footer->notar_reward_cert.slot = slot; /* signed another slot */
      int hash_bad = mode==4UL;

      fd_bank_t * b = add_replayable_block( ctx, parent, slot, ids+slot );
      mock_footer->bank_hash = b->f.bank_hash; /* the mocked finalize keeps it */
      if( hash_bad ) mock_footer->bank_hash.ul[ 0 ] ^= 1UL;
      static fd_capture_ctx_t cap[1];
      mock_cert_tiles  = mode==1UL ? 2UL : mode==2UL ? 0UL : 3UL;
      ctx->capture_ctx = mode==3UL ? cap : NULL;
      ulong refcnt0    = b->refcnt;
      ulong seq0[ 2 ]  = { test_stem_seqs[ ctx->exec_out[ 0 ].idx ], test_stem_seqs[ ctx->exec_out[ 1 ].idx ] };
      ulong done0      = test_stem_seqs[ out_idx ];
      int   dead       = replay_block_finalize( ctx, test_stem, b );

      ulong frag_cnt   = mode==0UL || mode==4UL ? 2UL : mode==1UL ? 1UL : 0UL;
      int   inline_bad = bad && frag_cnt!=2UL; /* the bad cert verifies on replay */
      int   dead_end   = bad || hash_bad;
      FD_TEST( dead==inline_bad );
      FD_TEST( b->cert_task_cnt==frag_cnt );
      FD_TEST( b->refcnt==refcnt0+frag_cnt );
      if( !frag_cnt ) {
        FD_TEST( b->state==( dead_end ? FD_BANK_STATE_DEAD : FD_BANK_STATE_FROZEN ) );
      } else if( !inline_bad ) {
        FD_TEST( b->state==FD_BANK_STATE_REPLAYABLE );
        FD_TEST( test_stem_seqs[ out_idx ]==done0 ); /* no slot_completed or slot_dead (with footer) yet */
      }

      /* the exec tiles: verify each frag, answer with a done frag */
      ulong k = 0UL;
      for( ulong t=0UL; t<2UL; t++ ) {
        ulong exec_idx = ctx->exec_out[ t ].idx;
        for( ulong seq=seq0[ t ]; seq<test_stem_seqs[ exec_idx ]; seq++, k++ ) {
          fd_frag_meta_t const * m = test_stem_mcaches[ exec_idx ] + fd_mcache_line_idx( seq, test_stem_depths[ exec_idx ] );
          FD_TEST( m->sig==((FD_EXECRP_TT_CERT_VERIFY<<32) | t) );
          fd_execrp_cert_verify_msg_t const * msg = fd_chunk_to_laddr_const( wksp, m->chunk );
          FD_TEST( msg->bank_idx==b->idx && msg->shred_version==CERT_TEST_SV );
          if( msg->has_hm ) { /* from replay's memo: the payload's H(m) */
            uchar pl[ FD_ALPENGLOW_CERT_PAYLOAD_MAX ]; blst_p2_affine h[1];
            fd_bls_hash_msg( pl, fd_alpenglow_cert_payload( msg->cert, msg->tag, msg->shred_version, pl ), h );
            FD_TEST( blst_p2_affine_is_equal( h, &msg->hm ) );
            hm_cnt++;
          }
          fd_execrp_task_done_msg_t done[1];
          done->bank_idx         = b->idx;
          done->cert_verify->err = !!fd_alpenglow_cert_verify( b, msg->cert, msg->tag, msg->quorum, msg->shred_version, NULL, msg->has_hm ? &msg->hm : NULL, &done->cert_verify->hm );
          done->cert_verify->has_hm = !msg->has_hm && !done->cert_verify->err;
          FD_TEST( done->cert_verify->err==( bad && k==1UL ) );
          ulong task_done0 = mock_sched_task_done_cnt;
          process_exec_task_done( ctx, test_stem, done, (FD_EXECRP_TT_CERT_VERIFY<<32) | t );
          if( done->cert_verify->has_hm ) { /* the tile's H(m) is now in replay's memo */
            uchar pl[ FD_ALPENGLOW_CERT_PAYLOAD_MAX ];
            ulong pl_sz = fd_alpenglow_cert_payload( msg->cert, msg->tag, msg->shred_version, pl );
            blst_p2_affine const * h = fd_footer_cache_hash_query( ctx->footer_cache, pl, pl_sz );
            FD_TEST( h && blst_p2_affine_is_equal( h, &done->cert_verify->hm ) );
          }
          FD_TEST( mock_sched_task_done_cnt==task_done0+1UL && mock_sched_task_done_type==FD_SCHED_TT_CERT_VERIFY && mock_sched_task_done_exec_idx==t );
          if( bad && k==1UL ) FD_TEST( b->state==FD_BANK_STATE_DEAD );
        }
      }
      FD_TEST( k==frag_cnt && !b->cert_task_cnt );
      FD_TEST( b->state==( dead_end ? FD_BANK_STATE_DEAD : FD_BANK_STATE_FROZEN ) ); /* completed on the last done frag */
      FD_TEST( b->refcnt==refcnt0 );
      if( !dead_end ) {
        fd_frag_meta_t const * m = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( test_stem_seqs[ out_idx ]-2UL, test_stem_depths[ out_idx ] );
        FD_TEST( m->sig==REPLAY_SIG_SLOT_COMPLETED );
        parent = b;
      }
      slot++;
      fd_banks_prune_cancel_info_t cancel[1];
      if( dead_end ) FD_TEST( fd_banks_prune_one_bank( ctx->banks, cancel ) );
    }
  }
  FD_TEST( hm_cnt ); /* earlier certs seeded the memo for later posts */
  ctx->capture_ctx     = NULL;
  mock_cert_tiles      = 0UL;
  mock_footer_finalize = 0;
  mock_footer_verify   = 0;
  FD_LOG_NOTICE(( "pass: test_footer_cert_tasks" ));
}

static void
test_slot_completed_keeps_leader_sentinel( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 100UL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_bank_t * root = setup_rooting_ctx( ctx, wksp, &root_id );
  fd_blockhashes_init( &root->f.block_hash_queue, 42UL );
  FD_TEST( fd_blockhashes_push_new( &root->f.block_hash_queue, &root_id ) );

  mock_footer_finalize = 1;
  memset( mock_footer, 0, sizeof(fd_block_footer_t) );

  /* What the leader schedule would hand back if it were consulted. */
  mock_next_leader_slot = 777UL;
  ctx->next_leader_slot = ULONG_MAX;

  fd_bank_t * b1 = add_replayable_block( ctx, root, 1UL, &id1 );
  FD_TEST( !replay_block_finalize( ctx, test_stem, b1 ) );
  FD_TEST( b1->state==FD_BANK_STATE_FROZEN );

  /* Completing a slot under Alpenglow must not disturb
     next_leader_slot: try_fini_leader uses ULONG_MAX to continue the
     leader window. */
  FD_TEST( ctx->next_leader_slot==ULONG_MAX );

  /* The epoch info the wait command reads is still refreshed. */
  FD_TEST( ctx->reset_slot==1UL       );
  FD_TEST( ctx->slots_per_epoch==128UL );
  FD_TEST( ctx->epoch_end_slot==127UL  );

  /* Under warmup the current epoch is short, but wait tests the gap it
     was asked for against the length the epochs grow to. */
  fd_epoch_schedule_derive( &b1->f.epoch_schedule, 128UL, 128UL, 1 );
  refresh_epoch_info( ctx, b1, 1UL );
  FD_TEST( ctx->slots_per_epoch==128UL );
  FD_TEST( ctx->epoch_end_slot ==31UL  );

  mock_footer_finalize = 0;
  FD_LOG_NOTICE(( "pass: test_slot_completed_keeps_leader_sentinel" ));
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
   the entire ancestry path from the rotor root, but most of those
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

  fd_hash_t mr_root = { .ul = { 100 } };
  init_root( ctx, &mr_root );

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

  fd_hash_t mr_root = { .ul = { 100 } };
  init_root( ctx, &mr_root );

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
   re-delivering from the rotor root down; the root bank is the
   (non-evictable) published root, so its direct child's FEC 0 is always
   OK -- which is what the OK step below demonstrates. */
static void
test_drain_rotor_fecs_skip_wait_reentry( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );

  fd_hash_t mr_root = { .ul = { 100 } };
  init_root( ctx, &mr_root );

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

/* setup_ag_root registers the root bank as a resolvable parent keyed
   {0, parent_bid}, frozen, so a FEC 0 naming that parent passes the
   parent checks. */

static void
setup_ag_root( fd_replay_tile_t * ctx,
               fd_hash_t const *  parent_bid ) {
  fd_hash_t mr_root = { .ul = { 100 } };
  init_root( ctx, &mr_root );

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
  setup_ag_root( ctx, &parent_bid );

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

/* test_rotor_fec_rooted_past: a redelivered FEC of a slot at or below
   the published root, or of a block whose parent is below it, is SKIPped:
   no MISSING_FEC and no drain, so a redelivery that lands behind a
   catch-up backlog cannot ask for another.  A FEC above the root whose
   parent is missing still DROPs. */

static void
test_rotor_fec_rooted_past( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_hash_t parent_bid = { .ul = { 0xBEEFUL } };
  setup_ag_root( ctx, &parent_bid );
  ctx->published_root_slot = 10UL;

  ulong     out_idx = ctx->replay_out->idx;
  ulong     seq0    = test_stem_seqs[ out_idx ];
  ulong     ing0    = mock_sched_fec_ingest_cnt;
  fd_hash_t gone    = { .ul = { 0xDEADUL } };
  fd_hash_t mr      = { .ul = { 701 } };

  FD_TEST( deliver_rotor_fec( ctx,  9UL, 0U,               8UL, &gone, &mr, 0, 0 )==0 ); /* below the root */
  FD_TEST( deliver_rotor_fec( ctx, 10UL, FD_FEC_SHRED_CNT, 9UL, &gone, &mr, 0, 0 )==0 ); /* the root, mid-slot */
  FD_TEST( deliver_rotor_fec( ctx, 12UL, 0U,               9UL, &gone, &mr, 0, 0 )==0 ); /* parent below the root */
  FD_TEST( deliver_rotor_fec( ctx, 12UL, FD_FEC_SHRED_CNT, 9UL, &gone, &mr, 0, 0 )==0 ); /* its next FEC, no bank */
  FD_TEST( ctx->drain_rotor_fecs==0 && test_stem_seqs[ out_idx ]==seq0 );
  FD_TEST( ctx->metrics.fec_rooted_past==4UL && mock_sched_fec_ingest_cnt==ing0 );

  FD_TEST( deliver_rotor_fec( ctx, 12UL, 0U, 11UL, &gone, &mr, 0, 0 )==0 );              /* missing parent above it */
  FD_TEST( ctx->drain_rotor_fecs==1 && test_stem_seqs[ out_idx ]==seq0+1UL );
  FD_TEST( replay_out_sig( ctx, seq0 )==REPLAY_SIG_MISSING_FEC );

  FD_LOG_NOTICE(( "pass: test_rotor_fec_rooted_past" ));
}

/* test_rotor_fec_merged_copies: rotor delivers a turbine copy (known_id
   0) and a repaired copy (known_id 1) of block B, then merges them into
   the turbine copy, which keeps known_id 0 and continues from its own
   consumed count, carrying B (see dedup in fd_rotor.c).  Whichever copy
   was ahead at the merge, the turbine copy's bank completes, takes
   {5, B}, and a child attaches to it.  In particular a turbine FEC that
   finds the repaired copy's incomplete bank under {5, B} is not
   SKIPped against it: that bank is a different stream, and treating
   it as this copy's progress stranded the block. */

static void
rotor_fec_merged_copies( fd_wksp_t * wksp,
                         uint        n_cnt,     /* FEC sets the repaired copy delivered before the merge */
                         uint        e_cnt ) {  /* FEC sets the turbine copy delivered before the merge */
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  fd_hash_t parent_bid = { .ul = { 0xBEEFUL } };
  setup_ag_root( ctx, &parent_bid );

  fd_hash_t     B      = { .ul = { 0x5150UL } }, zero = {0};
  fd_hash_t     mr[3]  = { { .ul = { 501 } }, { .ul = { 502 } }, { .ul = { 503 } } };
  ag_block_id_t key_id = ag_block_id( 5UL, B.uc );
  ulong         out_idx = ctx->replay_out->idx;
  ulong         seq0    = test_stem_seqs[ out_idx ];

  for( uint k=0U; k<3U; k++ ) {
    if( k<e_cnt ) FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, k*FD_FEC_SHRED_CNT, 0UL, &parent_bid, &zero, &mr[ k ], 0, 0 )==0 );
    if( k<n_cnt ) FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, k*FD_FEC_SHRED_CNT, 0UL, &parent_bid, &B,    &mr[ k ], 0, 1 )==0 );
  }
  for( uint k=e_cnt; k<3U; k++ ) FD_TEST( deliver_rotor_fec_bid( ctx, 5UL, k*FD_FEC_SHRED_CNT, 0UL, &parent_bid, &B, &mr[ k ], k==2U, 0 )==0 );

  fd_block_id_ele_t * ele = fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key_id, NULL, ctx->block_id_arr );
  FD_TEST( ele && ele->block_id_seen && ele->latest_fec_idx==2U*FD_FEC_SHRED_CNT );
  FD_TEST( ctx->drain_rotor_fecs==0 && test_stem_seqs[ out_idx ]==seq0 );

  fd_hash_t mr6  = { .ul = { 601 } };
  ulong     ing0 = mock_sched_fec_ingest_cnt;
  FD_TEST( deliver_rotor_fec( ctx, 6UL, 0U, 5UL, &B, &mr6, 0, 0 )==0 );
  FD_TEST( mock_sched_fec_ingest_cnt==ing0+1UL );
  FD_TEST( ctx->drain_rotor_fecs==0 );
}

static void
test_rotor_fec_merged_copies( fd_wksp_t * wksp ) {
  rotor_fec_merged_copies( wksp, 1U, 0U ); fd_wksp_reset( wksp, 42U ); /* repaired copy ahead */
  rotor_fec_merged_copies( wksp, 2U, 0U ); fd_wksp_reset( wksp, 42U ); /* repaired copy further ahead */
  rotor_fec_merged_copies( wksp, 1U, 1U ); fd_wksp_reset( wksp, 42U ); /* tie */
  rotor_fec_merged_copies( wksp, 1U, 2U ); fd_wksp_reset( wksp, 42U ); /* turbine copy ahead */
  rotor_fec_merged_copies( wksp, 0U, 2U );                              /* repaired copy delivered nothing */
  FD_LOG_NOTICE(( "pass: test_rotor_fec_merged_copies" ));
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
  setup_ag_root( ctx, &parent_bid );

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
  mark_bank_dead( ctx, test_stem, idx5, FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_BAD_FOOTER, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED, NULL );
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
  setup_ag_root( ctx, &parent_bid );
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
    mark_bank_dead( ctx, test_stem, idx, FD_EVENT_BLOCK_COMPLETED_DEAD_REASON_BAD_FOOTER, FD_EVENT_BLOCK_COMPLETED_ABANDONED_REASON_NOT_ABANDONED, NULL );
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

static void
test_identity_switch_quiesces_replay( fd_wksp_t * wksp ) {
  static fd_replay_tile_t   ctx[1];
  static fd_keyswitch_t     keyswitch[1];
  static fd_node_info_box_t node_info[1];

  setup_ctx( ctx, wksp );
  memset( keyswitch, 0, sizeof(keyswitch) );
  FD_TEST( fd_node_info_box_join( fd_node_info_box_new( node_info ) ) );
  void * vote_tracker_mem = fd_wksp_alloc_laddr( wksp, fd_vote_tracker_align(), fd_vote_tracker_footprint(), 1UL );
  FD_TEST( vote_tracker_mem );
  ctx->vote_tracker = fd_vote_tracker_join( fd_vote_tracker_new( vote_tracker_mem, 0UL ) );
  FD_TEST( ctx->vote_tracker );

  fd_pubkey_t old_identity = { .ul = { 0x11UL } };
  fd_pubkey_t new_identity = { .ul = { 0x22UL } };

  ctx->keyswitch          = keyswitch;
  ctx->node_info          = node_info;
  ctx->identity_pubkey[0] = old_identity;
  keyswitch->result       = ULONG_MAX;
  memcpy( keyswitch->bytes, &new_identity, sizeof(new_identity) );
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );

  ulong slot_out_idx = ctx->slot_out->idx;
  fd_mcache_seq_update( fd_mcache_seq_laddr( test_stem_mcaches[ slot_out_idx ] ), 40UL );
  ctx->slot_out_seq = fd_mcache_seq_laddr_const( test_stem_mcaches[ slot_out_idx ] );
  ctx->is_booted = 0;

  during_housekeeping( ctx );
  FD_TEST( fd_keyswitch_state_query( keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  FD_TEST( fd_pubkey_eq( ctx->identity_pubkey, &old_identity ) );

  ctx->is_booted = 1;
  ctx->is_leader = 1;
  fd_mcache_seq_update( fd_mcache_seq_laddr( test_stem_mcaches[ slot_out_idx ] ), 41UL );
  during_housekeeping( ctx );
  FD_TEST( fd_keyswitch_state_query( keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  FD_TEST( keyswitch->result==ULONG_MAX );
  FD_TEST( fd_pubkey_eq( ctx->identity_pubkey, &old_identity ) );

  ctx->is_leader = 0;
  fd_mcache_seq_update( fd_mcache_seq_laddr( test_stem_mcaches[ slot_out_idx ] ), 42UL );
  during_housekeeping( ctx );
  FD_TEST( ctx->halt_replay );
  FD_TEST( fd_keyswitch_state_query( keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( keyswitch->result==42UL );
  FD_TEST( fd_pubkey_eq( ctx->identity_pubkey, &new_identity ) );

  ulong idle_cnt = ctx->execrp_idle_cnt;
  int poll_in = 1;
  int charge_busy = 0;
  after_credit( ctx, test_stem, &poll_in, &charge_busy );
  FD_TEST( ctx->execrp_idle_cnt==idle_cnt );
  FD_TEST( poll_in );
  FD_TEST( !charge_busy );

  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  during_housekeeping( ctx );
  FD_TEST( !ctx->halt_replay );
  FD_TEST( fd_keyswitch_state_query( keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );

  FD_LOG_NOTICE(( "pass: test_identity_switch_quiesces_replay" ));
}

/* Votor switches identity after replay does, so a ParentReady it
   published for the old identity can survive the switch.  Once
   unhalted, replay leads that slot only if the new identity is still
   its scheduled leader. */

static void
test_ag_set_identity_leader_slot( fd_wksp_t * wksp,
                                  int         same_identity ) {
  static fd_replay_tile_t ctx[ 1 ];
  setup_ctx( ctx, wksp );
  setup_node_info( ctx );
  fd_hash_t parent_bid = { .ul = { 0xBEEFUL } };
  setup_ag_root( ctx, &parent_bid );

  static fd_keyswitch_t keyswitch[ 1 ];
  ctx->keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx->keyswitch );
  void * vote_tracker_mem = fd_wksp_alloc_laddr( wksp, fd_vote_tracker_align(), fd_vote_tracker_footprint(), 1UL );
  FD_TEST( vote_tracker_mem );
  ctx->vote_tracker = fd_vote_tracker_join( fd_vote_tracker_new( vote_tracker_mem, 42UL ) );
  FD_TEST( ctx->vote_tracker );
  ctx->slot_out_seq   = fd_mcache_seq_laddr_const( test_stem_mcaches[ ctx->slot_out->idx   ] );
  fd_mcache_seq_update( fd_mcache_seq_laddr( test_stem_mcaches[ ctx->replay_out->idx ] ), 40UL );
  fd_mcache_seq_update( fd_mcache_seq_laddr( test_stem_mcaches[ ctx->slot_out->idx   ] ),  7UL );

  fd_pubkey_t old_identity = { .ul = { 1UL } };
  fd_pubkey_t new_identity = { .ul = { same_identity ? 1UL : 2UL } };
  ctx->identity_pubkey[ 0 ] = old_identity;
  mock_leader_for_slot_override = 1;
  mock_leader_schedule_loaded   = 1;
  mock_slot_leader              = old_identity;

  *ctx->votor_leader    = (fd_votor_leader_t){ .slot = 1UL, .parent_slot = 0UL, .parent_block_id = parent_bid };
  ctx->next_leader_slot = 1UL;

  memcpy( keyswitch->bytes, new_identity.uc, sizeof(fd_pubkey_t) );
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( ctx );
  FD_TEST( ctx->halt_replay && keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( keyswitch->result==7UL ); /* votor reads replay_slot */
  FD_TEST( fd_pubkey_eq( ctx->identity_pubkey, &new_identity ) );
  FD_TEST( !try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL ) );

  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  during_housekeeping( ctx );
  FD_TEST( !ctx->halt_replay && keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );

  FD_TEST( try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL )==same_identity );
  FD_TEST( ctx->is_leader==same_identity );
  if( !same_identity ) FD_TEST( ctx->next_leader_slot==ULONG_MAX );

  FD_LOG_NOTICE(( "pass: test_ag_set_identity_leader_slot(same_identity=%d)", same_identity ));
}

/* Like deliver_rotor_fec_bid, for one of our own leader FECs. */

static int
deliver_leader_fec( fd_replay_tile_t * ctx,
                    ulong              slot,
                    uint               fec_set_idx,
                    ulong              parent_slot,
                    fd_hash_t const *  parent_block_id,
                    fd_hash_t const *  block_id,
                    fd_hash_t const *  mr,
                    int                slot_complete ) {
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
  fec->is_leader       = 1;
  ctx->execrp_idle_cnt = 2UL*ctx->in_cnt + 4UL;
  return returnable_frag( ctx, TEST_REPAIR_IN_IDX, 0UL, ROTOR_SIG_FEC_REPLAY, chunk,
                          sizeof(fd_rotor_replay_fec_t), 0UL, 0UL,
                          fd_frag_meta_ts_comp( fd_tickcount() ), test_stem );
}

/* setup_ag_leader_ctx boots an Alpenglow ctx rooted at slot 0 with a
   frozen slot 1 (id1) on top, and a ParentReady for leader slot 2 on
   slot 1 that our identity is scheduled for. */

static fd_bank_t *
setup_ag_leader_ctx( fd_replay_tile_t * ctx,
                     fd_wksp_t *        wksp,
                     fd_hash_t const *  root_id,
                     fd_hash_t const *  id1 ) {
  setup_ctx( ctx, wksp );
  setup_ag_root( ctx, root_id );

  fd_bank_t * root = fd_banks_root( ctx->banks );
  root->f.block_id         = *root_id;
  ctx->consensus_root      = *root_id;
  ctx->consensus_root_slot = 0UL;
  ctx->notified_root       = *root_id;
  ctx->notified_root_slot  = 0UL;
  ctx->notified_root_bank  = root;
  ctx->votor_final->slot   = ULONG_MAX;

  fd_bank_t * b1 = add_block( ctx, root, 1UL, id1 );

  fd_pubkey_t identity = { .ul = { 1UL } };
  ctx->identity_pubkey[ 0 ]     = identity;
  mock_leader_for_slot_override = 1;
  mock_leader_schedule_loaded   = 1;
  mock_slot_leader              = identity;

  *ctx->votor_leader    = (fd_votor_leader_t){ .slot = 2UL, .parent_slot = 1UL, .parent_block_id = *id1 };
  ctx->next_leader_slot = 2UL;
  return b1;
}

/* process_poh_message's footer path reads accounts this ctx does not
   have, so the footer finalize and producer time bounds are mocked. */

static void
end_leader_slot( fd_replay_tile_t * ctx,
                 ulong              slot ) {
  fd_poh_leader_slot_ended_t slot_ended = { .completed = 1, .slot = slot };
  mock_footer_finalize = 1;
  process_poh_message( ctx, test_stem, &slot_ended );
  mock_footer_finalize = 0;
  FD_TEST( ctx->recv_poh );
}

/* Our block id never comes back (rotor dropped our own shreds) while
   the cluster finalizes a sibling chain.  Once replay roots past the
   leader slot, the leader slot is abandoned instead of wedging
   is_leader, which in turn unblocks the root handoff, the bank prune
   and a deferred identity switch.  A late own FEC is then skipped
   without a redelivery request. */

static void
test_ag_leader_abandon_on_root_past_leader_slot( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 0xBEEFUL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_hash_t id3     = { .ul = { 203UL } };
  fd_bank_t * b1 = setup_ag_leader_ctx( ctx, wksp, &root_id, &id1 );

  static fd_keyswitch_t keyswitch[ 1 ];
  ctx->keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx->keyswitch );
  void * vote_tracker_mem = fd_wksp_alloc_laddr( wksp, fd_vote_tracker_align(), fd_vote_tracker_footprint(), 1UL );
  FD_TEST( vote_tracker_mem );
  ctx->vote_tracker = fd_vote_tracker_join( fd_vote_tracker_new( vote_tracker_mem, 42UL ) );
  FD_TEST( ctx->vote_tracker );
  ctx->slot_out_seq   = fd_mcache_seq_laddr_const( test_stem_mcaches[ ctx->slot_out->idx   ] );

  FD_TEST( try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL ) );
  fd_bank_t * leader = ctx->leader_bank;
  FD_TEST( ctx->is_leader && leader && leader->f.slot==2UL && leader->refcnt==1UL );
  ulong leader_idx = leader->idx;
  ulong out_idx    = ctx->replay_out->idx;

  /* FEC 0 of our block comes back, the rest never does. */
  fd_hash_t zero    = {0};
  fd_hash_t mr2_0   = { .ul = { 2001UL } };
  fd_hash_t mr2_32  = { .ul = { 2002UL } };
  FD_TEST( !deliver_leader_fec( ctx, 2UL, 0U, 1UL, &id1, &zero, &mr2_0, 0 ) );
  FD_TEST( fd_hash_eq( &ctx->block_id_arr[ leader_idx ].latest_mr, &mr2_0 ) );
  FD_TEST( !ctx->block_id_arr[ leader_idx ].block_id_seen );

  /* An identity switch arrives mid-slot and is deferred. */
  fd_pubkey_t new_identity = { .ul = { 2UL } };
  memcpy( keyswitch->bytes, new_identity.uc, sizeof(fd_pubkey_t) );
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_SWITCH_PENDING );

  /* Root below the leader slot: wait for the block id. */
  end_leader_slot( ctx, 2UL );
  FD_TEST( mock_sched_add_done_idx==leader_idx );
  FD_TEST( !try_fini_leader( ctx, test_stem ) );
  FD_TEST( ctx->is_leader && ctx->leader_bank==leader );

  /* The cluster finalizes a sibling of our slot.  Replay roots it, but
     the handoff stays gated on is_leader. */
  fd_bank_t * b3 = add_block( ctx, b1, 3UL, &id3 );
  try_advance_root_ag( ctx, ag_block_id( 3UL, id3.uc ) );
  FD_TEST( ctx->consensus_root_slot==3UL );
  FD_TEST( ctx->is_leader );
  FD_TEST( !try_notify_consensus_root( ctx, test_stem ) );

  /* Before slot_ended, pack and motor may still use the bank. */
  ctx->recv_poh = 0;
  FD_TEST( !try_fini_leader( ctx, test_stem ) );
  FD_TEST( ctx->is_leader && ctx->leader_bank==leader );
  ctx->recv_poh = 1;

  ulong seq0 = test_stem_seqs[ out_idx ];
  ulong used = fd_banks_pool_used_cnt( ctx->banks );
  FD_TEST( try_fini_leader( ctx, test_stem ) );
  FD_TEST( !ctx->is_leader && !ctx->recv_poh && !ctx->leader_bank );
  FD_TEST( leader->state==FD_BANK_STATE_DEAD && leader->refcnt==0UL );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX );       /* no chaining to slot 3 */
  FD_TEST( ctx->highwater_leader_slot==2UL );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0 );       /* no SLOT_DEAD, no BECAME_LEADER */
  FD_TEST( !try_fini_leader( ctx, test_stem ) );

  /* The root hands off and the dead leader bank prunes. */
  FD_TEST( try_notify_consensus_root( ctx, test_stem ) );
  FD_TEST( replay_out_sig( ctx, seq0 )==REPLAY_SIG_ROOT_ADVANCED );
  FD_TEST( ctx->notified_root_bank==b3 );
  mock_sched_cancel_idx = ULONG_MAX;
  FD_TEST( try_prune_bank( ctx ) );
  FD_TEST( mock_sched_cancel_idx==leader_idx );
  FD_TEST( !fd_banks_bank_query( ctx->banks, leader_idx ) );

  /* A late own FEC finds the stale {2, 0} entry of the pruned bank.  It
     is skipped: no drain, no MISSING_FEC. */
  ulong seq1 = test_stem_seqs[ out_idx ];
  FD_TEST( !deliver_leader_fec( ctx, 2UL, FD_FEC_SHRED_CNT, 1UL, &id1, &zero, &mr2_32, 0 ) );
  FD_TEST( !ctx->drain_rotor_fecs );
  FD_TEST( test_stem_seqs[ out_idx ]==seq1 );

  /* The deferred identity switch now completes. */
  during_housekeeping( ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( ctx->identity_pubkey, &new_identity ) );

  FD_LOG_NOTICE(( "pass: test_ag_leader_abandon_on_root_past_leader_slot" ));
}

/* Replay does not start a leader slot that is already settled: a final
   cert above the parent, a root above the parent, or a root at the
   parent's slot on a different block.  The same check stops the
   in-window chain from try_fini_leader. */

static void
test_ag_become_leader_refuses_settled_slot( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 0xBEEFUL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_hash_t id2     = { .ul = { 202UL } };
  fd_hash_t other1  = { .ul = { 301UL } };
  fd_hash_t id3     = { .ul = { 203UL } };
  fd_bank_t * b1 = setup_ag_leader_ctx( ctx, wksp, &root_id, &id1 );

  ctx->votor_final->slot = 3UL;
  FD_TEST( !try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL ) );
  FD_TEST( !ctx->is_leader && ctx->next_leader_slot==ULONG_MAX );
  ctx->votor_final->slot = ULONG_MAX;

  ctx->next_leader_slot    = 2UL;
  ctx->consensus_root_slot = 3UL;
  ctx->consensus_root      = id3;
  FD_TEST( !try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL ) );
  FD_TEST( !ctx->is_leader && ctx->next_leader_slot==ULONG_MAX );

  ctx->next_leader_slot    = 2UL;
  ctx->consensus_root_slot = 1UL;
  ctx->consensus_root      = other1;
  FD_TEST( !try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL ) );
  FD_TEST( !ctx->is_leader && ctx->next_leader_slot==ULONG_MAX );

  /* The cluster already produced a slot of the window (the network's
     copy of our past slot 3, replayed during catch-up): give it up. */
  ctx->next_leader_slot = 2UL;
  ctx->consensus_root   = id1;
  fd_hash_t net3 = { .ul = { 403UL } };
  fd_bank_t * b3 = add_replayable_block( ctx, b1, 3UL, &net3 );
  ulong produced0 = ctx->metrics.leader_slot_already_produced;
  FD_TEST( !try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL ) );
  FD_TEST( !ctx->is_leader && ctx->next_leader_slot==ULONG_MAX );
  FD_TEST( ctx->metrics.leader_slot_already_produced==produced0+1UL );
  b3->bank_seq++; /* the network block goes away */

  /* A LEADER replay still holds goes stale when certs make a later
     window ParentReady after it was sent: give it up. */
  setup_votor_input( ctx, wksp );
  ctx->next_leader_slot = 2UL;
  ctx->consensus_root   = id1;
  ulong chunk = ctx->in[ TEST_VOTOR_IN_IDX ].chunk0;
  fd_votor_msg_t * msg = fd_chunk_to_laddr( ctx->in[ TEST_VOTOR_IN_IDX ].mem, chunk );
  msg->parent_ready = (fd_votor_parent_ready_t){ .slot = 2UL+AG_SLOTS_PER_WINDOW };
  FD_TEST( !returnable_frag( ctx, TEST_VOTOR_IN_IDX, 0UL, FD_VOTOR_SIG_PARENT_READY, chunk, sizeof(fd_votor_msg_t), 0UL, 0UL, 0UL, test_stem ) );
  produced0 = ctx->metrics.leader_slot_already_produced;
  ulong superseded0 = ctx->metrics.leader_window_superseded;
  FD_TEST( !try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL ) );
  FD_TEST( !ctx->is_leader && ctx->next_leader_slot==ULONG_MAX );
  FD_TEST( ctx->metrics.leader_window_superseded==superseded0+1UL );
  FD_TEST( ctx->metrics.leader_slot_already_produced==produced0 ); /* nothing was produced */
  ctx->votor_parent_ready_slot = 0UL;

  /* Rooted at the parent itself: lead. */
  ctx->next_leader_slot = 2UL;
  ctx->consensus_root   = id1;
  FD_TEST( try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL ) );
  FD_TEST( ctx->is_leader && ctx->leader_bank->f.slot==2UL );
  fd_bank_t * leader = ctx->leader_bank;

  /* Finish slot 2 normally with a final cert for 3 already known: the
     window would chain to 3 on 2, which is settled. */
  fd_hash_t zero   = {0};
  fd_hash_t mr2_0  = { .ul = { 2001UL } };
  fd_hash_t mr2_32 = { .ul = { 2002UL } };
  end_leader_slot( ctx, 2UL );
  FD_TEST( !deliver_leader_fec( ctx, 2UL, 0U,               1UL, &id1, &zero, &mr2_0,  0 ) );
  FD_TEST( !deliver_leader_fec( ctx, 2UL, FD_FEC_SHRED_CNT, 1UL, &id1, &id2,  &mr2_32, 1 ) );
  FD_TEST( ctx->block_id_arr[ leader->idx ].block_id_seen );
  ctx->votor_final->slot = 3UL;
  ulong used = fd_banks_pool_used_cnt( ctx->banks );
  mock_footer_finalize = 1;
  FD_TEST( try_fini_leader( ctx, test_stem ) );
  mock_footer_finalize = 0;
  FD_TEST( leader->state==FD_BANK_STATE_FROZEN );
  FD_TEST( ctx->votor_leader->slot==3UL && ctx->votor_leader->parent_slot==2UL );
  FD_TEST( !ctx->is_leader && !ctx->leader_bank );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX );
  FD_TEST( ctx->highwater_leader_slot==2UL );
  FD_TEST( fd_banks_pool_used_cnt( ctx->banks )==used );

  FD_LOG_NOTICE(( "pass: test_ag_become_leader_refuses_settled_slot" ));
}

/* Our leader FECs bind to the existing leader bank and never enter
   sched, so a full sched or a full bank pool must not hold them back
   the way it holds back other FECs. */

static void
test_ag_leader_fec_not_gated( fd_wksp_t * wksp ) {
  static fd_replay_tile_t ctx[ 1 ];
  fd_hash_t root_id = { .ul = { 0xBEEFUL } };
  fd_hash_t id1     = { .ul = { 201UL } };
  fd_hash_t id2     = { .ul = { 202UL } };
  fd_bank_t * b1 = setup_ag_leader_ctx( ctx, wksp, &root_id, &id1 );
  FD_TEST( try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL ) );
  fd_bank_t * leader = ctx->leader_bank;

  fd_bank_t * tip = b1;
  while( fd_banks_can_start_bank( ctx->banks ) ) {
    tip = fd_banks_new_bank( ctx->banks, tip->idx, 0L, 0 );
    FD_TEST( tip );
  }
  mock_sched_capacity = 0UL;
  mock_sched_drained  = 0;

  /* Another block's FEC 0 waits. */
  fd_hash_t mr9 = { .ul = { 9001UL } };
  FD_TEST( deliver_rotor_fec( ctx, 9UL, 0U, 1UL, &id1, &mr9, 0, 0 )==1 );
  mock_sched_capacity = ULONG_MAX;
  FD_TEST( deliver_rotor_fec( ctx, 9UL, 0U, 1UL, &id1, &mr9, 0, 0 )==1 );
  mock_sched_capacity = 0UL;

  /* Ours goes through, FEC 0 past the full bank pool and the rest past
     the full sched, and the block id returns. */
  fd_hash_t zero   = {0};
  fd_hash_t mr2_0  = { .ul = { 2001UL } };
  fd_hash_t mr2_32 = { .ul = { 2002UL } };
  ulong seq0 = test_stem_seqs[ ctx->replay_out->idx ];
  mock_sched_capacity = ULONG_MAX;
  FD_TEST( !deliver_leader_fec( ctx, 2UL, 0U,               1UL, &id1, &zero, &mr2_0,  0 ) );
  FD_TEST( fd_hash_eq( &ctx->block_id_arr[ leader->idx ].latest_mr, &mr2_0 ) );
  mock_sched_capacity = 0UL;
  FD_TEST( !deliver_leader_fec( ctx, 2UL, FD_FEC_SHRED_CNT, 1UL, &id1, &id2,  &mr2_32, 1 ) );
  fd_block_id_ele_t * ele = &ctx->block_id_arr[ leader->idx ];
  FD_TEST( ele->block_id_seen && fd_hash_eq( &ele->dmr, &id2 ) );
  ag_block_id_t key2 = ag_block_id( 2UL, id2.uc );
  FD_TEST( fd_ag_block_id_map_ele_query( ctx->ag_block_id_map, &key2, NULL, ctx->block_id_arr )==ele );
  FD_TEST( !ctx->drain_rotor_fecs && test_stem_seqs[ ctx->replay_out->idx ]==seq0 );

  mock_sched_capacity = ULONG_MAX;
  mock_sched_drained  = 1;
  FD_LOG_NOTICE(( "pass: test_ag_leader_fec_not_gated" ));
}

/* Minimal context setup for on_snapshot_message with mock_snapshot_boot=1.
   Returns the root bank (at snapshot_slot). */
static fd_bank_t *
setup_snapshot_test_ctx( fd_replay_tile_t *   ctx,
                         fd_wksp_t *          wksp,
                         fd_runtime_stack_t * runtime_stack,
                         ulong                snapshot_slot ) {
  setup_mleaders( ctx );
  setup_timing( ctx, wksp );
  setup_stem( ctx, wksp );
  setup_node_info( ctx );

  ulong const bank_cnt = 4UL;
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( bank_cnt, bank_cnt, 8UL, 8UL ), 1UL );
  FD_TEST( banks_mem );
  ctx->banks = fd_banks_join( fd_banks_new( banks_mem, FD_STAKE_DELEGATIONS_FD, bank_cnt, bank_cnt, 8UL, 128UL, 8UL, 0, 43UL ) );
  FD_TEST( ctx->banks );

  fd_bank_t * root = fd_banks_init_bank( ctx->banks );
  FD_TEST( root );
  fd_features_disable_all( &root->f.features );
  root->f.features.alpenglow          = 0UL;
  root->f.slot                        = snapshot_slot;
  root->f.parent_slot                 = snapshot_slot ? (snapshot_slot - 1UL) : 0UL;
  /* Nonzero, else the WFS bank hash memcmp compares zero against zero
     and passes no matter what the check does. */
  root->f.bank_hash                   = (fd_hash_t){ .ul = { 0x9e3779b97f4a7c15UL ^ snapshot_slot,
                                                             0xbf58476d1ce4e5b9UL,
                                                             0x94d049bb133111ebUL,
                                                             0x2545f4914f6cdd1dUL } };
  root->f.slot_params                 = FD_SLOT_PARAMS_400MS;
  root->f.slot_params.hashes_per_tick = 4UL;
  root->f.slot_params_default         = FD_SLOT_PARAMS_400MS;
  root->f.ticks_per_slot              = 64UL;
  fd_epoch_schedule_derive( &root->f.epoch_schedule, 128UL, 128UL, 0 );
  fd_hash_t root_id = { .ul = { 100UL + snapshot_slot } };
  root->f.block_id  = root_id;
  fd_blockhashes_init( &root->f.block_hash_queue, 42UL );
  FD_TEST( fd_blockhashes_push_new( &root->f.block_hash_queue, &root_id ) );

  ctx->block_id_arr = fd_wksp_alloc_laddr( wksp, alignof(fd_block_id_ele_t), sizeof(fd_block_id_ele_t)*bank_cnt, 1UL );
  FD_TEST( ctx->block_id_arr );
  memset( ctx->block_id_arr, 0, sizeof(fd_block_id_ele_t)*bank_cnt );

  ulong  ag_chain_cnt = fd_ag_block_id_map_chain_cnt_est( bank_cnt );
  void * ag_map_mem   = fd_wksp_alloc_laddr( wksp, fd_ag_block_id_map_align(), fd_ag_block_id_map_footprint( ag_chain_cnt ), 1UL );
  FD_TEST( ag_map_mem );
  ctx->ag_block_id_map_seed = 7UL;
  ctx->ag_block_id_map      = fd_ag_block_id_map_join( fd_ag_block_id_map_new( ag_map_mem, ag_chain_cnt, ctx->ag_block_id_map_seed ) );
  FD_TEST( ctx->ag_block_id_map );

  ctx->block_id_len = bank_cnt;

  void * store_mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fd_store_footprint( 2UL, 1UL, 0UL, 0UL, 0UL, 1, 1UL ), 1UL );
  FD_TEST( store_mem );
  ctx->store = fd_store_join( fd_store_new( store_mem, 2UL, 1UL, 0UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 0UL, 1, 1UL ) );
  FD_TEST( ctx->store );
  FD_TEST( fd_store_map_ljoin( ctx->store, ctx->map_join ) );

  fd_memset( runtime_stack, 0, sizeof(fd_runtime_stack_t) );
  ctx->runtime_stack                  = runtime_stack;
  ctx->initial_block_id               = root_id;
  ctx->manifest_block_id              = root_id;
  ctx->has_manifest_block_id          = 1;
  ctx->has_expected_genesis_timestamp = 1;
  root->accdb_fork_id                 = (fd_accdb_fork_id_t){ .val=37U };
  root->parent_accdb_fork_id          = root->accdb_fork_id;
  mock_accdb_fork_id_next             = 0U;
  return root;
}

static void
snapshot_done( fd_replay_tile_t * ctx ) {
  static ulong wfs_metrics[ FD_METRICS_TOTAL_SZ/sizeof(ulong) ];
  volatile ulong * saved = fd_metrics_tl;
  fd_metrics_tl      = wfs_metrics;
  mock_snapshot_boot = 1;
  on_snapshot_message( ctx, test_stem, 0UL, 0UL, fd_ssmsg_sig( FD_SSMSG_REPLAY_READY ) );
  mock_snapshot_boot = 0;
  fd_metrics_tl      = saved;
}

static void
test_snapshot_boot_bank_migration_slot( fd_wksp_t * wksp ) {
  static fd_replay_tile_t   ctx[1];
  static fd_runtime_stack_t stack[1];

  memset( ctx, 0, sizeof(*ctx) );
  fd_bank_t * root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );
  mock_migration_slot = 64UL;
  snapshot_done( ctx );
  FD_TEST( root->f.alpenglow_migration_slot==64UL );

  FD_LOG_NOTICE(( "pass: test_snapshot_boot_bank_migration_slot" ));
}

static void
test_wfs_auto_override( fd_wksp_t * wksp ) {
  static fd_replay_tile_t  ctx[1];
  static fd_runtime_stack_t stack[1];

  /* auto + MATCH: override fires. */
  memset( ctx, 0, sizeof(*ctx) );
  fd_bank_t * root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;
  snapshot_done( ctx );
  FD_TEST( ctx->wait_for_vote_to_start_leader==FD_BOOLAU_FALSE );

  fd_wksp_reset( wksp, 42U );

  /* auto + NOOP (snapshot ahead): resolved to true, the leader gate
     stays armed because WFS is a no-op. */
  memset( ctx, 0, sizeof(*ctx) );
  root = setup_snapshot_test_ctx( ctx, wksp, stack, 200UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;
  snapshot_done( ctx );
  FD_TEST( ctx->wait_for_vote_to_start_leader==FD_BOOLAU_TRUE );
  FD_TEST( ctx->wfs_complete );

  fd_wksp_reset( wksp, 42U );

  /* explicit true + MATCH: NOT overridden.  Config validation rejects
     this combination at startup (see fd_config.c), so replay never sees
     it in practice; the case is retained to pin the tile behavior. */
  memset( ctx, 0, sizeof(*ctx) );
  root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_TRUE;
  snapshot_done( ctx );
  FD_TEST( ctx->wait_for_vote_to_start_leader==FD_BOOLAU_TRUE );

  fd_wksp_reset( wksp, 42U );

  /* explicit false: stays false. */
  memset( ctx, 0, sizeof(*ctx) );
  root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_FALSE;
  snapshot_done( ctx );
  FD_TEST( ctx->wait_for_vote_to_start_leader==FD_BOOLAU_FALSE );

  fd_wksp_reset( wksp, 42U );

  /* auto + MATCH, but the gossip WFS_DONE raced ahead of the
     snapshot.  MATCH still clears the gate: we booted at the restart
     slot, so our vote cannot be rooted regardless of wfs_complete. */
  memset( ctx, 0, sizeof(*ctx) );
  root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;
  ctx->wfs_complete                   = 1;
  snapshot_done( ctx );
  FD_TEST( ctx->wait_for_vote_to_start_leader==FD_BOOLAU_FALSE );

  fd_wksp_reset( wksp, 42U );

  /* WFS disabled: on_snapshot_message leaves the flag alone, because
     unprivileged_init already resolved it (tested below). */
  memset( ctx, 0, sizeof(*ctx) );
  setup_snapshot_test_ctx( ctx, wksp, stack, 0UL );
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;
  snapshot_done( ctx );
  FD_TEST( ctx->wait_for_vote_to_start_leader==FD_BOOLAU_AUTO );

  /* The WFS disabled path resolves auto to true at init, and leaves
     an explicit value untouched.  Idempotent. */
  FD_TEST( wfs_resolve_leader_gate_auto( FD_BOOLAU_AUTO  )==FD_BOOLAU_TRUE  );
  FD_TEST( wfs_resolve_leader_gate_auto( FD_BOOLAU_TRUE  )==FD_BOOLAU_TRUE  );
  FD_TEST( wfs_resolve_leader_gate_auto( FD_BOOLAU_FALSE )==FD_BOOLAU_FALSE );

  FD_LOG_NOTICE(( "pass: test_wfs_auto_override" ));
}

static void
test_wfs_error_aborts( fd_wksp_t * wksp ) {
  static fd_replay_tile_t   ctx[1];
  static fd_runtime_stack_t stack[1];

  memset( ctx, 0, sizeof(*ctx) );
  fd_bank_t * root = setup_snapshot_test_ctx( ctx, wksp, stack, 99UL );  /* boot slot 99 */
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;                           /* WFS slot 100 -> ERROR */
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;

  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    snapshot_done( ctx );
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );

  FD_LOG_NOTICE(( "pass: test_wfs_error_aborts" ));
}

static void
test_wfs_bank_hash_mismatch( fd_wksp_t * wksp ) {
  static fd_replay_tile_t   ctx[1];
  static fd_runtime_stack_t stack[1];

  /* MATCH with a bank hash one bit off the snapshot's: fatal. */
  memset( ctx, 0, sizeof(*ctx) );
  fd_bank_t * root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->expected_bank_hash.uc[ 31 ]   ^= 0x01;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;

  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    snapshot_done( ctx );
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );

  fd_wksp_reset( wksp, 42U );

  /* Same mismatch under NOOP: the network moved on, (S, H) are skipped
     by design, so the boot must survive.  This is what distinguishes
     the check firing on MATCH from it firing unconditionally. */
  memset( ctx, 0, sizeof(*ctx) );
  root = setup_snapshot_test_ctx( ctx, wksp, stack, 200UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->expected_bank_hash.uc[ 31 ]   ^= 0x01;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;
  snapshot_done( ctx );
  FD_TEST( ctx->wfs_complete );

  FD_LOG_NOTICE(( "pass: test_wfs_bank_hash_mismatch" ));
}

static void
test_wfs_done_idempotency( fd_wksp_t * wksp ) {
  static fd_replay_tile_t   ctx[1];
  static fd_runtime_stack_t stack[1];

  /* Set up a MATCH scenario: wfs_complete starts at 0 after
     snapshot_done because MATCH waits for the gossip WFS_DONE signal. */
  memset( ctx, 0, sizeof(*ctx) );
  fd_bank_t * root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;
  snapshot_done( ctx );
  FD_TEST( !ctx->wfs_complete );

  /* Register a gossip_out input so returnable_frag dispatches to
     the IN_KIND_GOSSIP_OUT handler. */
  ctx->in_kind[ 1UL ] = IN_KIND_GOSSIP_OUT;

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];

  /* First WFS_DONE: transitions wfs_complete from 0 to 1 and publishes. */
  returnable_frag( ctx, 1UL, 0UL, FD_GOSSIP_UPDATE_TAG_WFS_DONE,
                   0UL, 0UL, 0UL, 0UL,
                   fd_frag_meta_ts_comp( fd_tickcount() ), test_stem );
  FD_TEST( ctx->wfs_complete==1 );
  ulong seq1 = test_stem_seqs[ out_idx ];
  FD_TEST( seq1>seq0 );

  /* Second WFS_DONE: the early break fires.  Asserting wfs_complete
     alone would not catch its removal, since the handler re-sets the
     flag anyway.  The observable difference is the extra publish. */
  returnable_frag( ctx, 1UL, 0UL, FD_GOSSIP_UPDATE_TAG_WFS_DONE,
                   0UL, 0UL, 0UL, 0UL,
                   fd_frag_meta_ts_comp( fd_tickcount() ), test_stem );
  FD_TEST( ctx->wfs_complete==1 );
  FD_TEST( test_stem_seqs[ out_idx ]==seq1 );

  FD_LOG_NOTICE(( "pass: test_wfs_done_idempotency" ));
}

static void
test_wfs_boot_publish_order( fd_wksp_t * wksp ) {
  static fd_replay_tile_t   ctx[1];
  static fd_runtime_stack_t stack[1];

  /* The boot slot is announced unconditionally, completed before root
     before reset.  Votor owns the WFS gate, so replay does not hold
     these back. */

  memset( ctx, 0, sizeof(*ctx) );
  fd_bank_t * root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;

  ulong out_idx = ctx->replay_out->idx;
  ulong seq0    = test_stem_seqs[ out_idx ];

  mock_footer_finalize = 1;
  memset( mock_footer, 0, sizeof(fd_block_footer_t) );
  snapshot_done( ctx );
  mock_footer_finalize = 0;

  FD_TEST( !ctx->wfs_complete );
  FD_TEST( test_stem_seqs[ out_idx ]==seq0+4UL );
  ulong const expected[ 4 ] = { REPLAY_SIG_SLOT_COMPLETED, REPLAY_SIG_NEXT_LEADER, REPLAY_SIG_ROOT_ADVANCED, REPLAY_SIG_RESET };
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_frag_meta_t const * f = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( seq0+i, test_stem_depths[ out_idx ] );
    FD_TEST( f->sig==expected[ i ] );
  }

  /* publish_boot_slot stages the completed frag's payload itself. */
  fd_frag_meta_t const * completed_frag = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( seq0, test_stem_depths[ out_idx ] );
  fd_replay_slot_completed_t const * completed = fd_chunk_to_laddr_const( ctx->replay_out->mem, completed_frag->chunk );
  FD_TEST( completed->cost_tracker.block_cost_limit==ULONG_MAX );

  ulong seq1 = test_stem_seqs[ out_idx ];
  ctx->in_kind[ 1UL ] = IN_KIND_GOSSIP_OUT;
  returnable_frag( ctx, 1UL, 0UL, FD_GOSSIP_UPDATE_TAG_WFS_DONE,
                   0UL, 0UL, 0UL, 0UL,
                   fd_frag_meta_ts_comp( fd_tickcount() ), test_stem );
  FD_TEST( ctx->wfs_complete==1 );
  FD_TEST( test_stem_seqs[ out_idx ]==seq1+1UL );
  fd_frag_meta_t const * done = test_stem_mcaches[ out_idx ] + fd_mcache_line_idx( seq1, test_stem_depths[ out_idx ] );
  FD_TEST( done->sig==REPLAY_SIG_WFS_DONE );

  FD_LOG_NOTICE(( "pass: test_wfs_boot_publish_order" ));
}

static void
test_wfs_leader_gate( fd_wksp_t * wksp ) {
  static fd_replay_tile_t   ctx[1];
  static fd_runtime_stack_t stack[1];

  memset( ctx, 0, sizeof(*ctx) );
  fd_bank_t * root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );

  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->wait_for_vote_to_start_leader  = FD_BOOLAU_AUTO;
  snapshot_done( ctx );
  FD_TEST( !ctx->wfs_complete );

  /* All other preconditions for leadership are satisfied. */
  ctx->next_leader_slot      = 101UL;
  ctx->is_leader             = 0;

  /* Blocked by wfs_complete==0.  try_become_leader_ag short-circuits on
     an OR, so pin every earlier term open (replay_out->idx==ULONG_MAX in
     particular would return 0 on its own and hide the WFS gate). */
  FD_TEST( ctx->next_leader_slot!=ULONG_MAX );
  FD_TEST( !ctx->is_leader );
  FD_TEST( ctx->replay_out->idx!=ULONG_MAX );
  FD_TEST( !ctx->wfs_complete );
  FD_TEST( try_become_leader_ag( ctx, test_stem, FD_METRICS_SAMPLE_REASON_LEADER_START, 0UL )==0 );

  /* after_credit returns immediately when wfs_complete==0.  If the
     gate didn't fire, it would crash on our minimal ctx. */
  ctx->is_booted = 1;
  int opt_poll_in = 1;
  int charge_busy = 0;
  after_credit( ctx, test_stem, &opt_poll_in, &charge_busy );

  FD_LOG_NOTICE(( "pass: test_wfs_leader_gate" ));
}

static void
test_wfs_done_before_boot( fd_wksp_t * wksp ) {
  static fd_replay_tile_t   ctx[1];
  static fd_runtime_stack_t stack[1];

  memset( ctx, 0, sizeof(*ctx) );
  fd_bank_t * root = setup_snapshot_test_ctx( ctx, wksp, stack, 100UL );
  ctx->wfs_enabled                    = 1;
  ctx->wfs_hash_is_zero               = 0;
  ctx->expected_bank_hash             = root->f.bank_hash;
  ctx->wait_for_supermajority_at_slot = 100UL;
  ctx->expected_shred_version         = 1234;
  ctx->next_leader_slot               = ULONG_MAX;

  /* Full manifest consumed, incremental manifest not yet. */
  ctx->has_genesis_hash = 1;
  *ctx->genesis_hash    = (fd_hash_t){ .ul = { 0x1234567890abcdefUL, 0UL, 0UL, 0UL } };
  ctx->hard_fork_cnt    = 1UL;
  ctx->hard_forks[ 0 ]  = (fd_hard_fork_t){ .slot = 50UL, .cnt = 1UL };

  FD_TEST( !ctx->is_booted );

  ctx->in_kind[ 1UL ] = IN_KIND_GOSSIP_OUT;
  returnable_frag( ctx, 1UL, 0UL, FD_GOSSIP_UPDATE_TAG_WFS_DONE,
                   0UL, 0UL, 0UL, 0UL,
                   fd_frag_meta_ts_comp( fd_tickcount() ), test_stem );

  FD_TEST( ctx->wfs_complete==1 );

  /* Manifests keep arriving on the snap link after the signal.  The
     comparison must stay deferred, or the full snapshot's pre-restart
     hard forks abort the boot here. */
  maybe_verify_shred_version( ctx );
  FD_TEST( !ctx->is_booted );

  FD_LOG_NOTICE(( "pass: test_wfs_done_before_boot" ));
}

static void
test_wfs_shred_version_deferral( void ) {
  static fd_replay_tile_t ctx[1];
  memset( ctx, 0, sizeof(*ctx) );

  ctx->expected_shred_version = 1234;
  ctx->shred_version          = 5678; /* mismatch */
  ctx->hard_fork_cnt          = ULONG_MAX; /* skip compute_shred_version */

  /* WFS active, not booted: deferral fires, mismatch is not fatal. */
  ctx->wfs_enabled = 1;
  ctx->is_booted   = 0;
  maybe_verify_shred_version( ctx );

  /* WFS disabled, matching versions: completes normally. */
  ctx->wfs_enabled            = 0;
  ctx->expected_shred_version = 9999;
  ctx->shred_version          = 9999;
  maybe_verify_shred_version( ctx );

  /* WFS active and booted: the comparison runs, and matches. */
  ctx->wfs_enabled = 1;
  ctx->is_booted   = 1;
  maybe_verify_shred_version( ctx );

  FD_LOG_NOTICE(( "pass: test_wfs_shred_version_deferral" ));
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

  static uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_METRICS_ALIGN)));
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) ); /* leader paths run metrics_write */

  test_txn_completion_publish( wksp );              fd_wksp_reset( wksp, 42U );
  test_reward_cert_signer_count();
  test_snapshot_intervals_use_block_height();
  test_snapshot_found_deleted_state( wksp );        fd_wksp_reset( wksp, 42U );
  test_next_leader_slot_cache();
  test_wait_info_health_signal();
  test_wait_info_leader_gap();
  test_wait_info_snapshot_intervals();
  test_wait_info_produced_incr_cnt( wksp );         fd_wksp_reset( wksp, 42U );
  test_wfs_auto_override( wksp );                   fd_wksp_reset( wksp, 42U );
  test_snapshot_boot_bank_migration_slot( wksp );   fd_wksp_reset( wksp, 42U );
  test_wfs_error_aborts( wksp );                    fd_wksp_reset( wksp, 42U );
  test_wfs_bank_hash_mismatch( wksp );              fd_wksp_reset( wksp, 42U );
  test_wfs_done_idempotency( wksp );                fd_wksp_reset( wksp, 42U );
  test_wfs_boot_publish_order( wksp );              fd_wksp_reset( wksp, 42U );
  test_wfs_leader_gate( wksp );                     fd_wksp_reset( wksp, 42U );
  test_wfs_done_before_boot( wksp );                fd_wksp_reset( wksp, 42U );
  test_wfs_shred_version_deferral();
  test_consensus_root_notification_handoff( wksp ); fd_wksp_reset( wksp, 42U );
  test_root_from_votor_cert( wksp );                fd_wksp_reset( wksp, 42U );
  test_ag_rank_is_current();
  test_ag_delinquent_epoch_roll();
  test_ag_update_delinquent( wksp );                fd_wksp_reset( wksp, 42U );
  test_root_waits_for_replay( wksp );               fd_wksp_reset( wksp, 42U );
  test_root_out_of_order_certs( wksp );             fd_wksp_reset( wksp, 42U );
  test_root_lagging_replay( wksp );                 fd_wksp_reset( wksp, 42U );
  test_root_newer_first( wksp );                    fd_wksp_reset( wksp, 42U );
  test_root_from_footer( wksp );                    fd_wksp_reset( wksp, 42U );
  test_footer_cert_tasks( wksp );                   fd_wksp_reset( wksp, 42U );
  test_slot_completed_keeps_leader_sentinel( wksp ); fd_wksp_reset( wksp, 42U );
  test_drain_rotor_fecs( wksp );                    fd_wksp_reset( wksp, 42U );
  test_drain_rotor_fecs_skip_wait_reentry( wksp );  fd_wksp_reset( wksp, 42U );
  test_process_rotor_fec_skip_replayed( wksp );     fd_wksp_reset( wksp, 42U );
  test_rotor_fec_turbine_keying( wksp );            fd_wksp_reset( wksp, 42U );
  test_rotor_fec_rooted_past( wksp );               fd_wksp_reset( wksp, 42U );
  test_rotor_fec_merged_copies( wksp );             fd_wksp_reset( wksp, 42U );
  test_ag_set_identity_leader_slot( wksp, 1 );      fd_wksp_reset( wksp, 42U );
  test_ag_set_identity_leader_slot( wksp, 0 );      fd_wksp_reset( wksp, 42U );
  test_dead_block_children_drop( wksp );
  test_stale_id_key_does_not_shadow_rebuild( wksp ); fd_wksp_reset( wksp, 42U );
  test_identity_switch_quiesces_replay( wksp );     fd_wksp_reset( wksp, 42U );
  test_ag_leader_abandon_on_root_past_leader_slot( wksp ); fd_wksp_reset( wksp, 42U );
  test_ag_become_leader_refuses_settled_slot( wksp ); fd_wksp_reset( wksp, 42U );
  test_ag_leader_fec_not_gated( wksp );
  fd_wksp_reset( wksp, 42U );
  test_snapmk_start_leader_after_epoch_rollover( wksp );

  FD_TEST( mock_store_view_success_cnt==mock_store_view_release_cnt );

  fd_halt();
  return 0;
}
