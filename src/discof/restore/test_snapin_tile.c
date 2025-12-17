#include "fd_snapin_tile.c"
#include "../../disco/topo/fd_topob.h"
#include "utils/fd_ssctrl.h"
#include <stdlib.h> /* aligned_alloc */
#define WKSP_TAG 1UL

struct snapin_topo {
  fd_topo_t * topo;

  /* Shared memory objects */
  void * accdb_funk;
  void * txncache;

  /* Topo links */
  fd_topo_link_t * in_link;
  fd_topo_link_t * out_mf_link;
  fd_topo_link_t * out_ct_link;

  /* Tile context */
  void * scratch;

  /* Stem bits */
  fd_frag_meta_t * stem_mcaches [2];
  ulong            stem_seqs    [2];
  ulong            stem_depths  [2];
  ulong            stem_cr_avail[2];
  ulong            stem_min_cr_avail;
};
typedef struct snapin_topo snapin_topo_t;

static void
snapin_topo_init( snapin_topo_t * t,
                  fd_wksp_t *     wksp ) {
  fd_topo_t * topo = fd_wksp_alloc_laddr( wksp, alignof(fd_topo_t), sizeof(fd_topo_t), WKSP_TAG );
  FD_TEST( topo );
  t->topo = topo;
  fd_topob_new( topo, "snapin" );

  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "snapin" );
  topo_wksp->wksp = wksp;

  ulong const funk_rec_max = 32UL;
  ulong const funk_txn_max = 16UL;
  t->accdb_funk = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( funk_txn_max, funk_rec_max ), WKSP_TAG );
  FD_TEST( fd_funk_new( t->accdb_funk, WKSP_TAG, 1UL, funk_txn_max, funk_rec_max ) );
  fd_topo_obj_t * funk_obj = fd_topob_obj( topo, "funk", "snapin" );
  funk_obj->offset = fd_wksp_gaddr_fast( wksp, t->accdb_funk );

  ulong const txncache_max_live_slots   = 4UL;
  ulong const txncache_max_txn_per_slot = 4UL;
  t->txncache = fd_wksp_alloc_laddr( wksp, fd_txncache_shmem_align(), fd_txncache_shmem_footprint( txncache_max_live_slots, txncache_max_txn_per_slot ), WKSP_TAG );
  FD_TEST( fd_txncache_shmem_new( t->txncache, txncache_max_live_slots, txncache_max_txn_per_slot ) );
  fd_topo_obj_t * txncache_obj = fd_topob_obj( topo, "txncache", "snapin" );
  txncache_obj->offset = fd_wksp_gaddr_fast( wksp, t->txncache );

  ulong const      in_depth      = 4UL;
  ulong const      in_mtu        = USHORT_MAX;
  void *           in_mcache     = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( in_depth, 0UL ), WKSP_TAG );
  /*                             */fd_mcache_new( in_mcache, in_depth, 0UL, 0UL );
  fd_topo_obj_t *  in_mcache_obj = fd_topob_obj( topo, "mcache", "snapin" );
  in_mcache_obj->offset          = fd_wksp_gaddr_fast( wksp, in_mcache );
  ulong const      in_data_sz    = fd_dcache_req_data_sz( in_mtu, in_depth, 0UL, 1 );
  void *           in_dcache     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( in_data_sz, 0UL ), WKSP_TAG );
  FD_TEST( fd_dcache_new( in_dcache, in_data_sz, 0UL ) );
  fd_topo_obj_t *  in_dcache_obj = fd_topob_obj( topo, "dcache", "snapin" );
  in_dcache_obj->offset          = fd_wksp_gaddr_fast( wksp, in_dcache );
  fd_topo_link_t * in_link       = fd_topob_link( topo, "snapdc_in", "snapin", 4UL, in_mtu, 0UL );
  in_link->mcache_obj_id         = in_mcache_obj->id;
  in_link->dcache_obj_id         = in_dcache_obj->id;
  in_link->mcache                = fd_mcache_join( in_mcache );
  in_link->dcache                = fd_dcache_join( in_dcache );
  t->in_link                     = in_link;

  ulong const      out_ct_depth      = 4UL;
  void *           out_ct_mcache     = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( out_ct_depth, 0UL ), WKSP_TAG );
  FD_TEST( fd_mcache_new( out_ct_mcache, out_ct_depth, 0UL, 0UL ) );
  fd_topo_obj_t *  out_ct_mcache_obj = fd_topob_obj( topo, "mcache", "snapin" );
  out_ct_mcache_obj->offset          = fd_wksp_gaddr_fast( wksp, out_ct_mcache );
  fd_topo_link_t * out_ct_link       = fd_topob_link( topo, "snapin_ct", "snapin", 4UL, 0UL, 0UL );
  out_ct_link->mcache_obj_id         = out_ct_mcache_obj->id;
  out_ct_link->mcache                = fd_mcache_join( out_ct_mcache );
  t->out_ct_link                     = out_ct_link;

  ulong const      out_mf_depth      = 4UL;
  void *           out_mf_mcache     = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( out_mf_depth, 0UL ), WKSP_TAG );
  FD_TEST( fd_mcache_new( out_mf_mcache, out_mf_depth, 0UL, 0UL ) );
  fd_topo_obj_t *  out_mf_mcache_obj = fd_topob_obj( topo, "mcache", "snapin" );
  out_mf_mcache_obj->offset          = fd_wksp_gaddr_fast( wksp, out_mf_mcache );
  ulong const      out_mf_data_sz    = fd_dcache_req_data_sz( USHORT_MAX, out_mf_depth, 0UL, 1 );
  void *           out_mf_dcache     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( out_mf_data_sz, 0UL ), WKSP_TAG );
  FD_TEST( fd_dcache_new( out_mf_dcache, out_mf_data_sz, 0UL ) );
  fd_topo_obj_t *  out_mf_dcache_obj = fd_topob_obj( topo, "dcache", "snapin" );
  out_mf_dcache_obj->offset          = fd_wksp_gaddr_fast( wksp, out_mf_dcache );
  fd_topo_link_t * out_mf_link       = fd_topob_link( topo, "snapin_manif", "snapin", 4UL, 0UL, 0UL );
  out_mf_link->mcache_obj_id         = out_mf_mcache_obj->id;
  out_mf_link->dcache_obj_id         = out_mf_dcache_obj->id;
  out_mf_link->mcache                = fd_mcache_join( out_mf_mcache );
  out_mf_link->dcache                = fd_dcache_join( out_mf_dcache );
  t->out_mf_link                     = out_mf_link;

  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "snapin", "snapin", "snapin", 0UL, 0, 0 );
  topo_tile->snapin.use_vinyl       = 0;
  topo_tile->snapin.lthash_disabled = 1;
  topo_tile->snapin.max_live_slots  = 32UL;
  topo_tile->snapin.funk_obj_id     = funk_obj->id;
  topo_tile->snapin.txncache_obj_id = txncache_obj->id;

  fd_topob_tile_in ( topo, "snapin", 0UL, "snapin", "snapdc_in", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapin", 0UL, "snapin_ct",    0UL );
  fd_topob_tile_out( topo, "snapin", 0UL, "snapin_manif", 0UL );

  ulong const tile_footprint = scratch_footprint( topo_tile );
  FD_LOG_INFO(( "snapin tile has %lu bytes scratch region", tile_footprint ));
  void * tile_scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), tile_footprint, WKSP_TAG );
  FD_TEST( tile_scratch );
  t->scratch = tile_scratch;
  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", "snapin" );
  tile_obj->offset = fd_wksp_gaddr_fast( wksp, tile_scratch );
  topo_tile->tile_obj_id = tile_obj->id;

  t->stem_mcaches [0]  = t->out_ct_link->mcache;
  t->stem_mcaches [1]  = t->out_mf_link->mcache;
  t->stem_seqs    [0]  = 0UL;
  t->stem_seqs    [1]  = 0UL;
  t->stem_depths  [0]  = fd_mcache_depth( t->out_ct_link->mcache );
  t->stem_depths  [1]  = fd_mcache_depth( t->out_mf_link->mcache );
  t->stem_cr_avail[0]  = ULONG_MAX;
  t->stem_cr_avail[1]  = ULONG_MAX;
  t->stem_min_cr_avail = ULONG_MAX;

  unprivileged_init( topo, topo_tile );
}

static void
snapin_topo_fini( snapin_topo_t * topo ) {
  fd_wksp_free_laddr( fd_funk_delete( topo->accdb_funk ) );
  fd_wksp_free_laddr( topo->txncache );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( topo->in_link->mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( topo->in_link->dcache ) ) );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( topo->out_ct_link->mcache ) ) );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( topo->out_mf_link->mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( topo->out_mf_link->dcache ) ) );
  fd_wksp_free_laddr( topo->scratch );
  fd_wksp_free_laddr( topo->topo );
}

static void
test_funk_incremental( fd_wksp_t * wksp ) {
  snapin_topo_t t;
  snapin_topo_init( &t, wksp );

  fd_stem_context_t stem = {
    .mcaches      = t.stem_mcaches,
    .seqs         = t.stem_seqs,
    .depths       = t.stem_depths,
    .cr_avail     = t.stem_cr_avail,
    .min_cr_avail = &t.stem_min_cr_avail
  };

  fd_funk_t funk[1];
  FD_TEST( fd_funk_join( funk, t.accdb_funk ) );
  fd_funk_txn_xid_t root_xid = { .ul={ ULONG_MAX, ULONG_MAX } };
  FD_TEST( fd_funk_txn_xid_eq( fd_funk_last_publish( funk ), &root_xid ) );

  /* Mark full snapshot download as finished */

  fd_snapin_tile_t * ctx = t.scratch;
  ctx->state = FD_SNAPSHOT_STATE_FINISHING;
  FD_TEST( 0==returnable_frag(
      ctx,
      0UL,
      /* seq    */ 0UL,
      /* sig    */ FD_SNAPSHOT_MSG_CTRL_NEXT,
      /* chunk  */ 0UL,
      /* sz     */ 0UL,
      /* ctl    */ 0UL,
      /* tsorig */ 0UL,
      /* tspub  */ 0UL,
      /* stem   */ &stem
  ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );

  /* Start an incremental snapshot */

  FD_TEST( 0==returnable_frag(
      ctx,
      0UL,
      /* seq    */ 1UL,
      /* sig    */ FD_SNAPSHOT_MSG_CTRL_INIT_INCR,
      /* chunk  */ 0UL,
      /* sz     */ 0UL,
      /* ctl    */ 0UL,
      /* tsorig */ 0UL,
      /* tspub  */ 0UL,
      /* stem   */ &stem
  ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );

  fd_funk_txn_xid_t incremental_xid = { .ul={ LONG_MAX, LONG_MAX } };
  FD_TEST( fd_funk_txn_query( &incremental_xid, funk->txn_map ) );

  /* Inject a SlotHistory account to pass end-of-snapshot verification */

  fd_accdb_user_t accdb[1];
  FD_TEST( fd_accdb_user_v1_init( accdb, t.accdb_funk ) );
  {
    uchar const data[17] = {0UL};
    fd_accdb_rw_t rw[1];
    FD_TEST( fd_accdb_open_rw( accdb, rw, &root_xid, &fd_sysvar_slot_history_id, sizeof(data), FD_ACCDB_FLAG_CREATE|FD_ACCDB_FLAG_ROOT ) );
    fd_accdb_ref_owner_set   ( rw, &fd_sysvar_owner_id );
    fd_accdb_ref_data_set    ( rw, data, sizeof(data)  );
    fd_accdb_ref_lamports_set( rw, (ulong)1e6          );
    fd_accdb_close_rw( accdb, rw );
  }
  fd_accdb_user_fini( accdb );

  /* Finish incremental */

  ctx->state     = FD_SNAPSHOT_STATE_FINISHING;
  ctx->bank_slot = 3UL;
  FD_TEST( 0==returnable_frag(
      ctx,
      0UL,
      /* seq    */ 1UL,
      /* sig    */ FD_SNAPSHOT_MSG_CTRL_DONE,
      /* chunk  */ 0UL,
      /* sz     */ 0UL,
      /* ctl    */ 0UL,
      /* tsorig */ 0UL,
      /* tspub  */ 0UL,
      /* stem   */ &stem
  ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  fd_funk_txn_xid_t incr_xid = { .ul={ 3UL, 0UL } };
  FD_TEST( fd_funk_txn_xid_eq( fd_funk_last_publish( funk ), &incr_xid ) );

  /* Clean up */

  fd_funk_leave( funk, NULL );
  snapin_topo_fini( &t );
}

static void
test_funk_fail_full( fd_wksp_t * wksp ) {
  snapin_topo_t t;
  snapin_topo_init( &t, wksp );

  fd_stem_context_t stem = {
    .mcaches      = t.stem_mcaches,
    .seqs         = t.stem_seqs,
    .depths       = t.stem_depths,
    .cr_avail     = t.stem_cr_avail,
    .min_cr_avail = &t.stem_min_cr_avail
  };

  fd_snapin_tile_t * ctx = t.scratch;
  ctx->state = FD_SNAPSHOT_STATE_PROCESSING;

  fd_funk_t funk[1];
  FD_TEST( fd_funk_join( funk, t.accdb_funk ) );
  fd_funk_txn_xid_t root_xid = { .ul={ ULONG_MAX, ULONG_MAX } };
  FD_TEST( fd_funk_txn_xid_eq( fd_funk_last_publish( funk ), &root_xid ) );

  /* React to an error while downloading */

  FD_TEST( 0==returnable_frag(
      ctx,
      0UL,
      /* seq    */ 0UL,
      /* sig    */ FD_SNAPSHOT_MSG_CTRL_ERROR,
      /* chunk  */ 0UL,
      /* sz     */ 0UL,
      /* ctl    */ 0UL,
      /* tsorig */ 0UL,
      /* tspub  */ 0UL,
      /* stem   */ &stem
  ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR );

  /* React to a reset signal */

  FD_TEST( 0==returnable_frag(
      ctx,
      0UL,
      /* seq    */ 1UL,
      /* sig    */ FD_SNAPSHOT_MSG_CTRL_FAIL,
      /* chunk  */ 0UL,
      /* sz     */ 0UL,
      /* ctl    */ 0UL,
      /* tsorig */ 0UL,
      /* tspub  */ 0UL,
      /* stem   */ &stem
  ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );

  /* Clean up */

  fd_funk_leave( funk, NULL );
  snapin_topo_fini( &t );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  /* The snapin tile requires a large workspace (multiple GiB).  Since
     we are just doing functional testing here, not performance testing,
     use a demand-paged/slow normal page backed workspace via malloc.
     (Instead of requiring huge pages or wasting time zero-initializing
     upfront). */

  ulong const mem_req       = 5UL<<30;
  ulong       wksp_part_max = fd_wksp_part_max_est( mem_req, 1UL<<20 );
  ulong       wksp_data_max = fd_wksp_data_max_est( mem_req, wksp_part_max );
  void *      wksp_mem      = aligned_alloc( FD_SHMEM_NORMAL_PAGE_SZ, mem_req ); FD_TEST( wksp_mem );
  fd_wksp_t * wksp          = fd_wksp_new( wksp_mem, "snapin", 1U, wksp_part_max, wksp_data_max ); FD_TEST( wksp );
  fd_shmem_join_anonymous( "snapin", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, wksp_mem, FD_SHMEM_NORMAL_PAGE_SZ, mem_req>>FD_SHMEM_NORMAL_LG_PAGE_SZ );

  test_funk_incremental( wksp );
  test_funk_fail_full  ( wksp );

  /* Check for memory leaks */
  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  fd_shmem_leave_anonymous( wksp, NULL );
  free( fd_wksp_delete( wksp ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
