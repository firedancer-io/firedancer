#include "fd_snapin_test_topo.h"
#include "../fd_snapin_tile.c"
#include "../../../disco/topo/fd_topob.h"

#define WKSP_TAG 1UL

FD_FN_CONST ulong
fd_snapin_test_topo_align( void ) {
  return alignof(fd_snapin_test_topo_t);
}

FD_FN_CONST ulong
fd_snapin_test_topo_footprint( void ) {
  return sizeof(fd_snapin_test_topo_t);
}

void *
fd_snapin_test_topo_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_snapin_test_topo_align() ) ) ) {
    FD_LOG_WARNING(("unaligned shmem " ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_snapin_test_topo_t * snapin = FD_SCRATCH_ALLOC_APPEND( l, fd_snapin_test_topo_align(), fd_snapin_test_topo_footprint() );
  fd_memset( snapin, 0, sizeof(fd_snapin_test_topo_t) );

  FD_COMPILER_MFENCE();
  snapin->magic = FD_SNAPIN_TEST_TOPO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)snapin;
}

fd_snapin_test_topo_t *
fd_snapin_test_topo_join( void * shsnapin ) {
  if( FD_UNLIKELY( !shsnapin ) ) {
    FD_LOG_WARNING(( "NULL shsnapin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsnapin, fd_snapin_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsnapin" ));
    return NULL;
  }

  fd_snapin_test_topo_t * snapin = (fd_snapin_test_topo_t *)shsnapin;

  if( FD_UNLIKELY( snapin->magic!=FD_SNAPIN_TEST_TOPO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return snapin;
}

void
fd_snapin_test_topo_init( fd_snapin_test_topo_t * snapin,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp ) {
  /* set up scratch */
  fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ];
  ulong tile_footprint  = scratch_footprint( tile );
  void * tile_ctx       = fd_wksp_alloc_laddr( wksp, scratch_align(), tile_footprint, WKSP_TAG );
  snapin->ctx           = tile_ctx;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", "restore" );
  tile_obj->offset         = fd_wksp_gaddr_fast( wksp, tile_ctx );
  tile->tile_obj_id        = tile_obj->id;

  /* set up links */
  ulong id = fd_topo_find_link( topo, "snapdc_in", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapin->in_dc, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapin_manif", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapin->out_manif, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapin_ls", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapin->out_ls, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapin_wh", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapin->out_wh, topo, &topo->links[ id ] );

  fd_restore_init_stem( &snapin->mock_stem, topo, tile );

  /* make funk */
  ulong const funk_rec_max = 32UL;
  ulong const funk_txn_max = 16UL;
  snapin->accdb_funk = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( funk_txn_max, funk_rec_max ), WKSP_TAG );
  FD_TEST( fd_funk_new( snapin->accdb_funk, WKSP_TAG, 1UL, funk_txn_max, funk_rec_max ) );
  fd_topo_obj_t * funk_obj = fd_topob_obj( topo, "funk", "snapin" );
  funk_obj->offset = fd_wksp_gaddr_fast( wksp, snapin->accdb_funk );

  ulong const txncache_max_live_slots   = 4UL;
  ulong const txncache_max_txn_per_slot = 4UL;
  snapin->txncache = fd_wksp_alloc_laddr( wksp, fd_txncache_shmem_align(), fd_txncache_shmem_footprint( txncache_max_live_slots, txncache_max_txn_per_slot ), WKSP_TAG );
  FD_TEST( fd_txncache_shmem_new( snapin->txncache, txncache_max_live_slots, txncache_max_txn_per_slot ) );
  fd_topo_obj_t * txncache_obj = fd_topob_obj( topo, "txncache", "snapin" );
  txncache_obj->offset = fd_wksp_gaddr_fast( wksp, snapin->txncache );

  tile->snapin.use_vinyl       = 0;
  tile->snapin.lthash_disabled = 1;
  tile->snapin.max_live_slots  = 32UL;
  tile->snapin.funk_obj_id     = funk_obj->id;
  tile->snapin.txncache_obj_id = txncache_obj->id;
}

void
fd_snapin_test_topo_returnable_frag( fd_snapin_test_topo_t * snapin,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t *)snapin->ctx;

  fd_stem_context_t stem = {
    .mcaches             = snapin->mock_stem.out_mcache,
    .depths              = snapin->mock_stem.out_depth,
    .seqs                = snapin->mock_stem.seqs,
    .cr_avail            = snapin->mock_stem.cr_avail,
    .min_cr_avail        = &snapin->mock_stem.min_cr_avail,
    .cr_decrement_amount = 1UL
  };
  returnable_frag( ctx, in_idx, seq, sig, chunk, sz, ctl, tsorig, tspub, &stem );
}

void
fd_snapin_test_topo_fini( fd_snapin_test_topo_t * snapin ) {
  fd_wksp_free_laddr( snapin->ctx );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapin->in_dc.mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( snapin->out_manif.dcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( snapin->out_ls.dcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( snapin->out_wh.dcache ) ) );
}
