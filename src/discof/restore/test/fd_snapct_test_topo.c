#include "fd_snapct_test_topo.h"
#include "../fd_snapct_tile.c"
#include "../../../disco/topo/fd_topob.h"

#define WKSP_TAG 1UL

FD_FN_CONST ulong
fd_snapct_test_topo_align( void ) {
  return alignof(fd_snapct_test_topo_t);
}

FD_FN_CONST ulong
fd_snapct_test_topo_footprint( void ) {
  return sizeof(fd_snapct_test_topo_t);
}

void *
fd_snapct_test_topo_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_snapct_test_topo_align() ) ) ) {
    FD_LOG_WARNING(("unaligned shmem " ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_snapct_test_topo_t * snapct_topo = FD_SCRATCH_ALLOC_APPEND( l, fd_snapct_test_topo_align(), fd_snapct_test_topo_footprint() );
  fd_memset( snapct_topo, 0, sizeof(fd_snapct_test_topo_t) );

  FD_COMPILER_MFENCE();
  snapct_topo->magic = FD_SNAPCT_TEST_TOPO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)snapct_topo;
}

fd_snapct_test_topo_t *
fd_snapct_test_topo_join( void * shsnapct_topo ) {
  if( FD_UNLIKELY( !shsnapct_topo ) ) {
    FD_LOG_WARNING(( "NULL shsnapct_topo" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsnapct_topo, fd_snapct_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsnapct_topo" ));
    return NULL;
  }

  fd_snapct_test_topo_t * snapct_topo = (fd_snapct_test_topo_t *)shsnapct_topo;

  if( FD_UNLIKELY( snapct_topo->magic!=FD_SNAPCT_TEST_TOPO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return snapct_topo;
}

void
fd_snapct_test_topo_init( fd_snapct_test_topo_t * snapct_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp ) {
  /* set up scratch */
  fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapct", 0UL ) ];
  ulong tile_footprint  = scratch_footprint( tile );
  void * tile_ctx       = fd_wksp_alloc_laddr( wksp, scratch_align(), tile_footprint, WKSP_TAG );
  snapct_topo->ctx      = tile_ctx;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", "restore" );
  tile_obj->offset         = fd_wksp_gaddr_fast( wksp, tile_ctx );
  tile->tile_obj_id        = tile_obj->id;

  /* set up links */
  ulong id = fd_topo_find_link( topo, "snapld_dc", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapct_topo->in_snapld, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapls_ct", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapct_topo->in_ack, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapct_ld", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapct_topo->out_ld, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapct_repr", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapct_topo->out_repr, topo, &topo->links[ id ] );

  fd_restore_init_stem( &snapct_topo->mock_stem, topo, tile );

  /* TODO: maybe configurable in the future */
  fd_memcpy( tile->snapld.snapshots_path, snapshots_path, sizeof(snapshots_path) );
  tile->snapct.incremental_snapshots             = 1;
  tile->snapct.max_full_snapshots_to_keep        = 1;
  tile->snapct.max_incremental_snapshots_to_keep = 1;

  /* TODO: make these configurable */
  tile->snapct.sources.max_local_full_effective_age = 1000UL;
  tile->snapct.sources.max_local_incremental_age    = 1000UL;

  tile->snapct.sources.servers_cnt           = 0;
  tile->snapct.sources.gossip.allow_any      = 0;
  tile->snapct.sources.gossip.allow_list_cnt = 0;
  tile->snapct.sources.gossip.block_list_cnt = 0;

  privileged_init( topo, tile );
  unprivileged_init( topo, tile );
}

void
fd_snapct_test_topo_returnable_frag( fd_snapct_test_topo_t * snapct,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub ) {
  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)snapct->ctx;

  fd_stem_context_t stem = {
    .mcaches             = snapct->mock_stem.out_mcache,
    .depths              = snapct->mock_stem.out_depth,
    .seqs                = snapct->mock_stem.seqs,
    .cr_avail            = snapct->mock_stem.cr_avail,
    .min_cr_avail        = &snapct->mock_stem.min_cr_avail,
    .cr_decrement_amount = 1UL
  };
  returnable_frag( ctx, in_idx, seq, sig, chunk, sz, ctl, tsorig, tspub, &stem );
}

void
fd_snapct_test_topo_fini( fd_snapct_test_topo_t * snapct ) {
  fd_wksp_free_laddr( snapct->ctx );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapct->in_snapld.mcache ) ) );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapct->in_ack.mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( snapct->out_ld.dcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( snapct->out_repr.dcache ) ) );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapct->out_repr.mcache ) ) );
}