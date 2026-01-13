#include "fd_snapld_test_topo.h"
#include "../fd_snapld_tile.c"
#include "../../../disco/topo/fd_topob.h"

#define WKSP_TAG 1UL

FD_FN_CONST ulong
fd_snapld_test_topo_align( void ) {
  return alignof(fd_snapld_test_topo_t);
}

FD_FN_CONST ulong
fd_snapld_test_topo_footprint( void ) {
  return sizeof(fd_snapld_test_topo_t);
}

void *
fd_snapld_test_topo_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_snapld_test_topo_align() ) ) ) {
    FD_LOG_WARNING(("unaligned shmem " ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_snapld_test_topo_t * snapld_topo = FD_SCRATCH_ALLOC_APPEND( l, fd_snapld_test_topo_align(), fd_snapld_test_topo_footprint() );
  fd_memset( snapld_topo, 0, sizeof(fd_snapld_test_topo_t) );

  FD_COMPILER_MFENCE();
  snapld_topo->magic = FD_SNAPLD_TEST_TOPO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)snapld_topo;
}

fd_snapld_test_topo_t *
fd_snapld_test_topo_join( void * shsnapld_topo ) {
  if( FD_UNLIKELY( !shsnapld_topo ) ) {
    FD_LOG_WARNING(( "NULL shsnapld_topo" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsnapld_topo, fd_snapld_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsnapld_topo" ));
    return NULL;
  }

  fd_snapld_test_topo_t * snapld_topo = (fd_snapld_test_topo_t *)shsnapld_topo;

  if( FD_UNLIKELY( snapld_topo->magic!=FD_SNAPLD_TEST_TOPO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return snapld_topo;
}

void
fd_snapld_test_topo_init( fd_snapld_test_topo_t * snapld_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp ) {
  /* set up scratch */
  fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapld", 0UL ) ];
  ulong tile_footprint  = scratch_footprint( tile );
  void * tile_ctx       = fd_wksp_alloc_laddr( wksp, scratch_align(), tile_footprint, WKSP_TAG );
  snapld_topo->ctx      = tile_ctx;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", "restore" );
  tile_obj->offset         = fd_wksp_gaddr_fast( wksp, tile_ctx );
  tile->tile_obj_id        = tile_obj->id;

  /* set up links */
  ulong id = fd_topo_find_link( topo, "snapct_ld", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapld_topo->in_ct, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapld_dc", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapld_topo->out_dc, topo, &topo->links[ id ] );

  fd_restore_init_stem( &snapld_topo->mock_stem, topo, tile );

  /* init tile config and dummy setup */
  fd_memcpy( tile->snapld.snapshots_path, snapshots_path, sizeof(snapshots_path) );
  privileged_init( topo, tile );
  unprivileged_init( topo, tile );
}

void
fd_snapld_test_topo_returnable_frag( fd_snapld_test_topo_t * snapld,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub ) {
  fd_snapld_tile_t * ctx = (fd_snapld_tile_t *)snapld->ctx;

  fd_stem_context_t stem = {
    .mcaches             = snapld->mock_stem.out_mcache,
    .depths              = snapld->mock_stem.out_depth,
    .seqs                = snapld->mock_stem.seqs,
    .cr_avail            = snapld->mock_stem.cr_avail,
    .min_cr_avail        = &snapld->mock_stem.min_cr_avail,
    .cr_decrement_amount = 1UL
  };
  returnable_frag( ctx, in_idx, seq, sig, chunk, sz, ctl, tsorig, tspub, &stem );
}

void
fd_snapld_test_topo_fini( fd_snapld_test_topo_t * snapld ) {
  fd_wksp_free_laddr( snapld->ctx );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapld->in_ct.mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( snapld->out_dc.dcache ) ) );
}
