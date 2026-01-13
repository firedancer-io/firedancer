#include "fd_snapwh_test_topo.h"
#include "../fd_snapwh_tile.c"
#include "../../../disco/topo/fd_topob.h"

#define WKSP_TAG 1UL

FD_FN_CONST ulong
fd_snapwh_test_topo_align( void ) {
  return alignof(fd_snapwh_test_topo_t);
}

FD_FN_CONST ulong
fd_snapwh_test_topo_footprint( void ) {
  return sizeof(fd_snapwh_test_topo_t);
}

void *
fd_snapwh_test_topo_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_snapwh_test_topo_align() ) ) ) {
    FD_LOG_WARNING(("unaligned shmem " ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_snapwh_test_topo_t * snapwh_topo = FD_SCRATCH_ALLOC_APPEND( l, fd_snapwh_test_topo_align(), fd_snapwh_test_topo_footprint() );
  fd_memset( snapwh_topo, 0, sizeof(fd_snapwh_test_topo_t) );

  FD_COMPILER_MFENCE();
  snapwh_topo->magic = FD_SNAPWH_TEST_TOPO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)snapwh_topo;
}

fd_snapwh_test_topo_t *
fd_snapwh_test_topo_join( void * shsnapwh_topo ) {
  if( FD_UNLIKELY( !shsnapwh_topo ) ) {
    FD_LOG_WARNING(( "NULL shsnapwh_topo" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsnapwh_topo, fd_snapwh_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsnapwh_topo" ));
    return NULL;
  }

  fd_snapwh_test_topo_t * snapwh_topo = (fd_snapwh_test_topo_t *)shsnapwh_topo;

  if( FD_UNLIKELY( snapwh_topo->magic!=FD_SNAPWH_TEST_TOPO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return snapwh_topo;
}

void
fd_snapwh_test_topo_init( fd_snapwh_test_topo_t * snapwh_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp ) {
  /* set up scratch */
  fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapwh", 0UL ) ];
  ulong tile_footprint  = scratch_footprint( tile );
  void * tile_ctx       = fd_wksp_alloc_laddr( wksp, scratch_align(), tile_footprint, WKSP_TAG );
  snapwh_topo->ctx      = tile_ctx;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", "restore" );
  tile_obj->offset         = fd_wksp_gaddr_fast( wksp, tile_ctx );
  tile->tile_obj_id        = tile_obj->id;

  /* set up links */
  ulong id = fd_topo_find_link( topo, "snapin_wh", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapwh_topo->in_snapin, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapwh_wr", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapwh_topo->out_wr, topo, &topo->links[ id ] );

  fd_restore_init_stem( &snapwh_topo->mock_stem, topo, tile );
}

void
fd_snapwh_test_topo_during_frag( fd_snapwh_test_topo_t * snapwh,
                                 ulong                   in_idx,
                                 ulong                   seq,
                                 ulong                   sig,
                                 ulong                   chunk,
                                 ulong                   sz,
                                 ulong                   ctl ) {
  fd_snapwh_t * ctx = (fd_snapwh_t *)snapwh->ctx;

  during_frag( ctx, in_idx, seq, sig, chunk, sz, ctl );
}

void
fd_snapwh_test_topo_fini( fd_snapwh_test_topo_t * snapwh ) {
  fd_wksp_free_laddr( snapwh->ctx );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapwh->in_snapin.mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( snapwh->out_wr.dcache ) ) );
}
