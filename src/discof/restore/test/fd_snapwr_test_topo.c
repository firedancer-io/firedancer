#include "fd_snapwr_test_topo.h"
#include "../fd_snapwr_tile.c"
#include "../../../disco/topo/fd_topob.h"

#define WKSP_TAG 1UL

FD_FN_CONST ulong
fd_snapwr_test_topo_align( void ) {
  return alignof(fd_snapwr_test_topo_t);
}

FD_FN_CONST ulong
fd_snapwr_test_topo_footprint( void ) {
  return sizeof(fd_snapwr_test_topo_t);
}

void *
fd_snapwr_test_topo_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_snapwr_test_topo_align() ) ) ) {
    FD_LOG_WARNING(("unaligned shmem " ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_snapwr_test_topo_t * snapwr_topo = FD_SCRATCH_ALLOC_APPEND( l, fd_snapwr_test_topo_align(), fd_snapwr_test_topo_footprint() );
  fd_memset( snapwr_topo, 0, sizeof(fd_snapwr_test_topo_t) );

  FD_COMPILER_MFENCE();
  snapwr_topo->magic = FD_SNAPWR_TEST_TOPO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)snapwr_topo;
}

fd_snapwr_test_topo_t *
fd_snapwr_test_topo_join( void * shsnapwr_topo ) {
  if( FD_UNLIKELY( !shsnapwr_topo ) ) {
    FD_LOG_WARNING(( "NULL shsnapwr_topo" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsnapwr_topo, fd_snapwr_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsnapwr_topo" ));
    return NULL;
  }

  fd_snapwr_test_topo_t * snapwr_topo = (fd_snapwr_test_topo_t *)shsnapwr_topo;

  if( FD_UNLIKELY( snapwr_topo->magic!=FD_SNAPWR_TEST_TOPO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return snapwr_topo;
}

void
fd_snapwr_test_topo_init( fd_snapwr_test_topo_t * snapwr_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp ) {
  /* set up scratch */
  fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapwr", 0UL ) ];
  ulong tile_footprint  = scratch_footprint( tile );
  void * tile_ctx       = fd_wksp_alloc_laddr( wksp, scratch_align(), tile_footprint, WKSP_TAG );
  snapwr_topo->ctx      = tile_ctx;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", "restore" );
  tile_obj->offset         = fd_wksp_gaddr_fast( wksp, tile_ctx );
  tile->tile_obj_id        = tile_obj->id;

  /* set up links */
  ulong id = fd_topo_find_link( topo, "snapwh_wr", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapwr_topo->in_wh, topo, &topo->links[ id ] );

  fd_restore_init_stem( &snapwr_topo->mock_stem, topo, tile );
}

void
fd_snapwr_test_topo_during_frag( fd_snapwr_test_topo_t * snapwr,
                                 ulong                   in_idx,
                                 ulong                   seq,
                                 ulong                   sig,
                                 ulong                   chunk,
                                 ulong                   sz,
                                 ulong                   ctl ) {
  fd_snapwr_t * ctx = (fd_snapwr_t *)snapwr->ctx;

  during_frag( ctx, in_idx, seq, sig, chunk, sz, ctl );
}

void
fd_snapwr_test_topo_fini( fd_snapwr_test_topo_t * snapwr ) {
  fd_wksp_free_laddr( snapwr->ctx );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapwr->in_wh.mcache ) ) );
}
