#include "fd_snapls_test_topo.h"
#include "../fd_snapls_tile.c"
#include "../../../disco/topo/fd_topob.h"


#define WKSP_TAG 1UL

FD_FN_CONST ulong
fd_snapls_test_topo_align( void ) {
  return alignof(fd_snapls_test_topo_t);
}

FD_FN_CONST ulong
fd_snapls_test_topo_footprint( void ) {
  return sizeof(fd_snapls_test_topo_t);
}

void *
fd_snapls_test_topo_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_snapls_test_topo_align() ) ) ) {
    FD_LOG_WARNING(("unaligned shmem " ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_snapls_test_topo_t * snapls_topo = FD_SCRATCH_ALLOC_APPEND( l, fd_snapls_test_topo_align(), fd_snapls_test_topo_footprint() );
  fd_memset( snapls_topo, 0, sizeof(fd_snapls_test_topo_t) );

  FD_COMPILER_MFENCE();
  snapls_topo->magic = FD_SNAPLS_TEST_TOPO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)snapls_topo;
}

fd_snapls_test_topo_t *
fd_snapls_test_topo_join( void * shsnapls_topo ) {
  if( FD_UNLIKELY( !shsnapls_topo ) ) {
    FD_LOG_WARNING(( "NULL shsnapls_topo" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsnapls_topo, fd_snapls_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsnapls_topo" ));
    return NULL;
  }

  fd_snapls_test_topo_t * snapls_topo = (fd_snapls_test_topo_t *)shsnapls_topo;

  if( FD_UNLIKELY( snapls_topo->magic!=FD_SNAPLS_TEST_TOPO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return snapls_topo;
}

void
fd_snapls_test_topo_init( fd_snapls_test_topo_t * snapls_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp ) {
  /* set up scratch */
  fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapls", 0UL ) ];
  ulong tile_footprint  = scratch_footprint( tile );
  void * tile_ctx       = fd_wksp_alloc_laddr( wksp, scratch_align(), tile_footprint, WKSP_TAG );
  snapls_topo->ctx      = tile_ctx;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", "restore" );
  tile_obj->offset         = fd_wksp_gaddr_fast( wksp, tile_ctx );
  tile->tile_obj_id        = tile_obj->id;

  /* set up links */
  ulong id = fd_topo_find_link( topo, "snapin_ls", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapls_topo->in_snapin, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapla_ls", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapls_topo->in_snapla, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapls_ct", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapls_topo->out_ct, topo, &topo->links[ id ] );

  fd_restore_init_stem( &snapls_topo->mock_stem, topo, tile );
}

void
fd_snapls_test_topo_returnable_frag( fd_snapls_test_topo_t * snapls,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub ) {
  fd_snapls_tile_t * ctx = (fd_snapls_tile_t *)snapls->ctx;

  fd_stem_context_t stem = {
    .mcaches             = snapls->mock_stem.out_mcache,
    .depths              = snapls->mock_stem.out_depth,
    .seqs                = snapls->mock_stem.seqs,
    .cr_avail            = snapls->mock_stem.cr_avail,
    .min_cr_avail        = &snapls->mock_stem.min_cr_avail,
    .cr_decrement_amount = 1UL
  };
  returnable_frag( ctx, in_idx, seq, sig, chunk, sz, ctl, tsorig, tspub, &stem );
}

void
fd_snapls_test_topo_fini( fd_snapls_test_topo_t * snapls ) {
  fd_wksp_free_laddr( snapls->ctx );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapls->in_snapin.mcache ) ) );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapls->in_snapla.mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( snapls->out_ct.dcache ) ) );
}
