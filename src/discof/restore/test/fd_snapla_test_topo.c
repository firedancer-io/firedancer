#include "fd_snapla_test_topo.h"
#include "../fd_snapla_tile.c"
#include "../../../disco/topo/fd_topob.h"

#define WKSP_TAG 1UL

FD_FN_CONST ulong
fd_snapla_test_topo_align( void ) {
  return alignof(fd_snapla_test_topo_t);
}

FD_FN_CONST ulong
fd_snapla_test_topo_footprint( void ) {
  return sizeof(fd_snapla_test_topo_t);
}

void *
fd_snapla_test_topo_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_snapla_test_topo_align() ) ) ) {
    FD_LOG_WARNING(("unaligned shmem " ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_snapla_test_topo_t * snapla_topo = FD_SCRATCH_ALLOC_APPEND( l, fd_snapla_test_topo_align(), fd_snapla_test_topo_footprint() );
  fd_memset( snapla_topo, 0, sizeof(fd_snapla_test_topo_t) );

  FD_COMPILER_MFENCE();
  snapla_topo->magic = FD_SNAPLA_TEST_TOPO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)snapla_topo;
}

fd_snapla_test_topo_t *
fd_snapla_test_topo_join( void * shsnapla_topo ) {
  if( FD_UNLIKELY( !shsnapla_topo ) ) {
    FD_LOG_WARNING(( "NULL shsnapla_topo" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsnapla_topo, fd_snapla_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsnapla_topo" ));
    return NULL;
  }

  fd_snapla_test_topo_t * snapla_topo = (fd_snapla_test_topo_t *)shsnapla_topo;

  if( FD_UNLIKELY( snapla_topo->magic!=FD_SNAPLA_TEST_TOPO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return snapla_topo;
}

void
fd_snapla_test_topo_init( fd_snapla_test_topo_t * snapla_topo,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp ) {
  /* set up scratch */
  fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapla", 0UL ) ];
  ulong tile_footprint  = scratch_footprint( tile );
  void * tile_ctx       = fd_wksp_alloc_laddr( wksp, scratch_align(), tile_footprint, WKSP_TAG );
  snapla_topo->ctx      = tile_ctx;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", "restore" );
  tile_obj->offset         = fd_wksp_gaddr_fast( wksp, tile_ctx );
  tile->tile_obj_id        = tile_obj->id;

  /* set up links */
  ulong id = fd_topo_find_link( topo, "snapdc_in", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapla_topo->in_dc, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapla_ls", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapla_topo->out_ls, topo, &topo->links[ id ] );

  fd_restore_init_stem( &snapla_topo->mock_stem, topo, tile );
}

void
fd_snapla_test_topo_returnable_frag( fd_snapla_test_topo_t * snapla,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub ) {
  fd_snapla_tile_t * ctx = (fd_snapla_tile_t *)snapla->ctx;

  fd_stem_context_t stem = {
    .mcaches             = snapla->mock_stem.out_mcache,
    .depths              = snapla->mock_stem.out_depth,
    .seqs                = snapla->mock_stem.seqs,
    .cr_avail            = snapla->mock_stem.cr_avail,
    .min_cr_avail        = &snapla->mock_stem.min_cr_avail,
    .cr_decrement_amount = 1UL
  };
  returnable_frag( ctx, in_idx, seq, sig, chunk, sz, ctl, tsorig, tspub, &stem );
}

void
fd_snapla_test_topo_fini( fd_snapla_test_topo_t * snapla ) {
  fd_wksp_free_laddr( snapla->ctx );
  fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( snapla->in_dc.mcache ) ) );
  fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( snapla->out_ls.dcache ) ) );
}
