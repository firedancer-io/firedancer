#include "fd_snapin_tile.c"

#include <stdlib.h>

/* Regression: scratch_align() must cover the largest FD_LAYOUT_APPEND
   alignment in scratch_footprint (the 4096-aligned write buffer).  The
   footprint is computed from a zero base, so if the topology placed the
   tile object at a smaller alignment the runtime layout could consume
   up to align-scratch_align more bytes than the footprint and overflow
   into the next workspace object. */

static void
test_scratch_layout_fits( void ) {
  FD_TEST( scratch_align()>=alignof(fd_snapin_tile_t) );
  FD_TEST( scratch_align()>=fd_accdb_align() );
  FD_TEST( scratch_align()>=4096UL ); /* write buffer */

  fd_topo_tile_t tile[1];
  memset( tile, 0, sizeof(fd_topo_tile_t) );
  tile->snapin.max_live_slots = 1024UL;

  /* Replay unprivileged_init's layout for both tile kinds and verify it
     fits within the declared footprint. */
  for( ulong kind_id=0UL; kind_id<2UL; kind_id++ ) {
    tile->kind_id = kind_id;
    ulong footprint = scratch_footprint( tile );

    FD_SCRATCH_ALLOC_INIT( l, NULL );
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
    FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),          fd_accdb_footprint( tile->snapin.max_live_slots ) );
    if( !kind_id ) {
      FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),           fd_txncache_footprint( tile->snapin.max_live_slots )        );
      FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(),  fd_ssmanifest_parser_footprint()                            );
      FD_SCRATCH_ALLOC_APPEND( l, fd_slot_delta_parser_align(),  fd_slot_delta_parser_footprint()                            );
      FD_SCRATCH_ALLOC_APPEND( l, alignof(blockhash_group_t),    sizeof(blockhash_group_t)*FD_SNAPIN_MAX_SLOT_DELTA_GROUPS   );
      FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sstxncache_hash_t), sizeof(fd_sstxncache_hash_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );
    }
    FD_SCRATCH_ALLOC_APPEND( l, 4096UL, FD_SNAPIN_WRITE_BUF_SZ );
    ulong end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
    FD_TEST( end<=footprint );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_scratch_layout_fits();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
