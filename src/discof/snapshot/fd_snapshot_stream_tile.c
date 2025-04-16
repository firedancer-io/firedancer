#include "../tiles.h"

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_archiver_feeder_tile_ctx_t), sizeof(fd_archiver_feeder_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}