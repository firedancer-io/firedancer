#include "../../../../disco/tiles.h"

/* A /dev/null semantic tile which just drops (filters) every incoming
   packet it receives. */

static inline int
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig ) {
  (void)_ctx;
  (void)in_idx;
  (void)seq;
  (void)sig;

  return 1;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  void
#define STEM_CALLBACK_CONTEXT_ALIGN 1UL

#define STEM_CALLBACK_BEFORE_FRAG before_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_blackhole = {
  .name                 = "bhole",
  .populate_allowed_fds = populate_allowed_fds,
  .run                  = stem_run,
};
