#include "tiles.h"

/* A /dev/null semantic tile which just drops (filters) every incoming
   packet it receives. */

static void
before_frag( void * _ctx    FD_PARAM_UNUSED,
             ulong  in_idx  FD_PARAM_UNUSED,
             ulong  seq     FD_PARAM_UNUSED,
             ulong  sig     FD_PARAM_UNUSED,
             int *  opt_filter ) {
  *opt_filter = 1;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

static void
run( fd_topo_t *             topo,
     fd_topo_tile_t *        tile,
     void *                  scratch,
     fd_cnc_t *              cnc,
     ulong                   in_cnt,
     fd_frag_meta_t const ** in_mcache,
     ulong **                in_fseq,
     fd_frag_meta_t *        mcache,
     ulong                   out_cnt,
     ulong **                out_fseq ) {
  fd_mux_callbacks_t callbacks = {
    .before_frag   = before_frag,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               1UL,
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               NULL,
               &callbacks );
}

fd_topo_run_tile_t fd_tile_blackhole = {
  .name                 = "bhole",
  .populate_allowed_fds = populate_allowed_fds,
  .run                  = run,
};
