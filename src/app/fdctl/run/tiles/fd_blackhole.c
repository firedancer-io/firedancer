#include "../../../../disco/tiles.h"

/**
 * Tile used to filter out all packets when used as a consumer.
 * As the name suggests, it is a "black hole" for incoming packets.
*/

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
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_blackhole = {
  .name                     = "bhole",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_before_frag          = before_frag,
  .populate_allowed_fds     = populate_allowed_fds,
  .privileged_init          = NULL,
};
