#include "tiles.h"

static long allow_syscalls[] = {
  __NR_write, /* logging */
  __NR_fsync, /* logging, WARNING and above fsync immediately */
};

static ulong
allow_fds( void * scratch,
           ulong  out_fds_cnt,
           int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  return 2;
}

fd_tile_config_t fd_tile_netmux = {
  .mux_flags           = FD_MUX_FLAG_DEFAULT,
  .burst               = 1UL,
  .mux_ctx             = NULL,
  .allow_syscalls_cnt  = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls      = allow_syscalls,
  .allow_fds           = allow_fds,
  .scratch_align       = NULL,
  .scratch_footprint   = NULL,
  .privileged_init     = NULL,
  .unprivileged_init   = NULL,
};
