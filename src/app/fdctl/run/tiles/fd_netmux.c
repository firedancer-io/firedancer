#include "tiles.h"

#include "generated/netmux_seccomp.h"
#include <linux/unistd.h>

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_netmux( out_cnt, out, (unsigned int)fd_log_private_logfile_fd() );
  return sock_filter_policy_netmux_instr_cnt;
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

fd_tile_config_t fd_tile_netmux = {
  .mux_flags                = FD_MUX_FLAG_DEFAULT,
  .burst                    = 1UL,
  .mux_ctx                  = NULL,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = NULL,
  .scratch_footprint        = NULL,
  .privileged_init          = NULL,
  .unprivileged_init        = NULL,
};
