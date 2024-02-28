#include "fd_netmux_tile.h"

#include "generated/fd_netmux_tile_seccomp.h"
#include <linux/unistd.h>

ulong
fd_netmux_tile_seccomp_policy( void *               shnetmux,
                               struct sock_filter * out,
                               ulong                out_cnt ) {
  (void)shnetmux;
  populate_sock_filter_policy_fd_netmux_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_netmux_tile_instr_cnt;
}

ulong
fd_netmux_tile_allowed_fds( void * shnetmux,
                            int *  out,
                            ulong  out_cnt ) {
  (void)shnetmux;

  if( FD_UNLIKELY( out_cnt<2UL ) ) FD_LOG_ERR(( "out_cnt %lu", out_cnt ));

  ulong out_idx = 0UL;
  out[ out_idx++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) out[ out_idx++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_idx;
}

void
fd_netmux_tile_run( void *                  ctx,
                    fd_cnc_t *              cnc,
                    ulong                   in_cnt,
                    fd_frag_meta_t const ** in_mcache,
                    ulong **                in_fseq,
                    fd_frag_meta_t *        mcache,
                    ulong                   out_cnt,
                    ulong **                out_fseq ) {
  (void)ctx;

  fd_mux_callbacks_t callbacks = { 0 };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_DEFAULT,
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
