#ifndef HEADER_fd_src_disco_tiles_metric_fd_netmux_tile_h
#define HEADER_fd_src_disco_tiles_metric_fd_netmux_tile_h

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"

FD_PROTOTYPES_BEGIN

ulong
fd_netmux_tile_seccomp_policy( void *               shnetmux,
                               struct sock_filter * out,
                               ulong                out_cnt );

ulong
fd_netmux_tile_allowed_fds( void * shnetmux,
                            int *  out,
                            ulong  out_cnt );

void
fd_netmux_tile_run( void *                  ctx,
                    fd_cnc_t *              cnc,
                    ulong                   in_cnt,
                    fd_frag_meta_t const ** in_mcache,
                    ulong **                in_fseq,
                    fd_frag_meta_t *        mcache,
                    ulong                   out_cnt,
                    ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_metric_fd_netmux_tile_h */
