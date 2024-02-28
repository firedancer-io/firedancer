#ifndef HEADER_fd_src_disco_topo_fd_topo_builder_h
#define HEADER_fd_src_disco_topo_fd_topo_builder_h

#include "fd_topo.h"

void
fd_topo_builder_add_wksp( uchar *      pod,
                          char const * name,
                          ulong        loose_sz );

void
fd_topo_builder_add_links( uchar *      pod,
                           ulong        cnt,
                           char const * wksp_name,
                           char const * link_name,
                           ulong        depth,
                           int          reasm,
                           ulong        mtu,
                           ulong        burst );

void
fd_topo_builder_add_tiles( uchar *        pod,
                           ulong          cnt,
                           char const *   wksp_name,
                           char const *   tile_name,
                           char const *   primary_out_name,
                           ulong          primary_out_index,
                           int            is_solana_labs,
                           ushort const * cpu_idx );

void
fd_topo_builder_add_tile_ins( uchar *      pod,
                              ulong        cnt,
                              char const * wksp_name,
                              char const * tile_name,
                              ulong        tile_index,
                              char const * link_name,
                              ulong        link_index,
                              int          reliable,
                              int          polled );

void
fd_topo_builder_add_tile_outs( uchar *      pod,
                               ulong        cnt,
                               char const * tile_name,
                               ulong        tile_index,
                               char const * link_name,
                               ulong        link_index );

#endif /* HEADER_fd_src_util_topo_fd_topo_builder_h */
