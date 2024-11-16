#ifndef HEADER_fd_src_app_fddev_quic_trace_fd_quic_trace_h
#define HEADER_fd_src_app_fddev_quic_trace_fd_quic_trace_h

#include "../../../disco/topo/fd_topo.h"
#include "../../fdctl/run/tiles/fd_quic_tile.h"

/* fd_quic_trace_ctx is the relocated fd_quic_ctx_t of the target quic
   tile.  fd_quic_trace_ctx_remote is the original fd_quic_ctx_t, but
   the pointer itself is in the local address space. */

extern fd_quic_ctx_t         fd_quic_trace_ctx;
extern fd_quic_ctx_t const * fd_quic_trace_ctx_remote;

/* fd_quic_trace_target_fseq are the fseq counters published by the
   target quic tile */

extern ulong ** fd_quic_trace_target_fseq;

/* fd_tile_quic_trace_rx is the tile in fd_quic_trace_tx_tile.c */

extern fd_topo_run_tile_t fd_tile_quic_trace_rx;

#endif /* HEADER_fd_src_app_fddev_quic_trace_fd_quic_trace_h */
