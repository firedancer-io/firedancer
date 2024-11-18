#ifndef HEADER_fd_src_app_fddev_quic_trace_fd_quic_trace_h
#define HEADER_fd_src_app_fddev_quic_trace_fd_quic_trace_h

#include "../../../disco/topo/fd_topo.h"
#include "../../fdctl/run/tiles/fd_quic_tile.h"

struct fd_quic_trace_tile_ctx {
  uchar buffer[ FD_NET_MTU ];

  fd_wksp_t *           in_mem[ FD_TOPO_MAX_TILE_IN_LINKS ];
  ulong *               target_fseq[ FD_TOPO_MAX_TILE_IN_LINKS ];
  fd_quic_ctx_t const * remote_ctx;
};

typedef struct fd_quic_trace_tile_ctx fd_quic_trace_tile_ctx_t;

/* fd_quic_trace_target_fseq are the fseq counters published by the
   target quic tile */

extern ulong ** fd_quic_trace_target_fseq;

/* fd_tile_quic_trace_rx is the tile in fd_quic_trace_tx_tile.c */

extern fd_topo_run_tile_t fd_tile_quic_trace_rx;

void
quic_trace_run( ulong                      in_cnt,
                fd_frag_meta_t const **    in_mcache,
                ulong **                   in_fseq,
                ulong                      out_cnt,
                fd_frag_meta_t **          out_mcache,
                ulong                      cons_cnt,
                ulong *                    _cons_out,
                ulong **                   _cons_fseq,
                ulong                      burst,
                long                       lazy,
                fd_rng_t *                 rng,
                void *                     scratch,
                fd_quic_trace_tile_ctx_t * ctx );

#endif /* HEADER_fd_src_app_fddev_quic_trace_fd_quic_trace_h */
