#ifndef HEADER_fd_src_disco_net_fd_net_h
#define HEADER_fd_src_disco_net_fd_net_h

#include "../fd_disco_base.h"

#include "../fd_disco_base.h"
#include "../../tango/quic/fd_quic.h"
#include "../../tango/xdp/fd_xdp.h"

#define FD_NET_TILE_SCRATCH_ALIGN (128UL)
#define FD_NET_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt )                                \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
    FD_AIO_ALIGN,                FD_AIO_FOOTPRINT ),                                    \
    alignof(fd_verify_in_ctx_t), (in_cnt)*sizeof(fd_verify_in_ctx_t) ),                 \
    FD_MUX_TILE_SCRATCH_ALIGN,   FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),    \
    FD_VERIFY_TILE_SCRATCH_ALIGN )

FD_PROTOTYPES_BEGIN

int
fd_net_tile( fd_cnc_t *              cnc,                     /* Local join to the quic's command-and-control */
             ulong                   pid,                     /* Tile PID for diagnostic purposes */
             ulong                   in_cnt,
             const fd_frag_meta_t ** in_mcache,
             ulong **                in_fseq,
             ulong                   round_robin_cnt,
             ulong                   round_robin_id,
             ulong                   xsk_aio_cnt,             /* Number of xsk_aio producers to poll, indexed [0,xsk_aio_cnt)] */
             fd_xsk_aio_t **         xsk_aio,                 /* xsk_aio[xsk_aio_idx] is the local join to xsk_aio producer */
             fd_frag_meta_t *        mcache,                  /* Local join to the quic's frag stream output mcache */
             uchar *                 dcache,                  /* Local join to the quic's frag stream output dcache */
             ulong                   cr_max,                  /* Maximum number of flow control credits, 0 means use a reasonable default */
             long                    lazy,                    /* Lazyiness, <=0 means use a reasonable default */
             fd_rng_t *              rng,                     /* Local join to the rng this quic should use */
             void *                  scratch );               /* Tile scratch memory */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_net_h */
