#ifndef HEADER_fd_src_disco_tiles_net_fd_net_tile_h
#define HEADER_fd_src_disco_tiles_net_fd_net_tile_h

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"

#include "../../../waltz/quic/fd_quic.h"
#include "../../../waltz/xdp/fd_xdp.h"
#include "../../../waltz/xdp/fd_xsk_private.h"
#include "../../../waltz/ip/fd_ip.h"
#include "../../../util/net/fd_ip4.h"

#define FD_NET_TILE_PORT_ALLOW_CNT 3UL

#define FD_NET_TILE_ALIGN (4096UL)

struct fd_net_tile_args {
  char const * app_name;
  char const * interface;

  ulong        tidx;
  ulong        round_robin_cnt;
  ulong        xdp_rx_queue_size;
  ulong        xdp_tx_queue_size;
  ulong        xdp_aio_depth;
  uint         src_ip_addr;
  uchar        src_mac_addr[ 6 ];
  ushort       allow_ports[ FD_NET_TILE_PORT_ALLOW_CNT ];
};

typedef struct fd_net_tile_args fd_net_tile_args_t;

struct fd_net_tile_topo {
  fd_wksp_t * in_wksp;
  ulong       in_mtu;

  fd_wksp_t * out_wksp;
  void *      out_dcache;
  ulong       out_mtu;
};

typedef struct fd_net_tile_topo fd_net_tile_topo_t;

struct __attribute__((aligned(FD_NET_TILE_ALIGN))) fd_net_tile_private {
  ulong xsk_aio_cnt;
  fd_xsk_aio_t * xsk_aio[ 2 ];

  ulong round_robin_cnt;
  ulong round_robin_id;

  const fd_aio_t * tx;
  const fd_aio_t * lo_tx;

  uchar frame[ FD_NET_MTU ];

  fd_mux_context_t * mux;

  uint   src_ip_addr;
  uchar  src_mac_addr[ 6 ];
  ushort allow_ports[ FD_NET_TILE_PORT_ALLOW_CNT ];

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  fd_ip_t *   ip;
  long        ip_next_upd;
};

typedef struct fd_net_tile_private fd_net_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_net_tile_align( void );

FD_FN_PURE ulong
fd_net_tile_footprint( fd_net_tile_args_t const * args );

ulong
fd_net_tile_seccomp_policy( void *               shnet,
                            struct sock_filter * out,
                            ulong                out_cnt );

ulong
fd_net_tile_allowed_fds( void * shnet,
                         int *  out,
                         ulong  out_cnt );

void
fd_net_tile_join_privileged( void *                     shnet,
                             fd_net_tile_args_t const * args );

fd_net_tile_t *
fd_net_tile_join( void *                     shnet,
                  fd_net_tile_args_t const * args,
                  fd_net_tile_topo_t const * topo );

void
fd_net_tile_run( fd_net_tile_t *         ctx,
                 fd_cnc_t *              cnc,
                 ulong                   in_cnt,
                 fd_frag_meta_t const ** in_mcache,
                 ulong **                in_fseq,
                 fd_frag_meta_t *        mcache,
                 ulong                   out_cnt,
                 ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_net_fd_net_tile_h */
