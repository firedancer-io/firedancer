#ifndef HEADER_fd_src_app_fdctl_run_tiles_fd_quic_tile_h
#define HEADER_fd_src_app_fdctl_run_tiles_fd_quic_tile_h

#include "fd_tpu.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"
#include "../net/fd_net_tile.h"
#include "../../waltz/quic/fd_quic.h"
#include "../../util/io/fd_io.h"

#define FD_QUIC_TILE_IN_MAX (8UL)

extern fd_topo_run_tile_t fd_tile_quic;

typedef struct {
  fd_tpu_reasm_t * reasm;

  fd_stem_context_t * stem;

  fd_quic_t * quic;
  fd_aio_t    quic_tx_aio[1];

# define ED25519_PRIV_KEY_SZ (32)
# define ED25519_PUB_KEY_SZ  (32)
  uchar            tls_priv_key[ ED25519_PRIV_KEY_SZ ];
  uchar            tls_pub_key [ ED25519_PUB_KEY_SZ  ];
  fd_sha512_t      sha512[1]; /* used for signing */

  uchar buffer[ FD_NET_MTU ];

  ulong round_robin_cnt;
  ulong round_robin_id;

  fd_net_rx_bounds_t net_in_bounds[ FD_QUIC_TILE_IN_MAX ];

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  fd_wksp_t * verify_out_mem;

  long                     keylog_next_flush;
  int                      keylog_fd;
  fd_io_buffered_ostream_t keylog_stream;
  char                     keylog_buf[ 4096 ];

  struct {
    ulong txns_received_udp;
    ulong txns_received_quic_fast;
    ulong txns_received_quic_frag;
    ulong frag_ok_cnt;
    ulong frag_gap_cnt;
    ulong frag_dup_cnt;
    long  reasm_active;
    ulong reasm_overrun;
    ulong reasm_abandoned;
    ulong reasm_started;
    ulong udp_pkt_too_small;
    ulong udp_pkt_too_large;
    ulong quic_txn_too_small;
    ulong quic_txn_too_large;
  } metrics;
} fd_quic_ctx_t;

#endif /* HEADER_fd_src_app_fdctl_run_tiles_fd_quic_tile_h */
