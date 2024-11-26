#ifndef HEADER_fd_src_app_fdctl_run_tiles_fd_quic_tile_h
#define HEADER_fd_src_app_fdctl_run_tiles_fd_quic_tile_h

#include "../../../../disco/quic/fd_tpu.h"
#include "../../../../disco/stem/fd_stem.h"
#include "../../../../waltz/quic/fd_quic.h"

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

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  fd_wksp_t * verify_out_mem;

  double ns_per_tick;
  ulong  last_tick;
  ulong  last_wall;

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
    ulong quic_pkt_too_small;
    ulong quic_txn_too_small;
    ulong quic_txn_too_large;
  } metrics;
} fd_quic_ctx_t;

#endif /* HEADER_fd_src_app_fdctl_run_tiles_fd_quic_tile_h */
