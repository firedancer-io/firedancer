#ifndef HEADER_fd_src_disco_tiles_quic_fd_quic_tile_h
#define HEADER_fd_src_disco_tiles_quic_fd_quic_tile_h

/* fd_quic provides a QUIC server tile.

   This tile handles all incoming QUIC traffic.  Supported protocols
   currently include TPU/QUIC (transactions).

   At present, TPU is the only protocol deployed on QUIC.  It allows
   clients to send transactions to block producers (this tile).    In QUIC, this
   can occur in as little as a single packet (and an ACK by the server).

   The fd_quic tile acts as a plain old Tango producer writing to a cnc
   and an mcache.  The tile will defragment multi-packet TPU streams
   coming in from QUIC, such that each mcache/dcache pair forms a
   complete txn.  This requires the dcache mtu to be at least that of
   the largest allowed serialized txn size.

   QUIC tiles don't service network devices directly, but rely on
   packets being received by net tiles and forwarded on via. a mux
   (multiplexer).  An arbitrary number of QUIC tiles can be run, and
   these will round-robin packets from the networking queues based on
   the source IP address. */

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"

#include "../../quic/fd_tpu.h"
#include "../../keyguard/fd_keyguard_client.h"

#include "../../../waltz/quic/fd_quic.h"

#define FD_QUIC_TILE_ALIGN (4096UL)

struct fd_quic_tile_args {
  uint   reasm_cnt;
  ulong  max_concurrent_connections;
  ulong  max_concurrent_handshakes;
  ulong  max_inflight_quic_packets;
  ulong  tx_buf_size;
  ulong  max_concurrent_streams_per_connection;
  uint   ip_addr;
  uchar  src_mac_addr[ 6 ];
  ushort quic_transaction_listen_port;
  ushort legacy_transaction_listen_port;
  ulong  idle_timeout_millis;

  ulong  tidx;
  ulong  round_robin_cnt;

  char const * identity_key_path;
};

typedef struct fd_quic_tile_args fd_quic_tile_args_t;

struct fd_quic_tile_topo {
  fd_wksp_t * netmux_in_wksp;
  ulong       netmux_in_mtu;

  fd_wksp_t *      netmux_out_wksp;
  fd_frag_meta_t * netmux_out_mcache;
  void *           netmux_out_dcache;
  ulong            netmux_out_mtu;

  ulong            verify_out_depth;
  fd_wksp_t *      verify_out_wksp;
  fd_tpu_reasm_t * verify_out_reasm;

  fd_frag_meta_t * sign_out_mcache;
  void *           sign_out_dcache;
  fd_frag_meta_t * sign_in_mcache;
  void *           sign_in_dcache;
};

typedef struct fd_quic_tile_topo fd_quic_tile_topo_t;

struct __attribute__((aligned(FD_QUIC_TILE_ALIGN))) fd_quic_tile_private {
  fd_tpu_reasm_t * reasm;

  fd_mux_context_t * mux;

  fd_quic_t *      quic;
  const fd_aio_t * quic_rx_aio;

  ushort legacy_transaction_port; /* port for receiving non-QUIC (raw UDP) transactions on*/

  fd_keyguard_client_t keyguard_client[1];

  uchar buffer[ FD_NET_MTU ];

  ulong conn_seq; /* current quic connection sequence number */

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

  struct {
    ulong legacy_reasm_append [ FD_METRICS_COUNTER_QUIC_TILE_NON_QUIC_REASSEMBLY_APPEND_CNT ];
    ulong legacy_reasm_publish[ FD_METRICS_COUNTER_QUIC_TILE_NON_QUIC_REASSEMBLY_PUBLISH_CNT ];

    ulong reasm_append [ FD_METRICS_COUNTER_QUIC_TILE_REASSEMBLY_APPEND_CNT ];
    ulong reasm_publish[ FD_METRICS_COUNTER_QUIC_TILE_REASSEMBLY_PUBLISH_CNT ];
  } metrics;
};

typedef struct fd_quic_tile_private fd_quic_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_quic_tile_align( void );

FD_FN_PURE ulong
fd_quic_tile_footprint( fd_quic_tile_args_t const * args );

ulong
fd_quic_tile_seccomp_policy( void *               shquic,
                             struct sock_filter * out,
                             ulong                out_cnt );

ulong
fd_quic_tile_allowed_fds( void * shquic,
                          int *  out,
                          ulong  out_cnt );

void
fd_quic_tile_join_privileged( void *                      shquic,
                              fd_quic_tile_args_t const * args );

fd_quic_tile_t *
fd_quic_tile_join( void *                      shquic,
                   fd_quic_tile_args_t const * args,
                   fd_quic_tile_topo_t const * topo );

void
fd_quic_tile_run( fd_quic_tile_t *        ctx,
                  fd_cnc_t *              cnc,
                  ulong                   in_cnt,
                  fd_frag_meta_t const ** in_mcache,
                  ulong **                in_fseq,
                  fd_frag_meta_t *        mcache,
                  ulong                   out_cnt,
                  ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_quic_fd_quic_tile_h */
