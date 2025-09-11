#ifndef HEADER_fd_src_app_fdctl_run_tiles_fd_send_tile_h
#define HEADER_fd_src_app_fdctl_run_tiles_fd_send_tile_h

/* Sender tile signs and sends transactions to the current leader.
   Currently only supports transactions which require one signature.
   Designed with voting as primary use case. Signing those votes will
   eventually move to a separate consensus tile.*/
#define _GNU_SOURCE

#include "../../util/net/fd_net_headers.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/fd_disco.h"
#include "../../disco/pack/fd_microblock.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../waltz/quic/fd_quic.h"
#include "../../util/clock/fd_clock.h"

#define IN_KIND_SIGN   (0UL)
#define IN_KIND_GOSSIP (1UL)
#define IN_KIND_STAKE  (2UL)
#define IN_KIND_TOWER  (3UL)
#define IN_KIND_NET    (4UL)

/* Send votes to next FD_SEND_TARGET_LEADER_CNT leaders (slot x, x+4, x+8, ...) */
#define FD_SEND_TARGET_LEADER_CNT (3UL)

/* Connect FD_CONNECT_AHEAD_LEADER_CNT leaders ahead (slot x, x+4, x+8, ...) */
#define FD_SEND_CONNECT_AHEAD_LEADER_CNT  (6UL)

/* Agave currently rate limits connections per minute per IP */
#define FD_AGAVE_MAX_CONNS_PER_MINUTE (8UL)
/* so each of our connections must survive at least 60/8 = 7.5 seconds
   Let's conservatively go to 10 */
#define FD_SEND_QUIC_MIN_CONN_LIFETIME_SECONDS (10L)

/* the 1M lets this be integer math */
FD_STATIC_ASSERT((60*1000000)/FD_SEND_QUIC_MIN_CONN_LIFETIME_SECONDS <= 1000000*FD_AGAVE_MAX_CONNS_PER_MINUTE, "QUIC conn lifetime too low for rate limit");

#define FD_SEND_QUIC_IDLE_TIMEOUT_NS (2e9L)  /*  2 s  */
#define FD_SEND_QUIC_ACK_DELAY_NS    (25e6L) /* 25 ms */

/* quic ports first, so we can re-use idx to select conn ptr
   Don't rearrange, lots of stuff depends on this order. */
#define FD_SEND_PORT_QUIC_VOTE_IDX  (0UL)
#define FD_SEND_PORT_QUIC_TPU_IDX   (1UL)
#define FD_SEND_PORT_UDP_VOTE_IDX   (2UL)
#define FD_SEND_PORT_UDP_TPU_IDX    (3UL)
#define FD_SEND_PORT_QUIC_CNT       (2UL)
#define FD_SEND_PORT_CNT            (4UL)

struct fd_send_link_in {
  fd_wksp_t *  mem;
  ulong        chunk0;
  ulong        wmark;
  ulong        kind;
  void      *  dcache;
};
typedef struct fd_send_link_in fd_send_link_in_t;

struct fd_send_link_out {
  ulong            idx;
  fd_frag_meta_t * mcache;
  ulong *          sync;
  ulong            depth;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};
typedef struct fd_send_link_out fd_send_link_out_t;

struct fd_send_conn_entry {
  fd_pubkey_t      pubkey;
  uint             hash;

  fd_quic_conn_t * conn[ FD_SEND_PORT_UDP_VOTE_IDX ]; /* first non-quic port */
  long             last_ci_ns;
  uint             ip4s [ FD_SEND_PORT_CNT ]; /* net order */
  ushort           ports[ FD_SEND_PORT_CNT ]; /* host order */
  int              got_ci_msg;
};
typedef struct fd_send_conn_entry fd_send_conn_entry_t;


struct fd_send_tile_ctx {

  /* link things */
  #define FD_SEND_MAX_IN_LINK_CNT 32UL
  fd_stem_context_t *  stem;
  fd_send_link_in_t    in_links[ FD_SEND_MAX_IN_LINK_CNT ];
  fd_net_rx_bounds_t   net_in_bounds;
  fd_send_link_out_t   gossip_verify_out[ 1 ];
  fd_send_link_out_t   net_out          [ 1 ];

  fd_keyguard_client_t keyguard_client  [ 1 ];

  /* buffers btwn during_frag and after_frag :( */
  union {
    /* IN_KIND_GOSSIP */
    struct {
      fd_shred_dest_wire_t       contact_buf[ MAX_STAKED_LEADERS ];
      ulong                      contact_cnt;
    };

    /* IN_KIND_SIGN */
    uchar txn_buf[ sizeof(fd_txn_p_t) ] __attribute__((aligned(alignof(fd_txn_p_t))));

    /* IN_KIND_NET */
    uchar quic_buf[ FD_NET_MTU ];
  };

  /* networking things */
  uint               src_ip_addr;
  ushort             src_port;
  fd_ip4_udp_hdrs_t  packet_hdr[1]; /* template, but will be modified directly */
  ushort             net_id;

  /* tls pubkey */
  fd_pubkey_t identity_key  [ 1 ];    /* also tls pubkey - only really used by quic */

  /* Leader schedule tracking */
  fd_multi_epoch_leaders_t * mleaders;

  /* QUIC handles */
  fd_quic_t * quic;
  fd_aio_t    quic_tx_aio[1];

  /* Connection map for outgoing QUIC connections and contact info */
  fd_send_conn_entry_t * conn_map;

  /* timekeeping */
  long             now;            /* current time in ns!     */
  fd_clock_t       clock[1];       /* memory for fd_clock_t   */
  long             recal_next;     /* next recalibration time (ns) */
  ulong            housekeeping_ctr;

  struct {
    ulong leader_not_found;
    ulong staked_no_ci;
    ulong stale_ci;

    /* Contact info */
    ulong unstaked_ci_rcvd;
    ulong new_contact_info[FD_SEND_PORT_CNT][FD_METRICS_ENUM_NEW_CONTACT_OUTCOME_CNT];
    ulong ci_removed;

    /* Outcome of trying to send data */
    ulong send_result_cnt[FD_SEND_PORT_CNT][FD_METRICS_ENUM_TXN_SEND_RESULT_CNT];

    /* QUIC-specific metrics */
    ulong quic_hs_complete   [FD_METRICS_ENUM_SEND_QUIC_PORTS_CNT];
    ulong quic_conn_final    [FD_METRICS_ENUM_SEND_QUIC_PORTS_CNT];
    ulong ensure_conn_result [FD_METRICS_ENUM_SEND_QUIC_PORTS_CNT]
                                [FD_METRICS_ENUM_SEND_ENSURE_CONN_RESULT_CNT];

    /* Time spent waiting for tls_cv signatures */
    fd_histf_t sign_duration[ 1 ];
  } metrics;

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];
  uchar __attribute__((aligned(FD_CLOCK_ALIGN))) clock_mem[ FD_CLOCK_FOOTPRINT ];
};
typedef struct fd_send_tile_ctx fd_send_tile_ctx_t;

#endif
