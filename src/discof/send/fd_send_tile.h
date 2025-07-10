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
#include "../../flamenco/gossip/fd_gossip.h"
#include "../../waltz/quic/fd_quic.h"

#define IN_KIND_SIGN   (0UL)
#define IN_KIND_GOSSIP (1UL)
#define IN_KIND_STAKE  (2UL)
#define IN_KIND_TOWER  (3UL)
#define IN_KIND_NET    (4UL)

/* Send votes to leaders for next SEND_TO_LEADER_CNT slots */
#define SEND_TO_LEADER_CNT 4UL

#define QUIC_IDLE_TIMEOUT_NS (2e9)  /* 2 seconds */
#define QUIC_ACK_DELAY_NS    (25e6) /* 25ms */

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
  fd_quic_conn_t * conn;
  long             last_ci_ticks;
  uint             ip4_addr;
  ushort           udp_port;
};
typedef struct fd_send_conn_entry fd_send_conn_entry_t;


struct fd_send_tile_ctx {
  fd_pubkey_t identity_key[ 1 ];   /* also tls pubkey */
  fd_pubkey_t vote_acct_addr[ 1 ];

  fd_multi_epoch_leaders_t * mleaders;

  fd_shred_dest_wire_t       contact_buf[ MAX_STAKED_LEADERS ];
  ulong                      contact_cnt;

  uchar txn_buf[ sizeof(fd_txn_p_t) ] __attribute__((aligned(alignof(fd_txn_p_t))));

  uint                  src_ip_addr;
  ushort                src_port;
  fd_ip4_udp_hdrs_t     packet_hdr[1];

  #define fd_send_MAX_IN_LINK_CNT 32UL
  fd_send_link_in_t in_links[ fd_send_MAX_IN_LINK_CNT ];

  fd_send_link_out_t gossip_verify_out[1];
  fd_send_link_out_t net_out         [1];

  fd_keyguard_client_t keyguard_client[ 1 ];

  fd_quic_t * quic;
  fd_aio_t    quic_tx_aio[1];

  uchar quic_buf[ FD_NET_MTU ];

  fd_net_rx_bounds_t net_in_bounds;

  /* Connection map for outgoing QUIC connections and contact info */
  fd_send_conn_entry_t * conn_map;

  fd_stem_context_t * stem;
  long                now;

  struct {
    ulong leader_not_found;        /* Number of times slot leader not found when voting. */
    ulong contact_stale;           /* Number of reconnects skipped due to stale contact info */
    ulong quic_conn_create_failed; /* QUIC connection creation failed */

    /* Handling of new contact info */
    ulong new_contact_info[FD_METRICS_ENUM_NEW_CONTACT_OUTCOME_CNT];

    /* Outcome of trying to send data over quic */
    ulong quic_send_result_cnt[FD_METRICS_ENUM_TXN_QUIC_SEND_RESULT_CNT];

    /* Time spent waiting for tls_cv signatures */
    fd_histf_t sign_duration[ 1 ];
  } metrics;

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];

};
typedef struct fd_send_tile_ctx fd_send_tile_ctx_t;


/* A few larger functions to wrap QUIC interactions */

/* quic_connect initiates a quic connection. It uses the contact info
   stored in entry, and points the conn and entry to each other. Returns
   a handle to the new connection, and NULL if creating it failed */
fd_quic_conn_t *
quic_connect( fd_send_tile_ctx_t   * ctx,
              fd_send_conn_entry_t * entry );

/* quic_send sends a payload to 'pubkey' via quic. Requires an already
   established connection to 'pubkey'. */
void
quic_send( fd_send_tile_ctx_t  *  ctx,
           fd_pubkey_t const   *  pubkey,
           uchar const         *  payload,
           ulong                  payload_sz );

#endif
