#ifndef HEADER_fd_src_discof_rotor_fd_rotor_tile_private_h
#define HEADER_fd_src_discof_rotor_fd_rotor_tile_private_h

/* Internal types of the rotor tile. */

#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../repair/fd_repair.h"
#include "../repair/fd_repair_metrics.h"
#include "../repair/fd_inflight.h"
#include "../repair/fd_policy.h"
#include "../chainer/fd_chainer.h"
#include "fd_schedulor.h"
#include "fd_requestor.h"
#include "../../disco/fd_clock_tile.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_rnonce_ss.h"
#include "../../disco/store/fd_store.h"
#include "../../disco/topo/fd_topo.h"
#include "../../util/net/fd_net_headers.h"

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  };
  fd_net_rx_bounds_t net_rx;
} in_ctx_t;

struct out_ctx {
  ulong         idx;
  fd_wksp_t *   mem;
  ulong         chunk0;
  ulong         wmark;
  ulong         chunk;

  /* See repair tile for explanation of sign credit management */

  ulong in_idx;      /* index of the incoming link */
  ulong credits;     /* available credits for link */
  ulong max_credits; /* maximum credits (depth) */
};
typedef struct out_ctx out_ctx_t;

/* Data needed to sign and send a pong that is not contained in the
   pong msg itself. */

struct pong_data {
  fd_ip4_port_t  peer_addr;
  fd_hash_t      hash;
  uint           daddr;
  fd_pubkey_t    key;
};
typedef struct pong_data pong_data_t;

/* Sign credit management */

struct sign_req {
  ulong       key;       /* map key, ctx->pending_key_next */
  ulong       buflen;
  union {
    uchar           buf[sizeof(fd_repair_msg_t)];
    fd_repair_msg_t msg;
  };
  pong_data_t pong_data; /* populated only for pong msgs */
};
typedef struct sign_req sign_req_t;

#define MAP_NAME         fd_signs_map
#define MAP_KEY          key
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) (k==ULONG_MAX)
#define MAP_T            sign_req_t
#define MAP_MEMOIZE      0
#include "../../util/tmpl/fd_map_dynamic.c"

/* Request work queues */

/* Max number of validators that can be actively queried */
#define FD_REPAIR_PEER_MAX (FD_CONTACT_INFO_TABLE_SIZE)

struct sign_pending {
  fd_repair_msg_t msg;
  pong_data_t     pong_data; /* populated only for pong msgs */
};
typedef struct sign_pending sign_pending_t;

/* toss_queue is referred to "toss" because we don't care about tracking
   the requests, and we can fire and forget.  Should be used for
   requests where if we don't hear back, we don't care. E.g., pongs,
   initial warmup requests, etc. */

#define QUEUE_NAME       toss_queue
#define QUEUE_T          sign_pending_t
#define QUEUE_MAX        (2*FD_REPAIR_PEER_MAX)
#include "../../util/tmpl/fd_queue.c"

#define IN_KIND_CONTACT (0)
#define IN_KIND_NET     (1)
#define IN_KIND_SHRED   (2)
#define IN_KIND_SIGN    (3)
#define IN_KIND_SNAP    (4)
#define IN_KIND_GOSSIP  (5)
#define IN_KIND_GENESIS (6)
#define IN_KIND_REPLAY  (7)
#define IN_KIND_VOTOR   (8)

#define MAX_IN_LINKS      (32)
#define MAX_SIGN_TILE_CNT (16UL)
struct ctx {
  fd_clock_tile_t clock[1];

  ulong       repair_seed;
  fd_pubkey_t identity_public_key;

  fd_chainer_t *      chainer;   /* slot version / FEC store */
  fd_schedulor_t *    schedulor; /* blocks to check, by timeout */
  fd_requestor_t *    requestor; /* cursor walk of the block being repaired */
  fd_repair_t *       protocol;  /* repair message construction */
  fd_policy_t *       policy;    /* repair peers and selection */
  fd_inflights_t *    rtt;       /* sent requests by nonce, for response latency only */

  fd_store_t *     store;     /* rotor publishes/removes FEC sets to/from the store */
  fd_store_map_t   store_map[1];

  fd_keyswitch_t * keyswitch;
  int              halt_signing;

  /* When set, publish_fec_replay re-publishes the entire ancestry path
     of FECs from the chainer root down to the FEC being delivered, so
     replay can reconstruct a fork it evicted.  See fd_rotor_tile.h. */
  int         deliver_from_root;
  out_ele_t * redeliver;

  /* Pending sign requests */

  ulong            pending_key_next;
  sign_req_t *     signs_map;
  sign_pending_t * toss_queue;

  fd_wksp_t * wksp;

  fd_stem_context_t * stem;

  uchar    in_kind [ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];


  out_ctx_t net_out_ctx   [1];
  out_ctx_t replay_out_ctx[1];

  /* repair_sign links (to sign tiles 1+), round-robin */
  ulong     repair_sign_cnt;
  out_ctx_t repair_sign_out_ctx[ MAX_SIGN_TILE_CNT ];

  /* Buffer for incoming net frags */
  uchar net_buf[ FD_NET_MTU ];

  /* The snapshot manifest arrives on one frag and is applied on the
     DONE frag that follows; snapin_manif is reliable so the chunk
     stays valid in between. */
  ulong manifest_chunk;

  ushort            net_id;
  fd_ip4_udp_hdrs_t intake_hdr[1];

  fd_rnonce_ss_t repair_nonce_ss[1];
  uint           ag_nonce; /* counter nonce for alpenglow metadata requests */

  ulong turbine_slot0; /* first turbine slot seen */
  int   catchup_seeded; /* the root..turbine_slot0 seed burst has been sent */
  ulong current_slot;  /* highest turbine slot seen */

  struct {
    ulong send_pkt_cnt;
    ulong sent_by_kind[ 16 ];
    ulong checks;
    ulong no_peer;
    ulong malformed_ping;
    ulong unknown_peer_ping;
    ulong fail_sigverify_ping;
    ulong unsolicited_meta;
    ulong failed_parent_fec_count;
    ulong failed_fec_root;
    ulong fecs_delivered;
    ulong shred_old;               /* shreds at or below the root */
    ulong sign_unavail;            /* no sign tile credit available */

    /* the two replay message kinds rotor acts on, counted in before_frag */
    ulong replay_root_advanced;
    ulong replay_missing_fec;

    /* response side */
    ulong repair_shred_rx;         /* data shreds that arrived as repair responses */
    ulong shred_match_block_id;    /* ... credited to a ShredForBlockId request */
    ulong shred_match_positional;  /* ... credited to a positional Shred request */
    ulong shred_match_miss;        /* ... matching no outstanding request */
    ulong meta_rx;                 /* metadata responses received */
    ulong meta_malformed;          /* ... that failed to decode */
    ulong meta_ok_parent_fec_count;
    ulong meta_ok_fec_root;

    fd_histf_t response_latency[ 1 ];
  } metrics[ 1 ];

  /* Slot-level metrics */

  fd_repair_metrics_t * slot_metrics;

  /* Highest slot rotor has completed a FEC set for off the network,
     our own leader FEC sets excluded.  This is the cluster tip, and it is rotor's to
     track: replay used to derive it from the FEC sets repair forwarded
     indiscriminately, but rotor delivers only what is replayable and
     in order, so a delivered FEC's slot is the replay frontier rather
     than the tip.  Shipped to replay on every delivered FEC.  0 until
     the first FEC set completes. */
  ulong                 highest_fec_complete_slot;
};
typedef struct ctx ctx_t;

#endif /* HEADER_fd_src_discof_rotor_fd_rotor_tile_private_h */
