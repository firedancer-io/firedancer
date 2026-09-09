#ifndef HEADER_fd_src_discof_rotor_fd_rotor_tile_private_h
#define HEADER_fd_src_discof_rotor_fd_rotor_tile_private_h

/* Internal types of the rotor tile. */

#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../repair/fd_repair.h"
#include "../repair/fd_repair_metrics.h"
#include "../repair/fd_inflight.h"
#include "../repair/fd_policy.h"
#include "../chainer/fd_chainer.h"
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

/* ag_req_queue stores alpenglow metadata repair requests.  We can cap
   this queue at 1024 requests, as long as after_credit drains all
   meta requests. */

#define QUEUE_NAME       meta_queue
#define QUEUE_T          fd_repair_msg_t
#include "../../util/tmpl/fd_queue_dynamic.c"

#define MAX_IN_LINKS       (32)
#define MAX_SHRED_TILE_CNT ( 16UL )
#define MAX_SIGN_TILE_CNT  ( 16UL )

/* Max number of pending repair requests recently made to keep track of.
   Calculated generally as we estimate around 50k/s/core to sign
   requests. Assuming an over-provisioned 4 sign tiles just for repair,
   this means we can make up to ~200k requests per second.  With a dedup
   timeout of 80ms, this means we can make up to ~16k requests within
   the dedup timeout window.  We round up to the next power of two to
   get the dedup cache max.  Since we are sizing the dedup cache for a
   generous margin, and this number not particularly fragile or
   sensitive, we can leave it static. */
#define FD_REQLIM_CACHE_MAX (1<<20)

struct ctx {
  fd_clock_tile_t clock[1];

  ulong repair_seed;

  /* When set (alpenglow only), the repair policy walk emits ONLY
     block-id requests (ShredForBlockId, driven by known block_ids and
     the event-driven getParentAndFecSetCount/getFecRoot path).  All
     legacy positional emissions -- HighestShred, window Shred, Orphan,
     and the orphan-pass shred-0 -- are suppressed.  Used to exercise /
     test the block-id repair + catchup path in isolation. */
  int   block_id_repair_only;

  /* When set, publish_fec_replay re-publishes the entire ancestry path
     of FECs -- from the chainer root down to the FEC being delivered,
     in root-to-target order -- on every delivery, instead of just the
     single delivered FEC.  Lets replay reconstruct a fork from root
     without relying on incremental delivery.  The path is queued onto
     deliver_queue and drained one FEC per after_credit. */
  int         deliver_from_root;
  out_ele_t * deliver_queue; /* sized to the chainer's FEC capacity */

  fd_keyswitch_t * keyswitch;
  int              halt_signing;

  fd_chainer_t   * chainer; /* alpenglow chainer */
  fd_store_t     * store;   /* rotor publishes/removes FEC sets to/from the store */
  fd_store_map_t   store_map[1];
  fd_policy_t    * policy;
  fd_reqlim_t    * dedup;
  fd_inflights_t * inflights;
  fd_repair_t    * protocol;

  fd_pubkey_t identity_public_key;

  fd_wksp_t * wksp;

  fd_stem_context_t * stem;

  uchar    in_kind[ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];

  int skip_frag;

  out_ctx_t net_out_ctx[1];
  out_ctx_t repair_out_ctx[1];

  /* repair_sign links (to sign tiles 1+, or tile 0 when it is the only
     sign tile) - for round-robin distribution */
  ulong     repair_sign_cnt;
  out_ctx_t repair_sign_out_ctx[ MAX_SIGN_TILE_CNT ];

  ulong     sign_rrobin_idx;

  /* Pending sign requests for async operations */

  uint              pending_key_next;
  sign_req_t      * signs_map;    /* contains any request currently in the repair->sign or sign->repair dcache */
  sign_pending_t  * toss_queue;   /* contains any pong or initial warmup request waiting to be dispatched to repair->sign. Size is 2*FD_REPAIR_PEER_MAX */
  fd_repair_msg_t * meta_queue;   /* contains any alpenglow request waiting to be dispatched to sign->repair. Sized to one block's FEC sets (max_shreds_per_block/FD_FEC_SHRED_CNT) */

  ushort net_id;

  /* Buffers for incoming unreliable frags */
  uchar net_buf[ FD_NET_MTU ];
  uchar sign_buf[ sizeof(fd_ed25519_sig_t) ];

  /* Store chunk for incoming reliable frags */
  ulong chunk;
  ulong snap_out_chunk; /* store second to last chunk for snap_out */

  fd_ip4_udp_hdrs_t intake_hdr[1];

  fd_rnonce_ss_t repair_nonce_ss[1];
  uint           ag_nonce; /* simple incrementing nonce for alpenglow requests */

  ulong manifest_slot;
  struct {
    ulong      send_pkt_cnt;
    ulong      sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_CNT];
    ulong      current_slot;
    ulong      old_shred;
    ulong      last_requested_slot;
    ulong      last_requested_orphan;
    ulong      sign_tile_unavail;
    ulong      rerequest;
    ulong      malformed_ping;
    ulong      unknown_peer_ping;
    ulong      fail_sigverify_ping;
    fd_histf_t slot_compl_time[ 1 ];
    fd_histf_t response_latency[ 1 ];

    ulong failed_shred_block_id_cnt;
    ulong failed_fec_root_cnt;
    ulong failed_parent_fec_count_cnt;

    ulong fecs_delivered; /* diagnostic: FECs pushed to replay via out_queue */
  } metrics[ 1 ];

  /* Slot-level metrics */

  fd_repair_metrics_t * slot_metrics;
  ulong                 turbine_slot0;  // catchup considered complete after this slot
};
typedef struct ctx ctx_t;

#endif /* HEADER_fd_src_discof_rotor_fd_rotor_tile_private_h */
