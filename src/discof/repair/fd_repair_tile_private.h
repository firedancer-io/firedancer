#ifndef HEADER_fd_src_discof_repair_fd_repair_tile_private_h
#define HEADER_fd_src_discof_repair_fd_repair_tile_private_h

/* Internal types of the repair tile.  Included by the tile and by
   firedancer-dev's repair command, which reads the tile's ctx out of
   shared memory. */

#include "fd_repair_tile.h"
#include "fd_repair_metrics.h"
#include "fd_inflight.h"
#include "fd_repair.h"
#include "fd_policy.h"
#include "../forest/fd_forest.h"
#include "../../disco/fd_clock_tile.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_rnonce_ss.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../util/net/fd_net_headers.h"

#define MAX_IN_LINKS    (32)
#define MAX_SHRED_TILE_CNT ( 16UL )
#define MAX_SIGN_TILE_CNT  ( 16UL )

/* Max number of validators that can be actively queried */
#define FD_REPAIR_PEER_MAX (FD_CONTACT_INFO_TABLE_SIZE)

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

  /* Repair tile directly tracks credit outside of stem for these
     asynchronous sign links.  In particular, credits tracks the RETURN
     sign_repair link.  This is because repair_sign and
     sign_repair are unreliable.  If both links were reliable, and the
     links filled completely, stem would get into a deadlock.  Neither
     repair or sign would have credits, which would prevent frags from
     getting polled in repair or sign, which would prevent any credits
     from getting returned back to the tiles.  So the sign_repair return
     link must be unreliable. credits / max_credits are used by the
     repair_sign link,  but credits tracks the RETURN
     sign_repair link.

     Consider the scenario:

             repair_sign (depth 128)        sign_repair (depth 128)
     repair  ---------------------->  sign ------------------------> repair
             [rest free, r130, r129]       [r128, r127, ... , r1] (full)

     If repair is publishing too many requests too fast(common in
     catchup), and not polling enough frags from sign, without manual
     management the sign_repair link would be overrun.  Nothing is
     stopping repair from publishing more requests, because sign is
     functioning fast enough to handle the requests. However, nothing is
     stopping sign from polling the next request and signing it, and
     PUBLISHING it on the sign_repair link that is already full, because
     the sign_repair link is unreliable.

     This is why we need to manually track credits for the sign_repair
     link. We must ensure that there are never more than 128 items in
     the ENTIRE repair_sign -> sign tile -> sign_repair work queue, else
     there is always a possibility of an overrun in the sign_repair
     link.

     We can furthermore ensure some nice properties by having the
     repair_sign link have a greater depth than the sign_repair link.
     This way, we exclusively use manual credit management to control
     the rate at which we publish requests to sign.  This allows for
     repair_sign to also be unreliable.  Even when the repair sign link
     is "full", we can avoid backpressure and continue polling frags,
     without overruning the sign_repair link.

     To lose a frag to overrun isn't necessarily critical, but in
     general the repair tile relies on the fact that a signing task
     published to sign tile will always come back.  If we lose a frag to
     overrun, then there will be an entry in the pending signs structure
     that is never removed, and theoretically the map could fill up.
     Conceptually, with a reliable (unreliable links, but strictly
     controlled count-per-link) sign->repair->sign structure, there
     should be no eviction needed in this pending signs structure. */

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

struct sign_req {
  ulong       key;        /* map key, ctx->pending_key_next */
  ulong       buflen;
  union {
    uchar           buf[sizeof(fd_repair_msg_t)];
    fd_repair_msg_t msg;
  };
  pong_data_t  pong_data; /* populated only for pong msgs */
};
typedef struct sign_req sign_req_t;

#define MAP_NAME         fd_signs_map
#define MAP_KEY          key
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) (k==ULONG_MAX)
#define MAP_T            sign_req_t
#define MAP_MEMOIZE      0
#include "../../util/tmpl/fd_map_dynamic.c"

/* Because the sign tiles could be all busy when a contact info or a
   ping arrives, we need to save ping messages to be signed in a queue
   and dispatched in after_credit when there are sign tiles available.
   The size of the queue is sized to be the number of warm up
   requests we might burst to the queue all at once (at most
   FD_REPAIR_PEER_MAX), then doubled for good measure.

   There is a possibility that someone could spam pings to block other
   peers' pings (and prevent us from responding to those pings). To
   mitigate this, we track the number of pings currently living in the
   sign queue that belong to each peer.  If a peer already has a pong
   living in the sign queue, we drop the pings from that peer.

   The peer could send us a new bogus ping every time we pop their ping
   from the sign queue, but there would be no way to prevent other
   peers' pings from getting processed, so the wasted work and impact
   would be minimal.

   Typical flow is that a pong will get added to the pong_queue during
   an after_frag call.  Then on the following after_credit will get
   popped from the sign_queue and added to sign_map, and then dispatched
   to the sign tile.

   Note that after the first turbine shred arrives, the signs_queue also
   stores highest window index requests for slots between snapshot and
   turbine_slot0, which are dispatched first before any other requests
   as a catchup optimization.  This doesn't break any of the inflight
   invariants as highest window index requests do not get added to the
   inflight table. */

struct sign_pending {
  fd_repair_msg_t msg;
  pong_data_t     pong_data; /* populated only for pong msgs */
};
typedef struct sign_pending sign_pending_t;

#define QUEUE_NAME       fd_signs_queue
#define QUEUE_T          sign_pending_t
#define QUEUE_MAX        (2*FD_REPAIR_PEER_MAX)
#include "../../util/tmpl/fd_queue.c"

struct ctx {
  long tsdebug; /* timestamp for debug printing */

  fd_clock_tile_t clock[1];

  ulong repair_seed;

  fd_keyswitch_t * keyswitch;
  int              halt_signing;

  fd_ip4_port_t repair_intake_addr;

  fd_forest_t    * forest;
  fd_policy_t    * policy;
  fd_reqlim_t    * dedup;
  fd_inflights_t * inflights;
  fd_repair_t    * protocol;

  ulong enforce_fixed_fec_set; /* min slot where the feature is enforced */

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

  uint             pending_key_next;
  sign_req_t     * signs_map;  /* contains any request currently in the repair->sign or sign->repair dcache */
  sign_pending_t * pong_queue;  /* contains any pong or initial warmup request waiting to be dispatched to repair->sign. Size is 2*FD_REPAIR_PEER_MAX */

  ushort net_id;

  /* Buffers for incoming unreliable frags */
  uchar net_buf[ FD_NET_MTU ];
  uchar sign_buf[ sizeof(fd_ed25519_sig_t) ];

  /* Store chunk for incoming reliable frags */
  ulong chunk;
  ulong snap_out_chunk; /* store second to last chunk for snap_out */

  fd_ip4_udp_hdrs_t intake_hdr[1];

  fd_rnonce_ss_t repair_nonce_ss[1];

  ulong manifest_slot;
  struct {
    ulong send_pkt_cnt;
    ulong sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_CNT];
    ulong current_slot;
    ulong old_shred;
    ulong last_requested_slot;
    ulong last_requested_orphan;
    ulong sign_tile_unavail;
    ulong rerequest;
    ulong malformed_ping;
    ulong unknown_peer_ping;
    ulong fail_sigverify_ping;
    fd_histf_t slot_compl_time[ 1 ];
    fd_histf_t response_latency[ 1 ];
    ulong blk_evicted;
    ulong blk_failed_insert;

    ulong slot_evicted;
    ulong slot_evicted_by;
    ulong slot_failed_insert;

    ulong failed_chain_verify_cnt;
    ulong failed_chain_verify_slot;
  } metrics[ 1 ];

  /* Slot-level metrics */

  fd_repair_metrics_t * slot_metrics;
  ulong turbine_slot0;  // catchup considered complete after this slot
};
typedef struct ctx ctx_t;

#endif /* HEADER_fd_src_discof_repair_fd_repair_tile_private_h */
