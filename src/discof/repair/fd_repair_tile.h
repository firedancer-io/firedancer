#ifndef HEADER_fd_src_discof_repair_fd_repair_tile_h
#define HEADER_fd_src_discof_repair_fd_repair_tile_h

#include "fd_inflight.h"
#include "fd_policy.h"
#include "fd_repair.h"
#include "fd_repair_metrics.h"
#include "../forest/fd_forest.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_rnonce_ss.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../util/net/fd_net_headers.h"

#define MAX_IN_LINKS      (32)
#define MAX_SIGN_TILE_CNT (16)

/* Max number of validators that can be actively queried */
#define FD_REPAIR_PEER_MAX (FD_CONTACT_INFO_TABLE_SIZE)

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  };
  fd_net_rx_bounds_t net_rx;
} fd_repair_in_ctx_t;

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

typedef struct sign_req     sign_req_t;
typedef struct sign_pending sign_pending_t;

struct fd_repair_tile {
  long tsdebug; /* timestamp for debug printing */

  ulong repair_seed;

  fd_keyswitch_t * keyswitch;
  int              halt_signing;

  fd_ip4_port_t repair_intake_addr;
  fd_ip4_port_t repair_serve_addr;

  fd_forest_t    * forest;
  fd_policy_t    * policy;
  fd_inflights_t * inflights;
  fd_repair_t    * protocol;

  ulong enforce_fixed_fec_set; /* min slot where the feature is enforced */

  fd_pubkey_t identity_public_key;

  fd_wksp_t * wksp;

  fd_stem_context_t * stem;

  uchar    in_kind[ MAX_IN_LINKS ];
  fd_repair_in_ctx_t in_links[ MAX_IN_LINKS ];

  int skip_frag;

  out_ctx_t net_out_ctx[1];

  out_ctx_t repair_out_ctx[1];

  /* repair_sign links (to sign tiles 1+) - for round-robin distribution */

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
  fd_ip4_udp_hdrs_t serve_hdr [1];

  fd_rnonce_ss_t repair_nonce_ss[1];

  ulong manifest_slot;
  struct {
    ulong send_pkt_cnt;
    ulong sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_CNT];
    ulong repaired_slots;
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
typedef struct fd_repair_tile fd_repair_tile_t;

extern fd_topo_run_tile_t fd_tile_repair;

#endif /* HEADER_fd_src_discof_repair_fd_repair_tile_h */
