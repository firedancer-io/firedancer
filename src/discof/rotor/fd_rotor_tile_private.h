#ifndef HEADER_fd_src_discof_rotor_fd_rotor_tile_private_h
#define HEADER_fd_src_discof_rotor_fd_rotor_tile_private_h

/* Internal types of the rotor tile. */

#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../repair/fd_repair.h"
#include "../../disco/net/fd_net_tile.h"
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

#endif /* HEADER_fd_src_discof_rotor_fd_rotor_tile_private_h */
