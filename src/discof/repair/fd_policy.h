#ifndef HEADER_fd_src_choreo_policy_fd_policy_h
#define HEADER_fd_src_choreo_policy_fd_policy_h

/* fd_policy implements the policy of the Repair agent.  It determines
   what shreds the validator is expecting but has not yet received and
   needs to request via repair.  It also determines which peer(s) the
   validator should request the shred from.

   The default policy implementation is round-robin DFS with time-based
   dedup: round-robin through all the repair peers we know about, and
   depth-first search down the repair forest (see fd_forest.h).  This
   policy also dedups identical repair requests that occur within a
   specified amount of time window of each other (configurable on init
   as a hyperparameter).  With the DFS strategy, the smaller the tree,
   the sooner an element will be iterated again (when the DFS restarts
   from the root of the tree). */

#include "../../flamenco/types/fd_types_custom.h"
#include "fd_forest.h"
#include "fd_repair.h"

/* fd_policy_dedup implements a dedup cache for already sent Repair
   requests.  It is backed by a map and linked list, in which the least
   recently used (oldest Repair request) in the map is evicted when the
   map is full. */

typedef struct fd_policy_dedup fd_policy_dedup_t; /* forward decl */

/* fd_policy_dedup_ele describes an element in the dedup cache.  The key
   compactly encodes an fd_repair_req_t.

   | kind (2 bits)       | slot (32 bits)  | shred_idx (15 bits) |
   | 0x0 (SHRED)         | slot            | shred_idx           |
   | 0x1 (HIGHEST_SHRED) | slot            | >=shred_idx         |
   | 0x2 (ORPHAN)        | orphan slot     | N/A                 |

   Note the common header (sig, from, to, ts, nonce) is not included. */

struct fd_policy_dedup_ele {
  ulong key;      /* compact encoding of fd_repair_req_t detailed above */
  ulong prev;     /* reserved by lru */
  ulong next;     /* reserved by pool and map_chain */
  long  ts;       /* timestamp when the request was sent */
  ulong peer_idx; /* index of the peer to which the request was sent */
};
typedef struct fd_policy_dedup_ele fd_policy_dedup_ele_t;

FD_FN_CONST static inline ulong
fd_policy_dedup_key( uint kind, ulong slot, uint shred_idx ) {
  return (ulong)kind << 60 | slot << 15 | shred_idx;
}

FD_FN_CONST static inline uint  fd_policy_dedup_key_kind     ( ulong key ) { return (uint)fd_ulong_extract( key, 60, 63 ); }
FD_FN_CONST static inline ulong fd_policy_dedup_key_slot     ( ulong key ) { return       fd_ulong_extract( key, 28, 59 ); }
FD_FN_CONST static inline uint  fd_policy_dedup_key_shred_idx( ulong key ) { return (uint)fd_ulong_extract( key, 0, 15  ); }

#define POOL_NAME fd_policy_dedup_pool
#define POOL_T    fd_policy_dedup_ele_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_policy_dedup_map
#define MAP_ELE_T fd_policy_dedup_ele_t
#include "../../util/tmpl/fd_map_chain.c"

struct fd_policy_dedup {
  fd_policy_dedup_map_t * map;  /* map of dedup elements */
  fd_policy_dedup_ele_t * pool; /* memory pool of dedup elements */
  fd_policy_dedup_ele_t * lru;  /* singly-linked list of dedup elements by insertion order */
};

/* fd_policy_peers implements the data structures and bookkeeping for
   selecting repair peers via round-robin. */

struct fd_policy_peers {
  fd_pubkey_t * arr; /* array of repair peers */
  ulong         cnt; /* count of repair peers */
  ulong         idx; /* round-robin index of next peer */
};
typedef struct fd_policy_peers fd_policy_peers_t;

struct fd_policy {
  fd_policy_dedup_t * dedup; /* dedup cache of already sent requests */
  fd_policy_peers_t * peers; /* round-robin strategy for selecting repair peers */
  long                tsmax; /* maximum time for an iteration before resetting the DFS to root */
  long                tsref; /* reference timestamp for resetting DFS */
  fd_forest_iter_t    iterf; /* forest iterator */
};
typedef struct fd_policy fd_policy_t;

fd_repair_req_t *
fd_policy_req_next( fd_policy_t * policy, fd_forest_t * forest, fd_repair_t * repair );

#endif /* HEADER_fd_src_choreo_policy_fd_policy_h */
