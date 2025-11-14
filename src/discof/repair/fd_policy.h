#ifndef HEADER_fd_src_discof_repair_fd_policy_h
#define HEADER_fd_src_discof_repair_fd_policy_h

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
#include "../forest/fd_forest.h"
#include "../../util/net/fd_net_headers.h"
#include "fd_repair.h"

/* FD_POLICY_PEER_MAX specifies a hard bound for how many peers Policy
   needs to track.  4096 is derived from the BLS signature max, which
   is the maximum number of staked validators Solana can support. */

#define FD_POLICY_PEER_MAX (4096UL)

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
  ulong prev;   /* reserved by lru */
  ulong next;
  ulong hash;     /* reserved by pool and map_chain */
  long  req_ts;   /* timestamp when the request was sent */
};
typedef struct fd_policy_dedup_ele fd_policy_dedup_ele_t;

FD_FN_CONST static inline ulong
fd_policy_dedup_key( uint kind, ulong slot, uint shred_idx ) {
  return (ulong)kind << 61 | slot << 30 | shred_idx << 15;
}

FD_FN_CONST static inline uint  fd_policy_dedup_key_kind     ( ulong key ) { return (uint)fd_ulong_extract( key, 62, 63 ); }
FD_FN_CONST static inline ulong fd_policy_dedup_key_slot     ( ulong key ) { return       fd_ulong_extract( key, 30, 61 ); }
FD_FN_CONST static inline uint  fd_policy_dedup_key_shred_idx( ulong key ) { return (uint)fd_ulong_extract( key, 15, 29  ); }

#define POOL_NAME fd_policy_dedup_pool
#define POOL_T    fd_policy_dedup_ele_t
#define POOL_NEXT hash
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_policy_dedup_map
#define MAP_ELE_T fd_policy_dedup_ele_t
#define MAP_NEXT  hash
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME   fd_policy_dedup_lru
#define DLIST_ELE_T  fd_policy_dedup_ele_t
#define DLIST_NEXT   next
#define DLIST_PREV   prev
#include "../../util/tmpl/fd_dlist.c"
struct fd_policy_dedup {
  fd_policy_dedup_map_t * map;  /* map of dedup elements */
  fd_policy_dedup_ele_t * pool; /* memory pool of dedup elements */
  fd_policy_dedup_lru_t * lru;  /* singly-linked list of dedup elements by insertion order.  TODO: add eviction feature using linkedlist */
};

/* fd_policy_peer_t describes a peer validator that serves repairs.
   Peers are discovered through gossip, via a "ContactInfo" message that
   shares the validator's ip and repair server port. */

struct fd_policy_peer {
  fd_pubkey_t key;     /* map key, pubkey of the validator */
  uint        hash;    /* reserved for map */
  uint        ip4;     /* ip4 addr of the peer */
  ushort      port;    /* repair server port of the peer */
  ulong       req_cnt; /* count of requests we've sent to this peer */
  ulong       res_cnt; /* count of responses we've received from this peer */

  /* below are for measuring bandwidth usage */
  long  first_req_ts;
  long  last_req_ts;

  long  first_resp_ts;
  long  last_resp_ts;

  long  total_lat; /* total RTT over all responses in ns */
  ulong stake;

  ulong pool_idx;
};
typedef struct fd_policy_peer fd_policy_peer_t;

#define MAP_NAME              fd_policy_peer_map
#define MAP_T                 fd_policy_peer_t
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          null_pubkey
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key)     ((MAP_HASH_T)( (key).ul[1] ))
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_peer {
  fd_pubkey_t identity;
  ulong       next;
  ulong       prev;
};
typedef struct fd_peer fd_peer_t;

#define POOL_NAME fd_peer_pool
#define POOL_T    fd_peer_t
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fd_peer_dlist
#define DLIST_ELE_T fd_peer_t
#define DLIST_NEXT  next
#define DLIST_PREV  prev
#include "../../util/tmpl/fd_dlist.c"

/* fd_policy_peers implements the data structures and bookkeeping for
   selecting repair peers via round-robin. */

struct fd_policy_peers {
  fd_peer_t        * pool;  /* memory pool of repair peer pubkeys, contains entries of both dlist */
  fd_peer_dlist_t  * fast;  /* [0, FD_POLICY_LATENCY_THRESH]   ms latency group FD_POLICY_LATENCY_FAST */
  fd_peer_dlist_t  * slow;  /* (FD_POLICY_LATENCY_THRESH, inf) ms latency group FD_POLICY_LATENCY_SLOW */
  fd_policy_peer_t * map;   /* map dynamic of pubkey->peer data */
  struct {
     uint stage;                  /* < sizeof(bucket_stages)        */
     fd_peer_dlist_iter_t iter;   /* round-robin index of next peer */
  } select;
};
typedef struct fd_policy_peers fd_policy_peers_t;

#define FD_POLICY_LATENCY_FAST 1
#define FD_POLICY_LATENCY_SLOW 3

/* Policy parameters start */
#define FD_POLICY_LATENCY_THRESH 80e6L /* less than this is a BEST peer, otherwise a WORST peer */
#define FD_POLICY_DEDUP_TIMEOUT  100e6L /* how long wait to request the same shred */

/* Round robins through ALL the worst peers once, then round robins
   through ALL the best peers once, then round robins through ALL the
   best peers again, etc. All peers are initially added to the worst
   bucket, and moved once round trip times have been recorded. */

static const uint bucket_stages[7] = {
   FD_POLICY_LATENCY_SLOW, /* do a cycle through worst peers 1/7 times to see if any improvements are made */
   FD_POLICY_LATENCY_FAST,
   FD_POLICY_LATENCY_FAST,
   FD_POLICY_LATENCY_FAST,
   FD_POLICY_LATENCY_FAST,
   FD_POLICY_LATENCY_FAST,
   FD_POLICY_LATENCY_FAST,
};
/* Policy parameters end */

struct fd_policy {
  fd_policy_dedup_t dedup; /* dedup cache of already sent requests */
  fd_policy_peers_t peers; /* repair peers (strategy & data) */
  long              tsmax; /* maximum time for an iteration before resetting the DFS to root */
  long              tsref; /* reference timestamp for resetting DFS */

  ulong turbine_slot0;
  uint nonce;
};
typedef struct fd_policy fd_policy_t;

/* Constructors */

/* fd_policy_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as policy with up to
   ele_max eles and vote_max votes. */

FD_FN_CONST static inline ulong
fd_policy_align( void ) {
  return alignof(fd_policy_t);
}

FD_FN_CONST static inline ulong
fd_policy_footprint( ulong dedup_max, ulong peer_max ) {
  int lg_peer_max = fd_ulong_find_msb( fd_ulong_pow2_up( peer_max ) );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_policy_t),         sizeof(fd_policy_t)                           ),
      fd_policy_dedup_map_align(),  fd_policy_dedup_map_footprint ( dedup_max   ) ),
      fd_policy_dedup_pool_align(), fd_policy_dedup_pool_footprint( dedup_max   ) ),
      fd_policy_dedup_lru_align(),  fd_policy_dedup_lru_footprint()               ),
      fd_policy_peer_map_align(),   fd_policy_peer_map_footprint  ( lg_peer_max ) ),
      fd_peer_pool_align(),         fd_peer_pool_footprint        ( peer_max    ) ),
      fd_peer_dlist_align(),        fd_peer_dlist_footprint()                     ),
      fd_peer_dlist_align(),        fd_peer_dlist_footprint()                     ),
    fd_policy_align() );
}

/* fd_policy_new formats an unused memory region for use as a policy.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment. */

void *
fd_policy_new( void * shmem, ulong dedup_max, ulong peer_max, ulong seed );

/* fd_policy_join joins the caller to the policy.  policy points to the
   first byte of the memory region backing the policy in the caller's
   address space.  Returns a pointer in the local address space to
   policy on success. */

fd_policy_t *
fd_policy_join( void * policy );

/* fd_policy_leave leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include policy is NULL. */

void *
fd_policy_leave( fd_policy_t const * policy );

/* fd_policy_delete unformats a memory region used as a policy.  Assumes
   only the nobody is joined to the region.  Returns a pointer to the
   underlying shared memory region or NULL if used obviously in error
   (e.g. policy is obviously not a policy ... logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_policy_delete( void * policy );

/* fd_policy_next returns the next repair request that should be made.
   Currently implements the default round-robin DFS strategy. */

fd_repair_msg_t const *
fd_policy_next( fd_policy_t * policy, fd_forest_t * forest, fd_repair_t * repair, long now, ulong highest_known_slot, int * charge_busy );

fd_policy_peer_t const *
fd_policy_peer_insert( fd_policy_t * policy, fd_pubkey_t const * key, fd_ip4_port_t const * addr );

fd_policy_peer_t *
fd_policy_peer_query( fd_policy_t * policy, fd_pubkey_t const * key );

int
fd_policy_peer_remove( fd_policy_t * policy, fd_pubkey_t const * key );

fd_pubkey_t const *
fd_policy_peer_select( fd_policy_t * policy );

void
fd_policy_peer_request_update( fd_policy_t * policy, fd_pubkey_t const * to );

static inline fd_peer_dlist_t *
fd_policy_peer_latency_bucket( fd_policy_t * policy, long total_rtt /* ns */, ulong res_cnt ) {
   if( res_cnt == 0 || (long)(total_rtt / (long)res_cnt) > FD_POLICY_LATENCY_THRESH ) return policy->peers.slow;
   return policy->peers.fast;
}

void
fd_policy_peer_response_update( fd_policy_t * policy, fd_pubkey_t const * to, long rtt );

int
fd_policy_passes_throttle_threshold( fd_policy_t * policy, fd_forest_blk_t * ele );

void
fd_policy_set_turbine_slot0( fd_policy_t * policy, ulong slot );

#endif /* HEADER_fd_src_choreo_policy_fd_policy_h */
