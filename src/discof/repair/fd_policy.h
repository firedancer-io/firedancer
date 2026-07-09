#ifndef HEADER_fd_src_discof_repair_fd_policy_h
#define HEADER_fd_src_discof_repair_fd_policy_h

/* fd_policy implements the policy of the Repair agent.  It determines
   what next repair request the validator should make. It also
   determines which peer(s) the validator should make the request to.

   The default policy implementation is to prioritize discovering
   ancestry for orphaned slots first (making an orphan request), and
   then making forward progress on the main ancestry tree (making a
   regular request) when there are no orphan requests to make.

   Regular shred requests are made round-robin BFS with time-based
   dedup: round-robin through all the repair peers we know about, and
   BFS down the repair forest (see fd_forest.h).

   This policy dedups identical repair requests that occur within a
   specified amount of time window of each other. */

#include "../forest/fd_forest.h"
#include "../../util/net/fd_net_headers.h"
#include "fd_repair.h"
#include "fd_reqlim.h"
#include "../../disco/shred/fd_rnonce_ss.h"

/* fd_policy_peer_t describes a peer validator that serves repairs.
   Peers are discovered through gossip, via a "ContactInfo" message that
   shares the validator's ip and repair server port. */

struct fd_policy_peer {
  fd_pubkey_t key;     /* map key, pubkey of the validator */
  ulong       next;    /* reserved for map_chain, pool */
  uint        ip4;     /* ip4 addr of the peer */
  ushort      port;    /* repair server port of the peer */
  ulong       req_cnt; /* count of requests we've sent to this peer */
  ulong       res_cnt; /* count of responses we've received from this peer */

  struct {
    ulong next;
    ulong prev;
  } dlist;

  /* below are for measuring bandwidth usage */
  long  first_req_ts;
  long  last_req_ts;

  long  first_resp_ts;
  long  last_resp_ts;

  long  total_lat; /* total RTT over all responses in ns */
  long  ewma_lat;  /* exponential weighted moving average of RTT in ns */
  ulong stake;

  uint unanswered; /* requests sent since last response received */
  uint ping;       /* whether this peer currently has a ping in our sign queue */
};
typedef struct fd_policy_peer fd_policy_peer_t;

#define MAP_NAME                 fd_policy_peer_map
#define MAP_ELE_T                fd_policy_peer_t
#define MAP_KEY_T                fd_pubkey_t
#define MAP_KEY_EQ(k0,k1)        (!memcmp( (k0)->uc, (k1)->uc, 32UL ))
#define MAP_KEY_HASH(key,seed)   (seed^fd_ulong_load_8( (key)->uc ))
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_policy_peer_pool
#define POOL_T    fd_policy_peer_t
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fd_policy_peer_dlist
#define DLIST_ELE_T fd_policy_peer_t
#define DLIST_NEXT  dlist.next
#define DLIST_PREV  dlist.prev
#include "../../util/tmpl/fd_dlist.c"

/* fd_policy_peers implements the data structures and bookkeeping for
   selecting repair peers via round-robin. */

struct fd_policy_peers {
  fd_policy_peer_t * pool;        /* memory pool of peers */
  fd_policy_peer_dlist_t * fast;  /* peers with ewma RTT <= FD_POLICY_LATENCY_THRESH */
  fd_policy_peer_dlist_t * slow;  /* peers with ewma RTT >  FD_POLICY_LATENCY_THRESH or no RTT measured */
  fd_policy_peer_map_t * map;     /* map keyed by pubkey to peer data */
  struct {
     uint cnt;                                /* fast selections since last slow, wraps at FD_POLICY_FAST_PER_SLOW */
     fd_policy_peer_dlist_iter_t fast_iter;   /* round-robin iterator into fast list */
     fd_policy_peer_dlist_iter_t slow_iter;   /* round-robin iterator into slow list */
  } select;
};
typedef struct fd_policy_peers fd_policy_peers_t;

/* Policy parameters start */
#define FD_POLICY_LATENCY_THRESH       100e6L /* less than this is a BEST peer, otherwise a WORST peer */
#define FD_POLICY_FAST_PER_SLOW        6U     /* pick 6 fast peers per 1 slow peer */
#define FD_POLICY_EWMA_ALPHA_DENOM     8UL    /* EWMA weight = 1/DENOM, i.e. ewma = 7/8*old + 1/8*sample */
/* Policy parameters end */

struct fd_policy {
  fd_policy_peers_t peers; /* repair peers (strategy & data) */
  long              tsmax; /* maximum time for an iteration before resetting the DFS to root */
  long              tsref; /* reference timestamp for resetting DFS */

  fd_rnonce_ss_t    rnonce_ss[1];

  ulong turbine_slot0;
};
typedef struct fd_policy fd_policy_t;

/* Constructors */

/* fd_policy_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as policy with up to
   ele_max eles and vote_max votes. */

FD_FN_CONST static inline ulong
fd_policy_align( void ) {
  return 128UL;
}

FD_FN_CONST static inline ulong
fd_policy_footprint( ulong peer_max ) {
  ulong peer_chain_cnt = fd_policy_peer_map_chain_cnt_est( peer_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      fd_policy_align(),            sizeof(fd_policy_t)                             ),
      fd_policy_peer_map_align(),   fd_policy_peer_map_footprint ( peer_chain_cnt ) ),
      fd_policy_peer_pool_align(),  fd_policy_peer_pool_footprint( peer_max )       ),
      fd_policy_peer_dlist_align(), fd_policy_peer_dlist_footprint()                ),
      fd_policy_peer_dlist_align(), fd_policy_peer_dlist_footprint()                ),
    fd_policy_align() );
}

/* fd_policy_new formats an unused memory region for use as a policy.
   mem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  rnonce_ss is copied
   locally, so the read interest is not retained after this function
   returns. */

void *
fd_policy_new( void * shmem, ulong peer_max, ulong seed, fd_rnonce_ss_t const * rnonce_ss );

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
   Currently wraps on top of the forest iterator, but also handles
   making orphan requests and highest shred requests.  For non-normal
   repair requests, policy uses the dedup cache to deduplicate requests.
   For all normal requests, the caller must check the dedup cache before
   making a request. */

fd_repair_msg_t const *
fd_policy_next( fd_policy_t * policy, fd_reqlim_t * dedup, fd_forest_t * forest, fd_repair_t * repair, long now, ulong highest_known_slot, int * charge_busy );

/* fd_policy_peer_upsert upserts a peer into the policy.  If the peer
   does not exist, it is created.  If the peer already exists, it is
   updated.  Returns a pointer to the peer if a new peer was created,
   otherwise NULL (including on updates). */
fd_policy_peer_t const *
fd_policy_peer_upsert( fd_policy_t * policy, fd_pubkey_t const * key, fd_ip4_port_t const * addr );

fd_policy_peer_t *
fd_policy_peer_query( fd_policy_t * policy, fd_pubkey_t const * key );

int
fd_policy_peer_remove( fd_policy_t * policy, fd_pubkey_t const * key );

fd_pubkey_t const *
fd_policy_peer_select( fd_policy_t * policy );

void
fd_policy_peer_request_update( fd_policy_t * policy, fd_pubkey_t const * to );

static inline fd_policy_peer_dlist_t *
fd_policy_peer_latency_bucket( fd_policy_t * policy, long lat, ulong res_cnt ) {
   if( res_cnt == 0 || lat > FD_POLICY_LATENCY_THRESH ) return policy->peers.slow;
   return policy->peers.fast;
}

void
fd_policy_peer_response_update( fd_policy_t * policy, fd_pubkey_t const * to, long rtt );

void
fd_policy_set_turbine_slot0( fd_policy_t * policy, ulong slot );

#endif /* HEADER_fd_src_choreo_policy_fd_policy_h */
