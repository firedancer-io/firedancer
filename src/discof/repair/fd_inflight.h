#ifndef HEADER_fd_src_discof_repair_fd_inflight_h
#define HEADER_fd_src_discof_repair_fd_inflight_h

#include "fd_policy.h"

/* fd_inflight tracks repair requests that are inflight to other
   validators.  This module is useful for metrics and reporting.
   In-exact updates of orphan requests and highest window requests from
   this module are non-critical, but exact updates of shred requests are
   critical. Repair tile relies on this module to be able to re-request
   any shreds that it has sent, because policy next does not request any
   shred twice.

   Requests are key-ed by (slot, shred_idx, nonce) as in the current
   strategy (see fd_policy.h).  Since we generate the nonce based on the
   time bucketed by 16ms, which is less than the retransmission timeout,
   it's highly unlikely that a retransmission request will have the same
   nonce.  The chances that an inflight request does not get a response
   are non-negligible due to shred tile upstream deduping duplicates. */

/* Max number of pending requests */
#define FD_INFLIGHT_REQ_MAX (1<<20)

struct fd_inflight_key {
  ulong slot;       /* slot of the request */
  ulong shred_idx;  /* shred index of the request */
  ulong nonce;      /* computed nonce */
};
typedef struct fd_inflight_key fd_inflight_key_t;

struct __attribute__((aligned(128UL))) fd_inflight {
  fd_inflight_key_t key;
  ulong             next;          /* reserved for internal use by fd_pool and fd_map_chain */
  ulong             prev;          /* for fd_map_chain */
  long              timestamp_ns;  /* timestamp when request was created (nanoseconds) */
  fd_pubkey_t       pubkey;        /* public key of the peer */

  /* Reserved for DLL eviction */
  ulong             prevll;      /* pool index of previous element in DLL */
  ulong             nextll;      /* pool index of next element in DLL */
};
typedef struct fd_inflight fd_inflight_t;

#define POOL_NAME   fd_inflight_pool
#define POOL_T      fd_inflight_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME            fd_inflight_map
#define MAP_KEY             key
#define MAP_ELE_T           fd_inflight_t
#define MAP_KEY_T           fd_inflight_key_t
#define MAP_KEY_EQ(k0, k1)  (((k0)->nonce==(k1)->nonce) & ((k0)->shred_idx==(k1)->shred_idx) & ((k0)->slot==(k1)->slot))
#define MAP_KEY_HASH(k,s)   fd_hash( (s), (k), sizeof(fd_inflight_key_t) )
#define MAP_MULTI           1 /* It's possible but extremely unlikely that we'll insert duplicates */
/* Removal via the non-_fast version is kind of strange in the possible
   presence of duplicate keys. */
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME      fd_inflight_dlist
#define DLIST_ELE_T     fd_inflight_t
#define DLIST_PREV      prevll
#define DLIST_NEXT      nextll
#include "../../util/tmpl/fd_dlist.c"

struct ag_inflight {
  ulong     nonce;
  uint      kind;          /* AG_REPAIR_KIND_{PARENT_FEC_COUNT,FEC_ROOT} */
  ulong     next;          /* reserved for internal use by fd_pool and fd_map_chain */
  ulong     slot;
  fd_hash_t block_id;
  uint      fec_set_idx;
  long      timestamp_ns;  /* timestamp when request was created (nanoseconds) */
  ulong     prevll;        /* for ag_inflight_dlist (outstanding order) */
  ulong     nextll;
};
typedef struct ag_inflight ag_inflight_t;

#define POOL_NAME            ag_inflight_pool
#define POOL_T               ag_inflight_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME            ag_inflight_map
#define MAP_KEY             nonce
#define MAP_ELE_T           ag_inflight_t
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME      ag_inflight_dlist
#define DLIST_ELE_T     ag_inflight_t
#define DLIST_PREV      prevll
#define DLIST_NEXT      nextll
#include "../../util/tmpl/fd_dlist.c"
struct fd_inflights {
  /* Each element in the pool is either OUTSTANDING, POPPED (when it
     times out), or FREE.

            insert                  pop
     FREE  --------> OUTSTANDING -----------> POPPED
      ^                  |                      |
      |     remove       |  remove, or evicted  |
      -------------------------------------------

    All elements begin as FREE.  Elements that are FREE are released in
    the pool.  Elements that are OUTSTANDING are in map and
    outstanding_dl.  Elements that are POPPED are in popped_map and
    popped_dl.  If we need to acquire an element and the pool is empty,
    the oldest POPPED element will be evicted. */
  fd_inflight_t       * pool;
  fd_inflight_map_t   * map;
  fd_inflight_map_t   * popped_map;
  fd_inflight_dlist_t   outstanding_dl[1];
  fd_inflight_dlist_t   popped_dl[1];
  ulong                 popped_cnt;

  /* Alpenglow metadata requests */

  ag_inflight_t       * ag_pool;
  ag_inflight_map_t   * ag_map;
  ag_inflight_dlist_t   ag_outstanding_dl[1]; /* ag requests in insertion order, oldest at head */
};
typedef struct fd_inflights fd_inflights_t;

FD_FN_CONST static inline ulong
fd_inflights_align( void ) { return 128UL; }

FD_FN_CONST static inline ulong
fd_inflights_footprint( void ) {
  ulong chain_cnt = fd_inflight_map_chain_cnt_est( FD_INFLIGHT_REQ_MAX );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_inflights_t),  sizeof(fd_inflights_t)                            ),
      fd_inflight_pool_align(), fd_inflight_pool_footprint( FD_INFLIGHT_REQ_MAX ) ),
      fd_inflight_map_align(),  fd_inflight_map_footprint ( chain_cnt           ) ),
      fd_inflight_map_align(),  fd_inflight_map_footprint ( chain_cnt           ) ),
      ag_inflight_pool_align(), ag_inflight_pool_footprint( FD_INFLIGHT_REQ_MAX ) ),
      ag_inflight_map_align(),  ag_inflight_map_footprint ( chain_cnt           ) ),
    fd_inflights_align() );
}

void *
fd_inflights_new( void * shmem,
                  ulong  seed );

fd_inflights_t *
fd_inflights_join( void * shmem );

void
fd_inflights_request_insert( fd_inflights_t * table, ulong nonce, fd_pubkey_t const * pubkey, ulong slot, ulong shred_idx );

/* Matches a shred response to an inflight entry.  Returns the RTT in
   nanoseconds if a match is found, 0 otherwise.  This will remove all
   entries with the same (nonce, slot, shred_idx) tuple from both the
   outstanding and popped maps, and credits the response to the oldest
   entry. */
long
fd_inflights_request_match( fd_inflights_t * table, ulong nonce, ulong slot, ulong shred_idx, fd_pubkey_t * peer_out );

/* Important! Caller must guarantee that the request list is not empty.
   This function cannot fail and will always try to populate the output
   parameters. Typical use should only call this after
   fd_inflights_should_drain returns true. */
void
fd_inflights_request_pop( fd_inflights_t * table, ulong * nonce_out, ulong * slot_out, ulong * shred_idx_out );

static inline int
fd_inflights_should_drain( fd_inflights_t * table, long now ) {
  /* peek at head */
  if( FD_UNLIKELY( fd_inflight_dlist_is_empty( table->outstanding_dl, table->pool ) ) ) return 0;

  fd_inflight_t * inflight_req = fd_inflight_dlist_ele_peek_head( table->outstanding_dl, table->pool );
  if( FD_UNLIKELY( inflight_req->timestamp_ns + FD_REQLIM_DEDUP_TIMEOUT < now ) ) return 1;
  return 0;
}

/* Returns the number of new outstanding requests that can be made
   until the inflight pool is full, and there are no popped
   requests to evict.  If this is 0, then the next insert would
   evict an outstanding request. */

static inline ulong
fd_inflights_outstanding_free( fd_inflights_t * table ) {
  return fd_inflight_pool_free( table->pool ) + table->popped_cnt;
}

/* ag_inflights_should_drain mirrors fd_inflights_should_drain for the
   Alpenglow metadata (ParentAndFecSetCount / FecSetRoot) requests */

static inline int
ag_inflights_should_drain( fd_inflights_t * table, long now ) {
  /* peek at head */
  if( FD_UNLIKELY( ag_inflight_dlist_is_empty( table->ag_outstanding_dl, table->ag_pool ) ) ) return 0;

  ag_inflight_t * inflight_req = ag_inflight_dlist_ele_peek_head( table->ag_outstanding_dl, table->ag_pool );
  if( FD_UNLIKELY( inflight_req->timestamp_ns + FD_REQLIM_DEDUP_TIMEOUT < now ) ) return 1;
  return 0;
}

/* ag_inflights_request_insert adds an Alpenglow metadata request to the
   outstanding set (map + outstanding dlist, stamped with the current
   time).  Evicts the oldest outstanding request if the ag pool is
   full.  TODO are evictions okay? */
void
ag_inflights_request_insert( fd_inflights_t *    table,
                             ulong               nonce,
                             uint                kind,
                             ulong               slot,
                             fd_hash_t const *   block_id,
                             uint                fec_set_idx );

/* ag_inflights_request_pop pops the oldest outstanding ag request,
   returns its fields (including kind, so the caller can rebuild the
   exact request), removes it from the outstanding set and releases it.

   Similar to fd_inflights_request_pop, caller must guarantee that the
   request list is not empty. This function cannot fail and will always
   try to populate the output parameters. Typical use should only call
   this after ag_inflights_should_drain returns true. */
void
ag_inflights_request_pop( fd_inflights_t * table,
                          ulong *          nonce_out,
                          uint *           kind_out,
                          ulong *          slot_out,
                          fd_hash_t *      block_id_out,
                          uint *           fec_set_idx_out );

/* ag_inflights_request_match returns the outstanding ag request matching
   nonce (from both the map and the outstanding dlist), or NULL.  The
   returned element remains valid until the caller releases it with
   ag_inflight_pool_ele_release. TODO update fd_inflight API or this one
   to match */
ag_inflight_t *
ag_inflights_request_match( fd_inflights_t * table, ulong nonce );

void
fd_inflights_print( fd_inflight_dlist_t * dlist, fd_inflight_t * pool );

#endif /* HEADER_fd_src_discof_repair_fd_inflight_h */
