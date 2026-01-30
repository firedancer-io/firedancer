#ifndef HEADER_fd_src_discof_repair_fd_inflight_h
#define HEADER_fd_src_discof_repair_fd_inflight_h

#include "../../flamenco/types/fd_types.h"
#include "fd_policy.h"

/* fd_inflight tracks repair requests that are inflight to other
   validators.  This module is useful for metrics and reporting.
   In-exact updates of orphan requests and highest window requests from
   this module are non-critical, but exact updates of shred requests are
   critical. Repair tile relies on this module to be able to re-request
   any shreds that it has sent, because policy next does not request any
   shred twice.
   (TODO should this be rolled into policy.h?)

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
    FD_LAYOUT_INIT,
      alignof(fd_inflights_t),   sizeof(fd_inflights_t)                             ),
      fd_inflight_pool_align(),  fd_inflight_pool_footprint ( FD_INFLIGHT_REQ_MAX ) ),
      fd_inflight_map_align(),   fd_inflight_map_footprint  ( chain_cnt           ) ),
      fd_inflight_map_align(),   fd_inflight_map_footprint  ( chain_cnt           ) ),
    fd_inflights_align() );
}

void *
fd_inflights_new( void * shmem,
                  ulong  seed );

fd_inflights_t *
fd_inflights_join( void * shmem );

void
fd_inflights_request_insert( fd_inflights_t * table, ulong nonce, fd_pubkey_t const * pubkey, ulong slot, ulong shred_idx );

long
fd_inflights_request_remove( fd_inflights_t * table, ulong nonce, ulong slot, ulong shred_idx, fd_pubkey_t * peer_out );

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
  if( FD_UNLIKELY( inflight_req->timestamp_ns + FD_POLICY_DEDUP_TIMEOUT < now ) ) return 1;
  return 0;
}


void
fd_inflights_print( fd_inflight_map_t * map, fd_inflight_t * pool );

#endif /* HEADER_fd_src_discof_repair_fd_inflight_h */
