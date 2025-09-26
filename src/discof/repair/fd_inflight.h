#ifndef HEADER_fd_src_discof_repair_fd_inflight_h
#define HEADER_fd_src_discof_repair_fd_inflight_h

#include "../../flamenco/types/fd_types.h"

/* fd_inflights tracks repair requests that are inflight to other
   validators.  This module is not necessary for the repair protocol and
   strategy, but is useful for metrics and reporting.  Incorrect updates
   and removals from this module are non-critical.  Requests are key-ed
   by nonce as in the current strategy (see fd_policy.h), all requests
   have a unique nonce.  The chances that an inflight request does not
   get a response are non-negligible due to shred tile upstream deduping
   duplicates. */

/* Max number of pending requests */
#define FD_INFLIGHT_REQ_MAX (1<<20)

struct __attribute__((aligned(128UL))) fd_inflight {
  ulong         nonce;         /* unique identifier for the request */
  ulong         next;          /* reserved for internal use by fd_pool and fd_map_chain */
  long          timestamp_ns;  /* timestamp when request was created (nanoseconds) */
  fd_pubkey_t   pubkey;        /* public key of the peer */

  /* Reserved for DLL eviction */
  ulong          prevll;      /* pool index of previous element in DLL */
  ulong          nextll;      /* pool index of next element in DLL */
};
typedef struct fd_inflight fd_inflight_t;

#define POOL_NAME   fd_inflight_pool
#define POOL_T      fd_inflight_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME     fd_inflight_map
#define MAP_KEY      nonce
#define MAP_ELE_T    fd_inflight_t
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME      fd_inflight_dlist
#define DLIST_ELE_T     fd_inflight_t
#define DLIST_PREV      prevll
#define DLIST_NEXT      nextll
#include "../../util/tmpl/fd_dlist.c"

struct fd_inflights {
  fd_inflight_t       * pool;
  fd_inflight_map_t   * map;
  fd_inflight_dlist_t * dlist;
};
typedef struct fd_inflights fd_inflights_t;

FD_FN_CONST static inline ulong
fd_inflights_align( void ) { return 128UL; }

FD_FN_CONST static inline ulong
fd_inflights_footprint( void ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_inflights_t),   sizeof(fd_inflights_t)                             ),
      fd_inflight_pool_align(),  fd_inflight_pool_footprint ( FD_INFLIGHT_REQ_MAX ) ),
      fd_inflight_map_align(),   fd_inflight_map_footprint  ( FD_INFLIGHT_REQ_MAX ) ),
      fd_inflight_dlist_align(), fd_inflight_dlist_footprint()                      ),
    fd_inflights_align() );
}

void *
fd_inflights_new( void * shmem );

fd_inflights_t *
fd_inflights_join( void * shmem );

void
fd_inflights_request_insert( fd_inflights_t * table, ulong nonce, fd_pubkey_t const * pubkey );

long
fd_inflights_request_remove( fd_inflights_t * table, ulong nonce, fd_pubkey_t * peer_out );

fd_inflight_t *
fd_inflights_request_query ( fd_inflights_t * table, ulong nonce );

#endif /* HEADER_fd_src_discof_repair_fd_inflight_h */
