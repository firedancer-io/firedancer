#ifndef HEADER_fd_src_discof_repair_fd_reqlim_h
#define HEADER_fd_src_discof_repair_fd_reqlim_h

/* fd_reqlim implements a dedup cache for already sent Repair requests.
   It is backed by a map and linked list, in which the least recently
   used (oldest Repair request) in the map is evicted when the map is
   full. */

#include "../../util/fd_util.h"

#define FD_REQLIM_DEDUP_TIMEOUT 80000000L /* 80 ms - how long to wait before re-requesting the same shred */

FD_STATIC_ASSERT( 16000000L < FD_REQLIM_DEDUP_TIMEOUT, "DEDUP_TIMEOUT must be greater than 16ms to avoid rnonces from trivially clashing" );

/* fd_reqlim_ele describes an element in the dedup cache.  The key
   compactly encodes an fd_repair_req_t.

   | kind (4 bits) | slot (32 bits) | shred_idx (28 bits) |
   | bits 63:60    | bits 59:28     | bits 27:0           |

   kind uses the FD_REPAIR_KIND_* wire values directly.

   Note the common header (sig, from, to, ts, nonce) is not included. */

struct fd_reqlim_ele {
  ulong key;      /* compact encoding of fd_repair_req_t detailed above */
  ulong prev;     /* reserved by lru */
  ulong next;
  ulong hash;     /* reserved by pool and map_chain */
  long  req_ts;   /* timestamp when the request was sent */
};
typedef struct fd_reqlim_ele fd_reqlim_ele_t;

FD_FN_CONST static inline ulong
fd_reqlim_key( uint kind, ulong slot, uint shred_idx ) {
  ulong k = (ulong)fd_uint_extract_lsb( kind, 4 );
  ulong i = (ulong)fd_uint_extract_lsb( shred_idx, 28 );
  ulong s = fd_ulong_extract_lsb( slot, 32 );
  return k << 60 | s << 28 | i;
}

#define POOL_NAME fd_reqlim_pool
#define POOL_T    fd_reqlim_ele_t
#define POOL_NEXT hash
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_reqlim_map
#define MAP_ELE_T fd_reqlim_ele_t
#define MAP_NEXT  hash
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME   fd_reqlim_lru
#define DLIST_ELE_T  fd_reqlim_ele_t
#define DLIST_NEXT   next
#define DLIST_PREV   prev
#include "../../util/tmpl/fd_dlist.c"

struct fd_reqlim {
  fd_reqlim_map_t * map;  /* map of dedup elements */
  fd_reqlim_ele_t * pool; /* memory pool of dedup elements */
  fd_reqlim_lru_t * lru;  /* linked list of dedup elements by insertion order */
};
typedef struct fd_reqlim fd_reqlim_t;

/* Constructors */

FD_FN_CONST static inline ulong
fd_reqlim_align( void ) {
  return 128UL;
}

FD_FN_CONST static inline ulong
fd_reqlim_footprint( ulong dedup_max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      fd_reqlim_align(),      sizeof(fd_reqlim_t)                       ),
      fd_reqlim_map_align(),  fd_reqlim_map_footprint ( dedup_max )     ),
      fd_reqlim_pool_align(), fd_reqlim_pool_footprint( dedup_max )     ),
      fd_reqlim_lru_align(),  fd_reqlim_lru_footprint()                 ),
    fd_reqlim_align() );
}

/* fd_reqlim_new formats an unused memory region for use as a dedup
   cache.  mem is a non-NULL pointer to this region in the local address
   space with the required footprint and alignment. */

void *
fd_reqlim_new( void * shmem, ulong dedup_max, ulong seed );

/* fd_reqlim_join joins the caller to the dedup cache.  Returns a pointer
   in the local address space to dedup on success. */

fd_reqlim_t *
fd_reqlim_join( void * shdedup );

/* fd_reqlim_leave leaves a current local join. */

void *
fd_reqlim_leave( fd_reqlim_t const * dedup );

/* fd_reqlim_delete unformats a memory region used as a dedup cache. */

void *
fd_reqlim_delete( void * dedup );

/* fd_reqlim_next returns 1 if key is deduped (already sent within the
   dedup timeout window), 0 otherwise.  When not deduped, the key is
   inserted/refreshed in the cache with the current timestamp. */

int
fd_reqlim_next( fd_reqlim_t * dedup, ulong key, long now );

/* fd_reqlim_query returns 1 if key is in the dedup cache and was sent
   within the dedup timeout window, 0 otherwise.  Read-only: does not
   insert or update any state. */

int
fd_reqlim_query( fd_reqlim_t const * dedup, ulong key, long now );

#endif /* HEADER_fd_src_discof_repair_fd_reqlim_h */
