#ifndef HEADER_fd_src_discof_repair_fd_recorder_h
#define HEADER_fd_src_discof_repair_fd_recorder_h

/*
Recorder:

The recorder tracks peers and outstanding repair requests for the Solana
repair protocol. It maintains two hash maps: one for peers and one for
requests, with automatic expiration handling.

   The recorder manages:
   - Peer tracking with IP addresses and timestamps
   - Outstanding repair requests with nonces, timeouts, and target peers
   - Peer selection for new repair requests
   - Automatic cleanup of expired requests

   The recorder is designed for concurrent access from multiple tiles:
   - Allocated in a dedicated workspace for shared memory access
   - Protected by a read-write lock for thread-safe operations
   - Joinable by multiple tiles (e.g., repair tile, shredcap tile)

   Typical usage:

     // Create in workspace
     void * mem = fd_wksp_alloc_laddr( wksp, fd_recorder_align(),
                                       fd_recorder_footprint(), 1UL );
     fd_recorder_t * recorder = fd_recorder_join(
    fd_recorder_new( mem, seed, timeout_ns ) );

     // Access with appropriate locking
     fd_rwlock_write( &recorder->rw_lock );
     fd_recorder_peer_add( recorder, pubkey, ip4_port );
     fd_rwlock_unwrite( &recorder->rw_lock );

     // Query with read lock
     fd_rwlock_read( &recorder->rw_lock );
     fd_recorder_req_t * req = fd_recorder_req_query( recorder, nonce );
     // Use req...
     fd_rwlock_unread( &recorder->rw_lock );

   IMPORTANT: Pointers returned by query functions are only valid while the lock is held.
   Do not use returned pointers after releasing the lock. */


/* IMPORTANT NOTE ON LOCKING:
   Currently, the recorder does not implement locking given that it's
   only accessed by the repair tile. Initial implementation was to use
   locking in order to allow multiple tiles to access the recorder.
   However, this is no longer needed. Locking functionality remains in
   the library for future use, if needed, but is currently unused.
*/

#include "../../flamenco/types/fd_types.h"
#include "../../util/net/fd_net_headers.h"
#include "../../flamenco/fd_rwlock.h"
#include <stdbool.h>

#define FD_MAX_PEERS (1<<12)
#define MAX_REQUESTS (1000000UL)



/* FD_RECORDER_USE_HANDHOLDING: Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */
#define FD_RECORDER_USE_HANDHOLDING 0


#define FD_RECORDER_MAGIC (0xf17eda2ce7940570UL) /* firedancer recorder version 0 */

/* fd_recorder_req_t represents a single peer request in the system.
   Each request is tracked by a unique nonce and contains metadata
   about the request including timestamp, peer pubkey, and request data. */

struct __attribute__((aligned(128UL))) fd_recorder_req {
  ulong         nonce;         /* unique identifier for the request */
  ulong         next;          /* reserved for internal use by fd_pool and fd_map_chain */
  ulong         timestamp_ns;  /* timestamp when request was created (nanoseconds) */
  fd_pubkey_t   pubkey;        /* public key of the peer */

  /* Doubly linked list pointers for timeout management */
  ulong         prev_idx;      /* pool index of previous element in timeout list */
  ulong         next_idx;      /* pool index of next element in timeout list */

  /* Request-specific data (can be extended based on needs) */
  ulong         slot;          /* slot number for the request */
  ulong         shred_idx;     /* shred index within the slot */
};
typedef struct fd_recorder_req fd_recorder_req_t;

/* Define the memory pool for recorder requests */
#define POOL_NAME       fd_recorder_req_pool
#define POOL_T          fd_recorder_req_t
#include "../../util/tmpl/fd_pool.c"

/* Define the hash map for nonce -> request mapping */
#define MAP_NAME        fd_recorder_req_map
#define MAP_ELE_T       fd_recorder_req_t
#define MAP_KEY         nonce
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME      fd_recorder_req_dlist
#define DLIST_ELE_T     fd_recorder_req_t
#define DLIST_PREV      prev_idx
#define DLIST_NEXT      next_idx
#include "../../util/tmpl/fd_dlist.c"

struct __attribute__((aligned(64UL))) fd_recorder_peer {
  fd_pubkey_t   key;                  /* peer's public key */
  ulong         next;                 /* reserved for internal use by fd_map_chain */
  fd_ip4_port_t ip4;                  /* peer's IP */
  double        ewma_hr;              /* exponentially weighted moving average hit rate */
  double        ewma_rtt;             /* exponentially weighted moving average RTT */
  ulong         inflight_to_peer_cnt; /* number of inflight requests to this peer */
};
typedef struct fd_recorder_peer fd_recorder_peer_t;

/* Define the memory pool for recorder peers */
#define POOL_NAME fd_recorder_peer_pool
#define POOL_T    fd_recorder_peer_t
#include "../../util/tmpl/fd_pool.c"

/* Define the hash map for pubkey -> peer mapping */
#define MAP_NAME  fd_recorder_peer_map
#define MAP_ELE_T fd_recorder_peer_t
#define MAP_KEY   key
#define MAP_KEY_T fd_pubkey_t
#define MAP_KEY_EQ(k0,k1) (!memcmp( (k0), (k1), 32UL ))
#define MAP_KEY_HASH(key,seed) fd_hash((seed),(key),32UL)
#include "../../util/tmpl/fd_map_chain.c"

#define FD_RECORDER_MAGIC_INTERNAL (0xf17eda2ce7940570UL)

struct __attribute__((aligned(128UL))) fd_recorder {
  /* Metadata */
  ulong magic;
  ulong recorder_gaddr;        /* wksp gaddr of this in the backing wksp */
  ulong seed;                  /* seed for hash functions */
  ulong timeout_ns;            /* global timeout duration for requests in nanoseconds */
  fd_rwlock_t rw_lock;         /* read-write lock for the recorder */

  /* Memory pool, hash map, and dlist for reqs and peers */
  ulong req_pool_gaddr;
  ulong req_map_gaddr;
  ulong req_dlist_gaddr;
  ulong peer_pool_gaddr;
  ulong peer_map_gaddr;

  /* Stats */
  ulong total_active_requests;     /* current number of active requests */
  ulong total_expired_requests;    /* total number of expired requests */
  ulong total_handled_requests;    /* total number of handled requests */

  ulong peer_cnt;        /* current number of active peers */
  /* Peer arrays used for weighted round-robin selection */
  fd_pubkey_t * high_priority_peers[FD_MAX_PEERS];
  fd_pubkey_t * medium_priority_peers[FD_MAX_PEERS];
  fd_pubkey_t * low_priority_peers[FD_MAX_PEERS];
  fd_pubkey_t * zero_hr_peers[FD_MAX_PEERS];

  ulong high_priority_cnt;    /* number of high priority peers */
  ulong medium_priority_cnt;  /* number of medium priority peers */
  ulong low_priority_cnt;     /* number of low priority peers */
  ulong zero_hr_cnt;          /* number of zero HR peers */

  ulong high_priority_idx;    /* current index in high priority list */
  ulong medium_priority_idx;  /* current index in medium priority list */
  ulong low_priority_idx;     /* current index in low priority list */
  ulong zero_hr_idx;          /* current index in zero HR list */

  ulong cycle_position;       /* position in the weighted round-robin cycle */
  ulong cycle_count;          /* number of complete cycles */

};
typedef struct fd_recorder fd_recorder_t;

FD_PROTOTYPES_BEGIN

/* ================= CONSTRUCTORS ================= */

/* fd_recorder_{align,footprint} return the required alignment and
   footprint of memory suitable for use as recorder. */

FD_FN_CONST static inline ulong
fd_recorder_align( void ) {
  return alignof(fd_recorder_t);
}

FD_FN_CONST static inline ulong
fd_recorder_footprint( void ) {
  ulong req_chain_cnt = fd_recorder_req_map_chain_cnt_est( MAX_REQUESTS );
  ulong peer_chain_cnt = fd_recorder_peer_map_chain_cnt_est( FD_MAX_PEERS );

  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_recorder_t),                sizeof(fd_recorder_t) ),
      fd_recorder_req_pool_align(),          fd_recorder_req_pool_footprint( MAX_REQUESTS ) ),
      fd_recorder_req_map_align(),           fd_recorder_req_map_footprint( req_chain_cnt ) ),
      fd_recorder_req_dlist_align(),         fd_recorder_req_dlist_footprint() ),
      fd_recorder_peer_pool_align(),         fd_recorder_peer_pool_footprint( FD_MAX_PEERS ) ),
      fd_recorder_peer_map_align(),          fd_recorder_peer_map_footprint( peer_chain_cnt ) ),
    fd_recorder_align() );
}

/* fd_recorder_new formats an unused memory region for use as a recorder.
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  seed is an arbitrary
   value used for hash functions.  timeout_ns is the timeout duration in
   nanoseconds. */

void * fd_recorder_new( void * shmem, ulong seed, ulong timeout_ns );

/* fd_recorder_join joins the caller to the recorder. */

fd_recorder_t * fd_recorder_join( void * shrecorder );

/* fd_recorder_leave leaves a current local join. */

void * fd_recorder_leave( fd_recorder_t const * recorder );

/* fd_recorder_delete unformats a memory region used as a recorder. */

void * fd_recorder_delete( void * recorder );

/* ================= ACCESSORS ================= */

/* fd_recorder_wksp returns the local join to the wksp backing the
   recorder. The lifetime of the returned pointer is at least as long as
   the lifetime of the local join.  Assumes recorder is a current local
   join. */

FD_FN_PURE static inline fd_wksp_t * fd_recorder_wksp( fd_recorder_t const * recorder ) { return (fd_wksp_t *)( ( (ulong)recorder ) - recorder->recorder_gaddr ); }

/* fd_recorder_{req_pool,req_map,req_dlist,peer_pool,peer_map} returns a
   pointer in the caller's address space to the corresponding recorder
   field. const versions for each are also provided. */

FD_FN_PURE static inline fd_recorder_req_t             * fd_recorder_req_pool        ( fd_recorder_t       * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->req_pool_gaddr  ); }
FD_FN_PURE static inline fd_recorder_req_t       const * fd_recorder_req_pool_const  ( fd_recorder_t const * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->req_pool_gaddr  ); }
FD_FN_PURE static inline fd_recorder_req_map_t         * fd_recorder_req_map         ( fd_recorder_t       * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->req_map_gaddr   ); }
FD_FN_PURE static inline fd_recorder_req_map_t   const * fd_recorder_req_map_const   ( fd_recorder_t const * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->req_map_gaddr   ); }
FD_FN_PURE static inline fd_recorder_req_dlist_t       * fd_recorder_req_dlist       ( fd_recorder_t       * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->req_dlist_gaddr ); }
FD_FN_PURE static inline fd_recorder_req_dlist_t const * fd_recorder_req_dlist_const ( fd_recorder_t const * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->req_dlist_gaddr ); }
FD_FN_PURE static inline fd_recorder_peer_t            * fd_recorder_peer_pool       ( fd_recorder_t       * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->peer_pool_gaddr ); }
FD_FN_PURE static inline fd_recorder_peer_t      const * fd_recorder_peer_pool_const ( fd_recorder_t const * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->peer_pool_gaddr ); }
FD_FN_PURE static inline fd_recorder_peer_map_t        * fd_recorder_peer_map        ( fd_recorder_t       * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->peer_map_gaddr  ); }
FD_FN_PURE static inline fd_recorder_peer_map_t  const * fd_recorder_peer_map_const  ( fd_recorder_t const * recorder ) { return fd_wksp_laddr_fast( fd_recorder_wksp( recorder ), recorder->peer_map_gaddr  ); }


/* fd_recorder_{timeout_ns,req_cnt,peer_cnt} return recorder statistics and configuration. */
FD_FN_PURE static inline ulong fd_recorder_timeout_ns ( fd_recorder_t const * recorder ) { return recorder->timeout_ns;             }
FD_FN_PURE static inline ulong fd_recorder_req_cnt    ( fd_recorder_t const * recorder ) { return recorder->total_active_requests;  }
FD_FN_PURE static inline ulong fd_recorder_peer_cnt   ( fd_recorder_t const * recorder ) { return recorder->peer_cnt;               }

/* ================== ALL HANDLING OPERATIONS ================== */

/* LOCKING PROTOCOL:

   The recorder uses a read-write lock (rw_lock) for thread-safe
   concurrent access. All operations on the recorder require appropriate
   locking:

   - READ LOCK: Required for operations that only query/read data
     without modifying state
     - req_query, peer_query
     - req_oldest, req_newest
     - verify, print operations

   - WRITE LOCK: Required for operations that modify the data structure
     - req_insert, req_remove, req_expire
     - peer_add, peer_remove, peer_update
     - select_peers (modifies internal indices)

   Lock acquisition/release is the CALLER'S responsibility. The recorder
   functions do NOT acquire or release locks internally. Typical usage:

     fd_rwlock_read( &recorder->rw_lock );
     fd_recorder_req_t * req = fd_recorder_req_query( recorder, nonce );
     // Use req while lock is held...
     fd_rwlock_unread( &recorder->rw_lock );

   IMPORTANT: Pointers returned by query functions are only valid while
   the lock is held. Do not use returned pointers after releasing the
   lock. */

/* ================== REQUEST HANDLING ================== */

/* fd_recorder_req_insert inserts a new request into the recorder.
   Returns a pointer to the inserted request on success, NULL on
   failure. Failures can occur if the recorder is full or if the nonce
   already exists.

   Requires caller to hold WRITE LOCK on recorder->rw_lock */

fd_recorder_req_t *
fd_recorder_req_insert( fd_recorder_t *             recorder,
                        ulong                       nonce,
                        ulong                       timestamp_ns,
                        fd_pubkey_t const *         pubkey,
                        fd_ip4_port_t               ip4,
                        ulong                       slot,
                        ulong                       shred_idx );

/* fd_recorder_req_query looks up a request by its nonce.
   Returns a pointer to the request if found, NULL otherwise.

   Requires caller to hold READ LOCK on recorder->rw_lock
   The returned pointer is only valid while the lock is held. */

FD_FN_PURE static inline fd_recorder_req_t const *
fd_recorder_req_query_const( fd_recorder_t const * recorder, ulong nonce ) {
  fd_recorder_req_map_t const * req_map  = fd_recorder_req_map_const( recorder );
  fd_recorder_req_t const *     req_pool = fd_recorder_req_pool_const( recorder );
  return fd_recorder_req_map_ele_query_const( req_map, &nonce, NULL, req_pool );
}

FD_FN_PURE static inline fd_recorder_req_t *
fd_recorder_req_query( fd_recorder_t * recorder, ulong nonce ) {
  fd_recorder_req_map_t * req_map  = fd_recorder_req_map( recorder );
  fd_recorder_req_t *     req_pool = fd_recorder_req_pool( recorder );
  return fd_recorder_req_map_ele_query( req_map, &nonce, NULL, req_pool );
}

/* fd_recorder_req_remove removes a request by its nonce.
   Returns 0 on success, -1 if the request was not found.

   CONCURRENCY: Requires caller to hold WRITE LOCK on recorder->rw_lock */

int
fd_recorder_req_remove( fd_recorder_t * recorder, ulong nonce, int is_recv );

/* fd_recorder_req_expire removes all requests that have timed out based
   on the provided current timestamp.  Returns the number of expired
   requests.

   CONCURRENCY: Requires caller to hold WRITE LOCK on recorder->rw_lock */

ulong
fd_recorder_req_expire( fd_recorder_t * recorder, ulong current_ns, int is_recv );

/* fd_recorder_req_oldest returns the oldest request in the recorder
   (front of list). Returns NULL if the recorder is empty.

   CONCURRENCY: Requires caller to hold READ LOCK on recorder->rw_lock
   The returned pointer is only valid while the lock is held. */

FD_FN_PURE static inline fd_recorder_req_t const *
fd_recorder_req_oldest( fd_recorder_t const * recorder ) {
  fd_recorder_req_dlist_t const * dlist = fd_recorder_req_dlist_const( recorder );
  fd_recorder_req_t const * pool = fd_recorder_req_pool_const( recorder );
  if( FD_UNLIKELY( fd_recorder_req_dlist_is_empty( dlist, pool ) ) ) return NULL;
  return fd_recorder_req_dlist_ele_peek_head_const( dlist, pool );
}

/* fd_recorder_req_newest returns the newest request in the recorder
   (back of list). Returns NULL if the recorder is empty.

   CONCURRENCY: Requires caller to hold READ LOCK on recorder->rw_lock
   The returned pointer is only valid while the lock is held. */

FD_FN_PURE static inline fd_recorder_req_t const *
fd_recorder_req_newest( fd_recorder_t const * recorder ) {
  fd_recorder_req_dlist_t const * dlist = fd_recorder_req_dlist_const( recorder );
  fd_recorder_req_t const * pool = fd_recorder_req_pool_const( recorder );
  if( FD_UNLIKELY( fd_recorder_req_dlist_is_empty( dlist, pool ) ) ) return NULL;
  return fd_recorder_req_dlist_ele_peek_tail_const( dlist, pool );
}

/* ================== PEER HANDLING ================== */

/* fd_recorder_peer_add adds a new peer to the recorder.
   Returns a pointer to the peer on success, NULL on failure.

   CONCURRENCY: Requires caller to hold WRITE LOCK on recorder->rw_lock */
fd_recorder_peer_t *
fd_recorder_peer_add( fd_recorder_t *             recorder,
                      fd_pubkey_t const *         pubkey,
                      fd_ip4_port_t               ip4 );

/* fd_recorder_peer_query looks up a peer by its pubkey.
   Returns a pointer to the peer if found, NULL otherwise.

   CONCURRENCY: Requires caller to hold READ LOCK on recorder->rw_lock
   The returned pointer is only valid while the lock is held. */
FD_FN_PURE static inline fd_recorder_peer_t const *
fd_recorder_peer_query_const( fd_recorder_t const * recorder, fd_pubkey_t const * pubkey ) {
  fd_recorder_peer_map_t const * peer_map  = fd_recorder_peer_map_const( recorder );
  fd_recorder_peer_t const *     peer_pool = fd_recorder_peer_pool_const( recorder );
  return fd_recorder_peer_map_ele_query_const( peer_map, pubkey, NULL, peer_pool );
}

FD_FN_PURE static inline fd_recorder_peer_t *
fd_recorder_peer_query( fd_recorder_t * recorder, fd_pubkey_t const * pubkey ) {
  fd_recorder_peer_map_t * peer_map  = fd_recorder_peer_map( recorder );
  fd_recorder_peer_t *     peer_pool = fd_recorder_peer_pool( recorder );
  return fd_recorder_peer_map_ele_query( peer_map, pubkey, NULL, peer_pool );
}

/* fd_recorder_peer_remove removes a peer by its pubkey.
   Returns a pointer to the removed peer on success, NULL if the peer
   was not found.

   CONCURRENCY: Requires caller to hold WRITE LOCK on recorder->rw_lock */
fd_recorder_peer_t *
fd_recorder_peer_remove( fd_recorder_t *     recorder,
                         fd_pubkey_t const * pubkey );

/* fd_recorder_peer_update updates a peer by its pubkey.
   Returns a pointer to the peer on success, NULL on failure.

   CONCURRENCY: Requires caller to hold WRITE LOCK on recorder->rw_lock */
fd_recorder_peer_t *
fd_recorder_peer_update( fd_recorder_t *             recorder,
                         fd_pubkey_t const *         pubkey,
                         fd_ip4_port_t               ip4,
                         int                         is_recv,
                         ulong                       req_timestamp_ns,
                         ulong                       current_time );


/* ================== PEER SELECTION ================== */

/* fd_recorder_select_peer selects a single peer for repair, using a
   weighted round-robin algorithm. Returns a pointer to the pubkey of
   the selected peer, or NULL if no peers are available.

   CONCURRENCY: Requires caller to hold WRITE LOCK on recorder->rw_lock
   as this may modify internal state (peer selection indices) */
fd_pubkey_t *
fd_recorder_select_peer(fd_recorder_t * recorder);

/* fd_recorder_reshuffle_peers reshuffles peers into categories based on
   hit rate. Peers under 50ms RTT go to high priority, under 100ms to
   medium priority, remaining to low priority. Zero hit rate peers
   remain separate.

   CONCURRENCY: Requires caller to hold WRITE LOCK on recorder->rw_lock */
void
fd_recorder_reshuffle_peers_boundaries(fd_recorder_t * recorder);

/* fd_recorder_reshuffle_peers_cnt reshuffles peers into categories
   based on count. The quickest 500 peers go to high priority, next 500
   to medium priority, remaining to low priority. Zero hit rate peers
   remain separate.

   CONCURRENCY: Requires caller to hold WRITE LOCK on recorder->rw_lock */
void
fd_recorder_reshuffle_peers_cnt( fd_recorder_t * recorder );



/* ================== PRINT & VERIFY HELPERS ================== */

/* fd_recorder_print prints peer count

   CONCURRENCY: Requires caller to hold READ LOCK on recorder->rw_lock */

void
fd_recorder_print_summary( fd_recorder_t const * recorder );

/* fd_recorder_peer_print prints a peer.

   CONCURRENCY: Requires caller to hold READ LOCK on recorder->rw_lock */
void
fd_recorder_peer_print( fd_recorder_peer_t * peer );

/* fd_recorder_print_first_nonce prints the first nonce in the dlist.

   CONCURRENCY: Requires caller to hold READ LOCK on recorder->rw_lock */
void
fd_recorder_print_first_nonce( fd_recorder_t * recorder );


/* fd_recorder_verify checks that the recorder data structure is
   internally consistent. Returns 0 on success, -1 on failure.

   CONCURRENCY: Requires caller to hold READ LOCK on recorder->rw_lock */

int
fd_recorder_verify( fd_recorder_t const * recorder );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_repair_fd_recorder_h */
