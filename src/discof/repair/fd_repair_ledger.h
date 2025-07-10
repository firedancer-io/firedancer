#ifndef HEADER_fd_src_discof_repair_fd_peer_ledger_h
#define HEADER_fd_src_discof_repair_fd_peer_ledger_h

/*
Repair Ledger:

The repair ledger tracks peers and outstanding repair requests
   for the Solana repair protocol. It maintains two hash maps: one for peers
   and one for requests, with automatic expiration handling.

   The repair ledger manages:
   - Peer discovery and connection tracking with IP addresses and timestamps
   - Outstanding repair requests with nonces, timeouts, and target peers
   - Peer selection for new repair requests
   - Automatic cleanup of expired requests

   Typical usage:

     fd_repair_ledger_t * ledger = fd_repair_ledger_join( 
       fd_repair_ledger_new( mem, seed, timeout_ns ) );

     // Add a peer
     fd_repair_ledger_peer_add( ledger, pubkey, ip4_port, timestamp );

     // Insert a repair request
     fd_repair_ledger_req_insert( ledger, nonce, timestamp, pubkey, 
                                  ip4_port, slot, shred_index, type );

     // Query for a request by nonce
     fd_repair_ledger_req_t * req = fd_repair_ledger_req_query( ledger, nonce );

     // Select peers for new requests
     fd_pubkey_t * peers[MAX_PEERS];
     fd_repair_ledger_select_peers( ledger, count, peers );

     // Expire old requests
     fd_repair_ledger_req_expire( ledger, current_time );
  
┌─────────────────────────────────────────────────────────────────┐
│                    fd_repair_ledger_t                           │
│  ┌─────────────────┬─────────────────────────────────────────┐  │
│  │   Metadata      │         Statistics                      │  │
│  │  - magic        │  - req_cnt, req_expired_cnt             │  │
│  │  - seed         │  - req_handled_cnt, peer_cnt            │  │
│  │  - timeout_ns   │  - peer_pubkeys[MAX_PEERS]              │  │
│  └─────────────────┴─────────────────────────────────────────┘  │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │      REQUEST TRACKING SYSTEM - fd_repair_ledger_req_t       ││
│  │                                                             ││
│  │  ┌─────────────────┐    ┌─────────────────┐                 ││
│  │  │ req_pool        │    │ req_map         │                 ││
│  │  │ (Memory Pool)   │    │ (Hash Map)      │                 ││
│  │  │                 │    │ nonce -> req    │                 ││
│  │  │ [req][req][req] │◄──►│     O(1)        │                 ││
│  │  │ [.......free..] │    │    lookup       │                 ││
│  │  └─────────────────┘    └─────────────────┘                 ││
│  │           ▲                       ▲                         ││
│  │           │                       │                         ││
│  │           ▼                       ▼                         ││
│  │  ┌─────────────────────────────────────────┐                ││
│  │  │         req_dlist                       │                ││
│  │  │      (Doubly Linked List)               │                ││
│  │  │                                         │                ││
│  │  │ [oldest]◄──►[req]◄──►[req]◄──►[newest] │                 ││
│  │  │     ▲                             ▲     │                ││
│  │  │     │      Time-ordered for       │     │                ││
│  │  │     │       expiration           │     │                 ││
│  │  │   expire()                    insert()  │                ││
│  │  └─────────────────────────────────────────┘                ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │       PEER MANAGEMENT SYSTEM - fd_repair_ledger_peer_t      ││
│  │                                                             ││
│  │  ┌─────────────────┐    ┌─────────────────┐                 ││
│  │  │ peer_pool       │    │ peer_map        │                 ││
│  │  │ (Memory Pool)   │    │ (Hash Map)      │                 ││
│  │  │                 │    │ pubkey -> peer  │                 ││
│  │  │[peer][peer][..] │◄──►│     O(1)        │                 ││
│  │  │[....free.....] │    │    lookup       │                  ││
│  │  └─────────────────┘    └─────────────────┘                 ││
│  │           ▲                                                 ││
│  │           │                                                 ││
│  │           ▼                                                 ││
│  │  ┌─────────────────────────────────────────┐                ││
│  │  │        peer_pubkeys[]                   │                ││
│  │  │     (Round-robin Array)                 │                ││
│  │  │                                         │                ││
│  │  │ [pubkey0][pubkey1][pubkey2][......]     │                ││
│  │  │     ▲                                   │                ││
│  │  │     │ peer_pubkeys_idx (rotating)       │                ││
│  │  │     └── select_peers() uses this        │                ││
│  │  └─────────────────────────────────────────┘                ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘

Individual Data Structures:

┌─────────────────────────────────┐    ┌─────────────────────────────────┐
│     fd_repair_ledger_req_t      │    │     fd_repair_ledger_peer_t     │
│  ┌─────────────────────────────┐│    │  ┌─────────────────────────────┐│
│  │ - nonce (unique ID)         ││    │  │ - key (pubkey)              ││
│  │ - timestamp_ns              ││    │  │ - ip4 (IP address)          ││
│  │ - pubkey (links to peer)    ││    │  │ - last_send, last_recv      ││
│  │ - slot, shred_idx           ││    │  │ - ewma_hr (hit rate)        ││
│  │ - req_type                  ││    │  │ - ewma_rtt (round trip)     ││
│  │ - prev_idx, next_idx        ││    │  │ - num_inflight_req          ││
│  │   (for dlist)               ││    │  └─────────────────────────────┘│
│  └─────────────────────────────┘│    └─────────────────────────────────┘
└─────────────────────────────────┘

cursor draws nice diagrams

*/

#include "../../disco/fd_disco_base.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/net/fd_net_headers.h"
#include "../../util/log/fd_log.h"
#include "../../util/pod/fd_pod_format.h"
#include <stdbool.h>


/* FD_PEER_LEDGER_USE_HANDHOLDING: Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#define FD_REPAIR_KIND_PONG              (7U)
#define FD_REPAIR_KIND_SHRED_REQ         (8U)
#define FD_REPAIR_KIND_HIGHEST_SHRED_REQ (9U)
#define FD_REPAIR_KIND_ORPHAN_REQ        (10U)

#define MAX_PEERS (8192UL)
#define MAX_REQUESTS (1000000UL)

#ifndef FD_PEER_LEDGER_USE_HANDHOLDING
#define FD_PEER_LEDGER_USE_HANDHOLDING 1
#endif


#define FD_REPAIR_LEDGER_MAGIC (0xf17eda2ce7940570UL) /* firedancer repair_ledger version 0 */

/* fd_peer_ledger_req_t represents a single peer request in the system.
   Each request is tracked by a unique nonce and contains metadata
   about the request including timestamp, peer pubkey, and request data. */

struct __attribute__((aligned(128UL))) fd_repair_ledger_req {
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
  uint          req_type;      /* type of repair request */
};
typedef struct fd_repair_ledger_req fd_repair_ledger_req_t;

/* Define the memory pool for peer_ledger requests */
#define POOL_NAME       fd_repair_ledger_req_pool
#define POOL_T          fd_repair_ledger_req_t
#include "../../util/tmpl/fd_pool.c"

/* Define the hash map for nonce -> request mapping */
#define MAP_NAME        fd_repair_ledger_req_map
#define MAP_ELE_T       fd_repair_ledger_req_t
#define MAP_KEY         nonce
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME      fd_repair_ledger_req_dlist
#define DLIST_ELE_T     fd_repair_ledger_req_t
#define DLIST_PREV      prev_idx
#define DLIST_NEXT      next_idx
#include "../../util/tmpl/fd_dlist.c"

struct __attribute__((aligned(64UL))) fd_repair_ledger_peer {
  fd_pubkey_t   key;               /* peer's public key */
  ulong         next;              /* reserved for internal use by fd_map_chain */
  fd_ip4_port_t ip4;               /* peer's IP */
  long          last_send;          /* timestamp of last send to peer */
  long          last_recv;          /* timestamp of last receive from peer */
  ulong         ewma_hr;            /* exponentially weighted moving average hit rate */
  ulong         ewma_rtt;           /* exponentially weighted moving average RTT */
  ulong         num_inflight_req;   /* number of inflight requests to this peer */
  ulong         peer_list_idx;      /* index of the peer in the peer_list array */
  uint          pong_sent;          /* 1 if pong has been sent to this peer */
};
typedef struct fd_repair_ledger_peer fd_repair_ledger_peer_t;

/* Define the memory pool for peer_ledger peers */
#define POOL_NAME fd_repair_ledger_peer_pool
#define POOL_T    fd_repair_ledger_peer_t
#include "../../util/tmpl/fd_pool.c"

/* Define the hash map for pubkey -> peer mapping */
#define MAP_NAME  fd_repair_ledger_peer_map
#define MAP_ELE_T fd_repair_ledger_peer_t
#define MAP_KEY   key
#define MAP_KEY_T fd_pubkey_t
#define MAP_KEY_EQ(k0,k1) (!memcmp( (k0), (k1), 32UL ))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash( ((ulong *)(key))[0] ^ (seed) )
#include "../../util/tmpl/fd_map_chain.c"

#define FD_REPAIR_LEDGER_MAGIC (0xf17eda2ce7940570UL)

struct __attribute__((aligned(128UL))) fd_peer_ledger {
  /* Metadata */
  ulong magic;
  ulong peer_ledger_gaddr;     /* wksp gaddr of this in the backing wksp */
  ulong seed;                  /* seed for hash functions */
  ulong timeout_ns;            /* global timeout duration for requests in nanoseconds */
  
    /* Memory pool, hash map, and dlist for reqs and peers */
  ulong req_pool_gaddr;  
  ulong req_map_gaddr;   
  ulong req_dlist_gaddr; 
  ulong peer_pool_gaddr; 
  ulong peer_map_gaddr;

  /* Stats */
  ulong req_cnt;         /* current number of active requests */
  ulong req_max;         /* maximum number of concurrent requests */
  ulong req_expired_cnt; /* total number of expired requests */ // maybe remove?
  ulong req_handled_cnt; /* total number of handled requests */ // maybe remove?
 
  ulong peer_cnt;        /* current number of active peers */
  fd_pubkey_t peer_pubkeys[MAX_PEERS];
  ulong pubkeys_idx; /* index of the current peer in the peer_pubkeys array when iterating */

};
/* Renamed to fd_repair_ledger_t for clarity */
typedef struct fd_peer_ledger fd_repair_ledger_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_repair_ledger_{align,footprint} return the required alignment and
   footprint of memory suitable for use as repair_ledger. */

FD_FN_CONST static inline ulong
fd_repair_ledger_align( void ) {
  return alignof(fd_repair_ledger_t);
}

FD_FN_CONST static inline ulong
fd_repair_ledger_footprint( void ) {
  /* Calculate appropriate chain counts */
  ulong req_chain_cnt = fd_repair_ledger_req_map_chain_cnt_est( MAX_REQUESTS );
  ulong peer_chain_cnt = fd_repair_ledger_peer_map_chain_cnt_est( MAX_PEERS );
  
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_repair_ledger_t),              sizeof(fd_repair_ledger_t) ),
      fd_repair_ledger_req_pool_align(),          fd_repair_ledger_req_pool_footprint( MAX_REQUESTS ) ),
      fd_repair_ledger_req_map_align(),           fd_repair_ledger_req_map_footprint( req_chain_cnt ) ),
      fd_repair_ledger_req_dlist_align(),         fd_repair_ledger_req_dlist_footprint() ),
      fd_repair_ledger_peer_pool_align(),         fd_repair_ledger_peer_pool_footprint( MAX_PEERS ) ),
      fd_repair_ledger_peer_map_align(),          fd_repair_ledger_peer_map_footprint( peer_chain_cnt ) ),
    fd_repair_ledger_align() );
}

/* fd_repair_ledger_new formats an unused memory region for use as a repair_ledger.
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  seed is an arbitrary
   value used for hash functions.  timeout_ns is the timeout duration in
   nanoseconds. */

void *
fd_repair_ledger_new( void * shmem, ulong seed, ulong timeout_ns );

/* fd_repair_ledger_join joins the caller to the repair_ledger. */

fd_repair_ledger_t *
fd_repair_ledger_join( void * shrepair_ledger );

/* fd_repair_ledger_leave leaves a current local join. */

void *
fd_repair_ledger_leave( fd_repair_ledger_t const * repair_ledger );

/* fd_repair_ledger_delete unformats a memory region used as a repair_ledger. */

void *
fd_repair_ledger_delete( void * repair_ledger );

/* Accessors */

FD_FN_PURE static inline fd_wksp_t *
fd_repair_ledger_wksp( fd_repair_ledger_t const * repair_ledger ) {
  return (fd_wksp_t *)( ( (ulong)repair_ledger ) - repair_ledger->peer_ledger_gaddr );
}

FD_FN_PURE static inline fd_repair_ledger_req_t *
fd_repair_ledger_req_pool( fd_repair_ledger_t * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->req_pool_gaddr );
}

FD_FN_PURE static inline fd_repair_ledger_req_t const *
fd_repair_ledger_req_pool_const( fd_repair_ledger_t const * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->req_pool_gaddr );
}

FD_FN_PURE static inline fd_repair_ledger_req_map_t *
fd_repair_ledger_req_map( fd_repair_ledger_t * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->req_map_gaddr );
}

FD_FN_PURE static inline fd_repair_ledger_req_map_t const *
fd_repair_ledger_req_map_const( fd_repair_ledger_t const * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->req_map_gaddr );
}

FD_FN_PURE static inline fd_repair_ledger_req_dlist_t *
fd_repair_ledger_req_dlist( fd_repair_ledger_t * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->req_dlist_gaddr );
}

FD_FN_PURE static inline fd_repair_ledger_req_dlist_t const *
fd_repair_ledger_req_dlist_const( fd_repair_ledger_t const * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->req_dlist_gaddr );
}

/* fd_repair_ledger_timeout_ns returns the configured timeout duration. */

FD_FN_PURE static inline ulong
fd_repair_ledger_timeout_ns( fd_repair_ledger_t const * repair_ledger ) {
  return repair_ledger->timeout_ns;
}

/* fd_repair_ledger_req_cnt returns the current number of active requests. */

FD_FN_PURE static inline ulong
fd_repair_ledger_req_cnt( fd_repair_ledger_t const * repair_ledger ) {
  return repair_ledger->req_cnt;
}

/* fd_repair_ledger_peer_pool returns the peer pool. */
FD_FN_PURE static inline fd_repair_ledger_peer_t *
fd_repair_ledger_peer_pool( fd_repair_ledger_t * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->peer_pool_gaddr );
}

FD_FN_PURE static inline fd_repair_ledger_peer_t const *
fd_repair_ledger_peer_pool_const( fd_repair_ledger_t const * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->peer_pool_gaddr );
}

/* fd_repair_ledger_peer_map returns the peer map. */
FD_FN_PURE static inline fd_repair_ledger_peer_map_t *
fd_repair_ledger_peer_map( fd_repair_ledger_t * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->peer_map_gaddr );
}

FD_FN_PURE static inline fd_repair_ledger_peer_map_t const *
fd_repair_ledger_peer_map_const( fd_repair_ledger_t const * repair_ledger ) {
  return fd_wksp_laddr_fast( fd_repair_ledger_wksp( repair_ledger ), repair_ledger->peer_map_gaddr );
}

/* fd_repair_ledger_peer_cnt returns the current number of peers. */
FD_FN_PURE static inline ulong
fd_repair_ledger_peer_cnt( fd_repair_ledger_t const * repair_ledger ) {
  return repair_ledger->peer_cnt;
}

/* Operations */

/* Request operations - these handle the request ledger */

/* fd_repair_ledger_req_insert inserts a new request into the repair_ledger.
   Returns a pointer to the inserted request on success, NULL on failure.
   Failures can occur if the repair_ledger is full or if the nonce already exists. */

fd_repair_ledger_req_t *
fd_repair_ledger_req_insert( fd_repair_ledger_t *        repair_ledger,
                             ulong                       nonce,
                             ulong                       timestamp_ns,
                             fd_pubkey_t const *         pubkey,
                             fd_ip4_port_t               ip4,
                             ulong                       slot,
                             ulong                       shred_idx,
                             uint                        req_type );

/* fd_repair_ledger_req_query looks up a request by its nonce.
   Returns a pointer to the request if found, NULL otherwise. */

FD_FN_PURE static inline fd_repair_ledger_req_t const *
fd_repair_ledger_req_query_const( fd_repair_ledger_t const * repair_ledger, ulong nonce ) {
  fd_repair_ledger_req_map_t const * req_map  = fd_repair_ledger_req_map_const( repair_ledger );
  fd_repair_ledger_req_t const *     req_pool = fd_repair_ledger_req_pool_const( repair_ledger );
  return fd_repair_ledger_req_map_ele_query_const( req_map, &nonce, NULL, req_pool );
}

FD_FN_PURE static inline fd_repair_ledger_req_t *
fd_repair_ledger_req_query( fd_repair_ledger_t * repair_ledger, ulong nonce ) {
  fd_repair_ledger_req_map_t * req_map  = fd_repair_ledger_req_map( repair_ledger );
  fd_repair_ledger_req_t *     req_pool = fd_repair_ledger_req_pool( repair_ledger );
  return fd_repair_ledger_req_map_ele_query( req_map, &nonce, NULL, req_pool );
}

/* fd_repair_ledger_req_remove removes a request by its nonce.
   Returns 0 on success, -1 if the request was not found. */

int
fd_repair_ledger_req_remove( fd_repair_ledger_t * repair_ledger, ulong nonce );

/* fd_repair_ledger_req_expire removes all requests that have timed out based on
   the provided current timestamp.  Returns the number of expired requests. */

ulong
fd_repair_ledger_req_expire( fd_repair_ledger_t * repair_ledger, ulong current_ns );

/* fd_repair_ledger_req_oldest returns the oldest request in the repair_ledger (front of list).
   Returns NULL if the repair_ledger is empty. */

FD_FN_PURE static inline fd_repair_ledger_req_t const *
fd_repair_ledger_req_oldest( fd_repair_ledger_t const * repair_ledger ) {
  fd_repair_ledger_req_dlist_t const * dlist = fd_repair_ledger_req_dlist_const( repair_ledger );
  fd_repair_ledger_req_t const * pool = fd_repair_ledger_req_pool_const( repair_ledger );
  if( FD_UNLIKELY( fd_repair_ledger_req_dlist_is_empty( dlist, pool ) ) ) return NULL;
  return fd_repair_ledger_req_dlist_ele_peek_head_const( dlist, pool );
}

/* fd_repair_ledger_req_newest returns the newest request in the repair_ledger (back of list).
   Returns NULL if the repair_ledger is empty. */

FD_FN_PURE static inline fd_repair_ledger_req_t const *
fd_repair_ledger_req_newest( fd_repair_ledger_t const * repair_ledger ) {
  fd_repair_ledger_req_dlist_t const * dlist = fd_repair_ledger_req_dlist_const( repair_ledger );
  fd_repair_ledger_req_t const * pool = fd_repair_ledger_req_pool_const( repair_ledger );
  if( FD_UNLIKELY( fd_repair_ledger_req_dlist_is_empty( dlist, pool ) ) ) return NULL;
  return fd_repair_ledger_req_dlist_ele_peek_tail_const( dlist, pool );
}

/* Peer operations - these handle the peer ledger */

/* fd_repair_ledger_peer_add adds a new peer to the repair_ledger.
   Returns a pointer to the peer on success, NULL on failure. */
fd_repair_ledger_peer_t *
fd_repair_ledger_peer_add( fd_repair_ledger_t *        repair_ledger,
                            fd_pubkey_t const *         pubkey,
                            fd_ip4_port_t               ip4,
                            long                        current_time );

/* fd_repair_ledger_peer_query looks up a peer by its pubkey.
   Returns a pointer to the peer if found, NULL otherwise. */
FD_FN_PURE static inline fd_repair_ledger_peer_t const *
fd_repair_ledger_peer_query_const( fd_repair_ledger_t const * repair_ledger, fd_pubkey_t const * pubkey ) {
  fd_repair_ledger_peer_map_t const * peer_map  = fd_repair_ledger_peer_map_const( repair_ledger );
  fd_repair_ledger_peer_t const *     peer_pool = fd_repair_ledger_peer_pool_const( repair_ledger );
  return fd_repair_ledger_peer_map_ele_query_const( peer_map, (void *)pubkey, NULL, peer_pool );
}

FD_FN_PURE static inline fd_repair_ledger_peer_t *
fd_repair_ledger_peer_query( fd_repair_ledger_t * repair_ledger, fd_pubkey_t const * pubkey ) {
  fd_repair_ledger_peer_map_t * peer_map  = fd_repair_ledger_peer_map( repair_ledger );
  fd_repair_ledger_peer_t *     peer_pool = fd_repair_ledger_peer_pool( repair_ledger );
  return fd_repair_ledger_peer_map_ele_query( peer_map, (void *)pubkey, NULL, peer_pool );
}

/* fd_repair_ledger_peer_remove removes a peer by its pubkey.
   Returns a pointer to the removed peer on success, NULL if the peer was not found. */
fd_repair_ledger_peer_t *
fd_repair_ledger_peer_remove( fd_repair_ledger_t * repair_ledger, fd_pubkey_t const * pubkey );

/* fd_repair_ledger_peer_update updates a peer by its pubkey.
   Returns a pointer to the peer on success, NULL on failure. */
fd_repair_ledger_peer_t *
fd_repair_ledger_peer_update( fd_repair_ledger_t *        repair_ledger,
                               fd_pubkey_t const *         pubkey,
                               fd_ip4_port_t               ip4,
                               int                         is_recv,
                               long                        current_time );

/* fd_repair_ledger_verify checks that the repair_ledger data structure is internally
   consistent.  Returns 0 on success, -1 on failure. */

int
fd_repair_ledger_verify( fd_repair_ledger_t const * repair_ledger );

/* fd_repair_ledger_print prints peer count */

void
fd_repair_ledger_print( fd_repair_ledger_t const * repair_ledger );

void
fd_repair_ledger_peer_print( fd_repair_ledger_peer_t * peer );

void
fd_repair_ledger_select_peers(fd_repair_ledger_t * repair_ledger, uint num_peers, fd_pubkey_t * selected_peers[]);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_repair_fd_peer_ledger_h */ 