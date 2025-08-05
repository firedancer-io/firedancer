#ifndef HEADER_fd_src_flamenco_repair_fd_repair_h
#define HEADER_fd_src_flamenco_repair_fd_repair_h

#include "../gossip/fd_gossip_types.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../disco/metrics/generated/fd_metrics_repair.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../types/fd_types.h"


#define FD_REPAIR_DELIVER_FAIL_TIMEOUT -1
#define FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED -2

/* Maximum size of a network packet */
#define FD_REPAIR_MAX_PACKET_SIZE 1232

/* Scratch space is used by the repair library to allocate an
   active element table and to shuffle that table.
   TODO: update comment to reflect the reasoning behind
   these constants once they are fully understood and updated. */
#define FD_REPAIR_SCRATCH_MAX    (1UL << 30UL)
#define FD_REPAIR_SCRATCH_DEPTH  (1UL << 11UL)

/* Max number of validators that can be actively queried */
#define FD_ACTIVE_KEY_MAX (FD_CONTACT_INFO_TABLE_SIZE)
/* Max number of pending shred requests */
#define FD_NEEDED_KEY_MAX (1<<20)
/* Max number of sticky repair peers */
#define FD_REPAIR_STICKY_MAX   1024
/* Max number of validator identities in stake weights */
#define FD_STAKE_WEIGHTS_MAX (1<<14)
/* Max number of validator clients that we ping */
#define FD_REPAIR_PINGED_MAX (1<<14)
/* Sha256 pre-image size for pings */
#define FD_PING_PRE_IMAGE_SZ (48UL)
/* Number of peers to send requests to. */
#define FD_REPAIR_NUM_NEEDED_PEERS (1)
/* Maximum size for sign buffer, typically <= 160 bytes (e.g., pings, repairs) */
#define FD_REPAIR_MAX_SIGN_BUF_SIZE (256UL)


/* Hash a hash value */
FD_FN_PURE static inline
ulong fd_hash_hash( const fd_hash_t * key, ulong seed ) {
  return key->ul[0] ^ seed;
}


/* Test if two addresses are equal */
FD_FN_PURE static inline int
fd_repair_peer_addr_eq( const fd_ip4_port_t * key1, const fd_ip4_port_t * key2 ) {
  FD_STATIC_ASSERT(sizeof(fd_ip4_port_t) == sizeof(ulong),"messed up size");
  return key1->l == key2->l;
}

/* Hash an address */
FD_FN_PURE static inline ulong
fd_repair_peer_addr_hash( const fd_ip4_port_t * key, ulong seed ) {
  FD_STATIC_ASSERT(sizeof(fd_ip4_port_t) == sizeof(ulong),"messed up size");
  return (key->l + seed + 7242237688154252699UL)*9540121337UL;
}

/* Efficiently copy an address */
static inline void
fd_repair_peer_addr_copy( fd_ip4_port_t * keyd, const fd_ip4_port_t * keys ) {
  FD_STATIC_ASSERT(sizeof(fd_ip4_port_t) == sizeof(ulong),"messed up size");
  keyd->l = keys->l;
}

typedef uint fd_repair_nonce_t;

/* Active table element. This table is all validators that we are
   asking for repairs. */
struct fd_active_elem {
    fd_pubkey_t key;  /* Public identifier and map key */
    ulong next; /* used internally by fd_map_giant */

    fd_ip4_port_t addr;

    // TODO: switch to wma later
    ulong resp_cnt;       /* For calculating the average of the number of requests */
    ulong req_cnt;        /* total num of requests sent */
    long  total_latency;  /* For calculating the average of response latency */
    ulong stake;
};
/* Active table */
typedef struct fd_active_elem fd_active_elem_t;
#define MAP_NAME     fd_active_table
#define MAP_KEY_T    fd_pubkey_t
#define MAP_KEY_EQ(a,b) (0==memcmp( (a),(b),sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH fd_hash_hash
#define MAP_T        fd_active_elem_t
#include "../../util/tmpl/fd_map_giant.c"

enum fd_needed_elem_type {
  fd_needed_window_index, fd_needed_highest_window_index, fd_needed_orphan
};
FD_STATIC_ASSERT( fd_needed_window_index==FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_NEEDED_WINDOW_IDX,                 update repair metrics enums );
FD_STATIC_ASSERT( fd_needed_highest_window_index==FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_NEEDED_HIGHEST_WINDOW_IDX, update repair metrics enums );
FD_STATIC_ASSERT( fd_needed_orphan==FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_NEEDED_ORPHAN_IDX,                       update repair metrics enums );

struct fd_inflight_key {
  enum fd_needed_elem_type type;
  ulong slot;
  uint shred_index;
};
typedef struct fd_inflight_key fd_inflight_key_t;

struct fd_inflight_elem {
  fd_inflight_key_t key;
  long              last_send_time;
  uint              req_cnt;
  ulong             next;
};
typedef struct fd_inflight_elem fd_inflight_elem_t;

FD_FN_PURE static inline int
fd_inflight_eq( const fd_inflight_key_t * key1, const fd_inflight_key_t * key2 ) {
  return (key1->type == key2->type) &&
         (key1->slot == key2->slot) &&
         (key1->shred_index == key2->shred_index);
}

FD_FN_PURE static inline ulong
fd_inflight_hash( const fd_inflight_key_t * key, ulong seed ) {
  return (key->slot + seed)*9540121337UL + key->shred_index*131U;
}

static inline void
fd_inflight_copy( fd_inflight_key_t * keyd, const fd_inflight_key_t * keys ) {
  *keyd = *keys;
}

#define MAP_NAME     fd_inflight_table
#define MAP_KEY_T    fd_inflight_key_t
#define MAP_KEY_EQ   fd_inflight_eq
#define MAP_KEY_HASH fd_inflight_hash
#define MAP_KEY_COPY fd_inflight_copy
#define MAP_T        fd_inflight_elem_t
#include "../../util/tmpl/fd_map_giant.c"

FD_FN_PURE static inline int
fd_repair_nonce_eq( const fd_repair_nonce_t * key1, const fd_repair_nonce_t * key2 ) {
  return *key1 == *key2;
}

FD_FN_PURE static inline ulong
fd_repair_nonce_hash( const fd_repair_nonce_t * key, ulong seed ) {
  return (*key + seed + 7242237688154252699UL)*9540121337UL;
}

static inline void
fd_repair_nonce_copy( fd_repair_nonce_t * keyd, const fd_repair_nonce_t * keys ) {
  *keyd = *keys;
}

struct fd_pinged_elem {
  fd_ip4_port_t key;
  ulong next;
  fd_pubkey_t id;
  fd_hash_t token;
  int good;
};
typedef struct fd_pinged_elem fd_pinged_elem_t;

#define MAP_NAME     fd_pinged_table
#define MAP_KEY_T    fd_ip4_port_t
#define MAP_KEY_EQ   fd_repair_peer_addr_eq
#define MAP_KEY_HASH fd_repair_peer_addr_hash
#define MAP_KEY_COPY fd_repair_peer_addr_copy
#define MAP_T        fd_pinged_elem_t
#include "../../util/tmpl/fd_map_giant.c"

/* Pending sign request structure for async request handling */
struct fd_repair_pending_sign_req {
  ulong       nonce;        /* map key, unique nonce */
  ulong       next;         /* used internally by fd_map_chain */
  uchar       buf[FD_REPAIR_MAX_SIGN_BUF_SIZE];
  ulong       buflen;
  ulong       sig_offset;
  uint        dst_ip_addr;
  ushort      dst_port;
  fd_pubkey_t recipient;
  uchar       type;      /* needed window/highest window/orphan */
};
typedef struct fd_repair_pending_sign_req fd_repair_pending_sign_req_t;

#define POOL_NAME   fd_repair_pending_sign_req_pool
#define POOL_T      fd_repair_pending_sign_req_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME     fd_repair_pending_sign_req_map
#define MAP_KEY      nonce
#define MAP_ELE_T    fd_repair_pending_sign_req_t
#include "../../util/tmpl/fd_map_chain.c"

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

struct fd_peer {
  fd_pubkey_t   key;
  fd_ip4_port_t ip4;
};
typedef struct fd_peer fd_peer_t;

/* Global data for repair service */
struct fd_repair {
    /* Current time in nanosecs */
    long now;
    /* My public/private key */
    fd_pubkey_t * public_key;
    uchar * private_key;
    /* My repair addresses */
    fd_ip4_port_t service_addr;
    fd_ip4_port_t intake_addr;
    /* Table of validators that we are actively pinging, keyed by repair address */
    fd_active_elem_t * actives;

    fd_peer_t peers[ FD_ACTIVE_KEY_MAX ];
    ulong     peer_cnt; /* number of peers in the peers array */
    ulong     peer_idx; /* max number of peers in the peers array */

    /* Duplicate request detection table, keyed by request type, slot, and shred index */
    fd_inflight_elem_t * dupdetect;

    /* Table of inflight requests, keyed by nonce */
    fd_inflight_t       * inflight_pool;
    fd_inflight_map_t   * inflight_map;
    fd_inflight_dlist_t * inflight_dlist;

    /* Table of needed shreds */
    fd_repair_nonce_t next_nonce;
    /* Table of validator clients that we have pinged */
    fd_pinged_elem_t * pinged;
    /* Last batch of sends */
    long last_sends;
    /* Last statistics decay */
    long last_decay;
    /* Last statistics printout */
    long last_print;
    /* Random number generator */
    fd_rng_t rng[1];
    /* RNG seed */
    ulong seed;

    /* Pending sign requests for async operations */
    fd_repair_pending_sign_req_t     * pending_sign_pool;
    fd_repair_pending_sign_req_map_t * pending_sign_map;
};
typedef struct fd_repair fd_repair_t;

FD_FN_CONST static inline ulong
fd_repair_align ( void ) { return 128UL; }

FD_FN_CONST static inline ulong
fd_repair_footprint( ulong sign_tile_depth, ulong sign_tile_cnt ) {
  ulong sign_req_max = sign_tile_depth * sign_tile_cnt;
        sign_req_max = fd_ulong_pow2_up( sign_req_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_t),                    sizeof(fd_repair_t) );
  l = FD_LAYOUT_APPEND( l, fd_active_table_align(),                 fd_active_table_footprint(FD_ACTIVE_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_inflight_table_align(),               fd_inflight_table_footprint(FD_NEEDED_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_inflight_pool_align(),                fd_inflight_pool_footprint(FD_NEEDED_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_inflight_map_align(),                 fd_inflight_map_footprint (FD_NEEDED_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_inflight_dlist_align(),               fd_inflight_dlist_footprint()                 );
  l = FD_LAYOUT_APPEND( l, fd_pinged_table_align(),                 fd_pinged_table_footprint(FD_REPAIR_PINGED_MAX) );
  /* pending sign request structures - TODO: i think move this to the repair tile.... ts is pretty tile specific */
  l = FD_LAYOUT_APPEND( l, fd_repair_pending_sign_req_pool_align(), fd_repair_pending_sign_req_pool_footprint( sign_req_max ) );
  l = FD_LAYOUT_APPEND( l, fd_repair_pending_sign_req_map_align(),  fd_repair_pending_sign_req_map_footprint ( sign_req_max ) );
  return FD_LAYOUT_FINI(l, fd_repair_align() );
}

/* Global state of repair protocol */
FD_FN_CONST ulong         fd_repair_align    ( void );
FD_FN_CONST ulong         fd_repair_footprint( ulong sign_tile_depth, ulong sign_tile_cnt );
            void *        fd_repair_new      ( void * shmem, ulong sign_tile_depth, ulong sign_tile_cnt, ulong seed );
            fd_repair_t * fd_repair_join     ( void * shmap );
            void *        fd_repair_leave    ( fd_repair_t * join );
            void *        fd_repair_delete   ( void * shmap );

struct fd_repair_config {
    fd_pubkey_t * public_key;
    uchar * private_key;
    fd_ip4_port_t service_addr;
    fd_ip4_port_t intake_addr;
};
typedef struct fd_repair_config fd_repair_config_t;

/* Initialize the repair data structure */
int fd_repair_set_config( fd_repair_t * glob, const fd_repair_config_t * config );

/* Update the binding addr */
int fd_repair_update_addr( fd_repair_t * glob, const fd_ip4_port_t * intake_addr, const fd_ip4_port_t * service_addr );

/* Add a peer to talk to */
int fd_repair_add_active_peer( fd_repair_t * glob, fd_ip4_port_t const * addr, fd_pubkey_t const * id );

/* Set the current protocol time inf nanosecs. Call this as often as feasible. */
void fd_repair_settime( fd_repair_t * glob, long ts );

/* Get the current protocol time in nanosecs */
long fd_repair_gettime( fd_repair_t * glob );

/* Start timed events and other protocol behavior. settime MUST be called before this. */
int fd_repair_start( fd_repair_t * glob );

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. calling settime first is recommended. */
int fd_repair_continue( fd_repair_t * glob );

long
fd_repair_inflight_remove( fd_repair_t * glob,
                           ulong         slot,
                           uint          shred_index,
                           ulong         nonce );

/* Register a request for a shred */
int fd_repair_need_window_index( fd_repair_t * glob, ulong slot, uint shred_index );

int fd_repair_need_highest_window_index( fd_repair_t * glob, ulong slot, uint shred_index );

int fd_repair_need_orphan( fd_repair_t * glob, ulong slot );

int
fd_repair_construct_request_protocol( fd_repair_t          * glob,
                                      fd_repair_protocol_t * protocol,
                                      enum fd_needed_elem_type type,
                                      ulong                  slot,
                                      uint                   shred_index,
                                      fd_pubkey_t const    * recipient,
                                      uint                   nonce,
                                      long                   now );

/* Pending sign request operations */
fd_repair_pending_sign_req_t *
fd_repair_insert_pending_request( fd_repair_t *            repair,
                                   fd_repair_protocol_t *   protocol,
                                   uint                     dst_ip_addr,
                                   ushort                   dst_port,
                                   enum fd_needed_elem_type type,
                                   ulong                    slot,
                                   uint                     shred_index,
                                   long                     now,
                                   fd_pubkey_t const *      recipient );

fd_repair_pending_sign_req_t *
fd_repair_query_pending_request( fd_repair_t * repair,
                                 ulong         nonce );

int
fd_repair_remove_pending_request( fd_repair_t * repair,
                                  ulong         nonce );

/* TODO wrap this in an ifdef lawd help me */

#include "iptable.h"

#endif /* HEADER_fd_src_flamenco_repair_fd_repair_h */
