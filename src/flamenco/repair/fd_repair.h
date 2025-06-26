#ifndef HEADER_fd_src_flamenco_repair_fd_repair_h
#define HEADER_fd_src_flamenco_repair_fd_repair_h

#include "../gossip/fd_gossip.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../disco/metrics/generated/fd_metrics_repair.h"


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
#define FD_ACTIVE_KEY_MAX (1<<12)
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
#define FD_REPAIR_NUM_NEEDED_PEERS (2)

typedef fd_gossip_peer_addr_t fd_repair_peer_addr_t;

/* Hash a hash value */
FD_FN_PURE static inline
ulong fd_hash_hash( const fd_hash_t * key, ulong seed ) {
  return key->ul[0] ^ seed;
}


/* Test if two addresses are equal */
FD_FN_PURE static inline int
fd_repair_peer_addr_eq( const fd_repair_peer_addr_t * key1, const fd_repair_peer_addr_t * key2 ) {
  FD_STATIC_ASSERT(sizeof(fd_repair_peer_addr_t) == sizeof(ulong),"messed up size");
  return key1->l == key2->l;
}

/* Hash an address */
FD_FN_PURE static inline ulong
fd_repair_peer_addr_hash( const fd_repair_peer_addr_t * key, ulong seed ) {
  FD_STATIC_ASSERT(sizeof(fd_repair_peer_addr_t) == sizeof(ulong),"messed up size");
  return (key->l + seed + 7242237688154252699UL)*9540121337UL;
}

/* Efficiently copy an address */
static inline void
fd_repair_peer_addr_copy( fd_repair_peer_addr_t * keyd, const fd_repair_peer_addr_t * keys ) {
  FD_STATIC_ASSERT(sizeof(fd_repair_peer_addr_t) == sizeof(ulong),"messed up size");
  keyd->l = keys->l;
}

typedef uint fd_repair_nonce_t;

/* Active table element. This table is all validators that we are
   asking for repairs. */
struct fd_active_elem {
    fd_pubkey_t key;  /* Public identifier and map key */
    ulong next; /* used internally by fd_map_giant */

    fd_repair_peer_addr_t addr;
    // Might be worth keeping these fields, but currently response rate is pretty high.
    // latency could be a useful metric to keep track of.
    ulong avg_reqs; /* Moving average of the number of requests */
    ulong avg_reps; /* Moving average of the number of requests */
    long  avg_lat;  /* Moving average of response latency */
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

struct fd_inflight_key {
  enum fd_needed_elem_type type;
  ulong slot;
  uint shred_index;
};
typedef struct fd_inflight_key fd_inflight_key_t;

struct fd_inflight_elem {
  fd_inflight_key_t key;
  long               last_send_time;
  uint               req_cnt;
  ulong              next;
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
  fd_repair_peer_addr_t key;
  ulong next;
  fd_pubkey_t id;
  fd_hash_t token;
  int good;
};
typedef struct fd_pinged_elem fd_pinged_elem_t;
#define MAP_NAME     fd_pinged_table
#define MAP_KEY_T    fd_repair_peer_addr_t
#define MAP_KEY_EQ   fd_repair_peer_addr_eq
#define MAP_KEY_HASH fd_repair_peer_addr_hash
#define MAP_KEY_COPY fd_repair_peer_addr_copy
#define MAP_T        fd_pinged_elem_t
#include "../../util/tmpl/fd_map_giant.c"

struct fd_peer {
  fd_pubkey_t   key;
  fd_ip4_port_t ip4;
};
typedef struct fd_peer fd_peer_t;
/* Repair Metrics */
struct fd_repair_metrics {
  ulong recv_clnt_pkt;
  ulong recv_serv_pkt;
  ulong recv_serv_corrupt_pkt;
  ulong recv_serv_invalid_signature;
  ulong recv_serv_full_ping_table;
  ulong recv_serv_pkt_types[FD_METRICS_ENUM_REPAIR_SERV_PKT_TYPES_CNT];
  ulong recv_pkt_corrupted_msg;
  ulong send_pkt_cnt;
  ulong sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_CNT];
};
typedef struct fd_repair_metrics fd_repair_metrics_t;
#define FD_REPAIR_METRICS_FOOTPRINT ( sizeof( fd_repair_metrics_t ) )
/* Global data for repair service */
struct fd_repair {
    /* Current time in nanosecs */
    long now;
    /* My public/private key */
    fd_pubkey_t * public_key;
    uchar * private_key;
    /* My repair addresses */
    fd_repair_peer_addr_t service_addr;
    fd_repair_peer_addr_t intake_addr;
    /* Function used to send raw packets on the network */
    void * fun_arg;
    /* Table of validators that we are actively pinging, keyed by repair address */
    fd_active_elem_t * actives;

    /* TODO remove, along with good peer cache file */
    fd_pubkey_t actives_sticky[FD_REPAIR_STICKY_MAX]; /* cache of chosen repair peer samples */
    ulong       actives_sticky_cnt;
    ulong       actives_random_seed;

    fd_peer_t peers[ FD_ACTIVE_KEY_MAX ];
    ulong     peer_cnt; /* number of peers in the peers array */
    ulong     peer_idx; /* max number of peers in the peers array */

    /* Duplicate request detection table */
    fd_inflight_elem_t * dupdetect;

    /* Table of needed shreds */
    fd_repair_nonce_t oldest_nonce;
    fd_repair_nonce_t current_nonce;
    fd_repair_nonce_t next_nonce;
    /* Table of validator clients that we have pinged */
    fd_pinged_elem_t * pinged;
    /* Last batch of sends */
    long last_sends;
    /* Last statistics decay */
    long last_decay;
    /* Last statistics printout */
    long last_print;
    /* Last write to good peer cache file */
    long last_good_peer_cache_file_write;
    /* Random number generator */
    fd_rng_t rng[1];
    /* RNG seed */
    ulong seed;
    /* Stake weights */
    ulong stake_weights_cnt;
    fd_stake_weight_t * stake_weights;
    ulong stake_weights_temp_cnt;
    fd_stake_weight_t * stake_weights_temp;
    /* Path to the file where we write the cache of known good repair peers, to make cold booting faster */
    int good_peer_cache_file_fd;
    /* Metrics */
    fd_repair_metrics_t metrics;
};
typedef struct fd_repair fd_repair_t;

FD_FN_CONST static inline ulong
fd_repair_align ( void ) { return 128UL; }

FD_FN_CONST static inline ulong
fd_repair_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_t), sizeof(fd_repair_t) );
  l = FD_LAYOUT_APPEND( l, fd_active_table_align(), fd_active_table_footprint(FD_ACTIVE_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_inflight_table_align(), fd_inflight_table_footprint(FD_NEEDED_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_pinged_table_align(), fd_pinged_table_footprint(FD_REPAIR_PINGED_MAX) );
  /* regular and temp stake weights */
  l = FD_LAYOUT_APPEND( l, alignof(fd_stake_weight_t), FD_STAKE_WEIGHTS_MAX * sizeof(fd_stake_weight_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stake_weight_t), FD_STAKE_WEIGHTS_MAX * sizeof(fd_stake_weight_t) );
  return FD_LAYOUT_FINI(l, fd_repair_align() );
}

/* Global state of repair protocol */
FD_FN_CONST ulong         fd_repair_align    ( void );
FD_FN_CONST ulong         fd_repair_footprint( void );
            void *        fd_repair_new      ( void * shmem, ulong seed );
            fd_repair_t * fd_repair_join     ( void * shmap );
            void *        fd_repair_leave    ( fd_repair_t * join );
            void *        fd_repair_delete   ( void * shmap );

struct fd_repair_config {
    fd_pubkey_t * public_key;
    uchar * private_key;
    fd_repair_peer_addr_t service_addr;
    fd_repair_peer_addr_t intake_addr;
    int good_peer_cache_file_fd;
};
typedef struct fd_repair_config fd_repair_config_t;

/* Initialize the repair data structure */
int fd_repair_set_config( fd_repair_t * glob, const fd_repair_config_t * config );

/* Update the binding addr */
int fd_repair_update_addr( fd_repair_t * glob, const fd_repair_peer_addr_t * intake_addr, const fd_repair_peer_addr_t * service_addr );

/* Add a peer to talk to */
int fd_repair_add_active_peer( fd_repair_t * glob, fd_repair_peer_addr_t const * addr, fd_pubkey_t const * id );

/* Set the current protocol time inf nanosecs. Call this as often as feasible. */
void fd_repair_settime( fd_repair_t * glob, long ts );

/* Get the current protocol time in nanosecs */
long fd_repair_gettime( fd_repair_t * glob );

/* Start timed events and other protocol behavior. settime MUST be called before this. */
int fd_repair_start( fd_repair_t * glob );

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. calling settime first is recommended. */
int fd_repair_continue( fd_repair_t * glob );

int fd_repair_inflight_remove( fd_repair_t * glob,
                               ulong         slot,
                               uint          shred_index );

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

void fd_repair_add_sticky( fd_repair_t * glob, fd_pubkey_t const * id );

void fd_repair_set_stake_weights_init( fd_repair_t             * repair,
                                       fd_stake_weight_t const * stake_weights,
                                       ulong                     stake_weights_cnt );

void fd_repair_set_stake_weights_fini( fd_repair_t * repair );

fd_repair_metrics_t *
fd_repair_get_metrics( fd_repair_t * repair );


#endif /* HEADER_fd_src_flamenco_repair_fd_repair_h */
