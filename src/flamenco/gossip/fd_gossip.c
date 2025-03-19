#define _GNU_SOURCE 1
#include "fd_gossip.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../util/rng/fd_rng.h"
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/random.h>

/* Maximum size of a network packet */
#define PACKET_DATA_SIZE 1232
/* How long do we remember values (in millisecs) */
#define FD_GOSSIP_VALUE_EXPIRE ((ulong)(3600e3))   /* 1 hr */
/* Max age that values can be pushed/pulled (in millisecs) */
#define FD_GOSSIP_PULL_TIMEOUT ((ulong)(15e3))   /* 15 seconds */
/* Max number of validators that can be actively pinged */
#define FD_ACTIVE_KEY_MAX (1<<8)

/* Max number of CRDS values that can be remembered.

   As of 2.1.11 on 02/05/2025, Agave value table (approx) sizes on an unstaked node:
   | cluster  | num unique entries | num total (unique + purged) |
   | testnet  | ~800k              | 1.4m                        |
   | mainnet  | ~750k              | 1m                          |

   Purged values are counted because:
    - Our table (currently) does not "purge" values in the same sense Agave does
    - Purged values are included in bloom filter construction, so we need them anyway */
#define FD_VALUE_KEY_MAX (1<<21)
/* Max number of pending timed events */
#define FD_PENDING_MAX (1<<9)
/* Sample rate of bloom filters. */
#define FD_BLOOM_SAMPLE_RATE 8U
/* Number of bloom filter bits in an outgoing pull request packet */
#define FD_BLOOM_NUM_BITS (512U*8U) /* 0.5 Kbyte */
/* Max number of bloom filter keys in an outgoing pull request packet */
#define FD_BLOOM_MAX_KEYS 32U
/* Max number of packets in an outgoing pull request batch */
#define FD_BLOOM_MAX_PACKETS 32U
/* Number of bloom bits in a push prune filter */
#define FD_PRUNE_NUM_BITS (512U*8U) /* 0.5 Kbyte */
/* Number of bloom keys in a push prune filter */
#define FD_PRUNE_NUM_KEYS 4U
/* Max number of destinations a single message can be pushed */
#define FD_PUSH_VALUE_MAX 9
/* Max number of push destinations that we track */
#define FD_PUSH_LIST_MAX 12
/* Max length of queue of values that need pushing */
#define FD_NEED_PUSH_MAX (1<<12)
/* Max size of receive statistics table */
#define FD_STATS_KEY_MAX (1<<8)
/* Sha256 pre-image size for pings/pongs */
#define FD_PING_PRE_IMAGE_SZ (48UL)
/* Number of recognized CRDS enum members */
#define FD_KNOWN_CRDS_ENUM_MAX (14UL)
/* Prune data prefix
   https://github.com/anza-xyz/agave/blob/0c264859b127940f13673b5fea300131a70b1a8d/gossip/src/protocol.rs#L39 */
#define FD_GOSSIP_PRUNE_DATA_PREFIX "\xffSOLANA_PRUNE_DATA"

#define FD_NANOSEC_TO_MILLI(_ts_) ((ulong)(_ts_/1000000))

/* Maximum number of stake weights, mirrors fd_stake_ci */
#define MAX_STAKE_WEIGHTS (40200UL)

#define MAX_PEER_PING_COUNT (10000U)

/* Test if two addresses are equal */
FD_FN_PURE static int fd_gossip_peer_addr_eq( const fd_gossip_peer_addr_t * key1, const fd_gossip_peer_addr_t * key2 ) {
  FD_STATIC_ASSERT(sizeof(fd_gossip_peer_addr_t) == sizeof(ulong),"messed up size");
  return key1->l == key2->l;
}

/* Hash an address */
FD_FN_PURE static ulong fd_gossip_peer_addr_hash( const fd_gossip_peer_addr_t * key, ulong seed ) {
  FD_STATIC_ASSERT(sizeof(fd_gossip_peer_addr_t) == sizeof(ulong),"messed up size");
  return (key->l + seed + 7242237688154252699UL)*9540121337UL;
}

/* Efficiently copy an address */
static void fd_gossip_peer_addr_copy( fd_gossip_peer_addr_t * keyd, const fd_gossip_peer_addr_t * keys ) {
  FD_STATIC_ASSERT(sizeof(fd_gossip_peer_addr_t) == sizeof(ulong),"messed up size");
  keyd->l = keys->l;
}

/* All peers table element. The peers table is all known validator addresses/ids. */
struct fd_peer_elem {
    fd_gossip_peer_addr_t key;
    ulong next;
    fd_pubkey_t id;  /* Public indentifier */
    ulong wallclock; /* last time we heard about this peer */
    ulong stake;     /* Staking for this validator. Unimplemented. */
};
/* All peers table */
typedef struct fd_peer_elem fd_peer_elem_t;
#define MAP_NAME     fd_peer_table
#define MAP_KEY_T    fd_gossip_peer_addr_t
#define MAP_KEY_EQ   fd_gossip_peer_addr_eq
#define MAP_KEY_HASH fd_gossip_peer_addr_hash
#define MAP_KEY_COPY fd_gossip_peer_addr_copy
#define MAP_T        fd_peer_elem_t
#include "../../util/tmpl/fd_map_giant.c"

/* Active table element. This table is all validators that we are
   aggressively pinging for liveness checking. */
struct fd_active_elem {
    fd_gossip_peer_addr_t key;
    ulong next;
    fd_pubkey_t id;  /* Public indentifier */
    long pingtime;   /* Last time we sent a ping */
    uint pingcount;  /* Number of pings it took to get a pong */
    fd_hash_t pingtoken;  /* Random data used in ping/pong */
    long pongtime;   /* Last time we received a pong */
    ulong weight;    /* Selection weight */
};
/* Active table */
typedef struct fd_active_elem fd_active_elem_t;
#define MAP_NAME     fd_active_table
#define MAP_KEY_T    fd_gossip_peer_addr_t
#define MAP_KEY_EQ   fd_gossip_peer_addr_eq
#define MAP_KEY_HASH fd_gossip_peer_addr_hash
#define MAP_KEY_COPY fd_gossip_peer_addr_copy
#define MAP_T        fd_active_elem_t
#include "../../util/tmpl/fd_map_giant.c"

/* Initialize an active table element value */
void
fd_active_new_value(fd_active_elem_t * val) {
  val->pingcount = 1;
  val->pingtime = val->pongtime = 0;
  val->weight = 0;
  fd_memset(val->id.uc, 0, 32U);
  fd_memset(val->pingtoken.uc, 0, 32U);
}

/* Test if two hash values are equal */
int fd_hash_eq( const fd_hash_t * key1, const fd_hash_t * key2 ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    if (key1->ul[i] != key2->ul[i])
      return 0;
  return 1;
}

/* Hash a hash value */
ulong fd_hash_hash( const fd_hash_t * key, ulong seed ) {
  return key->ul[0] ^ seed;
}

/* Copy a hash value */
void fd_hash_copy( fd_hash_t * keyd, const fd_hash_t * keys ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    keyd->ul[i] = keys->ul[i];
}

/* Value table element. This table stores all received crds
   values. Keyed by the hash of the value data. */
struct fd_value_elem {
    fd_hash_t key;
    ulong next;
    fd_pubkey_t origin; /* Where did this value originate */
    ulong wallclock; /* Original timestamp of value in millis */
    uchar data[PACKET_DATA_SIZE]; /* Serialized form of value (bincode) including signature */
    ulong datalen;
};
/* Value table */
typedef struct fd_value_elem fd_value_elem_t;
#define MAP_NAME     fd_value_table
#define MAP_KEY_T    fd_hash_t
#define MAP_KEY_EQ   fd_hash_eq
#define MAP_KEY_HASH fd_hash_hash
#define MAP_KEY_COPY fd_hash_copy
#define MAP_T        fd_value_elem_t
#include "../../util/tmpl/fd_map_giant.c"

/* Weights table element. This table stores the weight for each peer
   (determined by stake). */
struct fd_weights_elem {
    fd_pubkey_t key;
    ulong next;
    ulong weight;
};
/* Weights table */
typedef struct fd_weights_elem fd_weights_elem_t;
#define MAP_NAME     fd_weights_table
#define MAP_KEY_T    fd_hash_t
#define MAP_KEY_EQ   fd_hash_eq
#define MAP_KEY_HASH fd_hash_hash
#define MAP_KEY_COPY fd_hash_copy
#define MAP_T        fd_weights_elem_t
#include "../../util/tmpl/fd_map_giant.c"

/* Queue of pending timed events, stored as a priority heap */
union fd_pending_event_arg {
    fd_gossip_peer_addr_t key;
};
typedef union fd_pending_event_arg fd_pending_event_arg_t;
typedef void (*fd_pending_event_fun)(struct fd_gossip * glob, fd_pending_event_arg_t * arg);
struct fd_pending_event {
    ulong left;
    ulong right;
    long key;
    fd_pending_event_fun fun;
    fd_pending_event_arg_t fun_arg;
};
typedef struct fd_pending_event fd_pending_event_t;
#define POOL_NAME fd_pending_pool
#define POOL_T    fd_pending_event_t
#define POOL_NEXT left
#include "../../util/tmpl/fd_pool.c"
#define HEAP_NAME      fd_pending_heap
#define HEAP_T         fd_pending_event_t
#define HEAP_LT(e0,e1) (e0->key < e1->key)
#include "../../util/tmpl/fd_heap.c"

/* Data structure representing an active push destination. There are
   only a small number of these. */
struct fd_push_state {
    fd_gossip_peer_addr_t addr; /* Destination address */
    fd_pubkey_t id;                /* Public indentifier */
    ulong drop_cnt;                /* Number of values dropped due to pruning */
    ulong prune_keys[FD_PRUNE_NUM_KEYS];     /* Keys used for bloom filter for pruning */
    ulong prune_bits[FD_PRUNE_NUM_BITS/64U]; /* Bits table used for bloom filter for pruning */
    uchar packet[PACKET_DATA_SIZE]; /* Partially assembled packet containing a fd_gossip_push_msg_t */
    uchar * packet_end_init;       /* Initial end of the packet when there are zero values */
    uchar * packet_end;            /* Current end of the packet including values so far */
    ulong next;
};
typedef struct fd_push_state fd_push_state_t;

#define POOL_NAME fd_push_states_pool
#define POOL_T    fd_push_state_t
#include "../../util/tmpl/fd_pool.c"

/* Receive statistics table element. */
struct fd_stats_elem {
    fd_gossip_peer_addr_t key; /* Keyed by sender */
    ulong next;
    long last;    /* Timestamp of last update */
    /* Duplicate counts by origin */
    struct {
        fd_pubkey_t origin;
        ulong cnt;
    } dups[8];
    ulong dups_cnt;
};
/* Receive statistics table. */
typedef struct fd_stats_elem fd_stats_elem_t;
#define MAP_NAME     fd_stats_table
#define MAP_KEY_T    fd_gossip_peer_addr_t
#define MAP_KEY_EQ   fd_gossip_peer_addr_eq
#define MAP_KEY_HASH fd_gossip_peer_addr_hash
#define MAP_KEY_COPY fd_gossip_peer_addr_copy
#define MAP_T        fd_stats_elem_t
#include "../../util/tmpl/fd_map_giant.c"

#define SET_NAME fd_gossip_filter_selection
#define SET_MAX  FD_BLOOM_MAX_PACKETS
#include "../../util/tmpl/fd_smallset.c"

struct fd_msg_stats_elem {
  ulong bytes_rx_cnt;
  ulong total_cnt;
  ulong dups_cnt;
};
/* Receive type statistics table. */
typedef struct fd_msg_stats_elem fd_msg_stats_elem_t;

/* Internal struct for maintaining
   a contact_info_v2 entry */
typedef struct {
  fd_crds_data_t crd;
  fd_gossip_contact_info_v2_t * ci;
  fd_gossip_ip_addr_t addrs[FD_GOSSIP_SOCKET_TAG_MAX];
  fd_gossip_socket_entry_t sockets[FD_GOSSIP_SOCKET_TAG_MAX];
  // uint extentions[1]; /* Unused */
} fd_gossip_node_contact_t;

static void
fd_gossip_init_node_contact( fd_gossip_node_contact_t * contact ) {
  fd_crds_data_new_disc( &contact->crd, fd_crds_data_enum_contact_info_v2 );
  contact->ci = &contact->crd.inner.contact_info_v2;
  contact->ci->addrs = contact->addrs;
  contact->ci->sockets = contact->sockets;
}

/* Internal node address book.
   Both ip addr and port* are stored
   in network order

   * contact_info_v2 stores port numbers
   in host order, so they need to be converted
   when copying over. See
   fd_gossip_refresh_contact_info_v2_sockets() */

typedef struct {
  fd_gossip_peer_addr_t gossip;
  fd_gossip_peer_addr_t serve_repair;
  fd_gossip_peer_addr_t tvu;
  fd_gossip_peer_addr_t tpu;
  fd_gossip_peer_addr_t tpu_quic;
  fd_gossip_peer_addr_t tpu_vote;
} fd_gossip_node_addrs_t;

/* Global data for gossip service */
struct fd_gossip {
    /* Concurrency lock */
    volatile ulong lock;
    /* Current time in nanosecs */
    long now;

    /* My official contact info in the gossip protocol */
    fd_gossip_node_contact_t my_contact;
    fd_gossip_node_addrs_t my_node_addrs;
    /* My gossip port address (ptr to gossip entry in my node addrs) */
    fd_gossip_peer_addr_t * my_addr;
    /* My public key (ptr to entry in my contact info) */
    fd_pubkey_t * public_key;

    /* Function used to deliver gossip messages to the application */
    fd_gossip_data_deliver_fun deliver_fun;
    /* Argument to fd_gossip_data_deliver_fun */
    void * deliver_arg;
    /* Function used to send raw packets on the network */
    fd_gossip_send_packet_fun send_fun;
    /* Argument to fd_gossip_send_packet_fun */
    void * send_arg;
    /* Function used to send packets for signing to remote tile */
    fd_gossip_sign_fun sign_fun;
    /* Argument to fd_gossip_sign_fun */
    void * sign_arg;

    /* Table of all known validators, keyed by gossip address */
    fd_peer_elem_t * peers;
    /* Table of validators that we are actively pinging, keyed by gossip address */
    fd_active_elem_t * actives;
    /* Queue of validators that might be added to actives */
    fd_gossip_peer_addr_t * inactives;
    ulong inactives_cnt;
#define INACTIVES_MAX 1024U

    /* Table of crds values that we have received in the last 60 minutes, keys by hash */
    fd_value_elem_t * values;
    /* The last timestamp that we pushed our own contact info */
    long last_contact_time;
    fd_hash_t last_contact_info_v2_key;

    /* Array of push destinations currently in use */
    fd_push_state_t * push_states[FD_PUSH_LIST_MAX];
    ulong push_states_cnt;
    fd_push_state_t * push_states_pool;
    /* Queue of values that need pushing */
    fd_hash_t * need_push;
    ulong need_push_head;
    ulong need_push_cnt;

    /* Table of receive statistics */
    fd_stats_elem_t * stats;
    /* Table of message type stats */
    fd_msg_stats_elem_t msg_stats[FD_KNOWN_CRDS_ENUM_MAX];

    /* Heap/queue of pending timed events */
    fd_pending_event_t * event_pool;
    fd_pending_heap_t * event_heap;

    /* Random number generator */
    fd_rng_t rng[1];
    /* RNG seed */
    ulong seed;
    /* Total number of packeets received */
    ulong recv_pkt_cnt;
    /* Total number of duplicate values received */
    ulong recv_dup_cnt;
    /* Total number of non-duplicate values received */
    ulong recv_nondup_cnt;
    /* Count of values pushed */
    ulong push_cnt;
    /* Count of values not pushed due to pruning */
    ulong not_push_cnt;

    /* Stake weights */
    fd_weights_elem_t * weights;

    /* List of added entrypoints at startup */
    ulong entrypoints_cnt;
    fd_gossip_peer_addr_t entrypoints[16];
    /* Metrics */
    fd_gossip_metrics_t metrics;
};

fd_gossip_metrics_t *
fd_gossip_get_metrics( fd_gossip_t * gossip ) {
  return &gossip->metrics;
}

FD_FN_CONST ulong
fd_gossip_align ( void ) { return 128UL; }

FD_FN_CONST ulong
fd_gossip_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_t), sizeof(fd_gossip_t) );
  l = FD_LAYOUT_APPEND( l, fd_peer_table_align(), fd_peer_table_footprint(FD_PEER_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_active_table_align(), fd_active_table_footprint(FD_ACTIVE_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_peer_addr_t), INACTIVES_MAX*sizeof(fd_gossip_peer_addr_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_hash_t), FD_NEED_PUSH_MAX*sizeof(fd_hash_t) );
  l = FD_LAYOUT_APPEND( l, fd_value_table_align(), fd_value_table_footprint(FD_VALUE_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_pending_pool_align(), fd_pending_pool_footprint(FD_PENDING_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_pending_heap_align(), fd_pending_heap_footprint(FD_PENDING_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_stats_table_align(), fd_stats_table_footprint(FD_STATS_KEY_MAX) );
  l = FD_LAYOUT_APPEND( l, fd_weights_table_align(), fd_weights_table_footprint(MAX_STAKE_WEIGHTS) );
  l = FD_LAYOUT_APPEND( l, fd_push_states_pool_align(), fd_push_states_pool_footprint(FD_PUSH_LIST_MAX) );
  l = FD_LAYOUT_FINI( l, fd_gossip_align() );
  return l;
}

void *
fd_gossip_new ( void * shmem, ulong seed ) {
  FD_SCRATCH_ALLOC_INIT(l, shmem);
  fd_gossip_t * glob = (fd_gossip_t*)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_t), sizeof(fd_gossip_t)) ;
  fd_memset(glob, 0, sizeof(fd_gossip_t));
  glob->seed = seed;

  void * shm = FD_SCRATCH_ALLOC_APPEND(l, fd_peer_table_align(), fd_peer_table_footprint(FD_PEER_KEY_MAX));
  glob->peers = fd_peer_table_join(fd_peer_table_new(shm, FD_PEER_KEY_MAX, seed));

  shm = FD_SCRATCH_ALLOC_APPEND(l, fd_active_table_align(), fd_active_table_footprint(FD_ACTIVE_KEY_MAX));
  glob->actives = fd_active_table_join(fd_active_table_new(shm, FD_ACTIVE_KEY_MAX, seed));

  glob->inactives = (fd_gossip_peer_addr_t*)FD_SCRATCH_ALLOC_APPEND(l, alignof(fd_gossip_peer_addr_t), INACTIVES_MAX*sizeof(fd_gossip_peer_addr_t));
  glob->need_push = (fd_hash_t*)FD_SCRATCH_ALLOC_APPEND(l, alignof(fd_hash_t), FD_NEED_PUSH_MAX*sizeof(fd_hash_t));

  shm = FD_SCRATCH_ALLOC_APPEND(l, fd_value_table_align(), fd_value_table_footprint(FD_VALUE_KEY_MAX));
  glob->values = fd_value_table_join(fd_value_table_new(shm, FD_VALUE_KEY_MAX, seed));

  glob->last_contact_time = 0;
  shm = FD_SCRATCH_ALLOC_APPEND(l, fd_pending_pool_align(), fd_pending_pool_footprint(FD_PENDING_MAX));
  glob->event_pool = fd_pending_pool_join(fd_pending_pool_new(shm, FD_PENDING_MAX));

  shm = FD_SCRATCH_ALLOC_APPEND(l, fd_pending_heap_align(), fd_pending_heap_footprint(FD_PENDING_MAX));
  glob->event_heap = fd_pending_heap_join(fd_pending_heap_new(shm, FD_PENDING_MAX));

  fd_rng_new(glob->rng, (uint)seed, 0UL);
  shm = FD_SCRATCH_ALLOC_APPEND(l, fd_stats_table_align(), fd_stats_table_footprint(FD_STATS_KEY_MAX));
  glob->stats = fd_stats_table_join(fd_stats_table_new(shm, FD_STATS_KEY_MAX, seed));

  shm = FD_SCRATCH_ALLOC_APPEND(l, fd_weights_table_align(), fd_weights_table_footprint(MAX_STAKE_WEIGHTS));
  glob->weights = fd_weights_table_join( fd_weights_table_new( shm, MAX_STAKE_WEIGHTS, seed ) );

  shm = FD_SCRATCH_ALLOC_APPEND(l, fd_push_states_pool_align(), fd_push_states_pool_footprint(FD_PUSH_LIST_MAX));
  glob->push_states_pool = fd_push_states_pool_join( fd_push_states_pool_new( shm, FD_PUSH_LIST_MAX ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, fd_gossip_align() );
  if ( scratch_top > (ulong)shmem + fd_gossip_footprint() ) {
    FD_LOG_ERR(("Not enough space allocated for gossip"));
  }
  return glob;
}

fd_gossip_t *
fd_gossip_join ( void * shmap ) { return (fd_gossip_t *)shmap; }

void *
fd_gossip_leave ( fd_gossip_t * join ) { return join; }

void *
fd_gossip_delete ( void * shmap ) {
  fd_gossip_t * glob = (fd_gossip_t *)shmap;
  fd_peer_table_delete( fd_peer_table_leave( glob->peers ) );
  fd_active_table_delete( fd_active_table_leave( glob->actives ) );

  fd_value_table_delete( fd_value_table_leave( glob->values ) );
  fd_pending_pool_delete( fd_pending_pool_leave( glob->event_pool ) );
  fd_pending_heap_delete( fd_pending_heap_leave( glob->event_heap ) );
  fd_stats_table_delete( fd_stats_table_leave( glob->stats ) );
  fd_weights_table_delete( fd_weights_table_leave( glob->weights ) );
  fd_push_states_pool_delete( fd_push_states_pool_leave( glob->push_states_pool ) );

  return glob;
}

static void
fd_gossip_lock( fd_gossip_t * gossip ) {
# if FD_HAS_THREADS
  for(;;) {
    if( FD_LIKELY( !FD_ATOMIC_CAS( &gossip->lock, 0UL, 1UL) ) ) break;
    FD_SPIN_PAUSE();
  }
# else
  gossip->lock = 1;
# endif
  FD_COMPILER_MFENCE();
}

static void
fd_gossip_unlock( fd_gossip_t * gossip ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( gossip->lock ) = 0UL;
}

/* FIXME: do these go in fd_types_custom instead? */
void
fd_gossip_ipaddr_from_socketaddr( fd_gossip_socket_addr_t const * addr, fd_gossip_ip_addr_t * out ) {
  if( FD_LIKELY( addr->discriminant == fd_gossip_socket_addr_enum_ip4 ) ) {
    fd_gossip_ip_addr_new_disc(out, fd_gossip_ip_addr_enum_ip4);
    out->inner.ip4 = addr->inner.ip4.addr;
  } else {
    fd_gossip_ip_addr_new_disc(out, fd_gossip_ip_addr_enum_ip6);
    out->inner.ip6 = addr->inner.ip6.addr;
  }
}

ushort
fd_gossip_port_from_socketaddr( fd_gossip_socket_addr_t const * addr ) {
  if( FD_LIKELY( addr->discriminant == fd_gossip_socket_addr_enum_ip4 ) ) {
    return addr->inner.ip4.port;
  } else {
    return addr->inner.ip6.port;
  }
}


void
fd_gossip_contact_info_v2_to_v1( fd_gossip_contact_info_v2_t const * v2,
                                 fd_gossip_contact_info_v1_t *       v1 ) {
  memset( v1, 0, sizeof(fd_gossip_contact_info_v1_t) );
  v1->id = v2->from;
  v1->shred_version = v2->shred_version;
  v1->wallclock = v2->wallclock;
  fd_gossip_contact_info_v2_find_proto_ident( v2, FD_GOSSIP_SOCKET_TAG_GOSSIP, &v1->gossip );
  fd_gossip_contact_info_v2_find_proto_ident( v2, FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR, &v1->serve_repair );
  fd_gossip_contact_info_v2_find_proto_ident( v2, FD_GOSSIP_SOCKET_TAG_TPU, &v1->tpu );
  fd_gossip_contact_info_v2_find_proto_ident( v2, FD_GOSSIP_SOCKET_TAG_TPU_VOTE, &v1->tpu_vote );
  fd_gossip_contact_info_v2_find_proto_ident( v2, FD_GOSSIP_SOCKET_TAG_TVU, &v1->tvu );
}

int
fd_gossip_contact_info_v2_find_proto_ident( fd_gossip_contact_info_v2_t const * contact_info,
                                            uchar                               proto_ident,
                                            fd_gossip_socket_addr_t *           out_addr ) {
  ushort port = 0;
  for( ulong i = 0UL; i<contact_info->sockets_len; i++ ) {
    fd_gossip_socket_entry_t const * socket_entry = &contact_info->sockets[ i ];
    port = (ushort)( port + socket_entry->offset );
    if( socket_entry->key==proto_ident ) {
      if( socket_entry->index>=contact_info->addrs_len) {
        continue;
      }

      /* fd_gossip_socket_addr->inner and fd_gossip_ip_addr
         are slightly different, so we can't just
         out_addr->ip = contact_info->addrs[ idx ] */
      fd_gossip_ip_addr_t * tmp = &contact_info->addrs[ socket_entry->index ];
      if( FD_LIKELY( tmp->discriminant == fd_gossip_ip_addr_enum_ip4 ) ) {
        out_addr->discriminant = fd_gossip_socket_addr_enum_ip4;
        out_addr->inner.ip4.addr = tmp->inner.ip4;
        out_addr->inner.ip4.port = port;
      } else {
        out_addr->discriminant = fd_gossip_socket_addr_enum_ip6;
        out_addr->inner.ip6.addr = tmp->inner.ip6;
        out_addr->inner.ip6.port = port;
      }
      return 1;
    }
  }

  return 0;
}

/* Convert my style of address to solana style */
int
fd_gossip_to_soladdr( fd_gossip_socket_addr_t * dst, fd_gossip_peer_addr_t const * src ) {
  fd_gossip_socket_addr_new_disc( dst, fd_gossip_socket_addr_enum_ip4 );
  dst->inner.ip4.port = ntohs(src->port);
  dst->inner.ip4.addr = src->addr;
  return 0;
}

/* Convert my style of address from solana style */
int
fd_gossip_from_soladdr(fd_gossip_peer_addr_t * dst, fd_gossip_socket_addr_t const * src ) {
  FD_STATIC_ASSERT(sizeof(fd_gossip_peer_addr_t) == sizeof(ulong),"messed up size");
  dst->l = 0;
  if (src->discriminant == fd_gossip_socket_addr_enum_ip4) {
    dst->port = htons(src->inner.ip4.port);
    dst->addr = src->inner.ip4.addr;
    return 0;
  } else {
    FD_LOG_ERR(("invalid address family %lu", (ulong)src->discriminant));
    return -1;
  }
}

/* Convert an address to a human readable string */
const char * fd_gossip_addr_str( char * dst, size_t dstlen, fd_gossip_peer_addr_t const * src ) {
  char tmp[INET_ADDRSTRLEN];
  snprintf(dst, dstlen, "%s:%u", inet_ntop(AF_INET, &src->addr, tmp, INET_ADDRSTRLEN), (uint)ntohs(src->port));
  return dst;
}

static void
fd_gossip_refresh_contact_info_v2_sockets( fd_gossip_node_addrs_t const * addrs, fd_gossip_node_contact_t * ci_int );

/* Set the gossip configuration */
int
fd_gossip_set_config( fd_gossip_t * glob, const fd_gossip_config_t * config ) {
  fd_gossip_lock( glob );

  char tmp[100];
  char keystr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( config->public_key->uc, NULL, keystr );
  FD_LOG_NOTICE(("configuring address %s id %s", fd_gossip_addr_str(tmp, sizeof(tmp), &config->my_addr), keystr));

  fd_gossip_init_node_contact( &glob->my_contact );

  fd_hash_copy(&glob->my_contact.ci->from, config->public_key);
  glob->public_key = &glob->my_contact.ci->from;

  fd_gossip_peer_addr_copy( &glob->my_node_addrs.gossip, &config->my_addr );
  fd_gossip_refresh_contact_info_v2_sockets( &glob->my_node_addrs, &glob->my_contact );
  glob->my_addr = &glob->my_node_addrs.gossip;

  glob->my_contact.ci->shred_version = config->shred_version;
  glob->my_contact.ci->outset = (ulong)config->node_outset;
  glob->my_contact.ci->version = config->my_version;

  glob->deliver_fun = config->deliver_fun;
  glob->deliver_arg = config->deliver_arg;
  glob->send_fun = config->send_fun;
  glob->send_arg = config->send_arg;
  glob->sign_fun = config->sign_fun;
  glob->sign_arg = config->sign_arg;

  fd_gossip_unlock( glob );

  return 0;
}

/* Updates the sockets and addrs lists in contact_info_v2 */
static void
fd_gossip_refresh_contact_info_v2_sockets( fd_gossip_node_addrs_t const * addrs, fd_gossip_node_contact_t * ci_int ) {
  fd_gossip_contact_info_v2_t * info = ci_int->ci;
  ushort last_port = 0;
  uchar addr_cnt = 0;
  uchar sock_cnt = 0;

  /* contact_info_v2 stores port numbers in host order,
     ip addresses remain in network order... */
  ushort gossip_port = fd_ushort_bswap( addrs->gossip.port );
  ushort serve_repair_port = fd_ushort_bswap( addrs->serve_repair.port );
  ushort tvu_port = fd_ushort_bswap( addrs->tvu.port );
  ushort tpu_port = fd_ushort_bswap( addrs->tpu.port );
  ushort tpu_quic_port = fd_ushort_bswap( (ushort)(addrs->tpu_quic.port) );
  ushort tpu_vote_port = fd_ushort_bswap( addrs->tpu_vote.port );

  /* Loop is bounded by number of if( xx_port > 0 ... ) statements  + 1, so 7. */
  for(;;) {
    fd_gossip_peer_addr_t const * min_addr = NULL;
    ushort min_port = USHORT_MAX;
    uchar min_key = 0;

    /* Find the next socket to add to the list, based on next min port number */
    if( gossip_port > 0 && gossip_port > last_port && gossip_port < min_port ) {
      min_key = FD_GOSSIP_SOCKET_TAG_GOSSIP;
      min_addr = &addrs->gossip;
      min_port = gossip_port;
    }
    if( serve_repair_port > 0 && serve_repair_port > last_port && serve_repair_port < min_port ) {
      min_key = FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR;
      min_addr = &addrs->serve_repair;
      min_port = serve_repair_port;
    }
    if( tvu_port > 0 && tvu_port > last_port && tvu_port < min_port ) {
      min_key = FD_GOSSIP_SOCKET_TAG_TVU;
      min_addr = &addrs->tvu;
      min_port = tvu_port;
    }
    if( tpu_port > 0 && tpu_port > last_port && tpu_port < min_port ) {
      min_key = FD_GOSSIP_SOCKET_TAG_TPU;
      min_addr = &addrs->tpu;
      min_port = tpu_port;
    }
    if( tpu_quic_port > 0 && tpu_quic_port > last_port && tpu_quic_port < min_port ) {
      min_key = FD_GOSSIP_SOCKET_TAG_TPU_QUIC;
      min_addr = &addrs->tpu;
      min_port = tpu_quic_port;
    }
    if( tpu_vote_port > 0 && tpu_vote_port > last_port && tpu_vote_port < min_port ) {
      min_key = FD_GOSSIP_SOCKET_TAG_TPU_VOTE;
      min_addr = &addrs->tpu_vote;
      min_port = tpu_vote_port;
    }
    if( min_port==USHORT_MAX ) {
      break;
    }

    if( FD_UNLIKELY( sock_cnt >= FD_GOSSIP_SOCKET_TAG_MAX )) {
      FD_LOG_ERR(("Too many sockets in contact info, possible broken implementation of fd_gossip_refresh_contact_info_v2_sockets"));
    }

    /* Check if ip addr exists in addrs list already */
    uchar min_addr_idx = 0;
    for( ; min_addr_idx < addr_cnt; min_addr_idx++ ) {
      if( info->addrs[min_addr_idx].inner.ip4 == min_addr->addr ) {
      break;
      }
    }

    if( min_addr_idx == addr_cnt ) {
      /* ip addr not found, add it */
      fd_gossip_ip_addr_new_disc( &info->addrs[ addr_cnt ], fd_gossip_ip_addr_enum_ip4 );
      info->addrs[ addr_cnt ].inner.ip4 = min_addr->addr;
      min_addr_idx = addr_cnt;
      addr_cnt++;
    }

    info->sockets[ sock_cnt ].index = min_addr_idx;
    info->sockets[ sock_cnt ].offset = (ushort)( min_port - last_port );
    info->sockets[ sock_cnt ].key = min_key;
    sock_cnt++;
    last_port = min_port;

    if( FD_UNLIKELY( min_key == FD_GOSSIP_SOCKET_TAG_TPU ) ){
      /* FIXME: This is a hack around the fact that TPU and TPU vote
         share the same port. */
        info->sockets[ sock_cnt ].index = min_addr_idx;
        info->sockets[ sock_cnt ].offset = 0U;
        info->sockets[ sock_cnt ].key = FD_GOSSIP_SOCKET_TAG_TPU_VOTE;
        sock_cnt++;
    }
  }

  info->addrs_len = addr_cnt;
  info->sockets_len = sock_cnt;
  info->extensions_len = 0;
}

int
fd_gossip_update_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * my_addr ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating address %s", fd_gossip_addr_str(tmp, sizeof(tmp), my_addr)));

  fd_gossip_lock( glob );
  fd_gossip_peer_addr_copy( &glob->my_node_addrs.gossip, my_addr );

  fd_gossip_refresh_contact_info_v2_sockets( &glob->my_node_addrs, &glob->my_contact );
  fd_gossip_unlock( glob );
  return 0;
}

int
fd_gossip_update_repair_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * serve ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating repair service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), serve)));

  fd_gossip_lock( glob );
  fd_gossip_peer_addr_copy( &glob->my_node_addrs.serve_repair, serve );

  fd_gossip_refresh_contact_info_v2_sockets( &glob->my_node_addrs, &glob->my_contact );
  fd_gossip_unlock( glob );
  return 0;
}

int
fd_gossip_update_tvu_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tvu ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating tvu service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), tvu)));

  fd_gossip_lock( glob );
  fd_gossip_peer_addr_copy( &glob->my_node_addrs.tvu, tvu );

  fd_gossip_refresh_contact_info_v2_sockets( &glob->my_node_addrs, &glob->my_contact );
  fd_gossip_unlock( glob );
  return 0;
}

int
fd_gossip_update_tpu_addr( fd_gossip_t * glob,
                           fd_gossip_peer_addr_t const * tpu,
                           fd_gossip_peer_addr_t const * tpu_quic ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating tpu service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), tpu) ));
  FD_LOG_NOTICE(("updating tpu_quic service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), tpu_quic ) ));

  fd_gossip_lock( glob );
  fd_gossip_peer_addr_copy( &glob->my_node_addrs.tpu, tpu );
  fd_gossip_peer_addr_copy( &glob->my_node_addrs.tpu_quic, tpu_quic );

  fd_gossip_refresh_contact_info_v2_sockets( &glob->my_node_addrs, &glob->my_contact );
  fd_gossip_unlock( glob );

  return 0;
}

int
fd_gossip_update_tpu_vote_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tpu_vote ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating tpu vote service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), tpu_vote)));

  fd_gossip_lock( glob );
  fd_gossip_peer_addr_copy(&glob->my_node_addrs.tpu_vote, tpu_vote);

  fd_gossip_refresh_contact_info_v2_sockets( &glob->my_node_addrs, &glob->my_contact );
  fd_gossip_unlock( glob );

  return 0;
}

void
fd_gossip_set_shred_version( fd_gossip_t * glob, ushort shred_version ) {
  glob->my_contact.ci->shred_version = shred_version;
}

/* Add an event to the queue of pending timed events. The resulting
   value needs "fun" and "fun_arg" to be set. */
static fd_pending_event_t *
fd_gossip_add_pending( fd_gossip_t * glob, long when ) {
  if (fd_pending_pool_free( glob->event_pool ) == 0)
    return NULL;
  fd_pending_event_t * ev = fd_pending_pool_ele_acquire( glob->event_pool );
  ev->key = when;
  fd_pending_heap_ele_insert( glob->event_heap, ev, glob->event_pool );
  return ev;
}

/* Send raw data as a UDP packet to an address */
static void
fd_gossip_send_raw( fd_gossip_t * glob, const fd_gossip_peer_addr_t * dest, void * data, size_t sz) {
  if ( sz > PACKET_DATA_SIZE ) {
    FD_LOG_ERR(("sending oversized packet, size=%lu", sz));
  }
  glob->metrics.send_packet_cnt += 1UL;
  fd_gossip_unlock( glob );
  (*glob->send_fun)(data, sz, dest, glob->send_arg);
  fd_gossip_lock( glob );
}

/* Send a gossip message to an address */
static void
fd_gossip_send( fd_gossip_t * glob, const fd_gossip_peer_addr_t * dest, fd_gossip_msg_t * gmsg ) {
  /* Encode the data */
  uchar buf[PACKET_DATA_SIZE];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + PACKET_DATA_SIZE;
  if ( fd_gossip_msg_encode( gmsg, &ctx ) ) {
    FD_LOG_ERR(( "fd_gossip_msg_encode failed" ));
  }
  size_t sz = (size_t)((const uchar *)ctx.data - buf);
  fd_gossip_send_raw( glob, dest, buf, sz);
  glob->metrics.send_message[ gmsg->discriminant ] += 1UL;
  // char tmp[100];
  // FD_LOG_WARNING(("sent msg type %u to %s size=%lu", gmsg->discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), dest), sz));
}

/* Initiate the ping/pong protocol to a validator address */
static void
fd_gossip_make_ping( fd_gossip_t * glob, fd_pending_event_arg_t * arg ) {
  /* Update the active table where we track the state of the ping/pong
     protocol */
  fd_gossip_peer_addr_t * key = &arg->key;
  fd_active_elem_t * val = fd_active_table_query(glob->actives, key, NULL);
  if (val == NULL) {
    if (fd_active_table_is_full(glob->actives)) {
      glob->metrics.send_ping_events[ FD_METRICS_ENUM_SEND_PING_EVENT_V_ACTIVES_TABLE_FULL_IDX ] += 1UL;
      return;
    }
    val = fd_active_table_insert(glob->actives, key);
    fd_active_new_value(val);
    glob->metrics.send_ping_events[ FD_METRICS_ENUM_SEND_PING_EVENT_V_ACTIVES_TABLE_INSERT_IDX ] += 1UL;
  } else {
    if (val->pongtime != 0)
      /* Success */
      return;
    if (val->pingcount++ >= MAX_PEER_PING_COUNT) {
      /* Give up. This is a bad peer. */
      glob->metrics.send_ping_events[ FD_METRICS_ENUM_SEND_PING_EVENT_V_MAX_PING_COUNT_EXCEEDED_IDX ] += 1UL;
      fd_active_table_remove(glob->actives, key);
      fd_peer_table_remove(glob->peers, key);
      return;
    }
  }
  val->pingtime = glob->now;
  /* Generate a new token when we start a fresh round of pinging */
  if (val->pingcount == 1U) {
    for ( ulong i = 0; i < FD_HASH_FOOTPRINT / sizeof(ulong); ++i ) {
      val->pingtoken.ul[i] = fd_rng_ulong(glob->rng);
    }
  }

  /* Keep pinging until we succeed */
  fd_pending_event_t * ev = fd_gossip_add_pending( glob, glob->now + (long)2e8 /* 200 ms */ );
  if (ev != NULL) {
    ev->fun = fd_gossip_make_ping;
    fd_gossip_peer_addr_copy(&ev->fun_arg.key, key);
  }

  fd_pubkey_t * public_key = glob->public_key;

  /* Build a ping message */
  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_ping);
  fd_gossip_ping_t * ping = &gmsg.inner.ping;
  fd_hash_copy( &ping->from, public_key );

  uchar pre_image[FD_PING_PRE_IMAGE_SZ];
  fd_memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  fd_memcpy( pre_image+16UL, val->pingtoken.uc, 32UL );

  fd_sha256_hash( pre_image, FD_PING_PRE_IMAGE_SZ, &ping->token );

  /* Sign it */

  (*glob->sign_fun)( glob->sign_arg, ping->signature.uc, pre_image, FD_PING_PRE_IMAGE_SZ, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 );

  fd_gossip_send( glob, key, &gmsg );
}

/* Respond to a ping from another validator */
static void
fd_gossip_handle_ping( fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_gossip_ping_t const * ping ) {
  /* Verify the signature */
  fd_sha512_t sha2[1];
  if (fd_ed25519_verify( /* msg */ ping->token.uc,
                         /* sz */ 32UL,
                         /* sig */ ping->signature.uc,
                         /* public_key */ ping->from.uc,
                         sha2 )) {
    glob->metrics.recv_ping_invalid_signature += 1UL;
    FD_LOG_WARNING(("received ping with invalid signature"));
    return;
  }

  /* Build a pong message */
  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_pong);
  fd_gossip_ping_t * pong = &gmsg.inner.pong;

  fd_pubkey_t * public_key = glob->public_key;

  fd_hash_copy( &pong->from, public_key );

  uchar pre_image[FD_PING_PRE_IMAGE_SZ];
  fd_memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  fd_memcpy( pre_image+16UL, ping->token.uc, 32UL);

  /* Generate response hash token */
  fd_sha256_hash( pre_image, FD_PING_PRE_IMAGE_SZ, &pong->token );

  /* Sign it */
  (*glob->sign_fun)( glob->sign_arg, pong->signature.uc, pre_image, FD_PING_PRE_IMAGE_SZ, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 );

  fd_gossip_send(glob, from, &gmsg);
}

/* Sign/timestamp an outgoing crds value */
static void
fd_gossip_sign_crds_value( fd_gossip_t * glob, fd_crds_value_t * crd ) {
  /* Update the identifier and timestamp */
  fd_pubkey_t * pubkey;
  ulong * wallclock;
  switch (crd->data.discriminant) {
  case fd_crds_data_enum_contact_info_v1:
    pubkey = &crd->data.inner.contact_info_v1.id;
    wallclock = &crd->data.inner.contact_info_v1.wallclock;
    break;
  case fd_crds_data_enum_vote:
    pubkey = &crd->data.inner.vote.from;
    wallclock = &crd->data.inner.vote.wallclock;
    break;
  case fd_crds_data_enum_lowest_slot:
    pubkey = &crd->data.inner.lowest_slot.from;
    wallclock = &crd->data.inner.lowest_slot.wallclock;
    break;
  case fd_crds_data_enum_snapshot_hashes:
    pubkey = &crd->data.inner.snapshot_hashes.from;
    wallclock = &crd->data.inner.snapshot_hashes.wallclock;
    break;
  case fd_crds_data_enum_accounts_hashes:
    pubkey = &crd->data.inner.accounts_hashes.from;
    wallclock = &crd->data.inner.accounts_hashes.wallclock;
    break;
  case fd_crds_data_enum_epoch_slots:
    pubkey = &crd->data.inner.epoch_slots.from;
    wallclock = &crd->data.inner.epoch_slots.wallclock;
    break;
  case fd_crds_data_enum_version_v1:
    pubkey = &crd->data.inner.version_v1.from;
    wallclock = &crd->data.inner.version_v1.wallclock;
    break;
  case fd_crds_data_enum_version_v2:
    pubkey = &crd->data.inner.version_v2.from;
    wallclock = &crd->data.inner.version_v2.wallclock;
    break;
  case fd_crds_data_enum_node_instance:
    pubkey = &crd->data.inner.node_instance.from;
    wallclock = &crd->data.inner.node_instance.wallclock;
    break;
  case fd_crds_data_enum_duplicate_shred:
    pubkey = &crd->data.inner.duplicate_shred.from;
    wallclock = &crd->data.inner.duplicate_shred.wallclock;
    break;
  case fd_crds_data_enum_incremental_snapshot_hashes:
    pubkey = &crd->data.inner.incremental_snapshot_hashes.from;
    wallclock = &crd->data.inner.incremental_snapshot_hashes.wallclock;
    break;
  case fd_crds_data_enum_contact_info_v2:
    pubkey = &crd->data.inner.contact_info_v2.from;
    wallclock = &crd->data.inner.contact_info_v2.wallclock;
    break;
  case fd_crds_data_enum_restart_last_voted_fork_slots:
    pubkey = &crd->data.inner.restart_last_voted_fork_slots.from;
    wallclock = &crd->data.inner.restart_last_voted_fork_slots.wallclock;
    break;
  case fd_crds_data_enum_restart_heaviest_fork:
    pubkey = &crd->data.inner.restart_heaviest_fork.from;
    wallclock = &crd->data.inner.restart_heaviest_fork.wallclock;
    break;
  default:
    return;
  }
  fd_pubkey_t * public_key = glob->public_key;
  fd_hash_copy(pubkey, public_key);
  *wallclock = FD_NANOSEC_TO_MILLI(glob->now); /* convert to ms */

  /* Sign it */
  uchar buf[PACKET_DATA_SIZE];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + PACKET_DATA_SIZE;
  if ( fd_crds_data_encode( &crd->data, &ctx ) ) {
    FD_LOG_WARNING(("fd_crds_data_encode failed"));
    return;
  }

  (*glob->sign_fun)( glob->sign_arg, crd->signature.uc, buf, (ulong)((uchar*)ctx.data - buf), FD_KEYGUARD_SIGN_TYPE_ED25519 );
}

/* Convert a hash to a bloom filter bit position
   https://github.com/anza-xyz/agave/blob/v2.1.7/bloom/src/bloom.rs#L136 */
static ulong
fd_gossip_bloom_pos( fd_hash_t * hash, ulong key, ulong nbits) {
  for ( ulong i = 0; i < 32U; ++i) {
    key ^= (ulong)(hash->uc[i]);
    key *= 1099511628211UL; // FNV prime
  }
  return key % nbits;
}

/* Choose a random active peer with good ping count */
static fd_active_elem_t *
fd_gossip_random_active( fd_gossip_t * glob ) {
  /* Create a list of active peers with minimal pings */
  fd_active_elem_t * list[FD_ACTIVE_KEY_MAX];
  ulong listlen = 0;
  ulong totweight = 0;
  for( fd_active_table_iter_t iter = fd_active_table_iter_init( glob->actives );
       !fd_active_table_iter_done( glob->actives, iter );
       iter = fd_active_table_iter_next( glob->actives, iter ) ) {
    fd_active_elem_t * ele = fd_active_table_iter_ele( glob->actives, iter );

    if (ele->pongtime == 0 && !fd_gossip_is_allowed_entrypoint( glob, &ele->key )) {
      continue;
    } else if (listlen == 0) {
      list[0] = ele;
      listlen = 1;
      totweight = ele->weight;
    } else if (ele->pingcount > list[0]->pingcount) {
      continue;
    } else if (ele->pingcount < list[0]->pingcount) {
      /* Reset the list */
      list[0] = ele;
      listlen = 1;
      totweight = ele->weight;
    } else {
      list[listlen++] = ele;
      totweight += ele->weight;
    }
  }
  if (listlen == 0 || totweight == 0)
    return NULL;
  /* Choose a random list element by weight */
  ulong w = fd_rng_ulong(glob->rng) % totweight;
  ulong j = 0;
  for( ulong i = 0; i < listlen; ++i) {
    if( w < j + list[i]->weight )
      return list[i];
    j += list[i]->weight;
  }
  FD_LOG_CRIT(( "I shouldn't be here" ));
  return NULL;
}

/* Generate a pull request for a random active peer */
static void
fd_gossip_random_pull( fd_gossip_t * glob, fd_pending_event_arg_t * arg ) {
  (void)arg;

  /* Try again in 5 sec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, glob->now + (long)100e6);
  if (ev) {
    ev->fun = fd_gossip_random_pull;
  }

  /* Pick a random partner */
  fd_active_elem_t * ele = fd_gossip_random_active(glob);
  if (ele == NULL)
    return;

  /* Compute the number of packets needed for all the bloom filter parts
     with a desired false positive rate <0.1% (upper bounded by FD_BLOOM_MAX_PACKETS ) */
  ulong nitems = fd_value_table_key_cnt(glob->values);
  ulong nkeys = 1;
  ulong npackets = 1;
  uint nmaskbits = 0;
  double e = 0;
  if (nitems > 0) {
    do {
      double n = ((double)nitems)/((double)npackets); /* Assume even division of values */
      double m = (double)FD_BLOOM_NUM_BITS;
      nkeys = fd_ulong_max(1U, (ulong)((m/n)*0.69314718055994530941723212145818 /* ln(2) */));
      nkeys = fd_ulong_min(nkeys, FD_BLOOM_MAX_KEYS);
      if (npackets == FD_BLOOM_MAX_PACKETS)
        break;
      double k = (double)nkeys;
      e = pow(1.0 - exp(-k*n/m), k);
      if (e < 0.001)
        break;
      nmaskbits++;
      npackets = 1U<<nmaskbits;
    } while (1);
  }
  FD_LOG_DEBUG(("making bloom filter for %lu items with %lu packets, %u maskbits and %lu keys %g error", nitems, npackets, nmaskbits, nkeys, e));

  /* Generate random keys */
  ulong keys[FD_BLOOM_MAX_KEYS];
  for (ulong i = 0; i < nkeys; ++i)
    keys[i] = fd_rng_ulong(glob->rng);
  /* Set all the bits */
  ulong num_bits_set[FD_BLOOM_MAX_PACKETS];
  for (ulong i = 0; i < npackets; ++i)
    num_bits_set[i] = 0;

  /* Bloom filter set sampling

    This effectively translates to sending out 1/(SAMPLE_RATE)
    of the full bloom filter set every new pull request
    loop.

    Some observations:
      - Duplicate CRDS received rate* decreases dramatically
        (from being 90% of incoming CRDS traffic to nearly negligible)
      - Unique CRDS received rate* doesn't appear to be affected by
        sampling

      * rate measured in values/minute
    https://github.com/anza-xyz/agave/blob/v2.1.11/gossip/src/crds_gossip_pull.rs#L157-L163 */
  ushort indices[FD_BLOOM_MAX_PACKETS];
  for( ushort i = 0; i < npackets; ++i) {
    indices[i] = i;
  }
  ushort indices_len = (ushort)npackets;
  ulong filter_sample_size = (indices_len + FD_BLOOM_SAMPLE_RATE - 1) / FD_BLOOM_SAMPLE_RATE;
  FD_TEST( filter_sample_size <= FD_BLOOM_MAX_PACKETS );

  fd_gossip_filter_selection_t selected_filters = fd_gossip_filter_selection_null();

  for( ushort i = 0; i < filter_sample_size; ++i) {
    ulong idx = fd_rng_ushort( glob->rng ) % indices_len;

    /* swap and remove */
    ushort filter_idx = indices[ idx ];
    indices[ idx ] = indices[ --indices_len ];

    /* insert */
    selected_filters = fd_gossip_filter_selection_insert( selected_filters, filter_idx );
  }

  FD_TEST( fd_gossip_filter_selection_cnt( selected_filters ) == filter_sample_size );


#define CHUNKSIZE (FD_BLOOM_NUM_BITS/64U)
  ulong bits[CHUNKSIZE * FD_BLOOM_MAX_PACKETS]; /* TODO: can we bound size based on sample rate instead? */
  fd_memset(bits, 0, CHUNKSIZE*8U*npackets);
  ulong expire = FD_NANOSEC_TO_MILLI(glob->now) - FD_GOSSIP_VALUE_EXPIRE;
  for( fd_value_table_iter_t iter = fd_value_table_iter_init( glob->values );
       !fd_value_table_iter_done( glob->values, iter );
       iter = fd_value_table_iter_next( glob->values, iter ) ) {
    fd_value_elem_t * ele = fd_value_table_iter_ele( glob->values, iter );
    fd_hash_t * hash = &(ele->key);
    /* Purge expired values */
    if (ele->wallclock < expire) {
      fd_value_table_remove( glob->values, hash );
      continue;
    }
    /* Choose which filter packet based on the high bits in the hash,
       https://github.com/anza-xyz/agave/blob/v2.1.7/gossip/src/crds_gossip_pull.rs#L167

       skip if packet not part of sample
       https://github.com/anza-xyz/agave/blob/v2.1.11/gossip/src/crds_gossip_pull.rs#L175-L177
      */

    ulong index = (nmaskbits == 0 ? 0UL : ( hash->ul[0] >> (64U - nmaskbits) ));
    if( FD_LIKELY( !fd_gossip_filter_selection_test( selected_filters, index ) ) ) {
      continue;
    };

    ulong * chunk = bits + (index*CHUNKSIZE);

    /* https://github.com/anza-xyz/agave/blob/v2.1.7/bloom/src/bloom.rs#L191 */
    for (ulong i = 0; i < nkeys; ++i) {
      ulong pos = fd_gossip_bloom_pos(hash, keys[i], FD_BLOOM_NUM_BITS);
      /* https://github.com/anza-xyz/agave/blob/v2.1.7/bloom/src/bloom.rs#L182-L185 */
      ulong * j = chunk + (pos>>6U); /* divide by 64 */
      ulong bit = 1UL<<(pos & 63U);
      if (!((*j) & bit)) {
        *j |= bit;
        num_bits_set[index]++;
      }
    }
  }

  /* Assemble the packets */
  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_pull_req);
  fd_gossip_pull_req_t * req = &gmsg.inner.pull_req;
  fd_crds_filter_t * filter = &req->filter;
  filter->mask_bits = nmaskbits;
  filter->filter.keys_len = nkeys;
  filter->filter.keys = keys;
  fd_gossip_bitvec_u64_t * bitvec = &filter->filter.bits;
  bitvec->len = FD_BLOOM_NUM_BITS;
  bitvec->has_bits = 1;
  bitvec->bits.vec_len = FD_BLOOM_NUM_BITS/64U;

  /* The "value" in the request is always my own contact info (v2) */
  fd_crds_value_t * value = &req->value;
  fd_crds_data_new_disc(&value->data, fd_crds_data_enum_contact_info_v2);
  fd_gossip_contact_info_v2_t * ci = &value->data.inner.contact_info_v2;
  fd_memcpy(ci, &glob->my_contact.crd.inner.contact_info_v2, sizeof(fd_gossip_contact_info_v2_t) );
  fd_gossip_sign_crds_value(glob, value);

  for( fd_gossip_filter_selection_iter_t iter = fd_gossip_filter_selection_iter_init( selected_filters );
       !fd_gossip_filter_selection_iter_done( iter );
       iter = fd_gossip_filter_selection_iter_next( iter ) ){
    ulong index = fd_gossip_filter_selection_iter_idx( iter );
    filter->mask = (nmaskbits == 0 ? ~0UL : ((index << (64U - nmaskbits)) | (~0UL >> nmaskbits)));
    filter->filter.num_bits_set = num_bits_set[index];
    bitvec->bits.vec = bits + (index*CHUNKSIZE);
    fd_gossip_send(glob, &ele->key, &gmsg);
  }
}

/* Handle a pong response */
static void
fd_gossip_handle_pong( fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_gossip_ping_t const * pong ) {
#define INC_RECV_PONG_EVENT_CNT( REASON ) glob->metrics.recv_pong_events[ FD_CONCAT3( FD_METRICS_ENUM_RECV_PONG_EVENT_V_,  REASON, _IDX ) ] += 1UL
  fd_active_elem_t * val = fd_active_table_query(glob->actives, from, NULL);
  if (val == NULL) {
    INC_RECV_PONG_EVENT_CNT( EXPIRED );
    FD_LOG_DEBUG(("received pong too late"));
    return;
  }

  uchar pre_image[FD_PING_PRE_IMAGE_SZ];
  fd_memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  fd_memcpy( pre_image+16UL, val->pingtoken.uc, 32UL );


  fd_hash_t pre_image_hash;
  fd_sha256_hash( pre_image, FD_PING_PRE_IMAGE_SZ, pre_image_hash.uc );

  /* Confirm response hash token */
  fd_sha256_t sha[1];
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );

  fd_sha256_append( sha, pre_image_hash.uc, 32UL );
  fd_hash_t pongtoken;
  fd_sha256_fini( sha, pongtoken.uc );
  if (memcmp(pongtoken.uc, pong->token.uc, 32UL) != 0) {
    INC_RECV_PONG_EVENT_CNT( WRONG_TOKEN );
    FD_LOG_DEBUG(( "received pong with wrong token" ));
    return;
  }

  /* Verify the signature */
  fd_sha512_t sha2[1];
  if (fd_ed25519_verify( /* msg */ pong->token.uc,
                         /* sz */ 32UL,
                         /* sig */ pong->signature.uc,
                         /* public_key */ pong->from.uc,
                         sha2 )) {
    INC_RECV_PONG_EVENT_CNT( INVALID_SIGNATURE );
    FD_LOG_WARNING(("received pong with invalid signature"));
    return;
  }

  val->pongtime = glob->now;
  fd_hash_copy(&val->id, &pong->from);

  /* Remember that this is a good peer */
  fd_peer_elem_t * peerval = fd_peer_table_query(glob->peers, from, NULL);
  if (peerval == NULL) {
    INC_RECV_PONG_EVENT_CNT( NEW_PEER );
    if (fd_peer_table_is_full(glob->peers)) {
      INC_RECV_PONG_EVENT_CNT( TABLE_FULL );
      FD_LOG_DEBUG(("too many peers"));
      return;
    }
    peerval = fd_peer_table_insert(glob->peers, from);
    peerval->stake = 0;
  }
  peerval->wallclock = FD_NANOSEC_TO_MILLI(glob->now); /* In millisecs */
  fd_hash_copy(&peerval->id, &pong->from);

  fd_weights_elem_t const * val2 = fd_weights_table_query_const( glob->weights, &val->id, NULL );
  val->weight = ( val2 == NULL ? 1UL : val2->weight );

}

/* Initiate a ping/pong with a random active partner to confirm it is
   still alive. */
static void
fd_gossip_random_ping( fd_gossip_t * glob, fd_pending_event_arg_t * arg ) {
  (void)arg;

  /* Try again in 1 sec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, glob->now + (long)100e8);
  if (ev) {
    ev->fun = fd_gossip_random_ping;
  }

  if (fd_pending_pool_free( glob->event_pool ) < 100U)
    return;

  ulong cnt = fd_active_table_key_cnt(glob->actives);
  if (cnt == 0 && glob->inactives_cnt == 0)
    return;
  fd_gossip_peer_addr_t * addr = NULL;
  if (glob->inactives_cnt > 0 && cnt < FD_ACTIVE_KEY_MAX)
    /* Try a new peer */
    addr = glob->inactives + (--(glob->inactives_cnt));
  else {
    /* Choose a random active peer */
    ulong i = fd_rng_ulong(glob->rng) % cnt;
    ulong j = 0;
    for( fd_active_table_iter_t iter = fd_active_table_iter_init( glob->actives );
         !fd_active_table_iter_done( glob->actives, iter );
         iter = fd_active_table_iter_next( glob->actives, iter ) ) {
      if (i == j++) {
        fd_active_elem_t * ele = fd_active_table_iter_ele( glob->actives, iter );
        if (glob->now - ele->pingtime < (long)60e9) /* minute cooldown */
          return;
        ele->pingcount = 0;
        ele->pongtime = 0;
        addr = &(ele->key);
        break;
      }
    }
  }

  fd_pending_event_arg_t arg2;
  fd_gossip_peer_addr_copy(&arg2.key, addr);
  fd_gossip_make_ping(glob, &arg2);
}

/* CRDS processing utils.
   TODO: move to a separate fd_crds file? Need to decouple gossip metrics first */

typedef struct{
  fd_crds_value_t * crd;                // Decoded CRDS value
  uchar encoded_val[PACKET_DATA_SIZE];  // Raw encoded form
  ulong encoded_len;                    // Length of encoded data
  fd_hash_t val_hash;                   // Hash of the value (used as key in the value table)
  fd_pubkey_t* pubkey;                  // Reference to origin's pubkey
  ulong wallclock;                      // Timestamp
} fd_crds_value_processed_t;

/* fd_crds_dedup_check returns 1 if key exists in the CRDS value table, 0 otherwise.
   Also logs the
    - the host that sent the duplicate message
    - origin of the actual CRDS value
   for use in making prune messages. */
static int
fd_crds_dup_check( fd_gossip_t * glob, fd_hash_t * key, const fd_gossip_peer_addr_t * from, const fd_pubkey_t * origin ) {
  fd_value_elem_t * msg = fd_value_table_query(glob->values, key, NULL);

  if (msg != NULL) {
    /* Already have this value */
    if (from != NULL) {
      /* Record the dup in the receive statistics table */
      fd_stats_elem_t * val = fd_stats_table_query(glob->stats, from, NULL);
      if (val == NULL) {
        if (!fd_stats_table_is_full(glob->stats)) {
          val = fd_stats_table_insert(glob->stats, from);
          val->dups_cnt = 0;
        }
      }
      if (val != NULL) {
        val->last = glob->now;
        for (ulong i = 0; i < val->dups_cnt; ++i){
          if (fd_hash_eq(&val->dups[i].origin, origin)) {
            val->dups[i].cnt++;
            goto found_origin;
          }
        }
        if (val->dups_cnt < 8) {
          ulong i = val->dups_cnt++;
          fd_hash_copy(&val->dups[i].origin, origin);
          val->dups[i].cnt = 1;
        }
        found_origin: ;
      }
    }
    return 1;
  } else {
    return 0;
  }
}
/* fd_crds_sigverify verifies the data in an encoded CRDS value.
   Assumes the following CRDS value layout (packed)
    {
      fd_signature_t signature;
      uchar* data;
    } */
static int
fd_crds_sigverify( uchar * crds_encoded_val, ulong crds_encoded_len, fd_pubkey_t * pubkey ) {

  fd_signature_t * sig = (fd_signature_t *)crds_encoded_val;
  uchar * data = (crds_encoded_val + sizeof(fd_signature_t));
  ulong datalen = crds_encoded_len - sizeof(fd_signature_t);

  static fd_sha512_t sha[1]; /* static is ok since ed25519_verify calls sha512_init */
  return fd_ed25519_verify( data,
                         datalen,
                         sig->uc,
                         pubkey->uc,
                         sha );
}


#define INC_RECV_CRDS_DROP_METRIC( REASON ) glob->metrics.recv_crds_drop_reason[ FD_CONCAT3( FD_METRICS_ENUM_CRDS_DROP_REASON_V_, REASON, _IDX ) ] += 1UL

/* fd_crds_insert sets up and inserts a fd_value_elem_t entry
   from a fully populated crd_p.

   This only fails if the table is full.   */
static void
fd_crds_insert( fd_gossip_t * glob, fd_crds_value_processed_t * crd_p ) {
  if( FD_UNLIKELY( fd_value_table_is_full( glob->values ) ) ) {
    INC_RECV_CRDS_DROP_METRIC( TABLE_FULL );
    FD_LOG_DEBUG(( "too many values" ));
    return;
  }

  fd_value_elem_t * ele = fd_value_table_insert(glob->values, &crd_p->val_hash );
  ele->wallclock = crd_p->wallclock;
  fd_hash_copy( &ele->origin, crd_p->pubkey );

  /* Store encoded form of full CRDS value (including signature) */
  fd_memcpy( ele->data, crd_p->encoded_val, crd_p->encoded_len );
  ele->datalen = crd_p->encoded_len;
}

/* fd_gossip_recv_crds_array processes crds_len crds values. First
   performs a filter pass, dropping duplicate/own values and
   exiting* on any sigverify failures. Then inserts the filtered
   values into the CRDS value table. Also performs housekeeping, like
   updating contact infos and push queue. The filtered crds data is
   finally dispatched via the glob->deliver_fun callback.

   *(an exit drops the full packet, so no values are inserted into the table)
   This only fails on a crds value encode failure, which is impossible if
   the value was derived from a gossip message decode. */
static void
fd_gossip_recv_crds_array( fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_crds_value_t * crds, ulong crds_len, fd_gossip_crds_route_t route ) {
  FD_SCRATCH_SCOPE_BEGIN{
    fd_crds_value_processed_t * filtered_crds = (fd_crds_value_processed_t *)fd_scratch_alloc( alignof(fd_crds_value_processed_t), sizeof(fd_crds_value_processed_t) * crds_len );
    ulong num_filtered_crds = 0;

    /* OK to reuse since sha256_init is called in every iteration */
    fd_sha256_t sha2[1];

    /* Filter pass */
    for( ulong i = 0; i < crds_len; ++i ) {
      fd_crds_value_processed_t * tmp = &filtered_crds[ num_filtered_crds ]; /* This will overwrite if previous value was dedup, should be safe */
      tmp->crd = &crds[ i ];

      /* Setup fd_crds_value_processed_t entry */

      if( FD_UNLIKELY( tmp->crd->data.discriminant>=FD_KNOWN_CRDS_ENUM_MAX ) ) {
        INC_RECV_CRDS_DROP_METRIC( UNKNOWN_DISCRIMINANT );
      } else {
        glob->metrics.recv_crds[ route ][ tmp->crd->data.discriminant ] += 1UL;
      }
      switch (tmp->crd->data.discriminant) {
      case fd_crds_data_enum_contact_info_v1:
        tmp->pubkey = &tmp->crd->data.inner.contact_info_v1.id;
        tmp->wallclock = tmp->crd->data.inner.contact_info_v1.wallclock;
        break;
      case fd_crds_data_enum_vote:
        tmp->pubkey = &tmp->crd->data.inner.vote.from;
        tmp->wallclock = tmp->crd->data.inner.vote.wallclock;
        break;
      case fd_crds_data_enum_lowest_slot:
        tmp->pubkey = &tmp->crd->data.inner.lowest_slot.from;
        tmp->wallclock = tmp->crd->data.inner.lowest_slot.wallclock;
        break;
      case fd_crds_data_enum_snapshot_hashes:
        tmp->pubkey = &tmp->crd->data.inner.snapshot_hashes.from;
        tmp->wallclock = tmp->crd->data.inner.snapshot_hashes.wallclock;
        break;
      case fd_crds_data_enum_accounts_hashes:
        tmp->pubkey = &tmp->crd->data.inner.accounts_hashes.from;
        tmp->wallclock = tmp->crd->data.inner.accounts_hashes.wallclock;
        break;
      case fd_crds_data_enum_epoch_slots:
        tmp->pubkey = &tmp->crd->data.inner.epoch_slots.from;
        tmp->wallclock = tmp->crd->data.inner.epoch_slots.wallclock;
        break;
      case fd_crds_data_enum_version_v1:
        tmp->pubkey = &tmp->crd->data.inner.version_v1.from;
        tmp->wallclock = tmp->crd->data.inner.version_v1.wallclock;
        break;
      case fd_crds_data_enum_version_v2:
        tmp->pubkey = &tmp->crd->data.inner.version_v2.from;
        tmp->wallclock = tmp->crd->data.inner.version_v2.wallclock;
        break;
      case fd_crds_data_enum_node_instance:
        tmp->pubkey = &tmp->crd->data.inner.node_instance.from;
        tmp->wallclock = tmp->crd->data.inner.node_instance.wallclock;
        break;
      case fd_crds_data_enum_duplicate_shred:
        tmp->pubkey = &tmp->crd->data.inner.duplicate_shred.from;
        tmp->wallclock = tmp->crd->data.inner.duplicate_shred.wallclock;
        break;
      case fd_crds_data_enum_incremental_snapshot_hashes:
        tmp->pubkey = &tmp->crd->data.inner.incremental_snapshot_hashes.from;
        tmp->wallclock = tmp->crd->data.inner.incremental_snapshot_hashes.wallclock;
        break;
      case fd_crds_data_enum_contact_info_v2:
        tmp->pubkey = &tmp->crd->data.inner.contact_info_v2.from;
        tmp->wallclock = tmp->crd->data.inner.contact_info_v2.wallclock;
        break;
      case fd_crds_data_enum_restart_last_voted_fork_slots:
        tmp->pubkey = &tmp->crd->data.inner.restart_last_voted_fork_slots.from;
        tmp->wallclock = tmp->crd->data.inner.restart_last_voted_fork_slots.wallclock;
        break;
      case fd_crds_data_enum_restart_heaviest_fork:
        tmp->pubkey = &tmp->crd->data.inner.restart_heaviest_fork.from;
        tmp->wallclock = tmp->crd->data.inner.restart_heaviest_fork.wallclock;
        break;
      default:
        tmp->wallclock = FD_NANOSEC_TO_MILLI(glob->now); /* In millisecs */
        break;
      }
      if (memcmp(tmp->pubkey->uc, glob->public_key->uc, 32U) == 0) {
        /* skip my own messages */
        INC_RECV_CRDS_DROP_METRIC( OWN_MESSAGE );
        continue;
      }

      /* Encode */
      fd_bincode_encode_ctx_t ctx;
      ctx.data = tmp->encoded_val;
      ctx.dataend = tmp->encoded_val + PACKET_DATA_SIZE;
      if ( fd_crds_value_encode( tmp->crd, &ctx ) ) {
        FD_LOG_ERR(("fd_crds_value_encode failed"));
      }
      tmp->encoded_len = (ulong)((uchar *)ctx.data - tmp->encoded_val);

      /* Get hash */
      fd_sha256_init( sha2 );
      fd_sha256_append( sha2, tmp->encoded_val, tmp->encoded_len );
      fd_sha256_fini( sha2, tmp->val_hash.uc );

      fd_msg_stats_elem_t * msg_stat = &glob->msg_stats[ tmp->crd->data.discriminant ];
      msg_stat->total_cnt++;
      msg_stat->bytes_rx_cnt += tmp->encoded_len;

      /* Dedup first */
      if ( fd_crds_dup_check( glob, &tmp->val_hash, from, tmp->pubkey ) ) {
        msg_stat->dups_cnt++;
        glob->recv_dup_cnt++;
        glob->metrics.recv_crds_duplicate_message[ route ][ tmp->crd->data.discriminant ]++;
        continue; /* skip this entry */
      }

      glob->recv_nondup_cnt++;
      /* Sigverify step
         Skip verifying epoch slots because they:
          - are not used anywhere within the client
            - still store them in table for forwarding +
              prune message construction
          - represent a significant portion of inbound CRDS
            traffic (~90%)
          - will be deprecated soon */
      if( tmp->crd->data.discriminant != fd_crds_data_enum_epoch_slots &&
          fd_crds_sigverify( tmp->encoded_val, tmp->encoded_len, tmp->pubkey ) ) {
        INC_RECV_CRDS_DROP_METRIC( INVALID_SIGNATURE );
        /* drop full packet on bad signature
           https://github.com/anza-xyz/agave/commit/d68b5de6c0fc07d60cf9749ae82c2651a549e81b */
        return;
      }
      num_filtered_crds++;
    }

    /* Insert pass */
    for( ulong i = 0; i < num_filtered_crds; ++i ) {
      fd_crds_value_processed_t * crd_p = &filtered_crds[ i ];
      fd_crds_insert(  glob, crd_p );

      if ( FD_UNLIKELY( glob->need_push_cnt < FD_NEED_PUSH_MAX ) ) {
        /* Remember that I need to push this value */
        ulong i = ((glob->need_push_head + (glob->need_push_cnt++)) & (FD_NEED_PUSH_MAX-1U));
        fd_hash_copy(glob->need_push + i, &crd_p->val_hash);
        glob->metrics.push_crds_queue_cnt = glob->need_push_cnt;
      } else {
        INC_RECV_CRDS_DROP_METRIC( PUSH_QUEUE_FULL );
      }

      fd_crds_value_t * crd = crd_p->crd;

      if (crd->data.discriminant == fd_crds_data_enum_contact_info_v2) {
        fd_gossip_contact_info_v2_t * info = &crd->data.inner.contact_info_v2;
        fd_gossip_socket_addr_t socket_addr;
        if( fd_gossip_contact_info_v2_find_proto_ident( info, FD_GOSSIP_SOCKET_TAG_GOSSIP, &socket_addr ) ) {
          if( fd_gossip_port_from_socketaddr( &socket_addr ) != 0) {
            /* Remember the peer */
            fd_gossip_peer_addr_t pkey;
            fd_memset(&pkey, 0, sizeof(pkey));
            fd_gossip_from_soladdr(&pkey, &socket_addr);
            fd_peer_elem_t * val = fd_peer_table_query(glob->peers, &pkey, NULL);
            if (val == NULL) {
              if (fd_peer_table_is_full(glob->peers)) {
                INC_RECV_CRDS_DROP_METRIC( PEER_TABLE_FULL );
                FD_LOG_DEBUG(("too many peers"));
              } else {
                val = fd_peer_table_insert(glob->peers, &pkey);

                if ( glob->inactives_cnt >= INACTIVES_MAX ) {
                  INC_RECV_CRDS_DROP_METRIC( INACTIVES_QUEUE_FULL );
                } else if ( fd_active_table_query(glob->actives, &pkey, NULL) == NULL ) {
                  /* Queue this peer for later pinging */
                  fd_gossip_peer_addr_copy(glob->inactives + (glob->inactives_cnt++), &pkey);
                }
              }
            }
            if (val != NULL) {
              val->wallclock = crd_p->wallclock;
              val->stake = 0;
              fd_hash_copy(&val->id, &info->from);
            } else {
              INC_RECV_CRDS_DROP_METRIC( DISCARDED_PEER );
            }
          }

          fd_gossip_peer_addr_t peer_addr = { .addr = socket_addr.inner.ip4.addr,
                                              /* FIXME: hardcode to ip4 inner? */
                                              .port = fd_ushort_bswap( fd_gossip_port_from_socketaddr( &socket_addr ) ) };
          if (glob->my_contact.ci->shred_version == 0U && fd_gossip_is_allowed_entrypoint( glob, &peer_addr )) {
            FD_LOG_NOTICE(("using shred version %lu", (ulong)crd->data.inner.contact_info_v2.shred_version));
            glob->my_contact.ci->shred_version = crd->data.inner.contact_info_v2.shred_version;
          }
        }
      }

      glob->metrics.gossip_peer_cnt[ FD_METRICS_ENUM_GOSSIP_PEER_STATE_V_INACTIVE_IDX ] = glob->inactives_cnt;

      /* Deliver the data upstream */
      fd_gossip_unlock( glob );
      (*glob->deliver_fun)(&crd->data, glob->deliver_arg);
      fd_gossip_lock( glob );
    }

  } FD_SCRATCH_SCOPE_END;
}
#undef INC_RECV_CRDS_DROP_METRIC

static int
verify_signable_data_with_prefix( fd_gossip_t * glob, fd_gossip_prune_msg_t * msg ) {
  fd_gossip_prune_sign_data_with_prefix_t signdata[1] = {0};
  signdata->prefix           = (uchar *)&FD_GOSSIP_PRUNE_DATA_PREFIX;
  signdata->prefix_len       = 18UL;
  signdata->data.pubkey      = msg->data.pubkey;
  signdata->data.prunes_len  = msg->data.prunes_len;
  signdata->data.prunes      = msg->data.prunes;
  signdata->data.destination = msg->data.destination;
  signdata->data.wallclock   = msg->data.wallclock;

  uchar buf[PACKET_DATA_SIZE];
  fd_bincode_encode_ctx_t ctx;
  ctx.data    = buf;
  ctx.dataend = buf + PACKET_DATA_SIZE;
  if ( fd_gossip_prune_sign_data_with_prefix_encode( signdata, &ctx ) ) {
    glob->metrics.handle_prune_fails[ FD_METRICS_ENUM_PRUNE_FAILURE_REASON_V_SIGN_ENCODING_FAILED_IDX ] += 1UL;
    FD_LOG_WARNING(("fd_gossip_prune_sign_data_encode failed"));
    return 1;
  }

  fd_sha512_t sha[1];
  return fd_ed25519_verify( /* msg */ buf,
                         /* sz  */ (ulong)((uchar*)ctx.data - buf),
                         /* sig */ msg->data.signature.uc,
                         /* public_key */ msg->data.pubkey.uc,
                         sha );
}

static int
verify_signable_data( fd_gossip_t * glob, fd_gossip_prune_msg_t * msg ) {
  fd_gossip_prune_sign_data_t signdata;
  signdata.pubkey      = msg->data.pubkey;
  signdata.prunes_len  = msg->data.prunes_len;
  signdata.prunes      = msg->data.prunes;
  signdata.destination = msg->data.destination;
  signdata.wallclock   = msg->data.wallclock;

  uchar buf[PACKET_DATA_SIZE];
  fd_bincode_encode_ctx_t ctx;
  ctx.data    = buf;
  ctx.dataend = buf + PACKET_DATA_SIZE;
  if ( fd_gossip_prune_sign_data_encode( &signdata, &ctx ) ) {
    glob->metrics.handle_prune_fails[ FD_METRICS_ENUM_PRUNE_FAILURE_REASON_V_SIGN_ENCODING_FAILED_IDX ] += 1UL;
    FD_LOG_WARNING(("fd_gossip_prune_sign_data_encode failed"));
    return 1;
  }

  fd_sha512_t sha[1];
  return fd_ed25519_verify( /* msg */ buf,
                         /* sz  */ (ulong)((uchar*)ctx.data - buf),
                         /* sig */ msg->data.signature.uc,
                         /* public_key */ msg->data.pubkey.uc,
                         sha );
}

/* Handle a prune request from somebody else */
static void
fd_gossip_handle_prune(fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_gossip_prune_msg_t * msg) {
  (void)from;

  /* Confirm the message is for me */
  if (memcmp(msg->data.destination.uc, glob->public_key->uc, 32U) != 0)
    return;

  /* Try to verify the signed data either with the prefix and not the prefix */
  if ( ! (  verify_signable_data( glob, msg ) == FD_ED25519_SUCCESS ||
            verify_signable_data_with_prefix( glob, msg ) == FD_ED25519_SUCCESS ) ) {
    glob->metrics.handle_prune_fails[ FD_METRICS_ENUM_PRUNE_FAILURE_REASON_V_INVALID_SIGNATURE_IDX ] += 1UL;
    FD_LOG_WARNING(( "received prune message with invalid signature" ));
    return;
  }

  /* Find the active push state which needs to be pruned */
  fd_push_state_t* ps = NULL;
  for (ulong i = 0; i < glob->push_states_cnt; ++i) {
    fd_push_state_t* s = glob->push_states[i];
    if (memcmp(msg->data.pubkey.uc, s->id.uc, 32U) == 0) {
      ps = s;
      break;
    }
  }
  if (ps == NULL)
    return;

  /* Set the bloom filter prune bits */
  for (ulong i = 0; i < msg->data.prunes_len; ++i) {
    fd_pubkey_t * p = msg->data.prunes + i;
    for (ulong j = 0; j < FD_PRUNE_NUM_KEYS; ++j) {
      ulong pos = fd_gossip_bloom_pos(p, ps->prune_keys[j], FD_PRUNE_NUM_BITS);
      ulong * j = ps->prune_bits + (pos>>6U); /* divide by 64 */
      ulong bit = 1UL<<(pos & 63U);
      *j |= bit;
    }
  }
}

static int
fd_gossip_push_value_nolock( fd_gossip_t * glob, fd_crds_data_t * data, fd_hash_t * key_opt );

/* Push an updated version of my contact info into values */
static void
fd_gossip_push_updated_contact(fd_gossip_t * glob) {
  /* See if we have a shred version yet */
  if (glob->my_contact.ci->shred_version == 0U)
    return;
  /* Update every 1 secs */
  if (glob->now - glob->last_contact_time < (long)1e9)
    return;

  if (glob->last_contact_time != 0) {
    fd_value_elem_t * ele = fd_value_table_query(glob->values, &glob->last_contact_info_v2_key, NULL);
    if (ele != NULL) {
      fd_value_table_remove( glob->values, &glob->last_contact_info_v2_key );
    }
  }

  glob->last_contact_time = glob->now;
  glob->my_contact.ci->wallclock = FD_NANOSEC_TO_MILLI(glob->now);
  fd_gossip_push_value_nolock(glob, &glob->my_contact.crd, &glob->last_contact_info_v2_key);
}

/* Respond to a pull request */
static void
fd_gossip_handle_pull_req(fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_gossip_pull_req_t * msg) {
#define INC_HANDLE_PULL_REQ_FAIL_METRIC( REASON ) glob->metrics.handle_pull_req_fails[ FD_CONCAT3( FD_METRICS_ENUM_PULL_REQ_FAIL_REASON_V_, REASON, _IDX ) ] += 1UL
  fd_active_elem_t * val = fd_active_table_query(glob->actives, from, NULL);
  if (val == NULL || val->pongtime == 0) {

    if ( val == NULL ) {
      INC_HANDLE_PULL_REQ_FAIL_METRIC( PEER_NOT_IN_ACTIVES );
    }
    else if ( val->pongtime == 0 ) {
      INC_HANDLE_PULL_REQ_FAIL_METRIC( UNRESPONSIVE_PEER );
    }

    /* Ping new peers before responding to requests */
    /* TODO: is this the right thing to do here? */
    if (fd_pending_pool_free( glob->event_pool ) < 100U) {
      INC_HANDLE_PULL_REQ_FAIL_METRIC( PENDING_POOL_FULL );
      return;
    }
    fd_pending_event_arg_t arg2;
    fd_gossip_peer_addr_copy(&arg2.key, from);
    fd_gossip_make_ping(glob, &arg2);
    return;
  }

  /* Encode an empty pull response as a template */
  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_pull_resp);
  fd_gossip_pull_resp_t * pull_resp = &gmsg.inner.pull_resp;
  fd_hash_copy( &pull_resp->pubkey, glob->public_key );

  uchar buf[PACKET_DATA_SIZE];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + PACKET_DATA_SIZE;
  if ( fd_gossip_msg_encode( &gmsg, &ctx ) ) {
    INC_HANDLE_PULL_REQ_FAIL_METRIC( ENCODING_FAILED );
    FD_LOG_WARNING(("fd_gossip_msg_encode failed"));
    return;
  }
  /* Reach into buffer to get the number of values */
  uchar * newend = (uchar *)ctx.data;
  ulong * crds_len = (ulong *)(newend - sizeof(ulong));

  /* Push an updated version of my contact info into values */
  fd_gossip_push_updated_contact(glob);

  /* Apply the bloom filter to my table of values */
  fd_crds_filter_t * filter = &msg->filter;
  ulong nkeys = filter->filter.keys_len;
  ulong * keys = filter->filter.keys;
  fd_gossip_bitvec_u64_t * bitvec = &filter->filter.bits;
  ulong * bitvec2 = bitvec->bits.vec;
  ulong expire = FD_NANOSEC_TO_MILLI(glob->now) - FD_GOSSIP_PULL_TIMEOUT;
  ulong hits = 0;
  ulong misses = 0;
  uint npackets = 0;
  for( fd_value_table_iter_t iter = fd_value_table_iter_init( glob->values );
       !fd_value_table_iter_done( glob->values, iter );
       iter = fd_value_table_iter_next( glob->values, iter ) ) {
    fd_value_elem_t * ele = fd_value_table_iter_ele( glob->values, iter );
    fd_hash_t * hash = &(ele->key);
    if (ele->wallclock < expire)
      continue;
    /* Execute the bloom filter */
    if (filter->mask_bits != 0U) {
      ulong m = (~0UL >> filter->mask_bits);
      if ((hash->ul[0] | m) != filter->mask)
        continue;
    }
    int miss = 0;
    for (ulong i = 0; i < nkeys; ++i) {
      ulong pos = fd_gossip_bloom_pos(hash, keys[i], bitvec->len);
      ulong * j = bitvec2 + (pos>>6U); /* divide by 64 */
      ulong bit = 1UL<<(pos & 63U);
      if (!((*j) & bit)) {
        miss = 1;
        break;
      }
    }
    if (!miss) {
      hits++;
      continue;
    }
    misses++;

    /* Add the value in already encoded form */
    if (newend + ele->datalen - buf > PACKET_DATA_SIZE) {
      /* Packet is getting too large. Flush it */
      ulong sz = (ulong)(newend - buf);
      fd_gossip_send_raw(glob, from, buf, sz);
      glob->metrics.send_message[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ]++;
      char tmp[100];
      FD_LOG_DEBUG(("sent msg type %u to %s size=%lu", gmsg.discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), from), sz));
      ++npackets;
      newend = (uchar *)ctx.data;
      *crds_len = 0;
    }
    fd_memcpy(newend, ele->data, ele->datalen);
    newend += ele->datalen;
    (*crds_len)++;
  }
      /* Record the number of hits and misses

       These metrics are imprecise as the numbers will vary
       per pull request. We keep them to surface
       obvious issues like 100% miss rate. */
       glob->metrics.handle_pull_req_bloom_filter_result[ FD_METRICS_ENUM_PULL_REQ_BLOOM_FILTER_RESULT_V_HIT_IDX ] += hits;
       glob->metrics.handle_pull_req_bloom_filter_result[ FD_METRICS_ENUM_PULL_REQ_BLOOM_FILTER_RESULT_V_MISS_IDX ] += misses;

  /* Flush final packet */
  if (newend > (uchar *)ctx.data) {
    ulong sz = (ulong)(newend - buf);
    fd_gossip_send_raw(glob, from, buf, sz);
    glob->metrics.send_message[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PULL_RESPONSE_IDX ]++;
    char tmp[100];
    FD_LOG_DEBUG(("sent msg type %u to %s size=%lu", gmsg.discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), from), sz));
    ++npackets;
  }

  if (misses) {
    FD_LOG_DEBUG(("responded to pull request with %lu values in %u packets (%lu filtered out)", misses, npackets, hits));
  }
  glob->metrics.handle_pull_req_npackets = npackets;
#undef INC_HANDLE_PULL_REQ_FAIL_METRIC
}



/* Handle any gossip message */
static void
fd_gossip_recv(fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_gossip_msg_t * gmsg) {
  if ( FD_LIKELY( gmsg->discriminant < FD_METRICS_COUNTER_GOSSIP_RECEIVED_GOSSIP_MESSAGES_CNT ) ) {
    glob->metrics.recv_message[gmsg->discriminant] += 1UL;
  } else {
    glob->metrics.recv_unknown_message += 1UL;
  }
  switch (gmsg->discriminant) {
  case fd_gossip_msg_enum_pull_req:
    fd_gossip_handle_pull_req(glob, from, &gmsg->inner.pull_req);
    break;
  case fd_gossip_msg_enum_pull_resp: {
    fd_gossip_pull_resp_t * pull_resp = &gmsg->inner.pull_resp;
    fd_gossip_recv_crds_array( glob, NULL, pull_resp->crds, pull_resp->crds_len, FD_GOSSIP_CRDS_ROUTE_PULL_RESP );
    break;
  }
  case fd_gossip_msg_enum_push_msg: {
    fd_gossip_push_msg_t * push_msg = &gmsg->inner.push_msg;
    fd_gossip_recv_crds_array( glob, from, push_msg->crds, push_msg->crds_len, FD_GOSSIP_CRDS_ROUTE_PUSH );
    break;
  }
  case fd_gossip_msg_enum_prune_msg:
    fd_gossip_handle_prune(glob, from, &gmsg->inner.prune_msg);
    break;
  case fd_gossip_msg_enum_ping:
    fd_gossip_handle_ping(glob, from, &gmsg->inner.ping);
    break;
  case fd_gossip_msg_enum_pong:
    fd_gossip_handle_pong(glob, from, &gmsg->inner.pong);
    break;
  }
}

/* Initiate connection to a peer */
int
fd_gossip_add_active_peer( fd_gossip_t *                 glob,
                           fd_gossip_peer_addr_t const * addr ) {
  fd_gossip_lock( glob );
  fd_active_elem_t * val = fd_active_table_query( glob->actives, addr, NULL );
  if( val==NULL ) {
    if( fd_active_table_is_full( glob->actives )) {
      FD_LOG_WARNING(( "too many actives" ));
      fd_gossip_unlock( glob );
      return -1;
    }
    val = fd_active_table_insert( glob->actives, addr );
    fd_active_new_value( val );
    val->pingcount = 0; /* Incremented in fd_gossip_make_ping */
  }
  fd_gossip_unlock( glob );
  return 0;
}

/* Improve the set of active push states */
static void
fd_gossip_refresh_push_states( fd_gossip_t * glob, fd_pending_event_arg_t * arg ) {
  (void)arg;

  /* Try again in 20 sec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, glob->now + (long)20e9);
  if (ev) {
    ev->fun = fd_gossip_refresh_push_states;
  }

  /* Delete states which no longer have active peers */
  for (ulong i = 0; i < glob->push_states_cnt; ++i) {
    fd_push_state_t* s = glob->push_states[i];
    if (fd_active_table_query(glob->actives, &s->addr, NULL) == NULL) {
      fd_push_states_pool_ele_release(glob->push_states_pool, glob->push_states[i]);
      /* Replace with the one at the end */
      glob->push_states[i--] = glob->push_states[--(glob->push_states_cnt)];
    }
  }
  if (glob->push_states_cnt == FD_PUSH_LIST_MAX) {
    /* Delete the worst destination based prune count */
    fd_push_state_t * worst_s = glob->push_states[0];
    ulong worst_i = 0;
    for (ulong i = 1; i < glob->push_states_cnt; ++i) {
      fd_push_state_t* s = glob->push_states[i];
      if (s->drop_cnt > worst_s->drop_cnt) {
        worst_s = s;
        worst_i = i;
      }
    }
    fd_push_states_pool_ele_release(glob->push_states_pool, worst_s);
    /* Replace with the one at the end */
    glob->push_states[worst_i] = glob->push_states[--(glob->push_states_cnt)];
  }

  /* Add random actives as new pushers */
  int failcnt = 0;
  while (glob->push_states_cnt < FD_PUSH_LIST_MAX && failcnt < 5) {
    fd_active_elem_t * a = fd_gossip_random_active( glob );
    if( a == NULL ) break;

    for (ulong i = 0; i < glob->push_states_cnt; ++i) {
      fd_push_state_t* s = glob->push_states[i];
      if (fd_gossip_peer_addr_eq(&s->addr, &a->key))
        goto skipadd;
    }
    failcnt = 0;

    /* Build the pusher state */
    fd_push_state_t * s = fd_push_states_pool_ele_acquire(glob->push_states_pool);
    fd_memset(s, 0, sizeof(fd_push_state_t));
    fd_gossip_peer_addr_copy(&s->addr, &a->key);
    fd_hash_copy(&s->id, &a->id);
    for (ulong j = 0; j < FD_PRUNE_NUM_KEYS; ++j)
      s->prune_keys[j] = fd_rng_ulong(glob->rng);

    /* Encode an empty push msg template */
    fd_gossip_msg_t gmsg[1] = {0};
    fd_gossip_msg_new_disc(gmsg, fd_gossip_msg_enum_push_msg);
    fd_gossip_push_msg_t * push_msg = &gmsg->inner.push_msg;
    fd_hash_copy( &push_msg->pubkey, glob->public_key );
    fd_bincode_encode_ctx_t ctx;
    ctx.data = s->packet;
    ctx.dataend = s->packet + PACKET_DATA_SIZE;
    if ( fd_gossip_msg_encode( gmsg, &ctx ) ) {
      FD_LOG_ERR(("fd_gossip_msg_encode failed"));
      return;
    }
    s->packet_end_init = s->packet_end = (uchar *)ctx.data;

    glob->push_states[glob->push_states_cnt++] = s;
    break;

  skipadd:
    ++failcnt;
  }

  glob->metrics.active_push_destinations = glob->push_states_cnt;
  glob->metrics.refresh_push_states_failcnt = (ulong)failcnt;
}

/* Push the latest values */
static void
fd_gossip_push( fd_gossip_t * glob, fd_pending_event_arg_t * arg ) {
  (void)arg;

  /* Try again in 100 msec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, glob->now + (long)1e8);
  if (ev) {
    ev->fun = fd_gossip_push;
  }

  /* Push an updated version of my contact info into values */
  fd_gossip_push_updated_contact(glob);

  /* Iterate across recent values */
  ulong expire = FD_NANOSEC_TO_MILLI(glob->now) - FD_GOSSIP_PULL_TIMEOUT;
  while (glob->need_push_cnt > 0) {
    fd_hash_t * h = glob->need_push + ((glob->need_push_head++) & (FD_NEED_PUSH_MAX-1));
    glob->need_push_cnt--;

    fd_value_elem_t * msg = fd_value_table_query(glob->values, h, NULL);
    if (msg == NULL || msg->wallclock < expire)
      continue;

    /* Iterate across push states */
    ulong npush = 0;
    for (ulong i = 0; i < glob->push_states_cnt && npush < FD_PUSH_VALUE_MAX; ++i) {
      fd_push_state_t* s = glob->push_states[i];

      /* Apply the pruning bloom filter */
      int pass = 0;
      for (ulong j = 0; j < FD_PRUNE_NUM_KEYS; ++j) {
        ulong pos = fd_gossip_bloom_pos(&msg->origin, s->prune_keys[j], FD_PRUNE_NUM_BITS);
        ulong * j = s->prune_bits + (pos>>6U); /* divide by 64 */
        ulong bit = 1UL<<(pos & 63U);
        if (!(*j & bit)) {
          pass = 1;
          break;
        }
      }
      if (!pass) {
        s->drop_cnt++;
        glob->not_push_cnt++;
        continue;
      }
      glob->push_cnt++;
      npush++;
      glob->metrics.push_crds[ (uint)msg->data[sizeof(fd_signature_t)] ]++; /* discriminant */

      ulong * crds_len = (ulong *)(s->packet_end_init - sizeof(ulong));
      /* Add the value in already encoded form */
      if (s->packet_end + msg->datalen - s->packet > PACKET_DATA_SIZE) {
        /* Packet is getting too large. Flush it */
        ulong sz = (ulong)(s->packet_end - s->packet);
        glob->metrics.send_message[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ]++;
        fd_gossip_send_raw(glob, &s->addr, s->packet, sz);
        char tmp[100];
        FD_LOG_DEBUG(("push to %s size=%lu", fd_gossip_addr_str(tmp, sizeof(tmp), &s->addr), sz));
        s->packet_end = s->packet_end_init;
        *crds_len = 0;
      }
      fd_memcpy(s->packet_end, msg->data, msg->datalen);
      s->packet_end += msg->datalen;
      (*crds_len)++;
    }
  }

  /* Flush partially full packets */
  for (ulong i = 0; i < glob->push_states_cnt; ++i) {
    fd_push_state_t* s = glob->push_states[i];
    if (s->packet_end != s->packet_end_init) {
      ulong * crds_len = (ulong *)(s->packet_end_init - sizeof(ulong));
      ulong sz = (ulong)(s->packet_end - s->packet);
      fd_gossip_send_raw(glob, &s->addr, s->packet, sz);
      glob->metrics.send_message[ FD_METRICS_ENUM_GOSSIP_MESSAGE_V_PUSH_IDX ]++;
      char tmp[100];
      FD_LOG_DEBUG(("push to %s size=%lu", fd_gossip_addr_str(tmp, sizeof(tmp), &s->addr), sz));
      s->packet_end = s->packet_end_init;
      *crds_len = 0;
    }
  }
}

/* Publish an outgoing value. The source id and wallclock are set by this function */
static int
fd_gossip_push_value_nolock( fd_gossip_t * glob, fd_crds_data_t * data, fd_hash_t * key_opt ) {
#define INC_PUSH_CRDS_DROP_METRIC( REASON ) \
  glob->metrics.push_crds_drop_reason[ FD_CONCAT3( FD_METRICS_ENUM_CRDS_DROP_REASON_V_, REASON , _IDX ) ] += 1UL

  if ( FD_UNLIKELY( data->discriminant >= FD_KNOWN_CRDS_ENUM_MAX ) ) {
    INC_PUSH_CRDS_DROP_METRIC( UNKNOWN_DISCRIMINANT );
    return -1;
  }


  /* Wrap the data in a value stub. Sign it. */
  fd_crds_value_t crd;
  fd_memcpy(&crd.data, data, sizeof(fd_crds_data_t));
  fd_gossip_sign_crds_value(glob, &crd);

  /* Perform the value hash to get the value table key */
  uchar buf[PACKET_DATA_SIZE];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + PACKET_DATA_SIZE;
  if ( fd_crds_value_encode( &crd, &ctx ) ) {
    INC_PUSH_CRDS_DROP_METRIC( ENCODING_FAILED );
    FD_LOG_ERR(("fd_crds_value_encode failed"));
    return -1;
  }
  fd_sha256_t sha2[1];
  fd_sha256_init( sha2 );
  ulong datalen = (ulong)((uchar*)ctx.data - buf);
  fd_sha256_append( sha2, buf, datalen );
  fd_hash_t key;
  fd_sha256_fini( sha2, key.uc );
  if ( key_opt != NULL )
    fd_hash_copy( key_opt, &key );

  /* Store the value for later pushing/duplicate detection */
  fd_value_elem_t * msg = fd_value_table_query(glob->values, &key, NULL);
  if (msg != NULL) {
    /* Already have this value, which is strange!
       NOTE: This is a different list from duplicate crds values received
       from the network (see metrics.recv_crds_duplicate_message).
       Reaching this path implies a crds value generated internally was
       detected as a duplicate. */
    glob->metrics.push_crds_duplicate[ data->discriminant ] += 1UL;
    return -1;
  }
  if (fd_value_table_is_full(glob->values)) {
    INC_PUSH_CRDS_DROP_METRIC( TABLE_FULL );
    FD_LOG_DEBUG(("too many values"));
    return -1;
  }
  msg = fd_value_table_insert(glob->values, &key);
  msg->wallclock = FD_NANOSEC_TO_MILLI(glob->now); /* convert to ms */
  fd_hash_copy(&msg->origin, glob->public_key);

  /* We store the serialized form for convenience */
  fd_memcpy(msg->data, buf, datalen);
  msg->datalen = datalen;

  if (glob->need_push_cnt < FD_NEED_PUSH_MAX) {
    /* Remember that I need to push this value */
    ulong i = ((glob->need_push_head + (glob->need_push_cnt++)) & (FD_NEED_PUSH_MAX-1U));
    fd_hash_copy(glob->need_push + i, &key);
  } else {
    INC_PUSH_CRDS_DROP_METRIC( PUSH_QUEUE_FULL );
  }

  glob->metrics.push_crds_queue_cnt = glob->need_push_cnt;
  glob->metrics.push_crds[ data->discriminant ] += 1UL;
  return 0;

#undef INC_PUSH_CRDS_DROP_METRIC
}

int
fd_gossip_push_value( fd_gossip_t * glob, fd_crds_data_t * data, fd_hash_t * key_opt ) {
  fd_gossip_lock( glob );
  int rc = fd_gossip_push_value_nolock( glob, data, key_opt );
  fd_gossip_unlock( glob );
  return rc;
}

/* Periodically make prune messages */
static void
fd_gossip_make_prune( fd_gossip_t * glob, fd_pending_event_arg_t * arg ) {
  (void)arg;

  /* Try again in 30 sec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, glob->now + (long)30e9);
  if (ev) {
    ev->fun = fd_gossip_make_prune;
  }

  long expire = glob->now - (long)FD_GOSSIP_VALUE_EXPIRE*((long)1e6);
  for( fd_stats_table_iter_t iter = fd_stats_table_iter_init( glob->stats );
       !fd_stats_table_iter_done( glob->stats, iter );
       iter = fd_stats_table_iter_next( glob->stats, iter ) ) {
    fd_stats_elem_t * ele = fd_stats_table_iter_ele( glob->stats, iter );
    if (ele->last < expire) {
      /* Entry hasn't been updated for a long time */
      glob->metrics.make_prune_stale_entry += 1UL;
      fd_stats_table_remove( glob->stats, &ele->key );
      continue;
    }
    /* Look for high duplicate counts */
    fd_pubkey_t origins[8];
    ulong origins_cnt = 0;
    for (ulong i = 0; i < ele->dups_cnt; ++i) {
      if (ele->dups[i].cnt >= 20U) {
        fd_hash_copy(&origins[origins_cnt++], &ele->dups[i].origin);
        glob->metrics.make_prune_high_duplicates += 1UL;
      }
    }
    glob->metrics.make_prune_requested_origins = origins_cnt;
    if (origins_cnt == 0U)
      continue;
    /* Get the peer id */
    fd_peer_elem_t * peerval = fd_peer_table_query(glob->peers, &ele->key, NULL);
    /* Always clean up to restart the dup counter */
    fd_stats_table_remove( glob->stats, &ele->key );
    if (peerval == NULL)
      continue;

    char keystr[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( peerval->id.uc, NULL, keystr );
    FD_LOG_DEBUG(("sending prune request for %lu origins to %s", origins_cnt, keystr));

    /* Make a prune request */
    fd_gossip_msg_t gmsg;
    fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_prune_msg);
    fd_gossip_prune_msg_t * prune_msg = &gmsg.inner.prune_msg;
    fd_hash_copy(&prune_msg->data.pubkey, glob->public_key);
    prune_msg->data.prunes_len = origins_cnt;
    prune_msg->data.prunes = origins;;
    fd_hash_copy(&prune_msg->data.destination, &peerval->id);
    ulong wc = prune_msg->data.wallclock = FD_NANOSEC_TO_MILLI(glob->now);

    fd_gossip_prune_sign_data_t signdata;
    fd_hash_copy(&signdata.pubkey, glob->public_key);
    signdata.prunes_len = origins_cnt;
    signdata.prunes = origins;
    fd_hash_copy(&signdata.destination, &peerval->id);
    signdata.wallclock = wc;

    uchar buf[PACKET_DATA_SIZE];
    fd_bincode_encode_ctx_t ctx;
    ctx.data = buf;
    ctx.dataend = buf + PACKET_DATA_SIZE;
    if ( fd_gossip_prune_sign_data_encode( &signdata, &ctx ) ) {
      glob->metrics.make_prune_sign_data_encode_failed += 1UL;
      FD_LOG_ERR(("fd_gossip_prune_sign_data_encode failed"));
      return;
    }

    (*glob->sign_fun)( glob->sign_arg, prune_msg->data.signature.uc, buf, (ulong)((uchar*)ctx.data - buf), FD_KEYGUARD_SIGN_TYPE_ED25519 );

    fd_gossip_send(glob, &peerval->key, &gmsg);
  }
}

/* Periodically log status. Removes old peers as a side event. */
static void
fd_gossip_log_stats( fd_gossip_t * glob, fd_pending_event_arg_t * arg ) {
  (void)arg;

  /* Try again in 60 sec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, glob->now + (long)60e9);
  if (ev) {
    ev->fun = fd_gossip_log_stats;
  }

  if( glob->recv_pkt_cnt == 0 )
    FD_LOG_WARNING(("received no gossip packets!!"));
  else
    FD_LOG_INFO(("received %lu packets", glob->recv_pkt_cnt));
  glob->recv_pkt_cnt = 0;
  FD_LOG_INFO(("received %lu dup values and %lu new", glob->recv_dup_cnt, glob->recv_nondup_cnt));
  glob->recv_dup_cnt = glob->recv_nondup_cnt = 0;
  FD_LOG_INFO(("pushed %lu values and filtered %lu", glob->push_cnt, glob->not_push_cnt));
  glob->push_cnt = glob->not_push_cnt = 0;

  for( ulong i = 0UL; i<FD_KNOWN_CRDS_ENUM_MAX; i++ ) {
    FD_LOG_INFO(( "received values - type: %2lu, total: %12lu, dups: %12lu, bytes: %12lu", i, glob->msg_stats[i].total_cnt, glob->msg_stats[i].dups_cnt, glob->msg_stats[i].bytes_rx_cnt ));
  }

  int need_inactive = (glob->inactives_cnt == 0);

  ulong wc = FD_NANOSEC_TO_MILLI(glob->now);
  ulong expire = wc - 4U*FD_GOSSIP_VALUE_EXPIRE;
  for( fd_peer_table_iter_t iter = fd_peer_table_iter_init( glob->peers );
       !fd_peer_table_iter_done( glob->peers, iter );
       iter = fd_peer_table_iter_next( glob->peers, iter ) ) {
    fd_peer_elem_t * ele = fd_peer_table_iter_ele( glob->peers, iter );
    if (ele->wallclock < expire) {
      /* Peer hasn't been updated for a long time */
      fd_peer_table_remove( glob->peers, &ele->key );
      continue;
    }
    fd_active_elem_t * act = fd_active_table_query(glob->actives, &ele->key, NULL);
    char buf[100];
    char keystr[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( ele->id.uc, NULL, keystr );
    FD_LOG_DEBUG(("peer at %s id %s age %.3f %s",
                   fd_gossip_addr_str(buf, sizeof(buf), &ele->key),
                   keystr,
                   ((double)(wc - ele->wallclock))*0.001,
                   ((act != NULL && act->pongtime != 0) ? "(active)" : "")));
    if (need_inactive && act == NULL && glob->inactives_cnt < INACTIVES_MAX)
      fd_gossip_peer_addr_copy(glob->inactives + (glob->inactives_cnt++), &ele->key);
  }


  glob->metrics.gossip_peer_cnt[ FD_METRICS_ENUM_GOSSIP_PEER_STATE_V_TOTAL_IDX ]     = fd_peer_table_key_cnt( glob->peers );
  glob->metrics.gossip_peer_cnt[ FD_METRICS_ENUM_GOSSIP_PEER_STATE_V_ACTIVE_IDX ]    = fd_active_table_key_cnt( glob->actives );
  glob->metrics.gossip_peer_cnt[ FD_METRICS_ENUM_GOSSIP_PEER_STATE_V_INACTIVE_IDX ]  = (ulong)glob->inactives_cnt;
}

/* Set the current protocol time in nanosecs */
void
fd_gossip_settime( fd_gossip_t * glob, long ts ) {
  glob->now = ts;
}

/* Get the current protocol time in nanosecs */
long
fd_gossip_gettime( fd_gossip_t * glob ) {
  return glob->now;
}

/* Start timed events and other protocol behavior */
int
fd_gossip_start( fd_gossip_t * glob ) {
  fd_gossip_lock( glob );
  /* Start pulling and pinging on a timer */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, glob->now + (long)1e9);
  ev->fun = fd_gossip_random_pull;
  ev = fd_gossip_add_pending(glob, glob->now + (long)5e9);
  ev->fun = fd_gossip_random_ping;
  ev = fd_gossip_add_pending(glob, glob->now + (long)60e9);
  ev->fun = fd_gossip_log_stats;
  ev = fd_gossip_add_pending(glob, glob->now + (long)20e9);
  ev->fun = fd_gossip_refresh_push_states;
  ev = fd_gossip_add_pending(glob, glob->now + (long)1e8);
  ev->fun = fd_gossip_push;
  ev = fd_gossip_add_pending(glob, glob->now + (long)30e9);
  ev->fun = fd_gossip_make_prune;
  fd_gossip_unlock( glob );

  return 0;
}

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. */
int
fd_gossip_continue( fd_gossip_t * glob ) {
  fd_gossip_lock( glob );
  do {
    fd_pending_event_t * ev = fd_pending_heap_ele_peek_min( glob->event_heap, glob->event_pool );
    if (ev == NULL || ev->key > glob->now)
      break;
    fd_pending_event_t evcopy;
    fd_memcpy(&evcopy, ev, sizeof(evcopy));
    fd_pending_heap_ele_remove_min( glob->event_heap, glob->event_pool );
    fd_pending_pool_ele_release( glob->event_pool, ev );
    (*evcopy.fun)(glob, &evcopy.fun_arg);
  } while (1);
  fd_gossip_unlock( glob );
  return 0;
}

/* Pass a raw gossip packet into the protocol. msg_name is the unix socket address of the sender */
int
fd_gossip_recv_packet( fd_gossip_t * glob, uchar const * msg, ulong msglen, fd_gossip_peer_addr_t const * from ) {
  fd_gossip_lock( glob );
  FD_SCRATCH_SCOPE_BEGIN {
    glob->recv_pkt_cnt++;
    glob->metrics.recv_pkt_cnt++;
    /* Deserialize the message */
    fd_bincode_decode_ctx_t ctx = {
      .data    = msg,
      .dataend = msg + msglen,
    };

    ulong total_sz = 0UL;
    if( FD_UNLIKELY( fd_gossip_msg_decode_footprint( &ctx, &total_sz ) ) ) {
      glob->metrics.recv_pkt_corrupted_msg += 1UL;
      FD_LOG_WARNING(( "corrupt gossip message" ));
      fd_gossip_unlock( glob );
      return -1;
    }

    uchar * mem = fd_scratch_alloc( fd_gossip_msg_align(), total_sz );
    if( FD_UNLIKELY( !mem ) ) {
      FD_LOG_ERR(( "Unable to allocate memory for gossip msg" ));
    }

    fd_gossip_msg_t * gmsg = fd_gossip_msg_decode( mem, &ctx );

    if( FD_UNLIKELY( ctx.data != ctx.dataend ) ) {
      glob->metrics.recv_pkt_corrupted_msg += 1UL;
      FD_LOG_WARNING(( "corrupt gossip message" ));
      fd_gossip_unlock( glob );
      return -1;
    }

    char tmp[100];

    FD_LOG_DEBUG(( "recv msg type %u from %s", gmsg->discriminant, fd_gossip_addr_str( tmp, sizeof(tmp), from ) ));
    fd_gossip_recv( glob, from, gmsg );

    fd_gossip_unlock( glob );
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

ushort
fd_gossip_get_shred_version( fd_gossip_t const * glob ) {
  return glob->my_contact.ci->shred_version;
}

void
fd_gossip_set_stake_weights( fd_gossip_t * gossip,
                             fd_stake_weight_t const * stake_weights,
                             ulong stake_weights_cnt ) {
  if( stake_weights == NULL ) {
    FD_LOG_ERR(( "stake weights NULL" ));
  }

  if( stake_weights_cnt > MAX_STAKE_WEIGHTS ) {
    FD_LOG_ERR(( "num stake weights (%lu) is larger than max allowed stake weights", stake_weights_cnt ));
  }

  fd_gossip_lock( gossip );

  /* Clear out the table for new stake weights. */
  for ( fd_weights_table_iter_t iter = fd_weights_table_iter_init( gossip->weights );
        !fd_weights_table_iter_done( gossip->weights, iter);
        iter = fd_weights_table_iter_next( gossip->weights, iter ) ) {
    fd_weights_elem_t * e = fd_weights_table_iter_ele( gossip->weights, iter );
    fd_weights_table_remove( gossip->weights, &e->key );
  }

  for( ulong i = 0; i < stake_weights_cnt; ++i ) {
    if( !stake_weights[i].stake ) continue;
    fd_weights_elem_t * val = fd_weights_table_insert( gossip->weights, &stake_weights[i].key );
    // Weight is log2(stake)^2
    ulong w = (ulong)fd_ulong_find_msb( stake_weights[i].stake ) + 1;
    val->weight = w*w;
  }

  for( fd_active_table_iter_t iter = fd_active_table_iter_init( gossip->actives );
       !fd_active_table_iter_done( gossip->actives, iter );
       iter = fd_active_table_iter_next( gossip->actives, iter ) ) {
    fd_active_elem_t * ele = fd_active_table_iter_ele( gossip->actives, iter );
    fd_weights_elem_t const * val = fd_weights_table_query_const( gossip->weights, &ele->id, NULL );
    ele->weight = ( val == NULL ? 1UL : val->weight );
  }

  fd_gossip_unlock( gossip );
}

void
fd_gossip_set_entrypoints( fd_gossip_t *         gossip,
                           fd_ip4_port_t const * entrypoints,
                           ulong                 entrypoints_cnt ) {
  gossip->entrypoints_cnt = entrypoints_cnt;
  for( ulong i=0UL; i<entrypoints_cnt; i++ ) {
    FD_LOG_NOTICE(( "gossip initial peer - addr: " FD_IP4_ADDR_FMT ":%u",
      FD_IP4_ADDR_FMT_ARGS( entrypoints[i].addr ), fd_ushort_bswap( entrypoints[i].port ) ));
    fd_gossip_add_active_peer( gossip, &entrypoints[i] );
    gossip->entrypoints[i] = entrypoints[i];
  }
}

uint
fd_gossip_is_allowed_entrypoint( fd_gossip_t * gossip, fd_gossip_peer_addr_t * addr ) {
  for( ulong i = 0UL; i<gossip->entrypoints_cnt; i++) {
    if (fd_gossip_peer_addr_eq( addr, &gossip->entrypoints[i]) ) return 1;
  }
  return 0;
}
