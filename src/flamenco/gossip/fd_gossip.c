#define _GNU_SOURCE 1
#include "fd_gossip.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/net/fd_eth.h"
#include "../../util/rng/fd_rng.h"
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/random.h>

#pragma GCC diagnostic ignored "-Wstrict-aliasing"

/* Maximum size of a network packet */
#define PACKET_DATA_SIZE 1232
/* How long do we remember values (in millisecs) */
#define FD_GOSSIP_VALUE_EXPIRE ((ulong)(60e3))   /* 1 minute */
/* Max age that values can be pushed/pulled (in millisecs) */
#define FD_GOSSIP_PULL_TIMEOUT ((ulong)(15e3))   /* 15 seconds */
/* Max number of validators that can be actively pinged */
#define FD_ACTIVE_KEY_MAX (1<<8)
/* Max number of values that can be remembered */
#define FD_VALUE_KEY_MAX (1<<16)
/* Max number of pending timed events */
#define FD_PENDING_MAX (1<<9)
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

#define FD_NANOSEC_TO_MILLI(_ts_) ((ulong)(_ts_/1000000))

/* Test if two addresses are equal */
static int fd_gossip_peer_addr_eq( const fd_gossip_peer_addr_t * key1, const fd_gossip_peer_addr_t * key2 ) {
  FD_STATIC_ASSERT(sizeof(fd_gossip_peer_addr_t) == sizeof(ulong),"messed up size");
  return key1->l == key2->l;
}

/* Hash an address */
static ulong fd_gossip_peer_addr_hash( const fd_gossip_peer_addr_t * key, ulong seed ) {
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
    uchar * data;    /* Serialized form of value (bincode) including signature */
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
    uchar packet[FD_ETH_PAYLOAD_MAX]; /* Partially assembled packet containing a fd_gossip_push_msg_t */
    uchar * packet_end_init;       /* Initial end of the packet when there are zero values */
    uchar * packet_end;            /* Current end of the packet including values so far */
};
typedef struct fd_push_state fd_push_state_t;

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

/* Global data for gossip service */
struct fd_gossip {
    /* Concurrency lock */
    volatile ulong lock;
    /* Current time in nanosecs */
    long now;
    /* My public/private key */
    fd_pubkey_t * public_key;
    uchar * private_key;
    /* My gossip port address */
    fd_gossip_peer_addr_t my_addr;
    /* My official contact info in the gossip protocol */
    fd_gossip_contact_info_v1_t my_contact_info;
    /* Temporary contact info used while retrieving the shred version */
    fd_gossip_contact_info_v1_t tmp_contact_info;
    uchar tmp_private_key[32U];
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
    /* Table of crds values that we have received in the last 5 minutes, keys by hash */
    fd_value_elem_t * values;
    /* The last timestamp hash that we pushed our own contact info */
    long last_contact_time;
    fd_hash_t last_contact_key;
    /* Array of push destinations currently in use */
    fd_push_state_t * push_states[FD_PUSH_LIST_MAX];
    ulong push_states_cnt;
    /* Queue of values that need pushing */
    fd_hash_t * need_push;
    ulong need_push_head;
    ulong need_push_cnt;
    /* Table of receive statistics */
    fd_stats_elem_t * stats;
    /* Heap/queue of pending timed events */
    fd_pending_event_t * event_pool;
    fd_pending_heap_t * event_heap;
    /* Random number generator */
    fd_rng_t rng[1];
    /* RNG seed */
    ulong seed;
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
    /* Heap allocator */
    fd_valloc_t valloc;
    /* List of allowed entrypoints, used for shred version */
    ulong allowed_entrypoints_cnt;
    uint allowed_entrypoints[16];
};

ulong
fd_gossip_align ( void ) { return alignof(fd_gossip_t); }

ulong
fd_gossip_footprint( void ) { return sizeof(fd_gossip_t); }

void *
fd_gossip_new ( void * shmem, ulong seed, fd_valloc_t valloc ) { 
  fd_memset(shmem, 0, sizeof(fd_gossip_t));
  fd_gossip_t * glob = (fd_gossip_t *)shmem;
  glob->valloc = valloc;
  glob->seed = seed;
  void * shm = fd_valloc_malloc(valloc, fd_peer_table_align(), fd_peer_table_footprint(FD_PEER_KEY_MAX));
  glob->peers = fd_peer_table_join(fd_peer_table_new(shm, FD_PEER_KEY_MAX, seed));
  shm = fd_valloc_malloc(valloc, fd_active_table_align(), fd_active_table_footprint(FD_ACTIVE_KEY_MAX));
  glob->actives = fd_active_table_join(fd_active_table_new(shm, FD_ACTIVE_KEY_MAX, seed));
  glob->inactives = (fd_gossip_peer_addr_t*)fd_valloc_malloc(valloc, alignof(fd_gossip_peer_addr_t), INACTIVES_MAX*sizeof(fd_gossip_peer_addr_t));
  glob->need_push = (fd_hash_t*)fd_valloc_malloc(valloc, alignof(fd_hash_t), FD_NEED_PUSH_MAX*sizeof(fd_hash_t));
  shm = fd_valloc_malloc(valloc, fd_value_table_align(), fd_value_table_footprint(FD_VALUE_KEY_MAX));
  glob->values = fd_value_table_join(fd_value_table_new(shm, FD_VALUE_KEY_MAX, seed));
  glob->last_contact_time = 0;
  shm = fd_valloc_malloc(valloc, fd_pending_pool_align(), fd_pending_pool_footprint(FD_PENDING_MAX));
  glob->event_pool = fd_pending_pool_join(fd_pending_pool_new(shm, FD_PENDING_MAX));
  shm = fd_valloc_malloc(valloc, fd_pending_heap_align(), fd_pending_heap_footprint(FD_PENDING_MAX));
  glob->event_heap = fd_pending_heap_join(fd_pending_heap_new(shm, FD_PENDING_MAX));
  fd_rng_new(glob->rng, (uint)seed, 0UL);
  shm = fd_valloc_malloc(valloc, fd_stats_table_align(), fd_stats_table_footprint(FD_STATS_KEY_MAX));
  glob->stats = fd_stats_table_join(fd_stats_table_new(shm, FD_STATS_KEY_MAX, seed));
  glob->weights = NULL;
  return glob;
}

fd_gossip_t *
fd_gossip_join ( void * shmap ) { return (fd_gossip_t *)shmap; }

void *
fd_gossip_leave ( fd_gossip_t * join ) { return join; }

void *
fd_gossip_delete ( void * shmap, fd_valloc_t valloc ) {
  fd_gossip_t * glob = (fd_gossip_t *)shmap;
  fd_valloc_free(valloc, fd_peer_table_delete(fd_peer_table_leave(glob->peers)));
  fd_valloc_free(valloc, fd_active_table_delete(fd_active_table_leave(glob->actives)));
  fd_valloc_free(valloc, glob->inactives);
  fd_valloc_free(valloc, glob->need_push);
  for (ulong i = 0; i < glob->push_states_cnt; ++i)
    fd_valloc_free(valloc, glob->push_states[i]);
  for( fd_value_table_iter_t iter = fd_value_table_iter_init( glob->values );
       !fd_value_table_iter_done( glob->values, iter );
       iter = fd_value_table_iter_next( glob->values, iter ) ) {
    fd_value_elem_t * ele = fd_value_table_iter_ele( glob->values, iter );
    fd_valloc_free(valloc, ele->data);
  }
  fd_valloc_free(valloc, fd_value_table_delete(fd_value_table_leave(glob->values)));
  fd_valloc_free(valloc, fd_pending_pool_delete(fd_pending_pool_leave(glob->event_pool)));
  fd_valloc_free(valloc, fd_pending_heap_delete(fd_pending_heap_leave(glob->event_heap)));
  fd_valloc_free(valloc, fd_stats_table_delete(fd_stats_table_leave(glob->stats)));
  if( glob->weights )
    fd_valloc_free(valloc, fd_weights_table_delete(fd_weights_table_leave(glob->weights)));
  return glob;
}

static void
fd_gossip_lock( fd_gossip_t * gossip ) {
  for(;;) {
    if( FD_LIKELY( !FD_ATOMIC_CAS( &gossip->lock, 0UL, 1UL) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
}

static void
fd_gossip_unlock( fd_gossip_t * gossip ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( gossip->lock ) = 0UL;
}

/* Convert my style of address to solana style */
int
fd_gossip_to_soladdr( fd_gossip_socket_addr_t * dst, fd_gossip_peer_addr_t const * src ) {
  dst->port = ntohs(src->port);
  fd_gossip_ip_addr_new_disc(&dst->addr, fd_gossip_ip_addr_enum_ip4);
  dst->addr.inner.ip4 = src->addr;
  return 0;
}

/* Convert my style of address from solana style */
int
fd_gossip_from_soladdr(fd_gossip_peer_addr_t * dst, fd_gossip_socket_addr_t const * src ) {
  FD_STATIC_ASSERT(sizeof(fd_gossip_peer_addr_t) == sizeof(ulong),"messed up size");
  dst->l = 0;
  dst->port = htons(src->port);
  if (src->addr.discriminant == fd_gossip_ip_addr_enum_ip4) {
    dst->addr = src->addr.inner.ip4;
    return 0;
  } else {
    FD_LOG_ERR(("invalid address family"));
    return -1;
  }
}

/* Convert an address to a human readable string */
const char * fd_gossip_addr_str( char * dst, size_t dstlen, fd_gossip_peer_addr_t const * src ) {
  char tmp[INET_ADDRSTRLEN];
  snprintf(dst, dstlen, "%s:%u", inet_ntop(AF_INET, &src->addr, tmp, INET_ADDRSTRLEN), (uint)ntohs(src->port));
  return dst;
}

/* Set the gossip configuration */
int
fd_gossip_set_config( fd_gossip_t * glob, const fd_gossip_config_t * config ) {
  fd_gossip_lock( glob );
  
  char tmp[100];
  char keystr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( config->public_key->uc, NULL, keystr );
  FD_LOG_NOTICE(("configuring address %s id %s", fd_gossip_addr_str(tmp, sizeof(tmp), &config->my_addr), keystr));

  glob->public_key = config->public_key;
  glob->private_key = config->private_key;
  fd_hash_copy(&glob->my_contact_info.id, config->public_key);
  fd_gossip_peer_addr_copy(&glob->my_addr, &config->my_addr);
  fd_gossip_to_soladdr(&glob->my_contact_info.gossip, &config->my_addr);
  glob->my_contact_info.shred_version = config->shred_version;
  glob->deliver_fun = config->deliver_fun;
  glob->deliver_arg = config->deliver_arg;
  glob->send_fun = config->send_fun;
  glob->send_arg = config->send_arg;
  glob->sign_fun = config->sign_fun;
  glob->sign_arg = config->sign_arg;

  if (config->shred_version == 0U) {
    /* Configure temp identity needed to retrieve shred version */
    FD_TEST( 32UL == getrandom( glob->tmp_private_key, 32UL, 0 ) );
    fd_sha512_t sha[1];
    fd_ed25519_public_from_private(glob->tmp_contact_info.id.key, glob->tmp_private_key, sha);
    fd_gossip_to_soladdr(&glob->tmp_contact_info.gossip, &config->my_addr);

    fd_base58_encode_32( glob->tmp_contact_info.id.uc, NULL, keystr );
    FD_LOG_NOTICE(("configuring temporary id %s", keystr));
  }

  fd_gossip_unlock( glob );

  return 0;
}

int
fd_gossip_update_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * my_addr ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating address %s", fd_gossip_addr_str(tmp, sizeof(tmp), my_addr)));

  fd_gossip_lock( glob );
  fd_gossip_peer_addr_copy(&glob->my_addr, my_addr);
  fd_gossip_to_soladdr(&glob->my_contact_info.gossip, my_addr);
  fd_gossip_to_soladdr(&glob->tmp_contact_info.gossip, my_addr);
  fd_gossip_unlock( glob );
  return 0;
}

int
fd_gossip_update_repair_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * serve ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating repair service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), serve)));

  fd_gossip_lock( glob );
  fd_gossip_to_soladdr(&glob->my_contact_info.serve_repair, serve);
  fd_gossip_unlock( glob );
  return 0;
}

int
fd_gossip_update_tvu_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tvu, const fd_gossip_peer_addr_t * tvu_fwd ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating tvu service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), tvu)));
  // FIXME
  FD_LOG_NOTICE(("updating tvu_fwd service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), tvu_fwd)));

  fd_gossip_lock( glob );
  fd_gossip_to_soladdr(&glob->my_contact_info.tvu, tvu);
  fd_gossip_to_soladdr(&glob->my_contact_info.tvu_fwd, tvu_fwd);
  fd_gossip_unlock( glob );
  return 0;
}

int
fd_gossip_update_tpu_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tpu ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating tpu service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), tpu)));

  fd_gossip_lock( glob );
  fd_gossip_to_soladdr(&glob->my_contact_info.tpu, tpu);
  fd_gossip_unlock( glob );
  
  return 0;
}

int
fd_gossip_update_tpu_vote_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tpu_vote ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating tpu vote service address %s", fd_gossip_addr_str(tmp, sizeof(tmp), tpu_vote)));

  fd_gossip_lock( glob );
  fd_gossip_to_soladdr(&glob->my_contact_info.tpu_vote, tpu_vote);
  fd_gossip_unlock( glob );
  
  return 0;
}

void
fd_gossip_set_shred_version( fd_gossip_t * glob, ushort shred_version ) {
  glob->my_contact_info.shred_version = shred_version;
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
  if ( sz > PACKET_DATA_SIZE )
    FD_LOG_ERR(("sending oversized packet, size=%lu", sz));
  fd_gossip_unlock( glob );
  (*glob->send_fun)(data, sz, dest, glob->send_arg);
  fd_gossip_lock( glob );
}

/* Send a gossip message to an address */
static void
fd_gossip_send( fd_gossip_t * glob, const fd_gossip_peer_addr_t * dest, fd_gossip_msg_t * gmsg ) {
  /* Encode the data */
  uchar buf[FD_ETH_PAYLOAD_MAX];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
  if ( fd_gossip_msg_encode( gmsg, &ctx ) ) {
    FD_LOG_WARNING(("fd_gossip_msg_encode failed"));
    return;
  }
  size_t sz = (size_t)((const uchar *)ctx.data - buf);
  fd_gossip_send_raw( glob, dest, buf, sz);
  // char tmp[100];
  // if ( gmsg->discriminant == 0) {
  //   FD_LOG_WARNING(("sent msg type %d to %s size=%lu", gmsg->discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), dest), sz));
  //   FD_LOG_HEXDUMP_WARNING(("dump: ", buf, sz));
  // }
}

/* Initiate the ping/pong protocol to a validator address */
static void
fd_gossip_make_ping( fd_gossip_t * glob, fd_pending_event_arg_t * arg ) {
  /* Update the active table where we track the state of the ping/pong
     protocol */
  fd_gossip_peer_addr_t * key = &arg->key;
  fd_active_elem_t * val = fd_active_table_query(glob->actives, key, NULL);
  if (val == NULL) {
    if (fd_active_table_is_full(glob->actives))
      return;
    val = fd_active_table_insert(glob->actives, key);
    fd_active_new_value(val);
  } else {
    if (val->pongtime != 0)
      /* Success */
      return;
    if (val->pingcount++ >= 50U) {
      /* Give up. This is a bad peer. */
      fd_active_table_remove(glob->actives, key);
      fd_peer_table_remove(glob->peers, key);
      return;
    }
  }
  val->pingtime = glob->now;
  /* Generate a new token when we start a fresh round of pinging */
  if (val->pingcount == 1U) {
    for ( ulong i = 0; i < FD_HASH_FOOTPRINT / sizeof(ulong); ++i )
      val->pingtoken.ul[i] = fd_rng_ulong(glob->rng);
  }

  /* Keep pinging until we succeed */
  fd_pending_event_t * ev = fd_gossip_add_pending( glob, glob->now + (long)2e8 /* 200 ms */ );
  if (ev != NULL) {
    ev->fun = fd_gossip_make_ping;
    fd_gossip_peer_addr_copy(&ev->fun_arg.key, key);
  }

  fd_pubkey_t * public_key = ( glob->my_contact_info.shred_version == 0U ? &glob->tmp_contact_info.id : glob->public_key );

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
  if (glob->my_contact_info.shred_version == 0U) {
    uchar * private_key = glob->tmp_private_key;
    fd_sha512_t sha[1];
    fd_ed25519_sign( /* sig */ ping->signature.uc,
                    /* msg */ ping->token.uc,
                    /* sz  */ 32UL,
                    /* public_key  */ public_key->key,
                    /* private_key */ private_key,
                    sha );
  } else {
    (*glob->sign_fun)(glob->sign_arg, ping->signature.uc, pre_image, FD_PING_PRE_IMAGE_SZ);
  }
  
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
    FD_LOG_WARNING(("received ping with invalid signature"));
    return;
  }

  /* Build a pong message */
  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_pong);
  fd_gossip_ping_t * pong = &gmsg.inner.pong;

  fd_pubkey_t * public_key = ( glob->my_contact_info.shred_version == 0U ? &glob->tmp_contact_info.id : glob->public_key );

  fd_hash_copy( &pong->from, public_key );

  uchar pre_image[FD_PING_PRE_IMAGE_SZ];
  fd_memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  fd_memcpy( pre_image+16UL, ping->token.uc, 32UL);

  /* Generate response hash token */
  fd_sha256_hash( pre_image, FD_PING_PRE_IMAGE_SZ, &pong->token );

  /* Sign it */
  if (glob->my_contact_info.shred_version == 0U) {
    uchar * private_key = glob->tmp_private_key;
    fd_ed25519_sign( /* sig */ pong->signature.uc,
                     /* msg */ pong->token.uc,
                     /* sz  */ 32UL,
                     /* public_key  */ public_key->key,
                     /* private_key */ private_key,
                     sha2 );
  } else {
    (*glob->sign_fun)(glob->sign_arg, pong->signature.uc, pre_image, FD_PING_PRE_IMAGE_SZ);
  }

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
  default:
    return;
  }
  fd_pubkey_t * public_key = ( glob->my_contact_info.shred_version == 0U ? &glob->tmp_contact_info.id : glob->public_key );
  fd_hash_copy(pubkey, public_key);
  *wallclock = FD_NANOSEC_TO_MILLI(glob->now); /* convert to ms */

  /* Sign it */
  uchar buf[FD_ETH_PAYLOAD_MAX];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
  if ( fd_crds_data_encode( &crd->data, &ctx ) ) {
    FD_LOG_WARNING(("fd_crds_data_encode failed"));
    return;
  }

  if (glob->my_contact_info.shred_version == 0U) {
    uchar * private_key = glob->tmp_private_key;
    fd_sha512_t sha[1];
    fd_ed25519_sign( /* sig */ crd->signature.uc,
                   /* msg */ buf,
                   /* sz  */ (ulong)((uchar*)ctx.data - buf),
                   /* public_key  */ public_key->key,
                   /* private_key */ private_key,
                   sha );
  } else {
    (*glob->sign_fun)(glob->sign_arg, crd->signature.uc, buf, (ulong)((uchar*)ctx.data - buf));
  }
}

/* Convert a hash to a bloom filter bit position */
static ulong
fd_gossip_bloom_pos( fd_hash_t * hash, ulong key, ulong nbits) {
  for ( ulong i = 0; i < 32U; ++i) {
    key ^= (ulong)(hash->uc[i]);
    key *= 1099511628211UL;
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
    if (ele->pongtime == 0) {
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
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, glob->now + (long)5e9);
  if (ev) {
    ev->fun = fd_gossip_random_pull;
  }

  /* Pick a random partner */
  fd_active_elem_t * ele = fd_gossip_random_active(glob);
  if (ele == NULL)
    return;

  /* Compute the number of packets needed for all the bloom filter parts */
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
  FD_LOG_DEBUG(("making bloom filter for %lu items with %lu packets and %lu keys %g error", nitems, npackets, nkeys, e));

  /* Generate random keys */
  ulong keys[FD_BLOOM_MAX_KEYS];
  for (ulong i = 0; i < nkeys; ++i)
    keys[i] = fd_rng_ulong(glob->rng);
  /* Set all the bits */
  ulong num_bits_set[FD_BLOOM_MAX_PACKETS];
  for (ulong i = 0; i < npackets; ++i)
    num_bits_set[i] = 0;
#define CHUNKSIZE (FD_BLOOM_NUM_BITS/64U)
  ulong bits[CHUNKSIZE * FD_BLOOM_MAX_PACKETS];
  fd_memset(bits, 0, CHUNKSIZE*8U*npackets);
  ulong expire = FD_NANOSEC_TO_MILLI(glob->now) - FD_GOSSIP_VALUE_EXPIRE;
  for( fd_value_table_iter_t iter = fd_value_table_iter_init( glob->values );
       !fd_value_table_iter_done( glob->values, iter );
       iter = fd_value_table_iter_next( glob->values, iter ) ) {
    fd_value_elem_t * ele = fd_value_table_iter_ele( glob->values, iter );
    fd_hash_t * hash = &(ele->key);
    /* Purge expired values */
    if (ele->wallclock < expire) {
      fd_valloc_free( glob->valloc, ele->data );
      fd_value_table_remove( glob->values, hash );
      continue;
    }
    /* Choose which filter packet based on the high bits in the hash */
    ulong index = (nmaskbits == 0 ? 0UL : ( hash->ul[0] >> (64U - nmaskbits) ));
    ulong * chunk = bits + (index*CHUNKSIZE);
    for (ulong i = 0; i < nkeys; ++i) {
      ulong pos = fd_gossip_bloom_pos(hash, keys[i], FD_BLOOM_NUM_BITS);
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

  /* The "value" in the request is always my own contact info */
  fd_crds_value_t * value = &req->value;
  fd_crds_data_new_disc(&value->data, fd_crds_data_enum_contact_info_v1);
  fd_gossip_contact_info_v1_t * ci = &value->data.inner.contact_info_v1;
  if (glob->my_contact_info.shred_version == 0U)
    fd_memcpy(ci, &glob->tmp_contact_info, sizeof(fd_gossip_contact_info_v1_t));
  else
    fd_memcpy(ci, &glob->my_contact_info, sizeof(fd_gossip_contact_info_v1_t));
  fd_gossip_sign_crds_value(glob, value);

  for (uint i = 0; i < npackets; ++i) {
    /* Update the filter mask specific part */
    filter->mask = (nmaskbits == 0 ? ~0UL : ((i << (64U - nmaskbits)) | (~0UL >> nmaskbits)));
    filter->filter.num_bits_set = num_bits_set[i];
    bitvec->bits.vec = bits + (i*CHUNKSIZE);
    fd_gossip_send(glob, &ele->key, &gmsg);
  }
}

/* Handle a pong response */
static void
fd_gossip_handle_pong( fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_gossip_ping_t const * pong ) {
  fd_active_elem_t * val = fd_active_table_query(glob->actives, from, NULL);
  if (val == NULL) {
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
    FD_LOG_WARNING(("received pong with invalid signature"));
    return;
  }

  val->pongtime = glob->now;
  fd_hash_copy(&val->id, &pong->from);

  /* Remember that this is a good peer */
  fd_peer_elem_t * peerval = fd_peer_table_query(glob->peers, from, NULL);
  if (peerval == NULL) {
    if (fd_peer_table_is_full(glob->peers)) {
      FD_LOG_DEBUG(("too many peers"));
      return;
    }
    peerval = fd_peer_table_insert(glob->peers, from);
    peerval->stake = 0;
  }
  peerval->wallclock = FD_NANOSEC_TO_MILLI(glob->now); /* In millisecs */
  fd_hash_copy(&peerval->id, &pong->from);

  if( glob->weights ) {
    fd_weights_elem_t const * val2 = fd_weights_table_query_const( glob->weights, &val->id, NULL );
    val->weight = ( val2 == NULL ? 1UL : val2->weight );
  } else {
    val->weight = 1UL;
  }
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
  if (cnt == 0)
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

/* Process an incoming crds value */
static void
fd_gossip_recv_crds_value(fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_pubkey_t * pubkey, fd_crds_value_t* crd) {
  /* Verify the signature */
  ulong wallclock;
  switch (crd->data.discriminant) {
  case fd_crds_data_enum_contact_info_v1:
    pubkey = &crd->data.inner.contact_info_v1.id;
    wallclock = crd->data.inner.contact_info_v1.wallclock;
    break;
  case fd_crds_data_enum_vote:
    pubkey = &crd->data.inner.vote.from;
    wallclock = crd->data.inner.vote.wallclock;
    break;
  case fd_crds_data_enum_lowest_slot:
    pubkey = &crd->data.inner.lowest_slot.from;
    wallclock = crd->data.inner.lowest_slot.wallclock;
    break;
  case fd_crds_data_enum_snapshot_hashes:
    pubkey = &crd->data.inner.snapshot_hashes.from;
    wallclock = crd->data.inner.snapshot_hashes.wallclock;
    break;
  case fd_crds_data_enum_accounts_hashes:
    pubkey = &crd->data.inner.accounts_hashes.from;
    wallclock = crd->data.inner.accounts_hashes.wallclock;
    break;
  case fd_crds_data_enum_epoch_slots:
    pubkey = &crd->data.inner.epoch_slots.from;
    wallclock = crd->data.inner.epoch_slots.wallclock;
    break;
  case fd_crds_data_enum_version_v1:
    pubkey = &crd->data.inner.version_v1.from;
    wallclock = crd->data.inner.version_v1.wallclock;
    break;
  case fd_crds_data_enum_version_v2:
    pubkey = &crd->data.inner.version_v2.from;
    wallclock = crd->data.inner.version_v2.wallclock;
    break;
  case fd_crds_data_enum_node_instance:
    pubkey = &crd->data.inner.node_instance.from;
    wallclock = crd->data.inner.node_instance.wallclock;
    break;
  case fd_crds_data_enum_duplicate_shred:
    pubkey = &crd->data.inner.duplicate_shred.from;
    wallclock = crd->data.inner.duplicate_shred.wallclock;
    break;
  case fd_crds_data_enum_incremental_snapshot_hashes:
    pubkey = &crd->data.inner.incremental_snapshot_hashes.from;
    wallclock = crd->data.inner.incremental_snapshot_hashes.wallclock;
    break;
  default:
    wallclock = FD_NANOSEC_TO_MILLI(glob->now); /* In millisecs */
    break;
  }
  if (memcmp(pubkey->uc, glob->public_key->uc, 32U) == 0 ||
      memcmp(pubkey->uc, glob->tmp_contact_info.id.uc, 32U) == 0)
    /* Ignore my own messages */
    return;
  uchar buf[FD_ETH_PAYLOAD_MAX];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
  if ( fd_crds_data_encode( &crd->data, &ctx ) ) {
    FD_LOG_ERR(("fd_crds_data_encode failed"));
    return;
  }
  fd_sha512_t sha[1];
  if (fd_ed25519_verify( /* msg */ buf,
                         /* sz  */ (ulong)((uchar*)ctx.data - buf),
                         /* sig */ crd->signature.uc,
                         /* public_key */ pubkey->uc,
                         sha )) {
    FD_LOG_DEBUG(("received crds_value with invalid signature"));
    return;
  }

  /* Perform the value hash to get the value table key */
  ctx.data = buf;
  ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
  if ( fd_crds_value_encode( crd, &ctx ) ) {
    FD_LOG_ERR(("fd_crds_value_encode failed"));
    return;
  }
  fd_sha256_t sha2[1];
  fd_sha256_init( sha2 );
  ulong datalen = (ulong)((uchar*)ctx.data - buf);
  fd_sha256_append( sha2, buf, datalen );
  fd_hash_t key;
  fd_sha256_fini( sha2, key.uc );

  fd_value_elem_t * msg = fd_value_table_query(glob->values, &key, NULL);
  if (msg != NULL) {
    /* Already have this value */
    glob->recv_dup_cnt++;
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
        for (ulong i = 0; i < val->dups_cnt; ++i)
          if (fd_hash_eq(&val->dups[i].origin, pubkey)) {
            val->dups[i].cnt++;
            goto found_origin;
          }
        if (val->dups_cnt < 8) {
          ulong i = val->dups_cnt++;
          fd_hash_copy(&val->dups[i].origin, pubkey);
          val->dups[i].cnt = 1;
        }
        found_origin: ;
      }
    }
    return;
  }

  /* Store the value for later pushing/duplicate detection */
  glob->recv_nondup_cnt++;
  if (fd_value_table_is_full(glob->values)) {
    FD_LOG_DEBUG(("too many values"));
    return;
  }
  msg = fd_value_table_insert(glob->values, &key);
  msg->wallclock = wallclock;
  fd_hash_copy(&msg->origin, pubkey);
  /* We store the serialized form for convenience */
  msg->data = fd_valloc_malloc(glob->valloc, 1U, datalen);
  fd_memcpy(msg->data, buf, datalen);
  msg->datalen = datalen;

  if (glob->need_push_cnt < FD_NEED_PUSH_MAX) {
    /* Remember that I need to push this value */
    ulong i = ((glob->need_push_head + (glob->need_push_cnt++)) & (FD_NEED_PUSH_MAX-1U));
    fd_hash_copy(glob->need_push + i, &key);
  }

  if (crd->data.discriminant == fd_crds_data_enum_contact_info_v1) {
    fd_gossip_contact_info_v1_t * info = &crd->data.inner.contact_info_v1;
    if (info->gossip.port != 0) {
      /* Remember the peer */
      fd_gossip_peer_addr_t pkey;
      fd_memset(&pkey, 0, sizeof(pkey));
      fd_gossip_from_soladdr(&pkey, &info->gossip);
      fd_peer_elem_t * val = fd_peer_table_query(glob->peers, &pkey, NULL);
      if (val == NULL) {
        if (fd_peer_table_is_full(glob->peers)) {
          FD_LOG_DEBUG(("too many peers"));
        } else {
          val = fd_peer_table_insert(glob->peers, &pkey);
          if (glob->inactives_cnt < INACTIVES_MAX &&
              fd_active_table_query(glob->actives, &pkey, NULL) == NULL) {
            /* Queue this peer for later pinging */
            fd_gossip_peer_addr_copy(glob->inactives + (glob->inactives_cnt++), &pkey);
          }
        }
      }
      if (val != NULL) {
        val->wallclock = wallclock;
        val->stake = 0;
        fd_hash_copy(&val->id, &info->id);
      }
    }
    
    if (glob->my_contact_info.shred_version == 0U && fd_gossip_is_allowed_entrypoint( glob, crd->data.inner.contact_info_v1.gossip.addr.inner.ip4 )) {
      FD_LOG_NOTICE(("using shred version %lu", (ulong)crd->data.inner.contact_info_v1.shred_version));
      glob->my_contact_info.shred_version = crd->data.inner.contact_info_v1.shred_version;
    }
  }

  /* Deliver the data upstream */
  fd_gossip_unlock( glob );
  (*glob->deliver_fun)(&crd->data, glob->deliver_arg);
  fd_gossip_lock( glob );
}

/* Handle a prune request from somebody else */
static void
fd_gossip_handle_prune(fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_gossip_prune_msg_t * msg) {
  (void)from;

  /* Confirm the message is for me */
  if (memcmp(msg->data.destination.uc, glob->public_key->uc, 32U) != 0)
    return;

  /* Verify the signature. This is hacky for prune messages */
  fd_gossip_prune_sign_data_t signdata;
  signdata.pubkey = msg->data.pubkey;
  signdata.prunes_len = msg->data.prunes_len;
  signdata.prunes = msg->data.prunes;
  signdata.destination = msg->data.destination;
  signdata.wallclock = msg->data.wallclock;

  uchar buf[FD_ETH_PAYLOAD_MAX];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
  if ( fd_gossip_prune_sign_data_encode( &signdata, &ctx ) ) {
    FD_LOG_ERR(("fd_gossip_prune_sign_data_encode failed"));
    return;
  }
  fd_sha512_t sha[1];
  if (fd_ed25519_verify( /* msg */ buf,
                         /* sz  */ (ulong)((uchar*)ctx.data - buf),
                         /* sig */ msg->data.signature.uc,
                         /* public_key */ msg->pubkey.uc,
                         sha )) {
    FD_LOG_WARNING(("received prune_msg with invalid signature"));
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
  if (glob->my_contact_info.shred_version == 0U)
    return;
  /* Update every 1 secs */
  if (glob->now - glob->last_contact_time < (long)1e9)
    return;

  if (glob->last_contact_time != 0) {
    /* Remove the old value */
    fd_value_elem_t * ele = fd_value_table_query(glob->values, &glob->last_contact_key, NULL);
    if (ele != NULL) {
      fd_valloc_free( glob->valloc, ele->data );
      fd_value_table_remove( glob->values, &glob->last_contact_key );
    }
  }
  
  glob->last_contact_time = glob->now;

  fd_crds_data_t crd;
  fd_crds_data_new_disc(&crd, fd_crds_data_enum_contact_info_v1);
  fd_gossip_contact_info_v1_t * ci = &crd.inner.contact_info_v1;
  fd_memcpy(ci, &glob->my_contact_info, sizeof(fd_gossip_contact_info_v1_t));

  fd_gossip_push_value_nolock(glob, &crd, &glob->last_contact_key);
}

/* Respond to a pull request */
static void
fd_gossip_handle_pull_req(fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_gossip_pull_req_t * msg) {
  fd_active_elem_t * val = fd_active_table_query(glob->actives, from, NULL);
  if (val == NULL || val->pongtime == 0) {
    /* Ping new peers before responding to requests */
    if (fd_pending_pool_free( glob->event_pool ) < 100U)
      return;
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

  uchar buf[FD_ETH_PAYLOAD_MAX];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
  if ( fd_gossip_msg_encode( &gmsg, &ctx ) ) {
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
      char tmp[100];
      FD_LOG_DEBUG(("sent msg type %d to %s size=%lu", gmsg.discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), from), sz));
      ++npackets;
      newend = (uchar *)ctx.data;
      *crds_len = 0;
    }
    fd_memcpy(newend, ele->data, ele->datalen);
    newend += ele->datalen;
    (*crds_len)++;
  }

  /* Flush final packet */
  if (newend > (uchar *)ctx.data) {
    ulong sz = (ulong)(newend - buf);
    fd_gossip_send_raw(glob, from, buf, sz);
    char tmp[100];
    FD_LOG_DEBUG(("sent msg type %d to %s size=%lu", gmsg.discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), from), sz));
    ++npackets;
  }

  if (misses)
    FD_LOG_DEBUG(("responded to pull request with %lu values in %u packets (%lu filtered out)", misses, npackets, hits));
}

/* Handle any gossip message */
static void
fd_gossip_recv(fd_gossip_t * glob, const fd_gossip_peer_addr_t * from, fd_gossip_msg_t * gmsg) {
  switch (gmsg->discriminant) {
  case fd_gossip_msg_enum_pull_req:
    fd_gossip_handle_pull_req(glob, from, &gmsg->inner.pull_req);
    break;
  case fd_gossip_msg_enum_pull_resp: {
    fd_gossip_pull_resp_t * pull_resp = &gmsg->inner.pull_resp;
    for (ulong i = 0; i < pull_resp->crds_len; ++i)
      fd_gossip_recv_crds_value(glob, NULL, &pull_resp->pubkey, pull_resp->crds + i);
    break;
  }
  case fd_gossip_msg_enum_push_msg: {
    fd_gossip_push_msg_t * push_msg = &gmsg->inner.push_msg;
    for (ulong i = 0; i < push_msg->crds_len; ++i)
      fd_gossip_recv_crds_value(glob, from, &push_msg->pubkey, push_msg->crds + i);
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
fd_gossip_add_active_peer( fd_gossip_t * glob, fd_gossip_peer_addr_t * addr ) {
  fd_gossip_lock( glob );
  fd_active_elem_t * val = fd_active_table_query(glob->actives, addr, NULL);
  if (val == NULL) {
    if (fd_active_table_is_full(glob->actives)) {
      FD_LOG_WARNING(("too many actives"));
      fd_gossip_unlock( glob );
      return -1;
    }
    val = fd_active_table_insert(glob->actives, addr);
    fd_active_new_value(val);
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
      fd_valloc_free(glob->valloc, s);
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
    fd_valloc_free(glob->valloc, worst_s);
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
    fd_push_state_t * s = (fd_push_state_t *)fd_valloc_malloc(glob->valloc, alignof(fd_push_state_t), sizeof(fd_push_state_t));
    fd_memset(s, 0, sizeof(fd_push_state_t));
    fd_gossip_peer_addr_copy(&s->addr, &a->key);
    fd_hash_copy(&s->id, &a->id);
    for (ulong j = 0; j < FD_PRUNE_NUM_KEYS; ++j)
      s->prune_keys[j] = fd_rng_ulong(glob->rng);

    /* Encode an empty push msg template */
    fd_gossip_msg_t gmsg;
    fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_push_msg);
    fd_gossip_push_msg_t * push_msg = &gmsg.inner.push_msg;
    fd_hash_copy( &push_msg->pubkey, glob->public_key );
    fd_bincode_encode_ctx_t ctx;
    ctx.data = s->packet;
    ctx.dataend = s->packet + FD_ETH_PAYLOAD_MAX;
    if ( fd_gossip_msg_encode( &gmsg, &ctx ) ) {
      FD_LOG_WARNING(("fd_gossip_msg_encode failed"));
      return;
    }
    s->packet_end_init = s->packet_end = (uchar *)ctx.data;

    glob->push_states[glob->push_states_cnt++] = s;
    break;

  skipadd:
    ++failcnt;
  }
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

      ulong * crds_len = (ulong *)(s->packet_end_init - sizeof(ulong));
      /* Add the value in already encoded form */
      if (s->packet_end + msg->datalen - s->packet > PACKET_DATA_SIZE) {
        /* Packet is getting too large. Flush it */
        ulong sz = (ulong)(s->packet_end - s->packet);
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
  /* Wrap the data in a value stub. Sign it. */
  fd_crds_value_t crd;
  fd_memcpy(&crd.data, data, sizeof(fd_crds_data_t));
  fd_gossip_sign_crds_value(glob, &crd);

  /* Perform the value hash to get the value table key */
  uchar buf[FD_ETH_PAYLOAD_MAX];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
  if ( fd_crds_value_encode( &crd, &ctx ) ) {
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
    /* Already have this value, which is strange! */
    return -1;
  }
  if (fd_value_table_is_full(glob->values)) {
    FD_LOG_DEBUG(("too many values"));
    return -1;
  }
  msg = fd_value_table_insert(glob->values, &key);
  msg->wallclock = FD_NANOSEC_TO_MILLI(glob->now); /* convert to ms */
  fd_hash_copy(&msg->origin, glob->public_key);
  /* We store the serialized form for convenience */
  msg->data = fd_valloc_malloc(glob->valloc, 1U, datalen);
  fd_memcpy(msg->data, buf, datalen);
  msg->datalen = datalen;

  if (glob->need_push_cnt < FD_NEED_PUSH_MAX) {
    /* Remember that I need to push this value */
    ulong i = ((glob->need_push_head + (glob->need_push_cnt++)) & (FD_NEED_PUSH_MAX-1U));
    fd_hash_copy(glob->need_push + i, &key);
  }
  return 0;
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
      fd_stats_table_remove( glob->stats, &ele->key );
      continue;
    }
    /* Look for high duplicate counts */
    fd_pubkey_t origins[8];
    ulong origins_cnt = 0;
    for (ulong i = 0; i < ele->dups_cnt; ++i) {
      if (ele->dups[i].cnt >= 20U)
        fd_hash_copy(&origins[origins_cnt++], &ele->dups[i].origin);
    }
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
    FD_LOG_NOTICE(("sending prune request for %lu origins to %s", origins_cnt, keystr));

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
    signdata.prunes = origins;;
    fd_hash_copy(&signdata.destination, &peerval->id);
    signdata.wallclock = wc;

    uchar buf[FD_ETH_PAYLOAD_MAX];
    fd_bincode_encode_ctx_t ctx;
    ctx.data = buf;
    ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
    if ( fd_gossip_prune_sign_data_encode( &signdata, &ctx ) ) {
      FD_LOG_ERR(("fd_gossip_prune_sign_data_encode failed"));
      return;
    }

    (*glob->sign_fun)(glob->sign_arg, prune_msg->data.signature.uc, buf, (ulong)((uchar*)ctx.data - buf));

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

  FD_LOG_NOTICE(("received %lu dup values and %lu new", glob->recv_dup_cnt, glob->recv_nondup_cnt));
  glob->recv_dup_cnt = glob->recv_nondup_cnt = 0;
  FD_LOG_NOTICE(("pushed %lu values and filtered %lu", glob->push_cnt, glob->not_push_cnt));
  glob->push_cnt = glob->not_push_cnt = 0;

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
  /* Deserialize the message */
  fd_gossip_msg_t gmsg;
  fd_bincode_decode_ctx_t ctx;
  ctx.data    = msg;
  ctx.dataend = msg + msglen;
  ctx.valloc  = glob->valloc;
  if (fd_gossip_msg_decode(&gmsg, &ctx)) {
    FD_LOG_WARNING(("corrupt gossip message"));
    fd_gossip_unlock( glob );
    return -1;
  }
  if (ctx.data != ctx.dataend) {
    FD_LOG_WARNING(("corrupt gossip message"));
    fd_gossip_unlock( glob );
    return -1;
  }

  char tmp[100];

  FD_LOG_DEBUG(("recv msg type %d from %s", gmsg.discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), from)));
  fd_gossip_recv(glob, from, &gmsg);

  fd_bincode_destroy_ctx_t ctx2;
  ctx2.valloc = glob->valloc;
  fd_gossip_msg_destroy(&gmsg, &ctx2);

  fd_gossip_unlock( glob );
  return 0;
}

ushort
fd_gossip_get_shred_version( fd_gossip_t const * glob ) {
  return glob->my_contact_info.shred_version;
}

void 
fd_gossip_set_stake_weights( fd_gossip_t * gossip, 
                             fd_stake_weight_t const * stake_weights,
                             ulong stake_weights_cnt ) {
  if( stake_weights == NULL ) {
    FD_LOG_ERR(( "stake weights NULL" ));
  }

  fd_gossip_lock( gossip );

  if( gossip->weights )
    fd_valloc_free(gossip->valloc, fd_weights_table_delete(fd_weights_table_leave(gossip->weights)));
  void * shm = fd_valloc_malloc(gossip->valloc, fd_weights_table_align(), fd_weights_table_footprint(stake_weights_cnt));
  gossip->weights = fd_weights_table_join(fd_weights_table_new(shm, stake_weights_cnt, gossip->seed));
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
fd_gossip_set_allowed_entrypoints( fd_gossip_t * gossip,
                                   uint allowed_entrypoints[static 16], 
                                   ulong allowed_entrypoints_cnt ) {
  gossip->allowed_entrypoints_cnt = allowed_entrypoints_cnt;
  for( ulong i = 0UL; i<allowed_entrypoints_cnt; i++) {
    gossip->allowed_entrypoints[i] = allowed_entrypoints[i];
  }
}

uint
fd_gossip_is_allowed_entrypoint( fd_gossip_t * gossip, uint entrypoint ) {
  for( ulong i=0UL; i<gossip->allowed_entrypoints_cnt; i++ ) {
    if( entrypoint == gossip->allowed_entrypoints[i] ) {
      return 1;
    }
  }
  return 0;
}
