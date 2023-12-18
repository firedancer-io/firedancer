#define _GNU_SOURCE 1
#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/net/fd_eth.h"
#include "../../util/rng/fd_rng.h"
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>

#pragma GCC diagnostic ignored "-Wstrict-aliasing"

/* Maximum size of a network packet */
#define PACKET_DATA_SIZE 1232
/* Max number of validators that can be actively queried */
#define FD_ACTIVE_KEY_MAX (1<<10)
/* Max number of pending shred requests */
#define FD_NEEDED_KEY_MAX (1<<12)
/* Max number of pending timed events */
#define FD_PENDING_MAX (1<<9)

/* Test if two hash values are equal */
static int fd_hash_eq( const fd_hash_t * key1, const fd_hash_t * key2 ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    if (key1->ul[i] != key2->ul[i])
      return 0;
  return 1;
}

/* Hash a hash value */
static ulong fd_hash_hash( const fd_hash_t * key, ulong seed ) {
  return key->ul[0] ^ seed;
}

/* Copy a hash value */
static void fd_hash_copy( fd_hash_t * keyd, const fd_hash_t * keys ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    keyd->ul[i] = keys->ul[i];
}

/* Test if two addresses are equal */
int fd_repair_peer_addr_eq( const fd_repair_peer_addr_t * key1, const fd_repair_peer_addr_t * key2 ) {
  FD_STATIC_ASSERT(sizeof(fd_repair_peer_addr_t) == sizeof(ulong),"messed up size");
  return key1->l == key2->l;
}

/* Hash an address */
ulong fd_repair_peer_addr_hash( const fd_repair_peer_addr_t * key, ulong seed ) {
  FD_STATIC_ASSERT(sizeof(fd_repair_peer_addr_t) == sizeof(ulong),"messed up size");
  return (key->l + seed + 7242237688154252699UL)*9540121337UL;
}

/* Efficiently copy an address */
void fd_repair_peer_addr_copy( fd_repair_peer_addr_t * keyd, const fd_repair_peer_addr_t * keys ) {
  FD_STATIC_ASSERT(sizeof(fd_repair_peer_addr_t) == sizeof(ulong),"messed up size");
  keyd->l = keys->l;
}

/* Active table element. This table is all validators that we are
   asking for repairs. */
struct fd_active_elem {
    fd_pubkey_t key;  /* Public indentifier */
    fd_repair_peer_addr_t addr;
    ulong next;
};
/* Active table */
typedef struct fd_active_elem fd_active_elem_t;
#define MAP_NAME     fd_active_table
#define MAP_KEY_T    fd_pubkey_t
#define MAP_KEY_EQ   fd_hash_eq
#define MAP_KEY_HASH fd_hash_hash
#define MAP_KEY_COPY fd_hash_copy
#define MAP_T        fd_active_elem_t
#include "../../util/tmpl/fd_map_giant.c"

typedef uint fd_repair_nonce_t;

int fd_repair_nonce_eq( const fd_repair_nonce_t * key1, const fd_repair_nonce_t * key2 ) {
  return *key1 == *key2;
}

ulong fd_repair_nonce_hash( const fd_repair_nonce_t * key, ulong seed ) {
  return (*key + seed + 7242237688154252699UL)*9540121337UL;
}

void fd_repair_nonce_copy( fd_repair_nonce_t * keyd, const fd_repair_nonce_t * keys ) {
  *keyd = *keys;
}

enum fd_needed_elem_type {
  fd_needed_window_index, fd_needed_highest_window_index, fd_needed_orphan
};

struct fd_needed_elem {
  fd_repair_nonce_t key;
  ulong next;
  fd_pubkey_t id;
  enum fd_needed_elem_type type;
  ulong slot;
  uint shred_index;
  long when;
};
typedef struct fd_needed_elem fd_needed_elem_t;
#define MAP_NAME     fd_needed_table
#define MAP_KEY_T    fd_repair_nonce_t
#define MAP_KEY_EQ   fd_repair_nonce_eq
#define MAP_KEY_HASH fd_repair_nonce_hash
#define MAP_KEY_COPY fd_repair_nonce_copy
#define MAP_T        fd_needed_elem_t
#include "../../util/tmpl/fd_map_giant.c"

/* Queue of pending timed events, stored as a priority heap */
union fd_pending_event_arg {
    fd_repair_peer_addr_t key;
};
typedef union fd_pending_event_arg fd_pending_event_arg_t;
typedef void (*fd_pending_event_fun)(struct fd_repair * glob, fd_pending_event_arg_t * arg);
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

/* Global data for repair service */
struct fd_repair {
    /* Current time in nanosecs */
    long now;
    /* My public/private key */
    fd_pubkey_t * public_key;
    uchar * private_key;
    /* My repair port address */
    fd_repair_peer_addr_t my_addr;
    /* Function used to deliver repair messages to the application */
    fd_repair_shred_deliver_fun deliver_fun;
    /* Function used to send raw packets on the network */
    fd_repair_send_packet_fun send_fun;
    /* Function used to deliver repair failure on the network */
    fd_repair_shred_deliver_fail_fun deliver_fail_fun;
    void * fun_arg;
    /* Table of validators that we are actively pinging, keyed by repair address */
    fd_active_elem_t * actives;
    /* Table of needed shreds */
    fd_needed_elem_t * needed;
    fd_repair_nonce_t oldest_nonce;
    fd_repair_nonce_t next_nonce;
    /* Heap/queue of pending timed events */
    fd_pending_event_t * event_pool;
    fd_pending_heap_t * event_heap;
    /* Random number generator */
    fd_rng_t rng[1];
    /* RNG seed */
    ulong seed;
    /* Heap allocator */
    fd_valloc_t valloc;
};

ulong
fd_repair_align ( void ) { return alignof(fd_repair_t); }

ulong
fd_repair_footprint( void ) { return sizeof(fd_repair_t); }

void *
fd_repair_new ( void * shmem, ulong seed, fd_valloc_t valloc ) {
  fd_memset(shmem, 0, sizeof(fd_repair_t));
  fd_repair_t * glob = (fd_repair_t *)shmem;
  glob->valloc = valloc;
  glob->seed = seed;
  void * shm = fd_valloc_malloc(valloc, fd_active_table_align(), fd_active_table_footprint(FD_ACTIVE_KEY_MAX));
  glob->actives = fd_active_table_join(fd_active_table_new(shm, FD_ACTIVE_KEY_MAX, seed));
  shm = fd_valloc_malloc(valloc, fd_needed_table_align(), fd_needed_table_footprint(FD_NEEDED_KEY_MAX));
  glob->needed = fd_needed_table_join(fd_needed_table_new(shm, FD_NEEDED_KEY_MAX, seed));
  glob->oldest_nonce = glob->next_nonce = 0;
  shm = fd_valloc_malloc(valloc, fd_pending_pool_align(), fd_pending_pool_footprint(FD_PENDING_MAX));
  glob->event_pool = fd_pending_pool_join(fd_pending_pool_new(shm, FD_PENDING_MAX));
  shm = fd_valloc_malloc(valloc, fd_pending_heap_align(), fd_pending_heap_footprint(FD_PENDING_MAX));
  glob->event_heap = fd_pending_heap_join(fd_pending_heap_new(shm, FD_PENDING_MAX));
  fd_rng_new(glob->rng, (uint)seed, 0UL);
  return glob;
}

fd_repair_t *
fd_repair_join ( void * shmap ) { return (fd_repair_t *)shmap; }

void *
fd_repair_leave ( fd_repair_t * join ) { return join; }

void *
fd_repair_delete ( void * shmap, fd_valloc_t valloc ) {
  fd_repair_t * glob = (fd_repair_t *)shmap;
  fd_valloc_free(valloc, fd_active_table_delete(fd_active_table_leave(glob->actives)));
  fd_valloc_free(valloc, fd_needed_table_delete(fd_needed_table_leave(glob->needed)));
  fd_valloc_free(valloc, fd_pending_pool_delete(fd_pending_pool_leave(glob->event_pool)));
  fd_valloc_free(valloc, fd_pending_heap_delete(fd_pending_heap_leave(glob->event_heap)));
  return glob;
}

/* Convert an address to a human readable string */
const char * fd_repair_addr_str( char * dst, size_t dstlen, fd_repair_peer_addr_t const * src ) {
  char tmp[INET_ADDRSTRLEN];
  snprintf(dst, dstlen, "%s:%u", inet_ntop(AF_INET, &src->addr, tmp, INET_ADDRSTRLEN), (uint)ntohs(src->port));
  return dst;
}

/* Set the repair configuration */
int
fd_repair_set_config( fd_repair_t * glob, const fd_repair_config_t * config ) {
  char tmp[100];
  char keystr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( config->public_key->uc, NULL, keystr );
  FD_LOG_NOTICE(("configuring address %s key %s", fd_repair_addr_str(tmp, sizeof(tmp), &config->my_addr), keystr));

  glob->public_key = config->public_key;
  glob->private_key = config->private_key;
  fd_repair_peer_addr_copy(&glob->my_addr, &config->my_addr);
  glob->deliver_fun = config->deliver_fun;
  glob->send_fun = config->send_fun;
  glob->fun_arg = config->fun_arg;
  glob->deliver_fail_fun = config->deliver_fail_fun;
  return 0;
}

int
fd_repair_update_addr( fd_repair_t * glob, const fd_repair_peer_addr_t * my_addr ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating address %s", fd_repair_addr_str(tmp, sizeof(tmp), my_addr)));

  fd_repair_peer_addr_copy(&glob->my_addr, my_addr);
  return 0;
}

/* Add an event to the queue of pending timed events. The resulting
   value needs "fun" and "fun_arg" to be set. */
fd_pending_event_t *
fd_repair_add_pending( fd_repair_t * glob, long when ) {
  if (fd_pending_pool_free( glob->event_pool ) == 0)
    return NULL;
  fd_pending_event_t * ev = fd_pending_pool_ele_acquire( glob->event_pool );
  ev->key = when;
  fd_pending_heap_ele_insert( glob->event_heap, ev, glob->event_pool );
  return ev;
}

/* Initiate connection to a peer */
int
fd_repair_add_active_peer( fd_repair_t * glob, fd_repair_peer_addr_t const * addr, fd_pubkey_t const * id ) {
  char tmp[100];
  char keystr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( id->uc, NULL, keystr );
  FD_LOG_DEBUG(("adding active peer address %s key %s", fd_repair_addr_str(tmp, sizeof(tmp), addr), keystr));

  fd_active_elem_t * val = fd_active_table_query(glob->actives, id, NULL);
  if (val == NULL) {
    if (fd_active_table_is_full(glob->actives)) {
      FD_LOG_WARNING(("too many actives"));
      return -1;
    }
    val = fd_active_table_insert(glob->actives, id);
    fd_repair_peer_addr_copy(&val->addr, addr);
  }
  return 0;
}

/* Set the current protocol time in nanosecs */
void
fd_repair_settime( fd_repair_t * glob, long ts ) {
  glob->now = ts;
}

/* Get the current protocol time in nanosecs */
long
fd_repair_gettime( fd_repair_t * glob ) {
  return glob->now;
}

static void
fd_repair_sign_and_send( fd_repair_t * glob, fd_repair_protocol_t * protocol, fd_gossip_peer_addr_t * addr) {
  fd_bincode_encode_ctx_t ctx;
  uchar buf[1024];
  ctx.data = buf;
  ctx.dataend = buf + sizeof(buf);
  FD_TEST(0 == fd_repair_protocol_encode(protocol, &ctx));

  // https://github.com/solana-labs/solana/blob/master/core/src/repair/serve_repair.rs#L874
  ulong buflen = (ulong)((uchar*)ctx.data - buf);
  fd_memcpy(buf + 64U, buf, 4U);
  fd_sha512_t sha[1];
  fd_signature_t sig;
  fd_ed25519_sign( /* sig */ &sig,
                   /* msg */ buf + 64U,
                   /* sz  */ buflen - 64U,
                   /* public_key  */ glob->public_key,
                   /* private_key */ glob->private_key,
                   sha );
  fd_memcpy(buf + 4U, &sig, 64U);

  (*glob->send_fun)(buf, buflen, addr, glob->fun_arg);
}

static void
fd_repair_send_requests( fd_repair_t * glob, fd_pending_event_arg_t * arg ) {
  (void)arg;

  /* Try again in 100 msec */
  fd_pending_event_t * ev = fd_repair_add_pending(glob, glob->now + (long)100e6);
  if (ev) {
    ev->fun = fd_repair_send_requests;
  }

  /* Garbage collect old requests */
  long expire = glob->now - (long)10e9; /* 10 seconds */
  fd_repair_nonce_t n;
  for ( n = glob->oldest_nonce; n != glob->next_nonce; ++n ) {
    fd_needed_elem_t * ele = fd_needed_table_query( glob->needed, &n, NULL );
    if ( NULL == ele )
      continue;
    if (ele->when > expire)
      break;
    (*glob->deliver_fail_fun)( &ele->id, ele->slot, ele->shred_index, glob->fun_arg, FD_REPAIR_DELIVER_FAIL_TIMEOUT );
    fd_needed_table_remove( glob->needed, &n );
  }
  glob->oldest_nonce = n;

  /* Send requests */
  ulong j = 0;
  for ( ; n != glob->next_nonce; ++n ) {
    fd_needed_elem_t * ele = fd_needed_table_query( glob->needed, &n, NULL );
    if ( NULL == ele )
      continue;
    fd_active_elem_t * active = fd_active_table_query( glob->actives, &ele->id, NULL );
    if ( NULL == active )
      continue;

    if (++j == 500U)
      break;

    fd_repair_protocol_t protocol;
    switch (ele->type) {
    case fd_needed_window_index: {
      fd_repair_protocol_new_disc(&protocol, fd_repair_protocol_enum_window_index);
      fd_repair_window_index_t * wi = &protocol.inner.window_index;
      fd_hash_copy(&wi->header.sender, glob->public_key);
      fd_hash_copy(&wi->header.recipient, &active->key);
      wi->header.timestamp = (ulong)glob->now/1000000LU;
      wi->header.nonce = n;
      wi->slot = ele->slot;
      wi->shred_index = ele->shred_index;
      break;
    }

    case fd_needed_highest_window_index: {
      fd_repair_protocol_new_disc(&protocol, fd_repair_protocol_enum_highest_window_index);
      fd_repair_highest_window_index_t * wi = &protocol.inner.highest_window_index;
      fd_hash_copy(&wi->header.sender, glob->public_key);
      fd_hash_copy(&wi->header.recipient, &active->key);
      wi->header.timestamp = (ulong)glob->now/1000000LU;
      wi->header.nonce = n;
      wi->slot = ele->slot;
      wi->shred_index = ele->shred_index;
      break;
    }

    case fd_needed_orphan: {
      fd_repair_protocol_new_disc(&protocol, fd_repair_protocol_enum_orphan);
      fd_repair_orphan_t * wi = &protocol.inner.orphan;
      fd_hash_copy(&wi->header.sender, glob->public_key);
      fd_hash_copy(&wi->header.recipient, &active->key);
      wi->header.timestamp = (ulong)glob->now/1000000LU;
      wi->header.nonce = n;
      wi->slot = ele->slot;
      break;
    }
    }

    fd_repair_sign_and_send(glob, &protocol, &active->addr);
}
}

/* Start timed events and other protocol behavior */
int
fd_repair_start( fd_repair_t * glob ) {
  fd_pending_event_t * ev = fd_repair_add_pending(glob, glob->now + (long)100e6);
  ev->fun = fd_repair_send_requests;
  return 0;
}

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. */
int
fd_repair_continue( fd_repair_t * glob ) {
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
  return 0;
}

static void
fd_repair_recv_ping(fd_repair_t * glob, fd_gossip_ping_t const * ping, fd_gossip_peer_addr_t const * from) {
  (void)from;
  fd_repair_protocol_t protocol;
  fd_repair_protocol_new_disc(&protocol, fd_repair_protocol_enum_pong);
  fd_gossip_ping_t * pong = &protocol.inner.pong;

  fd_hash_copy( &pong->from, glob->public_key );

  /* Generate response hash token */
  fd_sha256_t sha[1];
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, ping->token.uc,     32UL );
  fd_sha256_fini( sha, pong->token.uc );

  /* Sign it */
  fd_sha512_t sha2[1];
  fd_ed25519_sign( /* sig */ pong->signature.uc,
                   /* msg */ pong->token.uc,
                   /* sz  */ 32UL,
                   /* public_key  */ glob->public_key->uc,
                   /* private_key */ glob->private_key,
                   sha2 );

  fd_bincode_encode_ctx_t ctx;
  uchar buf[1024];
  ctx.data = buf;
  ctx.dataend = buf + sizeof(buf);
  FD_TEST(0 == fd_repair_protocol_encode(&protocol, &ctx));
  ulong buflen = (ulong)((uchar*)ctx.data - buf);

  (*glob->send_fun)(buf, buflen, from, glob->fun_arg);
}

int
fd_repair_recv_packet(fd_repair_t * glob, uchar const * msg, ulong msglen, fd_gossip_peer_addr_t const * from) {
  while (1) {
    fd_repair_response_t gmsg;
    fd_bincode_decode_ctx_t ctx;
    ctx.data    = msg;
    ctx.dataend = msg + msglen;
    ctx.valloc  = glob->valloc;
    if (fd_repair_response_decode(&gmsg, &ctx)) {
      /* Solana falls back to assuming we got a shred in this case
         https://github.com/solana-labs/solana/blob/master/core/src/repair/serve_repair.rs#L1198 */
      break;
    }
    fd_bincode_destroy_ctx_t ctx2;
    ctx2.valloc = glob->valloc;
    if (ctx.data != ctx.dataend) {
      fd_repair_response_destroy(&gmsg, &ctx2);
      break;
    }

    switch (gmsg.discriminant) {
    case fd_repair_response_enum_ping:
      fd_repair_recv_ping(glob, &gmsg.inner.ping, from);
      break;
    }

    fd_repair_response_destroy(&gmsg, &ctx2);
    return 0;
  }

  /* Look at the nonse */
  if ( msglen < sizeof(fd_repair_nonce_t) )
    return 0;
  ulong shredlen = msglen - sizeof(fd_repair_nonce_t); /* Nonce is at the end */
  fd_repair_nonce_t key = *(fd_repair_nonce_t const *)(msg + shredlen);
  fd_needed_elem_t * val = fd_needed_table_query(glob->needed, &key, NULL);
  if ( NULL == val )
    return 0;
  fd_needed_table_remove(glob->needed, &key);
  if ( key == glob->oldest_nonce )
    glob->oldest_nonce = key + 1U;

  fd_shred_t const * shred = fd_shred_parse(msg, shredlen);
  if (shred == NULL)
    FD_LOG_WARNING(("invalid shread"));
  else
    (*glob->deliver_fun)(shred, shredlen, from, glob->fun_arg);
  return 0;
}

int
fd_repair_need_window_index( fd_repair_t * glob, fd_pubkey_t const * id, ulong slot, uint shred_index ) {
  if (fd_needed_table_is_full(glob->needed)) {
    ( *glob->deliver_fail_fun )(id, slot, shred_index, glob->fun_arg, FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED );
    return -1;
  }
  fd_repair_nonce_t key = glob->next_nonce++;
  fd_needed_elem_t * val = fd_needed_table_insert(glob->needed, &key);
  fd_hash_copy(&val->id, id);
  val->type = fd_needed_window_index;
  val->slot = slot;
  val->shred_index = shred_index;
  val->when = glob->now;
  return 0;
}

int
fd_repair_need_highest_window_index( fd_repair_t * glob, fd_pubkey_t const * id, ulong slot, uint shred_index ) {
  if (fd_needed_table_is_full(glob->needed)) {
    ( *glob->deliver_fail_fun )(id, slot, shred_index, glob->fun_arg, FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED );
    return -1;
  }
  fd_repair_nonce_t key = glob->next_nonce++;
  FD_LOG_DEBUG(("inserting nonce %lu", key));
  fd_needed_elem_t * val = fd_needed_table_insert(glob->needed, &key);
  fd_hash_copy(&val->id, id);
  val->type = fd_needed_highest_window_index;
  val->slot = slot;
  val->shred_index = shred_index;
  val->when = glob->now;
  return 0;
}

int
fd_repair_need_orphan( fd_repair_t * glob, fd_pubkey_t const * id, ulong slot ) {
  if (fd_needed_table_is_full(glob->needed)) {
    ( *glob->deliver_fail_fun )(id, slot, UINT_MAX, glob->fun_arg, FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED );
    return -1;
  }
  fd_repair_nonce_t key = glob->next_nonce++;
  fd_needed_elem_t * val = fd_needed_table_insert(glob->needed, &key);
  fd_hash_copy(&val->id, id);
  val->type = fd_needed_orphan;
  val->slot = slot;
  val->shred_index = 0; /* unused */
  val->when = glob->now;
  return 0;
}
