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
#define FD_ACTIVE_KEY_MAX (1<<12)
/* Max number of pending shred requests */
#define FD_NEEDED_KEY_MAX (1<<18)
/* Max number of sticky repair peers */
#define FD_REPAIR_STICKY_MAX   32
/* Max number of validator identities in stake weights */
#define FD_STAKE_WEIGHTS_MAX (1<<14)

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

typedef uint fd_repair_nonce_t;

/* Active table element. This table is all validators that we are
   asking for repairs. */
struct fd_active_elem {
    fd_pubkey_t key;  /* Public indentifier and map key */
    ulong next; /* used internally by fd_map_giant */

    fd_repair_peer_addr_t addr;
    ulong avg_reqs; /* Moving average of the number of requests */
    ulong avg_reps; /* Moving average of the number of requests */
    long  avg_lat;  /* Moving average of response latency */
    uchar sticky;
    uchar permanent;
    long  first_request_time;
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

enum fd_needed_elem_type {
  fd_needed_window_index, fd_needed_highest_window_index, fd_needed_orphan
};

struct fd_dupdetect_key {
  enum fd_needed_elem_type type;
  ulong slot;
  uint shred_index;
};
typedef struct fd_dupdetect_key fd_dupdetect_key_t;

struct fd_dupdetect_elem {
  fd_dupdetect_key_t key;
  ulong next;
};
typedef struct fd_dupdetect_elem fd_dupdetect_elem_t;

int fd_dupdetect_eq( const fd_dupdetect_key_t * key1, const fd_dupdetect_key_t * key2 ) {
  return (key1->type == key2->type) &&
         (key1->slot == key2->slot) &&
         (key1->shred_index == key2->shred_index);
}

ulong fd_dupdetect_hash( const fd_dupdetect_key_t * key, ulong seed ) {
  return (key->slot + seed)*9540121337UL + key->shred_index*131U;
}

void fd_dupdetect_copy( fd_dupdetect_key_t * keyd, const fd_dupdetect_key_t * keys ) {
  *keyd = *keys;
}

#define MAP_NAME     fd_dupdetect_table
#define MAP_KEY_T    fd_dupdetect_key_t
#define MAP_KEY_EQ   fd_dupdetect_eq
#define MAP_KEY_HASH fd_dupdetect_hash
#define MAP_KEY_COPY fd_dupdetect_copy
#define MAP_T        fd_dupdetect_elem_t
#include "../../util/tmpl/fd_map_giant.c"

int fd_repair_nonce_eq( const fd_repair_nonce_t * key1, const fd_repair_nonce_t * key2 ) {
  return *key1 == *key2;
}

ulong fd_repair_nonce_hash( const fd_repair_nonce_t * key, ulong seed ) {
  return (*key + seed + 7242237688154252699UL)*9540121337UL;
}

void fd_repair_nonce_copy( fd_repair_nonce_t * keyd, const fd_repair_nonce_t * keys ) {
  *keyd = *keys;
}

struct fd_needed_elem {
  fd_repair_nonce_t key;
  ulong next;
  fd_pubkey_t id;
  fd_dupdetect_key_t dupkey;
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

/* Global data for repair service */
struct fd_repair {
    /* Concurrency lock */
    volatile ulong lock;
    /* Current time in nanosecs */
    long now;
    /* My public/private key */
    fd_pubkey_t * public_key;
    uchar * private_key;
    /* My repair addresses */
    fd_repair_peer_addr_t service_addr;
    fd_repair_peer_addr_t intake_addr;
    /* Function used to deliver repair messages to the application */
    fd_repair_shred_deliver_fun deliver_fun;
    /* Function used to send raw packets on the network */
    fd_repair_send_packet_fun send_fun;
    /* Function used to send packets for signing to remote tile */
    fd_repair_sign_fun sign_fun;
    /* Argument to fd_repair_sign_fun */
    void * sign_arg;
    /* Function used to deliver repair failure on the network */
    fd_repair_shred_deliver_fail_fun deliver_fail_fun;
    void * fun_arg;
    /* Table of validators that we are actively pinging, keyed by repair address */
    fd_active_elem_t * actives;
    fd_pubkey_t actives_sticky[FD_REPAIR_STICKY_MAX]; /* cache of chosen repair peer samples */
    ulong       actives_sticky_cnt;
    ulong       actives_random_seed;
    /* Duplicate request detection table */
    fd_dupdetect_elem_t * dupdetect;
    /* Table of needed shreds */
    fd_needed_elem_t * needed;
    fd_repair_nonce_t oldest_nonce;
    fd_repair_nonce_t current_nonce;
    fd_repair_nonce_t next_nonce;
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
    /* Stake weights */
    ulong stake_weights_cnt;
    fd_stake_weight_t * stake_weights;
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
  shm = fd_valloc_malloc(valloc, fd_dupdetect_table_align(), fd_dupdetect_table_footprint(FD_NEEDED_KEY_MAX));
  glob->dupdetect = fd_dupdetect_table_join(fd_dupdetect_table_new(shm, FD_NEEDED_KEY_MAX, seed));
  glob->stake_weights = fd_valloc_malloc( valloc, fd_stake_weight_align(), FD_STAKE_WEIGHTS_MAX * fd_stake_weight_footprint() );
  glob->stake_weights_cnt = 0;
  glob->last_sends = 0;
  glob->last_decay = 0;
  glob->last_print = 0;
  glob->oldest_nonce = glob->current_nonce = glob->next_nonce = 0;
  fd_rng_new(glob->rng, (uint)seed, 0UL);

  glob->actives_sticky_cnt   = 0;
  glob->actives_random_seed  = 0;

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
  fd_valloc_free(valloc, fd_dupdetect_table_delete(fd_dupdetect_table_leave(glob->dupdetect)));
  fd_valloc_free( valloc, glob->stake_weights );
  return glob;
}

static void
fd_repair_lock( fd_repair_t * repair ) {
  for(;;) {
    if( FD_LIKELY( !FD_ATOMIC_CAS( &repair->lock, 0UL, 1UL) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
}

static void
fd_repair_unlock( fd_repair_t * repair ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( repair->lock ) = 0UL;
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
  FD_LOG_NOTICE(("configuring address %s key %s", fd_repair_addr_str(tmp, sizeof(tmp), &config->intake_addr), keystr));

  glob->public_key = config->public_key;
  glob->private_key = config->private_key;
  fd_repair_peer_addr_copy(&glob->intake_addr, &config->intake_addr);
  fd_repair_peer_addr_copy(&glob->service_addr, &config->service_addr);
  glob->deliver_fun = config->deliver_fun;
  glob->send_fun = config->send_fun;
  glob->fun_arg = config->fun_arg;
  glob->sign_fun = config->sign_fun;
  glob->sign_arg = config->sign_arg;
  glob->deliver_fail_fun = config->deliver_fail_fun;
  return 0;
}

int
fd_repair_update_addr( fd_repair_t * glob, const fd_repair_peer_addr_t * intake_addr, const fd_repair_peer_addr_t * service_addr ) {
  char tmp[100];
  FD_LOG_NOTICE(("updating address %s", fd_repair_addr_str(tmp, sizeof(tmp), intake_addr)));

  fd_repair_peer_addr_copy(&glob->intake_addr, intake_addr);
  fd_repair_peer_addr_copy(&glob->service_addr, service_addr);
  return 0;
}

/* Initiate connection to a peer */
int
fd_repair_add_active_peer( fd_repair_t * glob, fd_repair_peer_addr_t const * addr, fd_pubkey_t const * id ) {
  fd_repair_lock( glob );
  char tmp[100];
  char keystr[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( id->uc, NULL, keystr );
  FD_LOG_DEBUG(("adding active peer address %s key %s", fd_repair_addr_str(tmp, sizeof(tmp), addr), keystr));

  fd_active_elem_t * val = fd_active_table_query(glob->actives, id, NULL);
  if (val == NULL) {
    if (fd_active_table_is_full(glob->actives)) {
      FD_LOG_DEBUG(("too many actives"));
      fd_repair_unlock( glob );
      return -1;
    }
    val = fd_active_table_insert(glob->actives, id);
    fd_repair_peer_addr_copy(&val->addr, addr);
    val->avg_reqs = 0;
    val->avg_reps = 0;
    val->avg_lat = 0;
    val->sticky = 0;
    val->first_request_time = 0;
    val->permanent = 0;
    FD_LOG_DEBUG( ( "adding repair peer %32J", val->key.uc ) );
  }
  fd_repair_unlock( glob );
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
  fd_signature_t sig;
  if( glob->sign_fun ) {
    (*glob->sign_fun)( glob->sign_arg, sig.uc, buf + 64U, buflen - 64U );
  } else {
    fd_sha512_t sha[1];
    fd_ed25519_sign( /* sig */ sig.uc,
                     /* msg */ buf + 64U,
                     /* sz  */ buflen - 64U,
                     /* public_key  */ glob->public_key->key,
                     /* private_key */ glob->private_key,
                     sha );
  }
  fd_memcpy(buf + 4U, &sig, 64U);

  (*glob->send_fun)(buf, buflen, addr, glob->fun_arg);
}

static void
fd_repair_send_requests( fd_repair_t * glob ) {
  /* Garbage collect old requests */
  long expire = glob->now - (long)1000e6; /* 1 seconds */
  fd_repair_nonce_t n;
  for ( n = glob->oldest_nonce; n != glob->next_nonce; ++n ) {
    fd_needed_elem_t * ele = fd_needed_table_query( glob->needed, &n, NULL );
    if ( NULL == ele )
      continue;
    if (ele->when > expire)
      break;
    // (*glob->deliver_fail_fun)( &ele->key, ele->slot, ele->shred_index, glob->fun_arg, FD_REPAIR_DELIVER_FAIL_TIMEOUT );
    fd_dupdetect_table_remove( glob->dupdetect, &ele->dupkey );
    fd_needed_table_remove( glob->needed, &n );
  }
  glob->oldest_nonce = n;  

  /* Send requests starting where we left off last time */
  if ( (int)(n - glob->current_nonce) < 0 )
    n = glob->current_nonce;
  ulong j = 0;
  ulong k = 0;
  for ( ; n != glob->next_nonce; ++n ) {
    ++k;
    fd_needed_elem_t * ele = fd_needed_table_query( glob->needed, &n, NULL );
    if ( NULL == ele )
      continue;
    fd_active_elem_t * active = fd_active_table_query( glob->actives, &ele->id, NULL );
    if ( NULL == active ) {
      fd_dupdetect_table_remove( glob->dupdetect, &ele->dupkey );
      fd_needed_table_remove( glob->needed, &n );
      continue;
    }
    if(j == 100U) break; 
    ++j;

    /* Track statistics */
    ele->when = glob->now;
    active->avg_reqs++;

    fd_repair_protocol_t protocol;
    switch (ele->dupkey.type) {
    case fd_needed_window_index: {
      fd_repair_protocol_new_disc(&protocol, fd_repair_protocol_enum_window_index);
      fd_repair_window_index_t * wi = &protocol.inner.window_index;
      fd_hash_copy(&wi->header.sender, glob->public_key);
      fd_hash_copy(&wi->header.recipient, &active->key);
      wi->header.timestamp = (ulong)glob->now/1000000LU;
      wi->header.nonce = n;
      wi->slot = ele->dupkey.slot;
      wi->shred_index = ele->dupkey.shred_index;
      break;
    }

    case fd_needed_highest_window_index: {
      fd_repair_protocol_new_disc(&protocol, fd_repair_protocol_enum_highest_window_index);
      fd_repair_highest_window_index_t * wi = &protocol.inner.highest_window_index;
      fd_hash_copy(&wi->header.sender, glob->public_key);
      fd_hash_copy(&wi->header.recipient, &active->key);
      wi->header.timestamp = (ulong)glob->now/1000000LU;
      wi->header.nonce = n;
      wi->slot = ele->dupkey.slot;
      wi->shred_index = ele->dupkey.shred_index;
      break;
    }

    case fd_needed_orphan: {
      fd_repair_protocol_new_disc(&protocol, fd_repair_protocol_enum_orphan);
      fd_repair_orphan_t * wi = &protocol.inner.orphan;
      fd_hash_copy(&wi->header.sender, glob->public_key);
      fd_hash_copy(&wi->header.recipient, &active->key);
      wi->header.timestamp = (ulong)glob->now/1000000LU;
      wi->header.nonce = n;
      wi->slot = ele->dupkey.slot;
      break;
    }
    }

    fd_repair_sign_and_send(glob, &protocol, &active->addr);
  }
  glob->current_nonce = n;
  if( k )
    FD_LOG_DEBUG(("checked %lu nonces, sent %lu packets", k, j));
}

static void
fd_repair_decay_stats( fd_repair_t * glob ) {
  for( fd_active_table_iter_t iter = fd_active_table_iter_init( glob->actives );
       !fd_active_table_iter_done( glob->actives, iter );
       iter = fd_active_table_iter_next( glob->actives, iter ) ) {
    fd_active_elem_t * ele = fd_active_table_iter_ele( glob->actives, iter );
#define DECAY(_v_) _v_ = _v_ - ((_v_)>>3U) /* Reduce by 12.5% */
    DECAY(ele->avg_reqs);
    DECAY(ele->avg_reps);
    DECAY(ele->avg_lat);
#undef DECAY
  }
}

/* Start timed events and other protocol behavior */
int
fd_repair_start( fd_repair_t * glob ) {
  glob->last_sends = glob->now;
  glob->last_decay = glob->now;
  glob->last_print = glob->now;
  return 0;
}

static void fd_repair_print_all_stats( fd_repair_t * glob );
static void fd_actives_shuffle( fd_repair_t * repair );

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. */
int
fd_repair_continue( fd_repair_t * glob ) {
  fd_repair_lock( glob );
  if ( glob->now - glob->last_sends > (long)10e6 ) { /* 10 millisecs */
    fd_repair_send_requests( glob );
    glob->last_sends = glob->now;
  }
  if ( glob->now - glob->last_print > (long)30e9 ) { /* 30 seconds */
    fd_repair_print_all_stats( glob );
    glob->last_print = glob->now;
    fd_actives_shuffle( glob );
    fd_repair_decay_stats( glob );
    glob->last_decay = glob->now;
  } else if ( glob->now - glob->last_decay > (long)15e9 ) { /* 15 seconds */
    fd_actives_shuffle( glob );
    fd_repair_decay_stats( glob );
    glob->last_decay = glob->now;
  }
  fd_repair_unlock( glob );
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
  if( glob->sign_fun ) {
    (*glob->sign_fun)( glob->sign_arg, pong->signature.uc, pong->token.uc, 32UL );
  } else {
    fd_sha512_t sha2[1];
    fd_ed25519_sign( /* sig */ pong->signature.uc,
                     /* msg */ pong->token.uc,
                     /* sz  */ 32UL,
                     /* public_key  */ glob->public_key->key,
                     /* private_key */ glob->private_key,
                     sha2 );
  }

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
  fd_repair_lock( glob );
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
    fd_repair_unlock( glob );
    return 0;
  }

  /* Look at the nonse */
  if ( msglen < sizeof(fd_repair_nonce_t) ) {
    fd_repair_unlock( glob );
    return 0;
  }
  ulong shredlen = msglen - sizeof(fd_repair_nonce_t); /* Nonce is at the end */
  fd_repair_nonce_t key = *(fd_repair_nonce_t const *)(msg + shredlen);
  fd_needed_elem_t * val = fd_needed_table_query(glob->needed, &key, NULL);
  if ( NULL == val ) {
    fd_repair_unlock( glob );
    return 0;
  }

  fd_active_elem_t * active = fd_active_table_query( glob->actives, &val->id, NULL );
  if ( NULL != active ) {
    /* Update statistics */
    active->avg_reps++;
    active->avg_lat += glob->now - val->when;
  }

  fd_shred_t const * shred = fd_shred_parse(msg, shredlen);
  fd_repair_unlock( glob );
  if (shred == NULL) {
    FD_LOG_WARNING(("invalid shread"));
  } else {
    (*glob->deliver_fun)(shred, shredlen, from, &val->id, glob->fun_arg);
  }

  return 0;
}

int
fd_repair_is_full( fd_repair_t * glob ) {
  return fd_needed_table_is_full(glob->needed);
}

/* Test if a peer is good. Returns 1 if the peer is "great", 0 if the peer is "good", and -1 if the peer sucks */
static int
is_good_peer( fd_active_elem_t * val ) {
  if( FD_UNLIKELY( NULL == val ) ) return -1;                          /* Very bad */
  if( val->avg_reqs < 20U ) return 0;                                  /* Not sure yet, good enough for now */
  if( (float)val->avg_reps < 0.01f*((float)val->avg_reqs) ) return -1; /* Very bad */
  if( (float)val->avg_reps < 0.8f*((float)val->avg_reqs) ) return 0;   /* 80%, Good but not great */
  if( (float)val->avg_lat > 0.3e9f*((float)val->avg_reps) ) return 0;  /* 300ms, Good but not great */
  return 1;                                                            /* Great! */
}

static void
fd_actives_shuffle( fd_repair_t * repair ) {
  if( repair->stake_weights_cnt == 0 ) {
    FD_LOG_WARNING(( "repair does not have stake weights yet, cannot shuffle active set" ));
    return;
  }

  FD_SCRATCH_SCOPE_BEGIN {
    /* Find all the usable stake holders */
    fd_active_elem_t ** leftovers = fd_scratch_alloc(
        alignof( fd_active_elem_t * ),
        sizeof( fd_active_elem_t * ) * repair->stake_weights_cnt );
    ulong leftovers_cnt = 0;
    for( ulong i = 0; i < repair->stake_weights_cnt; i++ ) {
      fd_stake_weight_t const * stake_weight = &repair->stake_weights[i];
      ulong stake = stake_weight->stake;
      if( !stake ) continue;
      fd_pubkey_t const * key = &stake_weight->key;
      fd_active_elem_t * peer = fd_active_table_query( repair->actives, key, NULL );
      if( NULL == peer || peer->sticky ) continue;
      leftovers[leftovers_cnt++] = peer;
    }

    fd_active_elem_t * best[FD_REPAIR_STICKY_MAX];
    ulong              best_cnt = 0;
    fd_active_elem_t * good[FD_REPAIR_STICKY_MAX];
    ulong              good_cnt = 0;

    for( fd_active_table_iter_t iter = fd_active_table_iter_init( repair->actives );
         !fd_active_table_iter_done( repair->actives, iter );
         iter = fd_active_table_iter_next( repair->actives, iter ) ) {
      fd_active_elem_t * peer = fd_active_table_iter_ele( repair->actives, iter );
      uchar sticky = peer->sticky;
      peer->sticky = 0; /* Already clear the sticky bit */
      if( peer->permanent ) {
        best[best_cnt++] = peer;
      } else if( sticky ) {
        /* See if we still like this peer */
        int r = is_good_peer( peer );
        if( r == 1 ) best[best_cnt++] = peer;
        else if( r == 0 ) good[good_cnt++] = peer;
      }
    }

    ulong tot_cnt = 0;
    for( ulong i = 0; i < best_cnt && tot_cnt < FD_REPAIR_STICKY_MAX - 2U; ++i ) {
      repair->actives_sticky[tot_cnt++] = best[i]->key;
      best[i]->sticky                       = (uchar)1;
    }
    for( ulong i = 0; i < good_cnt && tot_cnt < FD_REPAIR_STICKY_MAX - 2U; ++i ) {
      repair->actives_sticky[tot_cnt++] = good[i]->key;
      good[i]->sticky                       = (uchar)1;
    }
    if( leftovers_cnt ) {
      /* Always try afew new ones */
      ulong seed = repair->actives_random_seed;
      for( ulong i = 0; i < 3 && tot_cnt < FD_REPAIR_STICKY_MAX; ++i ) {
        seed                                  = ( seed + 774583887101UL ) * 131UL;
        fd_active_elem_t * peer               = leftovers[seed % leftovers_cnt];
        repair->actives_sticky[tot_cnt++] = peer->key;
        peer->sticky                          = (uchar)1;
      }
      repair->actives_random_seed = seed;
    }
    repair->actives_sticky_cnt = tot_cnt;

    FD_LOG_NOTICE(
        ( "selected %lu peers for repair (best was %lu, good was %lu, leftovers was %lu)",
          tot_cnt,
          best_cnt,
          good_cnt,
          leftovers_cnt ) );
  }
  FD_SCRATCH_SCOPE_END;
}

static fd_active_elem_t *
actives_sample( fd_repair_t * repair ) {
  ulong seed = repair->actives_random_seed;
  while( repair->actives_sticky_cnt ) {
    seed += 774583887101UL;
    fd_pubkey_t *      id   = &repair->actives_sticky[seed % repair->actives_sticky_cnt];
    fd_active_elem_t * peer = fd_active_table_query( repair->actives, id, NULL );
    if( NULL != peer ) {
      if( peer->first_request_time == 0U ) peer->first_request_time = repair->now;
      /* Aggressively throw away bad peers */
      if( peer->permanent ||
          repair->now - peer->first_request_time < (long)5e9 || /* Sample the peer for at least 5 seconds */
          is_good_peer( peer ) != -1 ) {
        repair->actives_random_seed = seed;
        return peer;
      }
      peer->sticky = 0;
    }
    *id = repair->actives_sticky[--( repair->actives_sticky_cnt )];
  }
  return NULL;
}


int
fd_repair_need_window_index( fd_repair_t * glob, ulong slot, uint shred_index ) {
  fd_repair_lock( glob );
  fd_active_elem_t * peer = actives_sample( glob );
  if (!peer) {
    FD_LOG_WARNING( ( "failed to find a good peer." ) );
    fd_repair_unlock( glob );
    return -1;
  };
  fd_pubkey_t * const id = &peer->key;
  fd_dupdetect_key_t dupkey = { .type = fd_needed_window_index, .slot = slot, .shred_index = shred_index };
  if( fd_dupdetect_table_query( glob->dupdetect, &dupkey, NULL ) != NULL ) {
    fd_repair_unlock( glob );
    return 0;
  }
  fd_dupdetect_table_insert( glob->dupdetect, &dupkey );
  
  if (fd_needed_table_is_full(glob->needed)) {
    fd_repair_unlock( glob );
    FD_LOG_NOTICE(("table full"));
    ( *glob->deliver_fail_fun )(&peer->key, slot, shred_index, glob->fun_arg, FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED );
    return -1;
  }
  
  fd_repair_nonce_t key = glob->next_nonce++;
  fd_needed_elem_t * val = fd_needed_table_insert(glob->needed, &key);
  fd_hash_copy(&val->id, id);
  val->dupkey = dupkey;
  val->when = glob->now;
  fd_repair_unlock( glob );
  return 1;
}

int
fd_repair_need_highest_window_index( fd_repair_t * glob, ulong slot, uint shred_index ) {
  fd_repair_lock( glob );
  fd_active_elem_t * peer = actives_sample( glob );
  if (!peer) {
    FD_LOG_WARNING( ( "failed to find a good peer." ) );
    fd_repair_unlock( glob );
    return -1;
  };
  fd_pubkey_t * const id = &peer->key;
  FD_LOG_DEBUG( ( "[repair] need highest %lu from %32J", slot, id ) );
  fd_dupdetect_key_t dupkey = { .type = fd_needed_highest_window_index, .slot = slot, .shred_index = shred_index };
  if( fd_dupdetect_table_query( glob->dupdetect, &dupkey, NULL ) != NULL ) {
    fd_repair_unlock( glob );
    return 0;
  }
  fd_dupdetect_table_insert( glob->dupdetect, &dupkey );
  
  if (fd_needed_table_is_full(glob->needed)) {
    fd_repair_unlock( glob );
    ( *glob->deliver_fail_fun )(id, slot, shred_index, glob->fun_arg, FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED );
    return -1;
  }
  
  fd_repair_nonce_t key = glob->next_nonce++;
  fd_needed_elem_t * val = fd_needed_table_insert(glob->needed, &key);
  fd_hash_copy(&val->id, id);
  val->dupkey = dupkey;
  val->when = glob->now;
  fd_repair_unlock( glob );
  return 0;
}

int
fd_repair_need_orphan( fd_repair_t * glob, ulong slot ) {
  fd_repair_lock( glob );
  fd_active_elem_t * peer = actives_sample( glob );
  if (!peer) {
    FD_LOG_WARNING( ( "failed to find a good peer." ) );
    fd_repair_unlock( glob );
    return -1;
  };
  fd_pubkey_t * const id = &peer->key;
  FD_LOG_NOTICE( ( "[repair] need orphan %lu from %32J", slot, id ) );
  fd_dupdetect_key_t dupkey = { .type = fd_needed_orphan, .slot = slot, .shred_index = UINT_MAX };
  if( fd_dupdetect_table_query( glob->dupdetect, &dupkey, NULL ) != NULL ) {
    fd_repair_unlock( glob );
    return 0;
  }
  fd_dupdetect_table_insert( glob->dupdetect, &dupkey );
  
  if (fd_needed_table_is_full(glob->needed)) {
    fd_repair_unlock( glob );
    ( *glob->deliver_fail_fun )(id, slot, UINT_MAX, glob->fun_arg, FD_REPAIR_DELIVER_FAIL_REQ_LIMIT_EXCEEDED );
    return -1;
  }

  fd_repair_nonce_t key = glob->next_nonce++;
  fd_needed_elem_t * val = fd_needed_table_insert(glob->needed, &key);
  fd_hash_copy(&val->id, id);
  val->dupkey = dupkey;
  val->when = glob->now;
  fd_repair_unlock( glob );
  return 0;
}

static void
print_stats( fd_active_elem_t * val ) {
  fd_pubkey_t const * id = &val->key;
  if( FD_UNLIKELY( NULL == val ) ) return;
  if( val->avg_reqs == 0 )
    FD_LOG_DEBUG(( "repair peer %32J: no requests sent", id ));
  else if( val->avg_reps == 0 )
    FD_LOG_NOTICE(( "repair peer %32J: avg_requests=%lu, no responses received", id, val->avg_reqs ));
  else
    FD_LOG_NOTICE(( "repair peer %32J: avg_requests=%lu, response_rate=%f, latency=%f",
                    id,
                    val->avg_reqs,
                    ((double)val->avg_reps)/((double)val->avg_reqs),
                    1.0e-9*((double)val->avg_lat)/((double)val->avg_reps) ));
}

static void
fd_repair_print_all_stats( fd_repair_t * glob ) {
  for( fd_active_table_iter_t iter = fd_active_table_iter_init( glob->actives );
       !fd_active_table_iter_done( glob->actives, iter );
       iter = fd_active_table_iter_next( glob->actives, iter ) ) {
    fd_active_elem_t * val = fd_active_table_iter_ele( glob->actives, iter );
    print_stats( val );
  }
  FD_LOG_NOTICE( ( "peer count: %lu", fd_active_table_key_cnt( glob->actives ) ) );
}

void fd_repair_add_sticky( fd_repair_t * glob, fd_pubkey_t const * id ) {
  fd_repair_lock( glob );
  glob->actives_sticky[glob->actives_sticky_cnt++] = *id;
  fd_repair_unlock( glob );
}

void fd_repair_set_permanent( fd_repair_t * glob, fd_pubkey_t const * id ) {
  fd_repair_lock( glob );
  fd_active_elem_t * val = fd_active_table_query(glob->actives, id, NULL);
  if( FD_LIKELY( val ) )
    val->permanent = 1;
  fd_repair_unlock( glob );
}

void 
fd_repair_set_stake_weights( fd_repair_t * repair, 
                             fd_stake_weight_t const * stake_weights,
                             ulong stake_weights_cnt ) {
  if( stake_weights == NULL ) {
    FD_LOG_ERR(( "stake weights NULL" ));
  }
  if( stake_weights_cnt > FD_STAKE_WEIGHTS_MAX ) {
    FD_LOG_ERR(( "too many stake weights" ));
  }

  fd_repair_lock( repair );

  fd_memset( repair->stake_weights, 0, FD_STAKE_WEIGHTS_MAX * fd_stake_weight_footprint() );
  fd_memcpy( repair->stake_weights, stake_weights, stake_weights_cnt * sizeof(fd_stake_weight_t) );
  repair->stake_weights_cnt = stake_weights_cnt;

  fd_repair_unlock( repair );
}
