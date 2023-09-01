#define _GNU_SOURCE 1
#include "fd_gossip.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../util/net/fd_eth.h"
#include "../../util/rng/fd_rng.h"
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <math.h>
#include <netdb.h>
#include <stdlib.h>

#pragma GCC diagnostic ignored "-Wstrict-aliasing"

/* Maximum size of a network packet */
#define PACKET_DATA_SIZE 1232
/* How long do we remember values (in millisecs) */
#define FD_GOSSIP_VALUE_EXPIRE ((ulong)(5*60e3)) /* 5 minutes */
/* Max age that values can be pushed/pulled (in millisecs) */
#define FD_GOSSIP_PULL_TIMEOUT ((ulong)(15e3))   /* 15 seconds */
/* Max number of validators that can be known */
#define FD_PEER_KEY_MAX (1<<14)
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

#define FD_GOSSIP_NETWORK_ADDR_NLONGS (sizeof(fd_gossip_network_addr_t)/sizeof(ulong))

fd_gossip_network_addr_t *
fd_gossip_resolve_hostport(const char* str /* host:port */, fd_gossip_network_addr_t * res) {
  fd_memset(res, 0, sizeof(fd_gossip_network_addr_t));
  
  char buf[128];
  uint i;
  for (i = 0; ; ++i) {
    if (str[i] == '\0' || i > sizeof(buf)-1U) {
      FD_LOG_ERR(("missing colon"));
      return NULL;
    }
    if (str[i] == ':') {
      buf[i] = '\0';
      break;
    }
    buf[i] = str[i];
  }
  
  struct hostent * host = gethostbyname( buf );
  if (host == NULL) {
    FD_LOG_WARNING(("unable to resolve host %s", buf));
    return NULL;
  }
  res->family = (sa_family_t)host->h_addrtype;
  if (res->family == AF_INET) {
    res->addr[0] = ((struct in_addr *)host->h_addr)->s_addr;
  } else if (res->family == AF_INET6) {
    uint * u6_addr32 = ((struct in6_addr *)host->h_addr)->s6_addr32;
    res->addr[0] = u6_addr32[0];
    res->addr[1] = u6_addr32[1];
    res->addr[2] = u6_addr32[2];
    res->addr[3] = u6_addr32[3];
  } else {
    FD_LOG_WARNING(("unknown address family in host entry"));
    return NULL;
  }

  int port = atoi(str + i + 1);
  if (port < 1024 || port > (int)USHORT_MAX) {
    FD_LOG_ERR(("invalid port number"));
    return NULL;
  }
  res->port = htons((ushort)port);

  return res;
}

int fd_gossip_network_addr_eq( const fd_gossip_network_addr_t * key1, const fd_gossip_network_addr_t * key2 ) {
  FD_STATIC_ASSERT(sizeof(fd_gossip_network_addr_t)%sizeof(ulong) == 0,"messed up size");
  const ulong * p1 = (const ulong*)key1;
  const ulong * p2 = (const ulong*)key2;
  for ( ulong i = 0; i < FD_GOSSIP_NETWORK_ADDR_NLONGS; ++i )
    if ( p1[i] != p2[i] )
      return 0;
  return 1;
}

ulong fd_gossip_network_addr_hash( const fd_gossip_network_addr_t * key, ulong seed ) {
  ulong buf[FD_GOSSIP_NETWORK_ADDR_NLONGS];
  for ( ulong i = 0; i < FD_GOSSIP_NETWORK_ADDR_NLONGS; ++i )
    buf[i] = ((const ulong *)key)[i];

  seed += 7242237688154252699UL;
  
#define ROLLUP(_result_,_prime_)                       \
  ulong _result_ = 0;                                  \
  do {                                                 \
    for ( ulong i = 0; i < FD_GOSSIP_NETWORK_ADDR_NLONGS; ++i ) { \
      _result_ = (_result_ + buf[i] + seed)*_prime_;   \
    }                                                  \
  } while (0)

#define ROTATE                                          \
  do {                                                  \
    ulong t = buf[0];                                   \
    for ( ulong i = 1; i < FD_GOSSIP_NETWORK_ADDR_NLONGS; ++i ) {  \
      ulong t2 = buf[i];                                \
      buf[i] = ((buf[i] >> 11UL) | (t << (64UL-11UL))); \
      t = t2;                                           \
    }                                                   \
    buf[0] = ((buf[0] >> 11UL) | (t << (64UL-11UL)));   \
  } while (0)

  ROLLUP(r0, 9540121337UL);
  ROTATE;
  ROLLUP(r1, 8420390273UL);
  ROTATE;
  ROLLUP(r2, 5007656803UL);
  ROTATE;
  ROLLUP(r3, 6941447377UL);
  ROTATE;
  ROLLUP(r4, 3848070227UL);
  ROTATE;
  ROLLUP(r5, 8384084351UL);

#undef ROLLUP
#undef ROTATE

  return (r0^r1)^(r2^r3)^(r4^r5);
}

void fd_gossip_network_addr_copy( fd_gossip_network_addr_t * keyd, const fd_gossip_network_addr_t * keys ) {
  FD_STATIC_ASSERT(sizeof(fd_gossip_network_addr_t)%sizeof(ulong) == 0,"messed up size");
  ulong * pd = (ulong*)keyd;
  const ulong * ps = (const ulong*)keys;
  for ( ulong i = 0; i < FD_GOSSIP_NETWORK_ADDR_NLONGS; ++i )
    pd[i] = ps[i];
}

/* All peers table element */
struct fd_peer_elem {
    fd_gossip_network_addr_t key;
    ulong next;
    fd_pubkey_t id;  /* Public indentifier */
    ulong wallclock; /* last time we heard about this peer */
    ulong stake;
};
/* All peers table */
typedef struct fd_peer_elem fd_peer_elem_t;
#define MAP_NAME     fd_peer_table
#define MAP_KEY_T    fd_gossip_network_addr_t
#define MAP_KEY_EQ   fd_gossip_network_addr_eq
#define MAP_KEY_HASH fd_gossip_network_addr_hash
#define MAP_KEY_COPY fd_gossip_network_addr_copy
#define MAP_T        fd_peer_elem_t
#include "../../util/tmpl/fd_map_giant.c"

/* Active table element */
struct fd_active_elem {
    fd_gossip_network_addr_t key;
    ulong next;
    fd_pubkey_t id;  /* Public indentifier */
    long pingtime;   /* Last time we sent a ping */
    uint pingcount;  /* Number of pings it took to get a pong */
    fd_hash_t pingtoken;  /* Random data used in ping/pong */
    long pongtime;   /* Last time we received a pong */
};
/* Active table */
typedef struct fd_active_elem fd_active_elem_t;
#define MAP_NAME     fd_active_table
#define MAP_KEY_T    fd_gossip_network_addr_t
#define MAP_KEY_EQ   fd_gossip_network_addr_eq
#define MAP_KEY_HASH fd_gossip_network_addr_hash
#define MAP_KEY_COPY fd_gossip_network_addr_copy
#define MAP_T        fd_active_elem_t
#include "../../util/tmpl/fd_map_giant.c"

void
fd_active_new_value(fd_active_elem_t * val) {
  val->pingcount = 1;
  val->pingtime = val->pongtime = 0;
  fd_memset(val->id.uc, 0, 32U);
  fd_memset(val->pingtoken.uc, 0, 32U);
}

int fd_hash_eq( const fd_hash_t * key1, const fd_hash_t * key2 ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    if (key1->ul[i] != key2->ul[i])
      return 0;
  return 1;
}

ulong fd_hash_hash( const fd_hash_t * key, ulong seed ) {
  return key->ul[0] ^ seed;
}

void fd_hash_copy( fd_hash_t * keyd, const fd_hash_t * keys ) {
  for (ulong i = 0; i < 32U/sizeof(ulong); ++i)
    keyd->ul[i] = keys->ul[i];
}

/* Value table element */
struct fd_value_elem {
    fd_hash_t key;
    ulong next;
    fd_pubkey_t origin;
    ulong wallclock; /* Original timestamp of value */
    uchar * data;    /* Serialized form of value (bincode) */
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

/* Queue of pending timed events */
union fd_pending_event_arg {
    fd_gossip_network_addr_t key;
};
typedef union fd_pending_event_arg fd_pending_event_arg_t;
typedef void (*fd_pending_event_fun)(struct fd_gossip_global * glob, fd_pending_event_arg_t * arg, long now);
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

/* Data structure representing an active push destination */
struct fd_push_state {
    fd_gossip_network_addr_t addr; /* Destination address */
    fd_pubkey_t id;                /* Public indentifier */
    ulong drop_cnt;                /* Number of values dropped due to pruning */
    ulong prune_keys[FD_PRUNE_NUM_KEYS];     /* Keys used for bloom filter for pruning */
    ulong prune_bits[FD_PRUNE_NUM_BITS/64U]; /* Bits table used for bloom filter for pruning */
    uchar packet[FD_ETH_PAYLOAD_MAX]; /* Partially assembled packet containing a fd_gossip_push_msg_t */
    uchar * packet_end_init;       /* Initial end of the packet when there are zero values */
    uchar * packet_end;            /* Current end of the packet including values so far */
};
typedef struct fd_push_state fd_push_state_t;

/* Global data for gossip service */
struct fd_gossip_global {
    /* My public/private key */
    fd_gossip_credentials_t my_creds;
    /* My gossip port address */
    fd_gossip_network_addr_t my_addr;
    /* My official contact info in the gossip protocol */
    fd_gossip_contact_info_t my_contact_info;
    /* Function used to deliver gossip messages to the application */
    fd_gossip_data_deliver_fun deliver_fun;
    void * deliver_fun_arg;
    /* Socket file descriptor */
    int sockfd;
    /* Table of all known validators, keyed by gossip address */
    fd_peer_elem_t * peers;
    /* Table of validators that we are actively pinging, keyed by gossip address */
    fd_active_elem_t * actives;
    /* Queue of validators that might be added to actives */
    fd_gossip_network_addr_t * inactives;
    ulong inactives_cnt;
#define INACTIVES_MAX 1024U
    /* Table of crds values that we have received in the last 5 minutes, keys by hash */
    fd_value_elem_t * values;
    /* Array of push destinations currently in use */
    fd_push_state_t * push_states[FD_PUSH_LIST_MAX];
    ulong push_states_cnt;
    /* Queue of values that need pushing */
    fd_hash_t * need_push;
    ulong need_push_head;
    ulong need_push_cnt;
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
    /* Heap allocator */
    fd_valloc_t valloc;
};

ulong
fd_gossip_global_align ( void ) { return alignof(fd_gossip_global_t); }

ulong
fd_gossip_global_footprint( void ) { return sizeof(fd_gossip_global_t); }

void *
fd_gossip_global_new ( void * shmem, ulong seed, fd_valloc_t valloc ) {
  fd_memset(shmem, 0, sizeof(fd_gossip_global_t));
  fd_gossip_global_t * glob = (fd_gossip_global_t *)shmem;
  glob->seed = seed;
  glob->sockfd = -1;
  void * shm = fd_valloc_malloc(valloc, fd_peer_table_align(), fd_peer_table_footprint(FD_PEER_KEY_MAX));
  glob->peers = fd_peer_table_join(fd_peer_table_new(shm, FD_PEER_KEY_MAX, seed));
  shm = fd_valloc_malloc(valloc, fd_active_table_align(), fd_active_table_footprint(FD_ACTIVE_KEY_MAX));
  glob->actives = fd_active_table_join(fd_active_table_new(shm, FD_ACTIVE_KEY_MAX, seed));
  glob->inactives = (fd_gossip_network_addr_t*)fd_valloc_malloc(valloc, alignof(fd_gossip_network_addr_t), INACTIVES_MAX*sizeof(fd_gossip_network_addr_t));
  glob->need_push = (fd_hash_t*)fd_valloc_malloc(valloc, alignof(fd_hash_t), FD_NEED_PUSH_MAX*sizeof(fd_hash_t));
  shm = fd_valloc_malloc(valloc, fd_value_table_align(), fd_value_table_footprint(FD_VALUE_KEY_MAX));
  glob->values = fd_value_table_join(fd_value_table_new(shm, FD_VALUE_KEY_MAX, seed));
  shm = fd_valloc_malloc(valloc, fd_pending_pool_align(), fd_pending_pool_footprint(FD_PENDING_MAX));
  glob->event_pool = fd_pending_pool_join(fd_pending_pool_new(shm, FD_PENDING_MAX));
  shm = fd_valloc_malloc(valloc, fd_pending_heap_align(), fd_pending_heap_footprint(FD_PENDING_MAX));
  glob->event_heap = fd_pending_heap_join(fd_pending_heap_new(shm, FD_PENDING_MAX));
  fd_rng_new(glob->rng, (uint)seed, 0UL);
  return glob;
}

fd_gossip_global_t *
fd_gossip_global_join ( void * shmap ) { return (fd_gossip_global_t *)shmap; }

void *
fd_gossip_global_leave ( fd_gossip_global_t * join ) { return join; }

void *
fd_gossip_global_delete ( void * shmap, fd_valloc_t valloc ) {
  fd_gossip_global_t * glob = (fd_gossip_global_t *)shmap;
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
  return glob;
}

int
fd_gossip_to_soladdr( fd_gossip_socket_addr_t * dst, fd_gossip_network_addr_t const * src ) {
  dst->port = ntohs(src->port);
  if (src->family == AF_INET) {
    fd_gossip_ip_addr_new_disc(&dst->addr, fd_gossip_ip_addr_enum_ip4);
    dst->addr.inner.ip4 = src->addr[0];
    return 0;
  } else if (src->family == AF_INET6) {
    fd_gossip_ip_addr_new_disc(&dst->addr, fd_gossip_ip_addr_enum_ip6);
    dst->addr.inner.ip6.ul[0] = src->addr[0];
    dst->addr.inner.ip6.ul[1] = src->addr[1];
    dst->addr.inner.ip6.ul[2] = src->addr[2];
    dst->addr.inner.ip6.ul[3] = src->addr[3];
    return 0;
  } else {
    FD_LOG_ERR(("invalid address family"));
    errno = 0;
    return -1;
  }
}

int
fd_gossip_from_soladdr(fd_gossip_network_addr_t * dst, fd_gossip_socket_addr_t const * src ) {
  dst->port = htons(src->port);
  if (src->addr.discriminant == fd_gossip_ip_addr_enum_ip4) {
    dst->family = AF_INET;
    dst->addr[0] = src->addr.inner.ip4;
    return 0;
  } else if (src->addr.discriminant == fd_gossip_ip_addr_enum_ip6) {
    dst->family = AF_INET6;
    dst->addr[0] = src->addr.inner.ip6.ul[0];
    dst->addr[1] = src->addr.inner.ip6.ul[1];
    dst->addr[2] = src->addr.inner.ip6.ul[2];
    dst->addr[3] = src->addr.inner.ip6.ul[3];
    return 0;
  } else {
    FD_LOG_ERR(("invalid address family"));
    errno = 0;
    return -1;
  }
}

int
fd_gossip_to_sockaddr( uchar * dst, fd_gossip_network_addr_t const * src ) {
  if (src->family == AF_INET) {
    fd_memset(dst, 0, sizeof(struct sockaddr_in));
    struct sockaddr_in * t = (struct sockaddr_in *)dst;
    t->sin_family = AF_INET;
    t->sin_addr.s_addr = src->addr[0];
    t->sin_port = src->port;
    return sizeof(struct sockaddr_in);
  } else if (src->family == AF_INET6) {
    fd_memset(dst, 0, sizeof(struct sockaddr_in6));
    struct sockaddr_in6 * t = (struct sockaddr_in6 *)dst;
    t->sin6_family = AF_INET6;
    uint * u6_addr32 = t->sin6_addr.__in6_u.__u6_addr32;
    u6_addr32[0] = src->addr[0];
    u6_addr32[1] = src->addr[1];
    u6_addr32[2] = src->addr[2];
    u6_addr32[3] = src->addr[3];
    t->sin6_port = src->port;
    return sizeof(struct sockaddr_in6);
  } else {
    FD_LOG_ERR(("invalid address family"));
    errno = 0;
    return -1;
  }
}

const char * fd_gossip_addr_str( char * dst, size_t dstlen, fd_gossip_network_addr_t const * src ) {
  if (src->family == AF_INET) {
    char tmp[INET_ADDRSTRLEN];
    snprintf(dst, dstlen, "%s:%u", inet_ntop(AF_INET, src->addr, tmp, INET_ADDRSTRLEN), (uint)ntohs(src->port));
    return dst;
  } else if (src->family == AF_INET6) {
    char tmp[INET6_ADDRSTRLEN];
    snprintf(dst, dstlen, "%s:%u", inet_ntop(AF_INET6, src->addr, tmp, INET6_ADDRSTRLEN), (uint)ntohs(src->port));
    return dst;
  } else {
    return "???";
  }
}

int
fd_gossip_from_sockaddr( fd_gossip_network_addr_t * dst, uchar const * src ) {
  fd_memset(dst, 0, sizeof(fd_gossip_network_addr_t));
  dst->family = ((const struct sockaddr *)src)->sa_family;
  if (dst->family == AF_INET) {
    const struct sockaddr_in * sa = (const struct sockaddr_in *)src;
    dst->addr[0] = sa->sin_addr.s_addr;
    dst->port = sa->sin_port;
  } else if (dst->family == AF_INET6) {
    const struct sockaddr_in6 * sa = (const struct sockaddr_in6 *)src;
    const uint * u6_addr32 = sa->sin6_addr.__in6_u.__u6_addr32;
    dst->addr[0] = u6_addr32[0];
    dst->addr[1] = u6_addr32[1];
    dst->addr[2] = u6_addr32[2];
    dst->addr[3] = u6_addr32[3];
    dst->port = sa->sin6_port;
  } else {
    FD_LOG_WARNING(("unknown address family in packet"));
    return -1;
  }
  return 0;
}

int
fd_gossip_global_set_config( fd_gossip_global_t * glob, const fd_gossip_config_t * config ) {
  fd_memcpy(&glob->my_creds, &config->my_creds, sizeof(fd_gossip_config_t));
  fd_memcpy(&glob->my_contact_info.id.uc, config->my_creds.public_key.uc, 32U);
  fd_memcpy(&glob->my_addr, &config->my_addr, sizeof(fd_gossip_network_addr_t));
  fd_gossip_to_soladdr(&glob->my_contact_info.gossip, &config->my_addr);
  glob->my_contact_info.shred_version = config->shred_version;
  glob->deliver_fun = config->deliver_fun;
  glob->deliver_fun_arg = config->deliver_fun_arg;
  return 0;
}

fd_pending_event_t *
fd_gossip_add_pending( fd_gossip_global_t * glob, long when ) {
  fd_pending_event_t * ev = fd_pending_pool_ele_acquire( glob->event_pool );
  if (ev == NULL)
    return NULL;
  ev->key = when;
  fd_pending_heap_ele_insert( glob->event_heap, ev, glob->event_pool );
  return ev;
}

void
fd_gossip_send_raw( fd_gossip_global_t * glob, fd_gossip_network_addr_t * dest, void * data, size_t sz) {
  uchar saddr[sizeof(struct sockaddr_in6)];
  int saddrlen = fd_gossip_to_sockaddr(saddr, dest);
  if ( saddrlen < 0 )
    return;
  if ( sz > PACKET_DATA_SIZE )
    FD_LOG_ERR(("sending oversized packet, size=%lu", sz));
  if ( sendto(glob->sockfd, data, sz, MSG_DONTWAIT,
              (const struct sockaddr *)saddr, (socklen_t)saddrlen) < 0 ) {
    FD_LOG_WARNING(("sendto failed: %s", strerror(errno)));
  }
}

void
fd_gossip_send( fd_gossip_global_t * glob, fd_gossip_network_addr_t * dest, fd_gossip_msg_t * gmsg ) {
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
  char tmp[100];
  FD_LOG_NOTICE(("sent msg type %d to %s size=%lu", gmsg->discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), dest), sz));
}

void
fd_gossip_make_ping( fd_gossip_global_t * glob, fd_pending_event_arg_t * arg, long now ) {
  fd_gossip_network_addr_t * key = &arg->key;
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
    if (val->pingcount++ == 5U) {
      /* Give up. This is a bad peer. */
      fd_active_table_remove(glob->actives, key);
      fd_peer_table_remove(glob->peers, key);
      return;
    }
  }
  val->pingtime = now;
  /* Generate a new token when we start a fresh round of pinging */
  if (val->pingcount == 1U) {
    for ( ulong i = 0; i < FD_HASH_FOOTPRINT / sizeof(ulong); ++i )
      val->pingtoken.ul[i] = fd_rng_ulong(glob->rng);
  }

  /* Keep pinging until we succeed */ 
  fd_pending_event_t * ev = fd_gossip_add_pending( glob, now + (long)2e8 /* 200 ms */ );
  if (ev != NULL) {
    ev->fun = fd_gossip_make_ping;
    fd_memcpy(&ev->fun_arg.key, key, sizeof(fd_gossip_network_addr_t));
  }

  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_ping);
  fd_gossip_ping_t * ping = &gmsg.inner.ping;
  fd_memcpy( ping->from.uc, glob->my_creds.public_key.uc, 32UL );
  fd_memcpy( ping->token.uc, val->pingtoken.uc, 32UL );

  /* Sign */
  fd_sha512_t sha[1];
  fd_ed25519_sign( /* sig */ ping->signature.uc,
                   /* msg */ ping->token.uc,
                   /* sz  */ 32UL,
                   /* public_key  */ glob->my_creds.public_key.uc,
                   /* private_key */ glob->my_creds.private_key,
                   sha );

  fd_gossip_send( glob, key, &gmsg );
}

void
fd_gossip_handle_ping( fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_ping_t const * ping ) {
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

  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_pong);
  fd_gossip_ping_t * pong = &gmsg.inner.pong;

  fd_memcpy( pong->from.uc, glob->my_creds.public_key.uc, 32UL );

  /* Generate response hash token */
  fd_sha256_t sha[1];
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, ping->token.uc,     32UL );
  fd_sha256_fini( sha, pong->token.uc );

  /* Sign */
  fd_ed25519_sign( /* sig */ pong->signature.uc,
                   /* msg */ pong->token.uc,
                   /* sz  */ 32UL,
                   /* public_key  */ glob->my_creds.public_key.uc,
                   /* private_key */ glob->my_creds.private_key,
                   sha2 );

  fd_gossip_send(glob, from, &gmsg);
}

void
fd_gossip_sign_crds_value( fd_gossip_global_t * glob, fd_crds_value_t * value ) {
  uchar buf[FD_ETH_PAYLOAD_MAX];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
  if ( fd_crds_data_encode( &value->data, &ctx ) ) {
    FD_LOG_WARNING(("fd_crds_data_encode failed"));
    return;
  }
  fd_sha512_t sha[1];
  fd_ed25519_sign( /* sig */ value->signature.uc,
                   /* msg */ buf,
                   /* sz  */ (ulong)((uchar*)ctx.data - buf),
                   /* public_key  */ glob->my_creds.public_key.uc,
                   /* private_key */ glob->my_creds.private_key,
                   sha );
}

static ulong
  fd_gossip_bloom_pos( fd_hash_t * hash, ulong key, ulong nbits) {
  for ( ulong i = 0; i < 32U; ++i) {
    key ^= (ulong)(hash->uc[i]);
    key *= 1099511628211UL;
  }
  return key % nbits;
}

/* Chooose a random active peer with good ping count */
fd_active_elem_t *
fd_gossip_random_active( fd_gossip_global_t * glob ) {
  /* Look for a random element with a low ping count */
  fd_active_elem_t * list[FD_ACTIVE_KEY_MAX];
  ulong listlen = 0;
  for( fd_active_table_iter_t iter = fd_active_table_iter_init( glob->actives );
       !fd_active_table_iter_done( glob->actives, iter );
       iter = fd_active_table_iter_next( glob->actives, iter ) ) {
    fd_active_elem_t * ele = fd_active_table_iter_ele( glob->actives, iter );
    if (ele->pongtime == 0) {
      continue;
    } else if (listlen == 0) {
      list[0] = ele;
      listlen = 1;
    } else if (ele->pingcount > list[0]->pingcount) {
      continue;
    } else if (ele->pingcount < list[0]->pingcount) {
      list[0] = ele;
      listlen = 1;
    } else {
      list[listlen++] = ele;
    }
  }
  if (listlen == 0)
    return NULL;
  // FD_LOG_NOTICE(("choosing from %lu with pingcount %lu", listlen, list[0]->pingcount));
  return list[fd_rng_ulong(glob->rng) % listlen];
}

void
fd_gossip_random_pull( fd_gossip_global_t * glob, fd_pending_event_arg_t * arg, long now ) {
  (void)arg;

  /* Try again in 5 sec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, now + (long)5e9);
  if (ev) {
    ev->fun = fd_gossip_random_pull;
  }

  /* Pick a random partner */
  fd_active_elem_t * ele = fd_gossip_random_active(glob);
  if (ele == NULL)
    return;

  /* Compute the number of packets */
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
  FD_LOG_NOTICE(("making bloom filter for %lu items with %lu packets and %lu keys %g error\n", nitems, npackets, nkeys, e));

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
  ulong expire = (ulong)(now / (long)1e6) - FD_GOSSIP_VALUE_EXPIRE;
  for( fd_value_table_iter_t iter = fd_value_table_iter_init( glob->values );
       !fd_value_table_iter_done( glob->values, iter );
       iter = fd_value_table_iter_next( glob->values, iter ) ) {
    fd_value_elem_t * ele = fd_value_table_iter_ele( glob->values, iter );
    fd_hash_t * hash = &(ele->key);
    if (ele->wallclock < expire) {
      fd_valloc_free( glob->valloc, ele->data );
      fd_value_table_remove( glob->values, hash );
      continue;
    }
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
  struct fd_gossip_bitvec_u64_inner bitsbits;
  bitvec->bits = &bitsbits;
  bitvec->len = FD_BLOOM_NUM_BITS;
  bitsbits.vec_len = FD_BLOOM_NUM_BITS/64U;

  fd_crds_value_t * value = &req->value;
  fd_crds_data_new_disc(&value->data, fd_crds_data_enum_contact_info);
  fd_gossip_contact_info_t * ci = &value->data.inner.contact_info;
  fd_memcpy(ci, &glob->my_contact_info, sizeof(fd_gossip_contact_info_t));
  ci->wallclock = (ulong)now/1000000; /* convert to ms */
  fd_gossip_sign_crds_value(glob, value);

  for (uint i = 0; i < npackets; ++i) {
    filter->mask = (nmaskbits == 0 ? ~0UL : ((i << (64U - nmaskbits)) | (~0UL >> nmaskbits)));
    filter->filter.num_bits_set = num_bits_set[i];
    bitsbits.vec = bits + (i*CHUNKSIZE);
    fd_gossip_send(glob, &ele->key, &gmsg);
  }
}

void
fd_gossip_handle_pong( fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_ping_t const * pong, long now ) {
  fd_active_elem_t * val = fd_active_table_query(glob->actives, from, NULL);
  if (val == NULL) {
    FD_LOG_NOTICE(("received pong too late"));
    return;
  }

  /* Confirm response hash token */
  fd_sha256_t sha[1];
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, val->pingtoken.uc,  32UL );
  fd_hash_t pongtoken;
  fd_sha256_fini( sha, pongtoken.uc );
  if (memcmp(pongtoken.uc, pong->token.uc, 32UL) != 0) {
    FD_LOG_WARNING(("received pong with wrong token"));
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
  
  val->pongtime = now;
  fd_memcpy(val->id.uc, pong->from.uc, 32U);

  /* Remember that this is a good peer */
  fd_peer_elem_t * peerval = fd_peer_table_query(glob->peers, from, NULL);
  if (peerval == NULL) {
    if (fd_peer_table_is_full(glob->peers)) {
      FD_LOG_WARNING(("too many peers"));
      return;
    }
    peerval = fd_peer_table_insert(glob->peers, from);
    peerval->stake = 0;
  }
  peerval->wallclock = (ulong)(now / (long)1e6); /* In millisecs */
  fd_memcpy(peerval->id.uc, pong->from.uc, 32U);
}

void
fd_gossip_random_ping( fd_gossip_global_t * glob, fd_pending_event_arg_t * arg, long now ) {
  (void)arg;

  /* Try again in 1 sec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, now + (long)1e9);
  if (ev) {
    ev->fun = fd_gossip_random_ping;
  }

  ulong cnt = fd_active_table_key_cnt(glob->actives);
  if (cnt == 0)
    return;
  fd_gossip_network_addr_t * addr = NULL;
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
        if (now - ele->pingtime < (long)60e9) /* minute cooldown */
          return;
        ele->pingcount = 0;
        ele->pongtime = 0;
        addr = &(ele->key);
        break;
      }
    }
  }

  fd_pending_event_arg_t arg2;
  fd_memcpy(&arg2.key, addr, sizeof(fd_gossip_network_addr_t));
  fd_gossip_make_ping(glob, &arg2, now);
}

void
fd_gossip_recv_crds_value(fd_gossip_global_t * glob, fd_pubkey_t * pubkey, fd_crds_value_t* crd, long now) {
  /* Verify the signature */
  ulong wallclock;
  switch (crd->data.discriminant) {
  case fd_crds_data_enum_contact_info:
    pubkey = &crd->data.inner.contact_info.id;
    wallclock = crd->data.inner.contact_info.wallclock;
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
  case fd_crds_data_enum_legacy_version:
    pubkey = &crd->data.inner.legacy_version.from;
    wallclock = crd->data.inner.legacy_version.wallclock;
    break;
  case fd_crds_data_enum_version:
    pubkey = &crd->data.inner.version.from;
    wallclock = crd->data.inner.version.wallclock;
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
    wallclock = (ulong)(now / (long)1e6); /* In millisecs */
    break;
  }
  if (memcmp(pubkey->uc, glob->my_creds.public_key.uc, 32U) == 0)
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
    FD_LOG_WARNING(("received crds_value with invalid signature"));
    return;
  }

  /* Perform the value hash */
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

  /* Store the value */
  fd_value_elem_t * msg = fd_value_table_query(glob->values, &key, NULL);
  if (msg != NULL) {
    /* Already have this value */
    glob->recv_dup_cnt++;
    return;
  }
  glob->recv_nondup_cnt++;
  if (fd_value_table_is_full(glob->values)) {
    FD_LOG_WARNING(("too many values"));
    return;
  }
  msg = fd_value_table_insert(glob->values, &key);
  msg->wallclock = wallclock;
  fd_memcpy(msg->origin.uc, pubkey->uc, 32U);
  msg->data = fd_valloc_malloc(glob->valloc, 1U, datalen);
  fd_memcpy(msg->data, buf, datalen);
  msg->datalen = datalen;

  if (glob->need_push_cnt < FD_NEED_PUSH_MAX) {
    /* Remember that I need to push this value */
    ulong i = ((glob->need_push_head + (glob->need_push_cnt++)) & (FD_NEED_PUSH_MAX-1U));
    fd_memcpy(glob->need_push + i, &key, sizeof(key));
  }

  if (crd->data.discriminant == fd_crds_data_enum_contact_info) {
    fd_gossip_contact_info_t * info = &crd->data.inner.contact_info;
    if (info->gossip.port != 0) {
      /* Remember the peer */
      fd_gossip_network_addr_t pkey;
      fd_memset(&pkey, 0, sizeof(pkey));
      fd_gossip_from_soladdr(&pkey, &info->gossip);
      fd_peer_elem_t * val = fd_peer_table_query(glob->peers, &pkey, NULL);
      if (val == NULL) {
        if (fd_peer_table_is_full(glob->peers)) {
          FD_LOG_WARNING(("too many peers"));
        } else {
          val = fd_peer_table_insert(glob->peers, &pkey);
          if (glob->inactives_cnt < INACTIVES_MAX &&
              fd_active_table_query(glob->actives, &pkey, NULL) == NULL) {
            /* Queue this peer for potential active status */
            fd_memcpy(glob->inactives + (glob->inactives_cnt++), &pkey, sizeof(pkey));
          }
        }
      }
      if (val != NULL) {
        val->wallclock = wallclock;
        val->stake = 0;
        fd_memcpy(val->id.uc, info->id.uc, 32U);
      }
    }
  }

  /* Deliver the data upstream */
  (*glob->deliver_fun)(&crd->data, glob->deliver_fun_arg, now);
}

void
fd_gossip_handle_prune(fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_prune_msg_t * msg) {
  (void)from;

  if (memcmp(msg->data.destination.uc, glob->my_creds.public_key.uc, 32U) != 0)
    return;

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
}

void
fd_gossip_handle_pull_req(fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_pull_req_t * msg, long now) {
  fd_active_elem_t * val = fd_active_table_query(glob->actives, from, NULL);
  if (val == NULL || val->pongtime == 0) {
    /* Ping new peers before responding to requests */
    fd_pending_event_arg_t arg2;
    fd_memcpy(&arg2.key, from, sizeof(fd_gossip_network_addr_t));
    fd_gossip_make_ping(glob, &arg2, now);
    return;
  }

  /* Encode an empty pull response as a template */
  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_pull_resp);
  fd_gossip_pull_resp_t * pull_resp = &gmsg.inner.pull_resp;
  fd_memcpy( pull_resp->pubkey.uc, glob->my_creds.public_key.uc, 32UL );

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

  fd_crds_filter_t * filter = &msg->filter;
  ulong nkeys = filter->filter.keys_len;
  ulong * keys = filter->filter.keys;
  fd_gossip_bitvec_u64_t * bitvec = &filter->filter.bits;
  ulong * bitvec2 = bitvec->bits->vec;
  ulong expire = (ulong)(now / (long)1e6) - FD_GOSSIP_PULL_TIMEOUT;
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
      FD_LOG_NOTICE(("sent msg type %d to %s size=%lu", gmsg.discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), from), sz));
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
    FD_LOG_NOTICE(("sent msg type %d to %s size=%lu", gmsg.discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), from), sz));
    ++npackets;
  }

  if (misses)
    FD_LOG_NOTICE(("responded to pull request with %lu values in %u packets (%lu filtered out)", misses, npackets, hits));
}

void
fd_gossip_recv(fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_msg_t * gmsg, long now) {
  switch (gmsg->discriminant) {
  case fd_gossip_msg_enum_pull_req:
    fd_gossip_handle_pull_req(glob, from, &gmsg->inner.pull_req, now);
    break;
  case fd_gossip_msg_enum_pull_resp: {
    fd_gossip_pull_resp_t * pull_resp = &gmsg->inner.pull_resp;
    for (ulong i = 0; i < pull_resp->crds_len; ++i)
      fd_gossip_recv_crds_value(glob, &pull_resp->pubkey, pull_resp->crds + i, now);
    break;
  }
  case fd_gossip_msg_enum_push_msg: {
    fd_gossip_push_msg_t * push_msg = &gmsg->inner.push_msg;
    for (ulong i = 0; i < push_msg->crds_len; ++i)
      fd_gossip_recv_crds_value(glob, &push_msg->pubkey, push_msg->crds + i, now);
    break;
  }
  case fd_gossip_msg_enum_prune_msg:
    fd_gossip_handle_prune(glob, from, &gmsg->inner.prune_msg);
    break;
  case fd_gossip_msg_enum_ping:
    fd_gossip_handle_ping(glob, from, &gmsg->inner.ping);
    break;
  case fd_gossip_msg_enum_pong:
    fd_gossip_handle_pong(glob, from, &gmsg->inner.pong, now);
    break;
  }
}

int
fd_gossip_add_active_peer( fd_gossip_global_t * glob, fd_gossip_network_addr_t * addr ) {
  fd_active_elem_t * val = fd_active_table_query(glob->actives, addr, NULL);
  if (val == NULL) {
    if (fd_active_table_is_full(glob->actives)) {
      FD_LOG_WARNING(("too many actives"));
      return -1;
    }
    val = fd_active_table_insert(glob->actives, addr);
    fd_active_new_value(val);
    val->pingcount = 0; /* Incremented in fd_gossip_make_ping */
  }
  return 0;
}

void
fd_gossip_refresh_push_states( fd_gossip_global_t * glob, fd_pending_event_arg_t * arg, long now ) {
  (void)arg;

  /* Try again in 20 sec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, now + (long)20e9);
  if (ev) {
    ev->fun = fd_gossip_refresh_push_states;
  }

  /* Delete states which no longer have active peers */
  for (ulong i = 0; i < glob->push_states_cnt; ++i) {
    fd_push_state_t* s = glob->push_states[i];
    if (fd_active_table_query(glob->actives, &s->addr, NULL) == NULL) {
      fd_valloc_free(glob->valloc, s);
      /* Replace with the one at the end */
      glob->push_states[i] = glob->push_states[--(glob->push_states_cnt)];
    }
  }
  if (glob->push_states_cnt == FD_PUSH_LIST_MAX) {
    /* Delete the worst destination */
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

  /* Make a list of actives that we are not pushing to */
  fd_active_elem_t * list[FD_ACTIVE_KEY_MAX];
  ulong listlen = 0;
  for( fd_active_table_iter_t iter = fd_active_table_iter_init( glob->actives );
       !fd_active_table_iter_done( glob->actives, iter );
       iter = fd_active_table_iter_next( glob->actives, iter ) ) {
    fd_active_elem_t * ele = fd_active_table_iter_ele( glob->actives, iter );
    for (ulong i = 0; i < glob->push_states_cnt; ++i) {
      fd_push_state_t* s = glob->push_states[i];
      if (fd_gossip_network_addr_eq(&s->addr, &ele->key))
        goto skipadd;
    }
    list[listlen++] = ele;
    skipadd: ;
  }

  /* Add random actives as new pushers */
  while (listlen > 0 && glob->push_states_cnt < FD_PUSH_LIST_MAX) {
    ulong i = fd_rng_ulong(glob->rng) % listlen;
    fd_active_elem_t * a = list[i];
    list[i] = list[--listlen];

    fd_push_state_t * s = (fd_push_state_t *)fd_valloc_malloc(glob->valloc, alignof(fd_push_state_t), sizeof(fd_push_state_t));
    fd_memset(s, 0, sizeof(fd_push_state_t));
    fd_memcpy(&s->addr, &a->key, sizeof(fd_gossip_network_addr_t));
    fd_memcpy(&s->id, &a->id, sizeof(fd_pubkey_t));
    for (ulong j = 0; j < FD_PRUNE_NUM_KEYS; ++j)
      s->prune_keys[j] = fd_rng_ulong(glob->rng);

    /* Encode an empty ushas a template */
    fd_gossip_msg_t gmsg;
    fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_push_msg);
    fd_gossip_push_msg_t * push_msg = &gmsg.inner.push_msg;
    fd_memcpy( push_msg->pubkey.uc, glob->my_creds.public_key.uc, 32UL );
    fd_bincode_encode_ctx_t ctx;
    ctx.data = s->packet;
    ctx.dataend = s->packet + FD_ETH_PAYLOAD_MAX;
    if ( fd_gossip_msg_encode( &gmsg, &ctx ) ) {
      FD_LOG_WARNING(("fd_gossip_msg_encode failed"));
      return;
    }
    s->packet_end_init = s->packet_end = (uchar *)ctx.data;

    glob->push_states[glob->push_states_cnt++] = s;
  }
}

void
fd_gossip_log_stats( fd_gossip_global_t * glob, fd_pending_event_arg_t * arg, long now ) {
  (void)arg;

  /* Try again in 60 sec */
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, now + (long)60e9);
  if (ev) {
    ev->fun = fd_gossip_log_stats;
  }

  FD_LOG_NOTICE(("received %lu dup values and %lu new", glob->recv_dup_cnt, glob->recv_nondup_cnt));
  glob->recv_dup_cnt = glob->recv_nondup_cnt = 0;

  int need_inactive = (glob->inactives_cnt == 0);
  
  ulong wc = (ulong)(now / (long)1e6);
  ulong expire = wc - 4U*FD_GOSSIP_VALUE_EXPIRE;
  for( fd_peer_table_iter_t iter = fd_peer_table_iter_init( glob->peers );
       !fd_peer_table_iter_done( glob->peers, iter );
       iter = fd_peer_table_iter_next( glob->peers, iter ) ) {
    fd_peer_elem_t * ele = fd_peer_table_iter_ele( glob->peers, iter );
    if (ele->wallclock < expire) {
      fd_peer_table_remove( glob->peers, &ele->key );
      continue;
    }
    fd_active_elem_t * act = fd_active_table_query(glob->actives, &ele->key, NULL);
    char buf[100];
    FD_LOG_NOTICE(("peer at %s id %32J age %.3f %s",
                   fd_gossip_addr_str(buf, sizeof(buf), &ele->key),
                   ele->id.uc,
                   ((double)(wc - ele->wallclock))*0.001,
                   ((act != NULL && act->pongtime != 0) ? "(active)" : "")));
    if (need_inactive && act == NULL && glob->inactives_cnt < INACTIVES_MAX)
      fd_memcpy(glob->inactives + (glob->inactives_cnt++), &ele->key, sizeof(ele->key));
  }
}

/* Main loop for socket reading/writing. Does not return until stopflag is non-zero */
int
fd_gossip_main_loop( fd_gossip_global_t * glob, fd_valloc_t valloc, volatile int * stopflag ) {
  glob->valloc = valloc;
  
  int fd;
  if ((fd = socket(glob->my_addr.family, SOCK_DGRAM, 0)) < 0) {
    FD_LOG_ERR(("socket failed: %s", strerror(errno)));
    return -1;
  }
  glob->sockfd = fd;
  int optval = 1<<20;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&optval, sizeof(int)) < 0) {
    FD_LOG_ERR(("setsocketopt failed: %s", strerror(errno)));
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&optval, sizeof(int)) < 0) {
    FD_LOG_ERR(("setsocketopt failed: %s", strerror(errno)));
    return -1;
  }
  uchar saddr[sizeof(struct sockaddr_in6)];
  int saddrlen = fd_gossip_to_sockaddr(saddr, &glob->my_addr);
  if (saddrlen < 0 || bind(fd, (struct sockaddr*)saddr, (uint)saddrlen) < 0) {
    FD_LOG_ERR(("bind failed: %s", strerror(errno)));
    return -1;
  }

  /* Start pulling and pinging on a timer */
  long now = fd_log_wallclock();
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, now + (long)1e9);
  ev->fun = fd_gossip_random_pull;
  ev = fd_gossip_add_pending(glob, now + (long)5e9);
  ev->fun = fd_gossip_random_ping;
  ev = fd_gossip_add_pending(glob, now + (long)60e9);
  ev->fun = fd_gossip_log_stats;
  ev = fd_gossip_add_pending(glob, now + (long)20e9);
  ev->fun = fd_gossip_refresh_push_states;

#define VLEN 32U
  struct mmsghdr msgs[VLEN];
  struct iovec iovecs[VLEN];
  uchar bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof(struct sockaddr_in6)]; /* sockaddr is smaller than sockaddr_in6 */

  while ( !*stopflag ) {
    if (fd_active_table_key_cnt(glob->actives) == 0) {
      FD_LOG_WARNING(("protocol failure, no active peers"));
      break;
    }
    
    fd_memset(msgs, 0, sizeof(msgs));
    for (uint i = 0; i < VLEN; i++) {
      iovecs[i].iov_base          = bufs[i];
      iovecs[i].iov_len           = FD_ETH_PAYLOAD_MAX;
      msgs[i].msg_hdr.msg_iov     = &iovecs[i];
      msgs[i].msg_hdr.msg_iovlen  = 1;
      msgs[i].msg_hdr.msg_name    = sockaddrs[i];
      msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
    }

    /* Execute pending timed events */
    now = fd_log_wallclock();
    do {
      fd_pending_event_t * ev = fd_pending_heap_ele_peek_min( glob->event_heap, glob->event_pool );
      if (ev == NULL || ev->key > now)
        break;
      fd_pending_event_t evcopy;
      fd_memcpy(&evcopy, ev, sizeof(evcopy));
      fd_pending_heap_ele_remove_min( glob->event_heap, glob->event_pool );
      fd_pending_pool_ele_release( glob->event_pool, ev );
      (*evcopy.fun)(glob, &evcopy.fun_arg, now);
    } while (1);

    /* Read more packets */
    int retval = recvmmsg(fd, msgs, VLEN, MSG_DONTWAIT, NULL);
    if (retval < 0) {
      if (errno == EINTR || errno == EWOULDBLOCK)
        continue;
      FD_LOG_ERR(("recvmmsg failed: %s", strerror(errno)));
      return -1;
    }
    if (retval == 0)
      continue;
    now = fd_log_wallclock();

    for (uint i = 0; i < (uint)retval; ++i) {
      // Get the source addr
      fd_gossip_network_addr_t from;
      if ( fd_gossip_from_sockaddr( &from, msgs[i].msg_hdr.msg_name ) )
        continue;

      fd_gossip_msg_t gmsg;
      fd_gossip_msg_new(&gmsg);
      fd_bincode_decode_ctx_t ctx;
      ctx.data    = bufs[i];
      ctx.dataend = bufs[i] + msgs[i].msg_len;
      ctx.valloc  = valloc;
      if (fd_gossip_msg_decode(&gmsg, &ctx)) {
        FD_LOG_WARNING(("corrupt gossip message"));
        continue;
      }
      if (ctx.data != ctx.dataend) {
        FD_LOG_WARNING(("corrupt gossip message"));
        continue;
      }

      char tmp[100];
      FD_LOG_DEBUG(("recv msg type %d from %s", gmsg.discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), &from)));
                       
      fd_gossip_recv(glob, &from, &gmsg, now);

      fd_bincode_destroy_ctx_t ctx2;
      ctx2.valloc = valloc;
      fd_gossip_msg_destroy(&gmsg, &ctx2);
    }
  }

  close(fd);
  glob->sockfd = -1;
  return 0;
}
