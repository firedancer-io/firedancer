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

#pragma GCC diagnostic ignored "-Wstrict-aliasing"

#define FD_GOSSIP_NETWORK_ADDR_NLONGS (sizeof(fd_gossip_network_addr_t)/sizeof(ulong))

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
    fd_pubkey_t id;
    ulong wallclock; /* last time we heard about this peer */
    ulong stake;
};
/* All peer table */
typedef struct fd_peer_elem fd_peer_elem_t;
#define MAP_NAME     fd_peer_table
#define MAP_KEY_T    fd_gossip_network_addr_t
#define MAP_KEY_EQ   fd_gossip_network_addr_eq
#define MAP_KEY_HASH fd_gossip_network_addr_hash
#define MAP_KEY_COPY fd_gossip_network_addr_copy
#define MAP_T        fd_peer_elem_t
#include "../../util/tmpl/fd_map_giant.c"
#define FD_PEER_KEY_MAX (1<<14)

/* Active table element */
struct fd_active_elem {
    fd_gossip_network_addr_t key;
    ulong next;
    fd_pubkey_t id;
    long pingtime;
    uint pingcount;
    fd_hash_t pingtoken;
    long pongtime;
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
#define FD_ACTIVE_KEY_MAX (1<<8)

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

/* Message table element */
struct fd_message_elem {
    fd_hash_t key;
    ulong next;
    ulong wallclock;
    uchar * data;
    ulong datalen;
};
/* Message table */
typedef struct fd_message_elem fd_message_elem_t;
#define MAP_NAME     fd_message_table
#define MAP_KEY_T    fd_hash_t
#define MAP_KEY_EQ   fd_hash_eq
#define MAP_KEY_HASH fd_hash_hash
#define MAP_KEY_COPY fd_hash_copy
#define MAP_T        fd_message_elem_t
#include "../../util/tmpl/fd_map_giant.c"
#define FD_MESSAGE_KEY_MAX (1<<15)

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
#define FD_PENDING_MAX (1<<9)

/* Global data for gossip service */
struct fd_gossip_global {
    fd_gossip_credentials_t my_creds;
    fd_gossip_network_addr_t my_addr;
    fd_gossip_contact_info_t my_contact_info;
    ulong seed;
    fd_gossip_data_deliver_fun deliver_fun;
    void * deliver_fun_arg;
    int sockfd;
    fd_peer_elem_t * peers;
    fd_active_elem_t * actives;
    fd_gossip_network_addr_t * inactives;
    ulong inactives_cnt;
#define INACTIVES_MAX 1024U
    fd_message_elem_t * messages;
    fd_pending_event_t * event_pool;
    fd_pending_heap_t * event_heap;
    fd_rng_t rng[1];
    int got_pull_resp;
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
  glob->inactives_cnt = 0;
  shm = fd_valloc_malloc(valloc, fd_message_table_align(), fd_message_table_footprint(FD_MESSAGE_KEY_MAX));
  glob->messages = fd_message_table_join(fd_message_table_new(shm, FD_MESSAGE_KEY_MAX, seed));
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
  for( fd_message_table_iter_t iter = fd_message_table_iter_init( glob->messages );
       !fd_message_table_iter_done( glob->messages, iter );
       iter = fd_message_table_iter_next( glob->messages, iter ) ) {
    fd_message_elem_t * ele = fd_message_table_iter_ele( glob->messages, iter );
    fd_valloc_free(valloc, ele->data);
  }
  fd_valloc_free(valloc, fd_message_table_delete(fd_message_table_leave(glob->messages)));
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
fd_gossip_global_set_config( fd_gossip_global_t * glob, const fd_gossip_config_t * config ) {
  fd_memcpy(&glob->my_creds, &config->my_creds, sizeof(fd_gossip_config_t));
  fd_memcpy(&glob->my_contact_info.id.uc, config->my_creds.public_key.uc, 32U);
  fd_memcpy(&glob->my_addr, &config->my_addr, sizeof(fd_gossip_network_addr_t));
  fd_gossip_to_soladdr(&glob->my_contact_info.gossip, &config->my_addr);
  glob->deliver_fun = config->deliver_fun;
  glob->deliver_fun_arg = config->deliver_fun_arg;
  return 0;
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
fd_gossip_send( fd_gossip_global_t * glob, fd_gossip_network_addr_t * dest, fd_gossip_msg_t * gmsg ) {
  uchar buf[FD_ETH_PAYLOAD_MAX];
  fd_bincode_encode_ctx_t ctx;
  ctx.data = buf;
  ctx.dataend = buf + FD_ETH_PAYLOAD_MAX;
  if ( fd_gossip_msg_encode( gmsg, &ctx ) ) {
    FD_LOG_WARNING(("fd_gossip_msg_encode failed"));
    return;
  }
  uchar saddr[sizeof(struct sockaddr_in6)];
  int saddrlen = fd_gossip_to_sockaddr(saddr, dest);
  if ( saddrlen < 0 )
    return;
  if ( sendto(glob->sockfd, buf, (size_t)((const uchar *)ctx.data - buf), MSG_DONTWAIT,
              (const struct sockaddr *)saddr, (socklen_t)saddrlen) < 0 ) {
    FD_LOG_WARNING(("sendto failed: %s", strerror(errno)));
  }

  char tmp[100];
  FD_LOG_NOTICE(("sent msg type %d to %s", gmsg->discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), dest)));
}

void
fd_gossip_make_ping( fd_gossip_global_t * glob, fd_pending_event_arg_t * arg, long now ) {
  fd_gossip_network_addr_t * key = &arg->key;
  fd_active_elem_t * val = fd_active_table_query(glob->actives, key, NULL);
  if (val == NULL) {
    val = fd_active_table_insert(glob->actives, key);
    if (val == NULL) {
      FD_LOG_WARNING(("too many actives"));
      return;
    }
    val->pingcount = 1;
    val->pongtime = 0;
    fd_memset(val->id.uc, 0, 32U);
  } else
    val->pingcount++;
  val->pingtime = now;

  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_ping);
  fd_gossip_ping_t * ping = &gmsg.inner.ping;

  fd_memcpy( ping->from.uc, glob->my_creds.public_key.uc, 32UL );

  for ( ulong i = 0; i < FD_HASH_FOOTPRINT / sizeof(ulong); ++i )
    ping->token.ul[i] = val->pingtoken.ul[i] = fd_rng_ulong(glob->rng);

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

void
fd_gossip_first_pull( fd_gossip_global_t * glob, fd_pending_event_arg_t * arg, long now ) {
  if (glob->got_pull_resp)
    return;

  /* Try again in 100 ms */
  fd_gossip_network_addr_t * key = &arg->key;
  fd_pending_event_t * ev = fd_gossip_add_pending(glob, now + (long)1e8);
  if (ev) {
    ev->fun = fd_gossip_first_pull;
    fd_memcpy(&ev->fun_arg.key, key, sizeof(fd_gossip_network_addr_t));
  }

  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_pull_req);
  fd_gossip_pull_req_t * req = &gmsg.inner.pull_req;
  fd_crds_filter_t * filter = &req->filter;
  filter->mask = ~0UL;
  filter->mask_bits = 0;
  static const ulong keys[1] = {0};
  filter->filter.keys_len = 1;
  filter->filter.keys = (ulong*)keys;
  filter->filter.num_bits_set = 0;
  fd_gossip_bitvec_u64_t * bits = &filter->filter.bits;
  struct fd_gossip_bitvec_u64_inner bitsbits;
  bits->bits = &bitsbits;
  bits->len = 64;
  bitsbits.vec_len = 1;
  static const ulong bv[1] = {0};
  bitsbits.vec = (ulong*)bv;

  fd_crds_value_t * value = &req->value;
  fd_crds_data_new_disc(&value->data, fd_crds_data_enum_contact_info);
  fd_gossip_contact_info_t * ci = &value->data.inner.contact_info;
  fd_memcpy(ci, &glob->my_contact_info, sizeof(fd_gossip_contact_info_t));
  ci->wallclock = (ulong)now/1000000; /* convert to ms */
  fd_gossip_sign_crds_value(glob, value);

  fd_gossip_send(glob, key, &gmsg);
}

void
fd_gossip_handle_pong( fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_ping_t const * pong, long now ) {
  fd_active_elem_t * val = fd_active_table_query(glob->actives, from, NULL);
  if (val == NULL) {
    FD_LOG_WARNING(("received unsolicited pong"));
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
  val->pingcount = 0; /* Start count over next time */
  fd_memcpy(val->id.uc, pong->from.uc, 32U);

  /* Trigger the first pull request */
  if (!glob->got_pull_resp) {
    fd_pending_event_t * ev = fd_gossip_add_pending(glob, 0 /* ASAP */);
    if (ev) {
      ev->fun = fd_gossip_first_pull;
      fd_memcpy(&ev->fun_arg.key, from, sizeof(fd_gossip_network_addr_t));
    }
  }
  /* Remember that this is a good peer */
  fd_peer_elem_t * peerval = fd_peer_table_query(glob->peers, from, NULL);
  if (peerval == NULL) {
    peerval = fd_peer_table_insert(glob->peers, from);
    if (peerval == NULL) {
      FD_LOG_WARNING(("too many peers"));
      return;
    }
    peerval->stake = 0;
  }
  peerval->wallclock = (ulong)(now / (long)1e6); /* In millisecs */
  fd_memcpy(peerval->id.uc, pong->from.uc, 32U);
}

void
fd_gossip_recv_crds_value(fd_gossip_global_t * glob, fd_pubkey_t * pubkey, fd_crds_value_t* crd, long now, fd_valloc_t valloc) {
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
    FD_LOG_ERR(("received crds_value with invalid signature"));
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

  /* Store the message */
  fd_message_elem_t * msg = fd_message_table_query(glob->messages, &key, NULL);
  if (msg != NULL)
    /* Already have this message */
    return;
  msg = fd_message_table_insert(glob->messages, &key);
  if (msg == NULL) {
    FD_LOG_WARNING(("too many messages"));
    return;
  }
  msg->wallclock = wallclock;
  msg->data = fd_valloc_malloc(valloc, 1U, datalen);
  fd_memcpy(msg->data, buf, datalen);
  msg->datalen = datalen;

  if (crd->data.discriminant == fd_crds_data_enum_contact_info) {
    fd_gossip_contact_info_t * info = &crd->data.inner.contact_info;
    if (info->gossip.port != 0) {
      /* Remember the peer */
      fd_gossip_network_addr_t pkey;
      fd_memset(&pkey, 0, sizeof(pkey));
      fd_gossip_from_soladdr(&pkey, &info->gossip);
      fd_peer_elem_t * val = fd_peer_table_query(glob->peers, &pkey, NULL);
      if (val == NULL) {
        val = fd_peer_table_insert(glob->peers, &pkey);
        if (glob->inactives_cnt < INACTIVES_MAX &&
            fd_active_table_query(glob->actives, &pkey, NULL) == NULL) {
          /* Queue this peer for potential active status */
          fd_memcpy(glob->inactives + (glob->inactives_cnt++), &pkey, sizeof(pkey));
        }
      }
      if (val == NULL)
        FD_LOG_WARNING(("too many peers"));
      else {
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
fd_gossip_recv(fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_msg_t * gmsg, long now, fd_valloc_t valloc) {
  switch (gmsg->discriminant) {
  case fd_gossip_msg_enum_pull_req:
    break;
  case fd_gossip_msg_enum_pull_resp: {
    glob->got_pull_resp = 1;
    fd_gossip_pull_resp_t * pull_resp = &gmsg->inner.pull_resp;
    for (ulong i = 0; i < pull_resp->crds_len; ++i)
      fd_gossip_recv_crds_value(glob, &pull_resp->pubkey, pull_resp->crds + i, now, valloc);
    break;
  }
  case fd_gossip_msg_enum_push_msg: {
    fd_gossip_push_msg_t * push_msg = &gmsg->inner.push_msg;
    for (ulong i = 0; i < push_msg->crds_len; ++i)
      fd_gossip_recv_crds_value(glob, &push_msg->pubkey, push_msg->crds + i, now, valloc);
    break;
  }
  case fd_gossip_msg_enum_prune_msg:
    break;
  case fd_gossip_msg_enum_ping:
    fd_gossip_handle_ping(glob, from, &gmsg->inner.ping);
    break;
  case fd_gossip_msg_enum_pong:
    fd_gossip_handle_pong(glob, from, &gmsg->inner.pong, now);
    break;
  }
}

int fd_gossip_add_active_peer( fd_gossip_global_t * glob, fd_gossip_network_addr_t * addr ) {
  fd_pending_event_t * ev = fd_gossip_add_pending( glob, 0L /* next chance we get */ );
  if (ev == NULL)
    return 0;
  ev->fun = fd_gossip_make_ping;
  fd_memcpy(&ev->fun_arg.key, addr, sizeof(fd_gossip_network_addr_t));
  return 0;
}

/* Main loop for socket reading/writing. Does not return until stopflag is non-zero */
int
fd_gossip_main_loop( fd_gossip_global_t * glob, fd_valloc_t valloc, volatile int * stopflag ) {
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

#define VLEN 32U
  struct mmsghdr msgs[VLEN];
  struct iovec iovecs[VLEN];
  uchar bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof(struct sockaddr_in6)]; /* sockaddr is smaller than sockaddr_in6 */

  while ( !*stopflag ) {
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
    long now = fd_log_wallclock();
    do {
      fd_pending_event_t * ev = fd_pending_heap_ele_peek_min( glob->event_heap, glob->event_pool );
      if (ev == NULL || ev->key > now)
        break;
      (*ev->fun)(glob, &ev->fun_arg, now);
      fd_pending_heap_ele_remove_min( glob->event_heap, glob->event_pool );
      fd_pending_pool_ele_release( glob->event_pool, ev );
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
      FD_LOG_NOTICE(("recv msg type %d from %s", gmsg.discriminant, fd_gossip_addr_str(tmp, sizeof(tmp), &from)));
                       
      fd_gossip_recv(glob, &from, &gmsg, now, valloc);

      fd_bincode_destroy_ctx_t ctx2;
      ctx2.valloc = valloc;
      fd_gossip_msg_destroy(&gmsg, &ctx2);
    }
  }

  close(fd);
  glob->sockfd = -1;
  return 0;
}
