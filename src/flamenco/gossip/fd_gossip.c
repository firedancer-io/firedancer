#define _GNU_SOURCE 1
#include "fd_gossip.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../util/net/fd_eth.h"
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/time.h>

#pragma GCC diagnostic ignored "-Wstrict-aliasing"

/* Key used for active sets and contact lists */
struct __attribute__((aligned(8UL))) fd_ping_key {
    fd_pubkey_t id;
    fd_gossip_network_addr_t addr;
};
#define FD_PING_KEY_NLONGS (sizeof(fd_ping_key_t)/sizeof(ulong))
typedef struct fd_ping_key fd_ping_key_t;

int fd_ping_key_eq( const fd_ping_key_t * key1, const fd_ping_key_t * key2 ) {
  FD_STATIC_ASSERT(sizeof(fd_ping_key_t)%sizeof(ulong) == 0,"messed up size");
  const ulong * p1 = (const ulong*)key1;
  const ulong * p2 = (const ulong*)key2;
  for ( ulong i = 0; i < FD_PING_KEY_NLONGS; ++i )
    if ( p1[i] != p2[i] )
      return 0;
  return 1;
}

ulong fd_ping_key_hash( const fd_ping_key_t * key, ulong seed ) {
  ulong buf[FD_PING_KEY_NLONGS];
  for ( ulong i = 0; i < FD_PING_KEY_NLONGS; ++i )
    buf[i] = ((const ulong *)key)[i];

  seed += 7242237688154252699UL;
  
#define ROLLUP(_result_,_prime_)                       \
  ulong _result_ = 0;                                  \
  do {                                                 \
    for ( ulong i = 0; i < FD_PING_KEY_NLONGS; ++i ) { \
      _result_ = (_result_ + buf[i] + seed)*_prime_;   \
    }                                                  \
  } while (0)

#define ROTATE                                          \
  do {                                                  \
    ulong t = buf[0];                                   \
    for ( ulong i = 1; i < FD_PING_KEY_NLONGS; ++i ) {  \
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

void fd_ping_key_copy( fd_ping_key_t * keyd, const fd_ping_key_t * keys ) {
  FD_STATIC_ASSERT(sizeof(fd_ping_key_t)%sizeof(ulong) == 0,"messed up size");
  ulong * pd = (ulong*)keyd;
  const ulong * ps = (const ulong*)keys;
  for ( ulong i = 0; i < FD_PING_KEY_NLONGS; ++i )
    pd[i] = ps[i];
}

/* Contact table element */
struct fd_contact_elem {
    fd_ping_key_t key;
    ulong next;
    fd_gossip_contact_info_t info;
};
/* Contact table */
typedef struct fd_contact_elem fd_contact_elem_t;
#define MAP_NAME     fd_contact_table
#define MAP_KEY_T    fd_ping_key_t
#define MAP_KEY_EQ   fd_ping_key_eq
#define MAP_KEY_HASH fd_ping_key_hash
#define MAP_KEY_COPY fd_ping_key_copy
#define MAP_T        fd_contact_elem_t
#include "../../util/tmpl/fd_map_giant.c"
#define FD_CONTACT_KEY_MAX (1<<16)

/* Active table element */
struct fd_active_elem {
    fd_ping_key_t key;
    ulong next;
    ulong pingtime;
    fd_hash_t pingtoken;
    ulong pongtime;
};
/* Active table */
typedef struct fd_active_elem fd_active_elem_t;
#define MAP_NAME     fd_active_table
#define MAP_KEY_T    fd_ping_key_t
#define MAP_KEY_EQ   fd_ping_key_eq
#define MAP_KEY_HASH fd_ping_key_hash
#define MAP_KEY_COPY fd_ping_key_copy
#define MAP_T        fd_active_elem_t
#include "../../util/tmpl/fd_map_giant.c"
#define FD_ACTIVE_KEY_MAX (1<<8)

/* Global data for gossip service */
struct fd_gossip_global {
    fd_gossip_credentials_t my_creds;
    fd_gossip_network_addr_t my_addr;
    ulong seed;
    int sockfd;
    fd_contact_elem_t * contacts;
    fd_active_elem_t * actives;
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
  void * shm = fd_valloc_malloc(valloc, fd_contact_table_align(), fd_contact_table_footprint(FD_CONTACT_KEY_MAX));
  glob->contacts = fd_contact_table_join(fd_contact_table_new(shm, FD_CONTACT_KEY_MAX, seed));
  shm = fd_valloc_malloc(valloc, fd_active_table_align(), fd_active_table_footprint(FD_ACTIVE_KEY_MAX));
  glob->actives = fd_active_table_join(fd_active_table_new(shm, FD_ACTIVE_KEY_MAX, seed));
  return glob;
}

fd_gossip_global_t *
fd_gossip_global_join ( void * shmap ) { return (fd_gossip_global_t *)shmap; }

void *
fd_gossip_global_leave ( fd_gossip_global_t * join ) { return join; }

void *
fd_gossip_global_delete ( void * shmap, fd_valloc_t valloc ) {
  fd_gossip_global_t * glob = (fd_gossip_global_t *)shmap;
  fd_valloc_free(valloc, fd_contact_table_leave(fd_contact_table_delete(glob->contacts)));
  fd_valloc_free(valloc, fd_active_table_leave(fd_active_table_delete(glob->actives)));
  return glob;
}

int
fd_gossip_global_set_config( fd_gossip_global_t * glob, const fd_gossip_config_t * config ) {
  glob->my_creds = config->my_creds;
  fd_memcpy(&glob->my_addr, &config->my_addr, sizeof(fd_gossip_network_addr_t));
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
}

void
fd_gossip_handle_ping( fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_ping_t const * ping ) {
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
  fd_sha512_t sha2[1];
  fd_ed25519_sign( /* sig */ pong->signature.uc,
                   /* msg */ ping->token.uc,
                   /* sz  */ 32UL,
                   /* public_key  */ glob->my_creds.public_key.uc,
                   /* private_key */ glob->my_creds.private_key,
                   sha2 );

  fd_gossip_send(glob, from, &gmsg);
}

void
fd_gossip_handle_pong( fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_ping_t const * pong, ulong now ) {
  fd_ping_key_t key;
  fd_memcpy(key.id.uc, pong->from.uc, 32U);
  fd_memcpy(&key.addr, from, sizeof(fd_gossip_network_addr_t));
  fd_active_elem_t * val = fd_active_table_query(glob->actives, &key, NULL);
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
  if (fd_ed25519_verify( /* msg */ val->pingtoken.uc,
                         /* sz */ 332UL,
                         /* sig */ pong->signature.uc,
                         /* public_key */ pong->from.uc,
                         sha2 )) {
    FD_LOG_WARNING(("received pong with invalid signature"));
    return;
  }
  
  val->pongtime = now;
}

void
fd_gossip_recv(fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_msg_t * gmsg, ulong now) {
  switch (gmsg->discriminant) {
  case fd_gossip_msg_enum_pull_req:
    break;
  case fd_gossip_msg_enum_pull_resp:
    break;
  case fd_gossip_msg_enum_push_msg:
    break;
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
  struct timespec timeout;

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
    
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;
    
    int retval = recvmmsg(fd, msgs, VLEN, 0, &timeout);
    if (retval < 0) {
      FD_LOG_ERR(("recvmmsg failed: %s", strerror(errno)));
      return -1;
    }
    if (retval == 0)
      continue;
    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0) {
      FD_LOG_ERR(("gettimeofday failed: %s", strerror(errno)));
      return -1;
    }
    ulong now = ((ulong)tv.tv_sec)*1000000000UL + ((ulong)tv.tv_usec)*1000UL;

    for (uint i = 0; i < (uint)retval; ++i) {
      // Get the source addr
      fd_gossip_network_addr_t from;
      if ( fd_gossip_from_sockaddr( &from, sockaddrs[i] ) )
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
