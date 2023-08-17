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

/* Global data for gossip service */
struct fd_gossip_global {
    fd_gossip_credentials_t my_creds;
    fd_gossip_network_addr_t my_addr;
    ulong seed;
    int sockfd;
    fd_contact_elem_t * contacts;
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
  return glob;
}

int
fd_gossip_global_set_config( fd_gossip_global_t * glob, const fd_gossip_config_t * config ) {
  glob->my_creds = config->my_creds;
  glob->my_addr = config->my_addr;
  return 0;
}

void
fd_gossip_handle_ping_request( fd_gossip_global_t * glob, fd_gossip_network_addr_t * from, fd_gossip_ping_t const * ping ) {
  (void)from;
  
  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new_disc(&gmsg, fd_gossip_msg_enum_pong);
  fd_gossip_ping_t * pong = &gmsg.inner.pong;

  memcpy( pong->from.uc, glob->my_creds.public_key.uc, 32UL );

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
}

void
fd_gossip_recv_packet(fd_gossip_global_t * glob, fd_valloc_t valloc, fd_gossip_network_addr_t * from, ulong msg_len, const uchar * msg) {
  fd_gossip_msg_t gmsg;
  fd_gossip_msg_new(&gmsg);
  fd_bincode_decode_ctx_t ctx;
  ctx.data    = msg;
  ctx.dataend = msg + msg_len;
  ctx.valloc  = valloc;
  if (fd_gossip_msg_decode(&gmsg, &ctx)) {
    FD_LOG_WARNING(("corrupt gossip message"));
    return;
  }
  if (ctx.data != ctx.dataend) {
    FD_LOG_WARNING(("corrupt gossip message"));
    return;
  }

  switch (gmsg.discriminant) {
  case fd_gossip_msg_enum_pull_req:
    break;
  case fd_gossip_msg_enum_pull_resp:
    break;
  case fd_gossip_msg_enum_push_msg:
    break;
  case fd_gossip_msg_enum_prune_msg:
    break;
  case fd_gossip_msg_enum_ping:
    fd_gossip_handle_ping_request(glob, from, &gmsg.inner.ping);
    break;
  case fd_gossip_msg_enum_pong:
    break;
  }

  fd_bincode_destroy_ctx_t ctx2;
  ctx2.valloc  = valloc;
  fd_gossip_msg_destroy(&gmsg, &ctx2);
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
  if (glob->my_addr.family == AF_INET) {
    struct sockaddr_in myaddr;
    memset((char *)&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = glob->my_addr.addr[0];
    myaddr.sin_port = glob->my_addr.port;
    if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
      FD_LOG_ERR(("bind failed: %s", strerror(errno)));
      return -1;
    }
  } else if (glob->my_addr.family == AF_INET6) {
    struct sockaddr_in6 myaddr;
    memset((char *)&myaddr, 0, sizeof(myaddr));
    myaddr.sin6_family = AF_INET6;
    uint * u6_addr32 = myaddr.sin6_addr.__in6_u.__u6_addr32;
    u6_addr32[0] = glob->my_addr.addr[0];
    u6_addr32[1] = glob->my_addr.addr[1];
    u6_addr32[2] = glob->my_addr.addr[2];
    u6_addr32[3] = glob->my_addr.addr[3];
    myaddr.sin6_port = glob->my_addr.port;
    if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
      FD_LOG_ERR(("bind failed: %s", strerror(errno)));
      return -1;
    }
  } else {
    FD_LOG_ERR(("invalid address family"));
    return -1;
  }

#define VLEN 32U
  struct mmsghdr msgs[VLEN];
  struct iovec iovecs[VLEN];
  uchar bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  struct sockaddr sockaddrs[VLEN];
  struct timespec timeout;

  while ( !*stopflag ) {
    fd_memset(msgs, 0, sizeof(msgs));
    for (uint i = 0; i < VLEN; i++) {
      iovecs[i].iov_base         = bufs[i];
      iovecs[i].iov_len          = FD_ETH_PAYLOAD_MAX;
      msgs[i].msg_hdr.msg_iov    = &iovecs[i];
      msgs[i].msg_hdr.msg_iovlen = 1;
      msgs[i].msg_hdr.msg_name   = &sockaddrs[i];
      msgs[i].msg_hdr.msg_iovlen = sizeof(struct sockaddr);
    }
    
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;
    
    int retval = recvmmsg(fd, msgs, VLEN, 0, &timeout);
    if (retval < 0) {
      FD_LOG_ERR(("recvmmsg failed: %s", strerror(errno)));
      return -1;
    }

    for (uint i = 0; i < (uint)retval; ++i) {
      // Get the source addr
      fd_gossip_network_addr_t from;
      fd_memset(&from, 0, sizeof(from));
      from.family = sockaddrs[i].sa_family;
      if (from.family == AF_INET) {
        const struct sockaddr_in * sa = (const struct sockaddr_in *)&sockaddrs[i];
        from.addr[0] = sa->sin_addr.s_addr;
        from.port = sa->sin_port;
      } else if (from.family == AF_INET6) {
        const struct sockaddr_in6 * sa = (const struct sockaddr_in6 *)&sockaddrs[i];
        const uint * u6_addr32 = sa->sin6_addr.__in6_u.__u6_addr32;
        from.addr[0] = u6_addr32[0];
        from.addr[1] = u6_addr32[1];
        from.addr[2] = u6_addr32[2];
        from.addr[3] = u6_addr32[3];
        from.port = sa->sin6_port;
      } else {
        FD_LOG_WARNING(("unknown address family in packet"));
        continue;
      }
      fd_gossip_recv_packet(glob, valloc, &from, msgs[i].msg_len, bufs[i]);
    }
  }

  close(fd);
  glob->sockfd = -1;
  return 0;
}
