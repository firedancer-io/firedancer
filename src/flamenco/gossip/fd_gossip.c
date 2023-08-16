#include "fd_gossip.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include <sys/socket.h>
#include <netinet/in.h>

/* Key used for active sets and contact lists */
struct __attribute__((aligned(8UL))) fd_ping_key {
    fd_pubkey_t id;
    sa_family_t family;   /* AF_INET or AF_INET6 */
    in_port_t   port;     /* port number, host byte order */
    union fd_gossip_ip_addr_inner ip_addr;
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

  return (((r0^r1)^(r2^r3))^(r4^r5));
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
    ulong seed;
    fd_contact_elem_t * contacts;
};

ulong
fd_gossip_global_align ( void ) { return alignof(fd_gossip_global_t); }

ulong
fd_gossip_global_footprint( void ) { return sizeof(fd_gossip_global_t); }

void *
fd_gossip_global_new ( void * shmem, ulong seed, fd_valloc_t valloc ) {
  fd_gossip_global_t * glob = (fd_gossip_global_t *)shmem;
  glob->seed = seed;
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

void
fd_gossip_handle_ping_request( fd_gossip_ping_t        const * ping,
                               fd_gossip_ping_t              * pong,
                               fd_gossip_credentials_t const * creds ) {

  memcpy( pong->from.uc, creds->public_key, 32UL );

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
                   /* public_key  */ creds->public_key,
                   /* private_key */ creds->private_key,
                   sha2 );
}
