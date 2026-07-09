#ifndef HEADER_fd_src_discof_restore_utils_fd_sspeer_h
#define HEADER_fd_src_discof_restore_utils_fd_sspeer_h

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_net_headers.h"
#include "../../../flamenco/fd_flamenco_base.h"

struct fd_sspeer_key {
  union {
    fd_pubkey_t pubkey[ 1 ];        /* gossip peers: key by pubkey. */
    struct {                        /* HTTP server peers: key by hostname + addr. */
      char          hostname[ 256 ];
      fd_ip4_port_t resolved_addr;  /* disambiguates multiple IPs for same hostname. */
    } url;
  };
  int           is_url;
};

typedef struct fd_sspeer_key fd_sspeer_key_t;

FD_FN_UNUSED static inline int
fd_sspeer_key_eq( fd_sspeer_key_t const * k0,
                  fd_sspeer_key_t const * k1 ) {
  if( k0->is_url!=k1->is_url ) return 0;
  if( k0->is_url ) {
    return !strncmp( k0->url.hostname, k1->url.hostname, sizeof(k0->url.hostname) )
           && k0->url.resolved_addr.l==k1->url.resolved_addr.l;
  }
  return !memcmp( k0->pubkey, k1->pubkey, FD_PUBKEY_FOOTPRINT );
}

FD_FN_UNUSED static inline ulong
fd_sspeer_key_hash( fd_sspeer_key_t const * key,
                    ulong                   seed ) {
  if( key->is_url ) {
    /* Use strnlen in case the string is not properly \0 terminated.
       Ideally, one would prefer sizeof(key->url.hostname) but that
       requires guaranteed zero-padding. */
    ulong h = fd_hash( seed, key->url.hostname, strnlen( key->url.hostname, sizeof(key->url.hostname) ) );
    /* fd_ip4_port_t is not a complete 64bit ulong, therefore compose
       the word from its parts to avoid random unused bytes. */
    ulong a = (ulong)key->url.resolved_addr.addr | ( ((ulong)key->url.resolved_addr.port) << 32 );
    /* Chaining "a" through fd_hash would give better avalanche
       properties, but it is probably overkill for a chain hash map. */
    return h ^ a;
  }
  return fd_hash( seed, key->pubkey, FD_PUBKEY_FOOTPRINT );
}

#endif /* HEADER_fd_src_discof_restore_utils_fd_sspeer_h */
