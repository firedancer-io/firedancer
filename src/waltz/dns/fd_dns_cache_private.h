#ifndef HEADER_fd_src_disco_dns_fd_dns_cache_private_h
#define HEADER_fd_src_disco_dns_fd_dns_cache_private_h

#include "fd_dns_cache.h"

/* FD_DNS_CACHE_MAGIC identifies a dns_cache object. */
#define FD_DNS_CACHE_MAGIC (0x918f5f61df79898cUL) /* random */

/* Declare a header-only object pool of DNS cache domains. */

#define POOL_NAME  fd_dns_cache_name_pool
#define POOL_T     fd_dns_cache_ele_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

/* Declare a header-only object pool of DNS cache addresses. */

#define POOL_NAME  fd_dns_cache_addr_pool
#define POOL_T     fd_dns_cache_addr_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

struct fd_dns_cache_private {
  ulong magic;

  ulong map_off;
  ulong name_pool_off;
  ulong addr_pool_off;

  /* child objects follow */
};

/* fd_dns_cache_key is a util to construct a key object.
   fqdn_len MUST be bounds checked before calling this function. */

static inline fd_dns_cache_key_t
fd_dns_cache_key( char const * fqdn,
                  ulong        fqdn_len ) {
  /* FIXME fd_memcpy is a bit wasteful */
  fd_dns_cache_key_t key;
  key.name_len = (uchar)fqdn_len;
  fd_memcpy( &key.name, fqdn, fqdn_len );
  return key;
}

#endif /* HEADER_fd_src_disco_dns_fd_dns_cache_private_h */
