#ifndef HEADER_fd_src_waltz_resolv_fd_lookup_h
#define HEADER_fd_src_waltz_resolv_fd_lookup_h

#include <stdint.h>
#include <stddef.h>
#include <features.h>
#include <netinet/in.h>
#include "fd_netdb.h"

struct aibuf {
  fd_addrinfo_t ai;
  union sa {
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
  } sa;
  short slot, ref;
};

struct address {
  int   family;
  uint  scopeid;
  uchar addr[16];
  int   sortkey;
};

#define MAXNS 3

struct fd_resolvconf {
  struct address ns[MAXNS];
  uint nns, attempts, ndots;
  uint timeout;
};

typedef struct fd_resolvconf fd_resolvconf_t;

/* The limit of 48 results is a non-sharp bound on the number of addresses
 * that can fit in one 512-byte DNS packet full of v4 results and a second
 * packet full of v6 results. Due to headers, the actual limit is lower. */
#define MAXADDRS 48
#define MAXSERVS 2

__attribute__((__visibility__("hidden"))) int
fd_lookup_name( struct address buf[ static MAXADDRS ],
                char           canon[ static 256 ],
                const char *   name,
                int            family,
                int            flags );

__attribute__((__visibility__("hidden"))) int
fd_lookup_ipliteral( struct address buf[ static 1 ],
                     const char *   name,
                     int            family );

__attribute__((__visibility__("hidden"))) int
fd_get_resolv_conf( fd_resolvconf_t * );

__attribute__((__visibility__("hidden"))) int
fd_res_msend_rc( int,
                 uchar const * const *,
                 int const *,
                 uchar * const *,
                 int *,
                 int,
                 fd_resolvconf_t const * );

__attribute__((__visibility__("hidden"))) int
fd_dns_parse( uchar const *,
              int,
              int (*)( void *,
                       int,
                       void const *,
                       int,
                       void const *,
                       int ),
              void * );

/* Firedancer extension: pre-opened file descriptors */

extern FD_TL int fd_etc_hosts_fd;
extern FD_TL int fd_etc_resolv_conf_fd;

#endif /* HEADER_fd_src_waltz_resolv_fd_lookup_h */
