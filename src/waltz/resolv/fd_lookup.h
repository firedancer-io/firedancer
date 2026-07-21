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

/* Firedancer extension: non-blocking IPv4 resolution primitives, used
   by fd_adns.  See fd_lookup_name.c. */

#define FD_DNS_QUERY_MTU (280)

/* fd_dns_ip4_local resolves name without network I/O (IPv4 literal or
   /etc/hosts).  Writes up to addr_max addresses (network byte order)
   to addrs.  Returns the count (>0), 0 if the name needs DNS, or an
   FD_EAI_* error. */

__attribute__((__visibility__("hidden"))) int
fd_dns_ip4_local( char const * name,
                  uint *       addrs,
                  ulong        addr_max );

/* fd_dns_ip4_query builds an A-record query packet for name.  Returns
   the packet length, or FD_EAI_NONAME on a malformed name.  Bytes 0-1
   of the packet are the (randomized) query id; answers echo it. */

__attribute__((__visibility__("hidden"))) int
fd_dns_ip4_query( char const * name,
                  uchar        query[ static FD_DNS_QUERY_MTU ] );

/* fd_dns_ip4_answer parses a DNS answer packet.  Writes up to addr_max
   A records (network byte order) to addrs and returns the count, or an
   FD_EAI_* error (FD_EAI_AGAIN on SERVFAIL/short packet). */

__attribute__((__visibility__("hidden"))) int
fd_dns_ip4_answer( uchar const * answer,
                   ulong         answer_sz,
                   uint *        addrs,
                   ulong         addr_max );

/* fd_dns_nameservers loads the configured IPv4 nameservers from
   /etc/resolv.conf (falling back to 127.0.0.1).  Returns the count
   written to addrs (network byte order), or FD_EAI_SYSTEM.  If
   opt_timeout/opt_attempts are non-NULL they receive the resolv.conf
   options (or their defaults). */

__attribute__((__visibility__("hidden"))) int
fd_dns_nameservers( uint * addrs,
                    ulong  addr_max,
                    uint * opt_timeout,
                    uint * opt_attempts );

/* Firedancer extension: pre-opened file descriptors */

extern FD_TL int fd_etc_hosts_fd;
extern FD_TL int fd_etc_resolv_conf_fd;

#endif /* HEADER_fd_src_waltz_resolv_fd_lookup_h */
