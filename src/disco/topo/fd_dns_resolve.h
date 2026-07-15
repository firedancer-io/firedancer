#ifndef HEADER_fd_src_disco_topo_fd_dns_resolve_h
#define HEADER_fd_src_disco_topo_fd_dns_resolve_h

/* fd_dns_resolve provides blocking hostname->IPv4 resolution helpers
   for tile privileged_init and standalone commands.

   Except for fd_dns_peer_parse these block on the network (getaddrinfo
   or a drained fd_adns) and so must only be used before a tile enters
   its seccomp sandbox, never on the hot path.  For DNS inside the
   sandbox use fd_adns directly (src/waltz/resolv), see the snapct and
   bundle tiles. */

#include "../../util/net/fd_net_headers.h" /* fd_ip4_port_t */

#include <netdb.h> /* struct addrinfo */

FD_PROTOTYPES_BEGIN

/* fd_dns_resolve_address resolves a single address to a single IPv4
   address.  If address is already a valid IPv4 dotted-quad it is parsed
   directly; otherwise it is resolved via DNS and the first IPv4 record
   is returned via *ip_addr (network byte order).  Returns 1 on success,
   0 on failure (a warning is logged on DNS failure). */

int
fd_dns_resolve_address( char const * address,
                        uint *       ip_addr );

/* fd_dns_resolve_addresses resolves a hostname to up to ip_addr_cnt
   IPv4 addresses, written into ip_addrs[].addr (network byte order;
   .port is left untouched).  hints may be NULL (defaults to AF_INET).
   Returns the number of addresses resolved (a warning is logged on DNS
   failure, returning 0). */

int
fd_dns_resolve_addresses( char const *            address,
                          struct addrinfo const * hints,
                          fd_ip4_port_t *         ip_addrs,
                          ulong                   ip_addr_cnt );

#define FD_DNS_RESOLVE_PEERS_MAX (16UL)

/* fd_dns_resolve_peers resolves peer_cnt (<=FD_DNS_RESOLVE_PEERS_MAX)
   peer strings, stored in fixed peer_stride byte cstr slots starting at
   peers, to one IPv4 address each in out[].  The lookups for all peers
   run concurrently on one socket (fd_adns) rather than head-of-line
   blocking on each name in turn, so the wall clock cost is that of the
   slowest single lookup.  All fds opened for resolution are closed
   again before returning (callers are headed into a sandbox).  Fatal
   on malformed entries or resolution failure. */

void
fd_dns_resolve_peers( char const *    peers,
                      ulong           peer_stride,
                      ulong           peer_cnt,
                      char const *    config_str,
                      fd_ip4_port_t * out );

/* fd_dns_peer_parse splits a peer string "[http(s)://]host[:port]"
   into hostname / port (network byte order; defaults to 443 for https
   when no port is given) / *is_https (may be NULL), without doing any
   DNS resolution.  Safe to call inside a seccomp sandbox.  Fatal on a
   malformed peer string (config_str names the offending config key). */

void
fd_dns_peer_parse( char const * peer,
                   char const * config_str,
                   char         hostname[ static 256UL ],
                   ushort *     port,
                   int *        is_https );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_topo_fd_dns_resolve_h */
