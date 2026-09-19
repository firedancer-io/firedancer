#ifndef HEADER_fd_src_disco_shred_fd_shred_dest_resolver_h
#define HEADER_fd_src_disco_shred_fd_shred_dest_resolver_h

#include "fd_shred_dest.h"
#include "../topo/fd_dns_resolve.h"

/* Resolves endpoint_cnt (<=FD_DNS_RESOLVE_PEERS_MAX) strict host:port
   strings from NUL-terminated FD_HOSTPORT_BUF_MAX-byte slots concurrently.
   out must have endpoint_cnt entries; writes the first IPv4 address in
   network order and port in host order, leaving other fields untouched.
   Fatal on malformed input or resolution failure.  Call from
   privileged_init before sandbox entry. */

void
fd_shred_resolve_additional_destinations( char const                  endpoints[][ FD_HOSTPORT_BUF_MAX ],
                                          ulong                       endpoint_cnt,
                                          char const *                config_key,
                                          fd_shred_dest_weighted_t * out );

#endif /* HEADER_fd_src_disco_shred_fd_shred_dest_resolver_h */
