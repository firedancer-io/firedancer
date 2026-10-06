#ifndef HEADER_fd_src_discof_restore_utils_fd_ssboot_h
#define HEADER_fd_src_discof_restore_utils_fd_ssboot_h

#include "../../../disco/topo/fd_dns_resolve.h"
#include "../../../util/log/fd_log.h"
#include "../../../util/net/fd_ip4.h"

FD_PROTOTYPES_BEGIN

/* fd_ssboot_server_parse turns the [snapshots.instant_boot] server
   string into an address and the hostname it was written with.  Only a
   plain IPv4 literal is accepted: the tiles that talk to the serving
   validator have no DNS client of their own.  Fatal on anything
   else. */

static inline void
fd_ssboot_server_parse( char const *    server,
                        char            hostname[ static FD_FQDN_BUF_MAX ],
                        fd_ip4_port_t * addr ) {
  ushort port;
  int    is_https;
  fd_dns_peer_parse( server, "snapshots.instant_boot.server", hostname, &port, &is_https );
  if( FD_UNLIKELY( is_https ) ) {
    FD_LOG_ERR(( "[snapshots.instant_boot] server \"%s\" must be plain http", server ));
  }
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( hostname, &addr->addr ) ) ) {
    FD_LOG_ERR(( "[snapshots.instant_boot] server \"%s\" must give an IPv4 address", server ));
  }
  addr->port = port;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssboot_h */
