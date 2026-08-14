#include "fd_dns_resolve.h"
#include "../../waltz/resolv/fd_adns.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../util/fd_util.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#define FD_DNS_RESOLVE_TIMEOUT_NANOS (90L*1000L*1000L*1000L)

int
fd_dns_resolve_address( char const * address,
                        uint *       ip_addr ) {
  if( FD_LIKELY( fd_cstr_to_ip4_addr( address, ip_addr ) ) ) return 1;

  struct addrinfo hints = { .ai_family = AF_INET };
  struct addrinfo * res;
  int err = getaddrinfo( address, NULL, &hints, &res );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "cannot resolve address \"%s\": %i-%s", address, err, gai_strerror( err ) ));
    return 0;
  }

  int resolved = 0;
  for( struct addrinfo * cur=res; cur; cur=cur->ai_next ) {
    if( FD_UNLIKELY( cur->ai_addr->sa_family!=AF_INET ) ) continue;
    struct sockaddr_in const * addr = (struct sockaddr_in const *)cur->ai_addr;
    *ip_addr = addr->sin_addr.s_addr;
    resolved = 1;
    break;
  }

  freeaddrinfo( res );
  return resolved;
}

int
fd_dns_resolve_addresses( char const *            address,
                          struct addrinfo const * hints,
                          fd_ip4_port_t *         ip_addrs,
                          ulong                   ip_addr_cnt ) {
  struct addrinfo default_hints = { .ai_family = AF_INET };
  if( FD_UNLIKELY( !hints ) ) {
    hints = &default_hints;
  }

  struct addrinfo * res;
  int err = getaddrinfo( address, NULL, hints, &res );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "cannot resolve address \"%s\": %i-%s", address, err, gai_strerror( err ) ));
    return 0;
  }

  int resolved = 0;
  for( struct addrinfo * cur=res; cur; cur=cur->ai_next ) {
    if( FD_UNLIKELY( (ulong)resolved>=ip_addr_cnt ) ) break;
    if( FD_UNLIKELY( cur->ai_addr->sa_family!=AF_INET ) ) continue;
    struct sockaddr_in const * addr = (struct sockaddr_in const *)cur->ai_addr;
    ip_addrs[ resolved ].addr = addr->sin_addr.s_addr;
    resolved++;
  }

  freeaddrinfo( res );
  return resolved;
}

void
fd_dns_peer_parse( char const * peer,
                   char const * config_str,
                   char         hostname[ static 256UL ],
                   ushort *     port,
                   int *        is_https ) {

  /* Split host:port */
  int          https     = 0;
  char const * host_port = peer;
  if( FD_LIKELY( strncmp( peer, "http://", 7UL )==0 ) ) {
    host_port += 7UL;
  } else if( FD_LIKELY( strncmp( peer, "https://", 8UL )==0 ) ) {
    host_port += 8UL;
    https      = 1;
  }
  if( FD_LIKELY( is_https ) ) *is_https = https;

  char const * colon    = strrchr( host_port, ':' );
  char const * host_end = colon;
  if( FD_UNLIKELY( !colon && !https ) ) {
    FD_LOG_ERR(( "invalid [%s] entry \"%s\": no port number", config_str, host_port ));
  } else if( FD_LIKELY( !colon && https ) ) {
    host_end = host_port + strlen( host_port );
  }

  ulong fqdn_len = (ulong)( host_end-host_port );
  if( FD_UNLIKELY( !fqdn_len ) ) {
    FD_LOG_ERR(( "invalid [%s] entry \"%s\": no hostname", config_str, host_port ));
  }
  if( FD_UNLIKELY( fqdn_len>255 ) ) {
    FD_LOG_ERR(( "invalid [%s] entry \"%s\": hostname too long", config_str, host_port ));
  }
  fd_memcpy( hostname, host_port, fqdn_len );
  hostname[ fqdn_len ] = '\0';

  if( FD_LIKELY( colon ) ) {
    char const * port_str = host_end+1;
    char const * endptr   = NULL;
    ulong _port = strtoul( port_str, (char **)&endptr, 10 );
    if( FD_UNLIKELY( endptr==port_str || !_port || _port>USHORT_MAX || *endptr!='\0' ) ) {
      FD_LOG_ERR(( "invalid [%s] entry \"%s\": invalid port number", config_str, host_port ));
    }
    *port = fd_ushort_bswap( (ushort)_port );
  } else {
    /* use default https port */
    *port = fd_ushort_bswap( 443U );
  }
}

void
fd_dns_resolve_peers( char const *    peers,
                      ulong           peer_stride,
                      ulong           peer_cnt,
                      char const *    config_str,
                      fd_ip4_port_t * out ) {
  if( FD_UNLIKELY( peer_cnt>FD_DNS_RESOLVE_PEERS_MAX ) ) FD_LOG_ERR(( "too many [%s] entries (%lu)", config_str, peer_cnt ));
  if( FD_UNLIKELY( !peer_cnt ) ) return;

  char hostname[ FD_DNS_RESOLVE_PEERS_MAX ][ 256UL ];
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    fd_dns_peer_parse( peers+i*peer_stride, config_str, hostname[ i ], &out[ i ].port, NULL );
  }

  /* All queries in flight concurrently on one socket, so the wall
     clock cost is that of the slowest single lookup.  The fds are
     opened and closed within this call: callers are about to enter a
     sandbox that requires no stray fds. */
  fd_netdb_fds_t netdb_fds[1];
  int netdb_opened = !!fd_netdb_open_fds( netdb_fds ); /* NULL if already open (owned by caller) */

  /* Thread local: tiles resolve concurrently under
     fd_topo_run_single_process (and netdb fds are FD_TL already) */
  static FD_TL uchar shadns[ 16384UL ] __attribute__((aligned(32UL)));
  FD_TEST( fd_adns_footprint( FD_DNS_RESOLVE_PEERS_MAX )<=sizeof(shadns) );
  fd_adns_t * adns = fd_adns_join( fd_adns_new( shadns, peer_cnt ) );
  FD_TEST( adns );

  for( ulong i=0UL; i<peer_cnt; i++ ) FD_TEST( !fd_adns_resolve( adns, hostname[ i ], i ) );

  ulong resolved_cnt = 0UL;
  long  deadline     = fd_log_wallclock()+FD_DNS_RESOLVE_TIMEOUT_NANOS;
  for(;;) {
    long now = fd_log_wallclock();
    fd_adns_result_t res[ 1 ];
    while( fd_adns_advance( adns, now, res ) ) {
      if( FD_UNLIKELY( res->err ) )
        FD_LOG_ERR(( "failed to resolve [%s] entry \"%s\" (%s)", config_str, peers+res->req_id*peer_stride, fd_gai_strerror( res->err ) ));
      out[ res->req_id ].addr = res->addrs[ 0 ];
      resolved_cnt++;
    }
    if( FD_LIKELY( resolved_cnt==peer_cnt ) ) break;
    if( FD_UNLIKELY( now>deadline ) ) FD_LOG_ERR(( "timed out resolving [%s]", config_str ));
    FD_SPIN_PAUSE();
  }

  fd_adns_delete( fd_adns_leave( adns ) );
  if( FD_LIKELY( netdb_opened ) ) fd_netdb_close_fds();
}
