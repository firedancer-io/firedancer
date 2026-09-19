#include "fd_shred_dest_resolver.h"

#include "../../util/net/fd_ip4.h"

#include <string.h>

void
fd_shred_resolve_additional_destinations( char const                  endpoints[][ FD_HOSTPORT_BUF_MAX ],
                                          ulong                       endpoint_cnt,
                                          char const *                config_key,
                                          fd_shred_dest_weighted_t * out ) {
  FD_TEST( endpoint_cnt<=FD_DNS_RESOLVE_PEERS_MAX );

  char  dns_peers[ FD_DNS_RESOLVE_PEERS_MAX ][ FD_HOSTPORT_BUF_MAX ];
  uchar dns_idx  [ FD_DNS_RESOLVE_PEERS_MAX ];
  ulong dns_cnt = 0UL;
  for( ulong i=0UL; i<endpoint_cnt; i++ ) {
    char const * endpoint = endpoints[ i ];
    char const * colon    = strchr( endpoint, ':' );
    if( FD_UNLIKELY( !colon || colon[ 1UL+strspn( colon+1, "0123456789" ) ] ) )
      FD_LOG_ERR(( "invalid [%s] entry \"%s\": expected host:port", config_key, endpoint ));

    char hostname[ FD_FQDN_BUF_MAX ];
    fd_dns_peer_parse( endpoint, config_key, hostname, &out[ i ].port, NULL );
    out[ i ].port = fd_ushort_bswap( out[ i ].port );
    if( FD_LIKELY( (ulong)(colon-endpoint)<=15UL && fd_cstr_to_ip4_addr( hostname, &out[ i ].ip4 ) ) ) continue;

    fd_memcpy( dns_peers[ dns_cnt ], endpoint, sizeof(dns_peers[ dns_cnt ]) );
    dns_idx[ dns_cnt ] = (uchar)i;
    dns_cnt++;
  }

  if( !dns_cnt ) return;

  fd_ip4_port_t resolved[ FD_DNS_RESOLVE_PEERS_MAX ];
  fd_dns_resolve_peers( dns_peers[ 0 ], sizeof(dns_peers[ 0 ]), dns_cnt, config_key, resolved );
  for( ulong i=0UL; i<dns_cnt; i++ ) out[ dns_idx[ i ] ].ip4 = resolved[ i ].addr;
}
