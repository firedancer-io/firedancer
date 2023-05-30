#ifndef HEADER_fd_src_app_frank_fd_frank_turbine_common_h
#define HEADER_fd_src_app_frank_fd_frank_turbine_common_h

#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

#include <stdio.h> /* Needed for I/O on private key */

struct __attribute__((packed)) fd_shred_pkt {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];

  uchar payload[FD_SHRED_MAX_SZ];
};
typedef struct fd_shred_pkt fd_shred_pkt_t;

static inline int
send_loop_helper( fd_aio_t const * tx_aio,
                  fd_aio_pkt_info_t const * data,
                  ulong cnt ) {
  ulong total_sent = 0UL;
  while( total_sent<cnt ) {
    ulong okay_cnt = 0UL;
    int send_rc = fd_aio_send( tx_aio, data+total_sent, cnt-total_sent, &okay_cnt );
    if( FD_LIKELY( send_rc>=0 ) ) return send_rc;
    if( FD_UNLIKELY( send_rc!=FD_AIO_ERR_AGAIN ) ) return send_rc;
    total_sent += okay_cnt;
  }
  return 0;

}

struct fd_net_endpoint {
  uchar  mac[6];
  /* Both of these are stored in network byte order */
  ushort port;
  uint   ip4;
};
typedef struct fd_net_endpoint fd_net_endpoint_t;

static inline fd_net_endpoint_t *
fd_net_endpoint_load( uchar const * pod, fd_net_endpoint_t * out ) {
  char const * _mac  = fd_pod_query_cstr(   pod, "mac",       NULL );
  char const * _ip   = fd_pod_query_cstr(   pod, "ip",        NULL );
  ushort        _port = fd_pod_query_ushort( pod, "port", (ushort)0 );

  if( FD_UNLIKELY( !_mac  ) ) { FD_LOG_WARNING(( "mac not found"  )); return NULL; }
  if( FD_UNLIKELY( !_ip   ) ) { FD_LOG_WARNING(( "ip not found"   )); return NULL; }
  if( FD_UNLIKELY( !_port ) ) { FD_LOG_WARNING(( "port not found" )); return NULL; }

  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _mac, out->mac ) ) ) {
    FD_LOG_WARNING(( "Parsing %s as mac failed", _mac ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _ip, &out->ip4 ) ) ) {
    FD_LOG_WARNING(( "Parsing %s as ip4 failed", _ip ));
    return NULL;
  }

  out->ip4  = fd_uint_bswap(   out->ip4 );
  out->port = fd_ushort_bswap( _port    );

  if( FD_UNLIKELY( fd_ip4_addr_is_mcast( out->ip4 ) ) ) {
    fd_eth_mac_ip4_mcast( out->mac, out->ip4 );
    FD_LOG_NOTICE(( "Multicast address " FD_IP4_ADDR_FMT " detected.  Rewriting mac to " FD_ETH_MAC_FMT, FD_IP4_ADDR_FMT_ARGS( out->ip4 ), FD_ETH_MAC_FMT_ARGS( out->mac ) ));
  }

  return out;
}

static inline void
read_key( char const * key_path, uchar * shred_key ) {
  FILE * key_file = fopen( key_path, "r" );
  if( FD_UNLIKELY( !key_file ) ) FD_LOG_ERR(( "Opening key file (%s) failed", key_path ));

  if( FD_UNLIKELY( 1!=fscanf( key_file, "[%hhu", &shred_key[0] ) ) ) FD_LOG_ERR(( "parsing key file failed at pos=0" ));
  for( ulong i=1UL; i<64UL; i++ ) if( FD_UNLIKELY( 1!=fscanf( key_file, ",%hhu", &shred_key[i] ) ) ) FD_LOG_ERR(( "parsing key file failed at pos=%lu", i ));
  fclose( key_file );
}


#endif /* HEADER_fd_src_app_frank_fd_frank_turbine_common_h */
