#include "tiles.h"

#include <stdarg.h>
#include <stdio.h>

FD_FN_CONST fd_tile_config_t *
fd_topo_tile_to_config( fd_topo_tile_t const * tile ) {
  switch( tile->kind ) {
    case FD_TOPO_TILE_KIND_NET:    return &fd_tile_net;
    case FD_TOPO_TILE_KIND_NETMUX: return &fd_tile_netmux;
    case FD_TOPO_TILE_KIND_QUIC:   return &fd_tile_quic;
    case FD_TOPO_TILE_KIND_VERIFY: return &fd_tile_verify;
    case FD_TOPO_TILE_KIND_DEDUP:  return &fd_tile_dedup;
    case FD_TOPO_TILE_KIND_PACK:   return &fd_tile_pack;
    case FD_TOPO_TILE_KIND_BANK:   return &fd_tile_bank;
    case FD_TOPO_TILE_KIND_POH:    return &fd_tile_poh;
    case FD_TOPO_TILE_KIND_SHRED:  return &fd_tile_shred;
    case FD_TOPO_TILE_KIND_STORE:  return &fd_tile_store;
    case FD_TOPO_TILE_KIND_SIGN:   return &fd_tile_sign;
    case FD_TOPO_TILE_KIND_METRIC: return &fd_tile_metric;
    default: FD_LOG_ERR(( "unknown tile kind %lu", tile->kind ));
  }
}

void *
fd_wksp_pod_map1( uchar const * pod,
                  char const *  format,
                  ... ) {
  char s[ 256 ];

  va_list args;
  va_start( args, format );
  int len = vsnprintf( s, sizeof(s), format, args );
  va_end( args );
  if( FD_UNLIKELY( len < 0 ) )
    FD_LOG_ERR(( "vsnprintf failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( (ulong)len >= sizeof(s) ) )
    FD_LOG_ERR(( "vsnprintf truncated output (maxlen=%lu)", sizeof(s) ));

  return fd_wksp_pod_map( pod, s );
}
